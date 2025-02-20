/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libkyrka/libkyrka.h>

#include "confession.h"

static void	tunnel_event(KYRKA *, union kyrka_event *, void *);
static void	tunnel_clear_send(const void *, size_t, u_int64_t, void *);
static void	tunnel_crypto_send(const void *, size_t, u_int64_t, void *);
static void	tunnel_cathedral_send(const void *, size_t, u_int64_t, void *);

/*
 * Initialize our KYRKA tunnel object, configuring it with either a
 * shared secret or a cathedral configuration.
 */
void
confessions_tunnel_initialize(struct state *state,
    struct kyrka_cathedral_cfg *cfg)
{
	PRECOND(state != NULL);
	/* cfg is optional. */

	state->seq = 0;

	if ((state->tunnel = kyrka_ctx_alloc(tunnel_event, state)) == NULL)
		fatal("failed to allocate new KYRKA context");

	if (cfg != NULL) {
		cfg->udata = state;
		cfg->send = tunnel_cathedral_send;
		if (kyrka_cathedral_config(state->tunnel, cfg) == -1)
			fatal("cathedral config: %d",
			    kyrka_last_error(state->tunnel));
	} else {
		if (kyrka_secret_load(state->tunnel, state->secret) == -1)
			fatal("kyrka_secret_load: %d",
			    kyrka_last_error(state->tunnel));
	}

	if (kyrka_heaven_ifc(state->tunnel, tunnel_clear_send, state) == -1)
		fatal("failed to set heaven interface");

	if (kyrka_purgatory_ifc(state->tunnel, tunnel_crypto_send, state) == -1)
		fatal("failed to set purgatory interface");

	state->last_rx = state->now;
}

/*
 * Called every second to manage the tunnel by checking if we need to
 * offer fresh keys or if the peer timed out somehow.
 */
void
confessions_tunnel_manage(struct state *state)
{
	PRECOND(state != NULL);

	if (state->mode == CONFESSIONS_MODE_CATHEDRAL &&
	    state->now >= state->cathedral_notify) {
		state->cathedral_notify = state->now + 5;

		if (kyrka_cathedral_notify(state->tunnel) == -1)
			fatal("failed to notify cathedral");

		if (kyrka_cathedral_nat_detection(state->tunnel) == -1)
			fatal("failed to send NAT detect");
	}

	if (state->now >= state->key_refresh) {
		state->key_send = state->now;
		state->key_refresh = state->now + 120;
		if (kyrka_key_generate(state->tunnel) == -1)
			fatal("failed to generate key offer");
	}

	if (state->now >= state->key_send) {
		state->key_send = state->now + 1;
		if (kyrka_key_offer(state->tunnel) == -1 &&
		    kyrka_last_error(state->tunnel) != KYRKA_ERROR_NO_SECRET) {
			fatal("failed to offer key: %d",
			    kyrka_last_error(state->tunnel));
		}
	}

	if (state->last_rx != 0 && (state->now - state->last_rx) >= 5)
		kyrka_peer_timeout(state->tunnel);
}

/*
 * We received an event from a KYRKA context, look at what it is and
 * act upon the event if needed.
 */
static void
tunnel_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	struct in_addr		in;
	struct state		*state;

	PRECOND(ctx != NULL);
	PRECOND(evt != NULL);
	PRECOND(udata != NULL);

	state = udata;

	switch (evt->type) {
	case KYRKA_EVENT_TX_ACTIVE:
		/*
		 * A bit of an oxymoron maybe, but when we get an TX active
		 * event it means we received a key offer from the peer.
		 */
		state->last_rx = state->now;
		printf("TX SA active 0x%08x\n", evt->tx.spi);
		break;
	case KYRKA_EVENT_RX_ACTIVE:
		printf("RX SA active 0x%08x\n", evt->rx.spi);
		break;
	case KYRKA_EVENT_TX_EXPIRED:
		printf("TX SA 0x%08x expired\n", evt->tx.spi);
		break;
	case KYRKA_EVENT_TX_ERASED:
		printf("TX SA 0x%08x erased, peer inactive\n", evt->tx.spi);
		break;
	case KYRKA_EVENT_PEER_UPDATE:
		in.s_addr = evt->peer.ip;
		state->peer_ip = evt->peer.ip;
		state->peer_port = evt->peer.port;

		if (state->peer_ip != state->cathedral_ip &&
		    state->peer_port != state->cathedral_port) {
			printf("p2p active %s:%u\n",
			    inet_ntoa(in), evt->peer.port);
		}
		break;
	}
}

/*
 * Callback from libkyrka when plaintext data is available to us.
 * The plaintext data is voice so decode it via OPUS and pass it
 * to audio via the playback ring.
 */
static void
tunnel_clear_send(const void *data, size_t len, u_int64_t seq, void *udata)
{
	u_int8_t		*ptr;
	struct state		*state;
	int			idx, samples;
	opus_int16		pcm[CONFESSIONS_SAMPLE_COUNT];

	PRECOND(data != NULL);
	PRECOND(udata != NULL);

	state = udata;
	state->last_rx = state->now;

	if (seq != state->seq + 1) {
		printf(">> packet loss detected\n");
		if ((samples = opus_decode(state->decoder,
		    NULL, 0, pcm, CONFESSIONS_SAMPLE_COUNT, 0)) < 0) {
			printf("opus_decode: %d\n", samples);
			return;
		}
	} else {
		if ((samples = opus_decode(state->decoder,
		    data, len, pcm, CONFESSIONS_SAMPLE_COUNT, 0)) < 0) {
			printf("opus_decode: %d\n", samples);
			return;
		}
	}

	if ((ptr = confessions_ring_dequeue(&state->buffers)) == NULL) {
		printf("%s: out of buffers\n", __func__);
		return;
	}

	state->seq = seq;

	for (idx = 0; idx < samples; idx++) {
		ptr[2 * idx] = pcm[idx] & 0xff;
		ptr[2 * idx + 1] = (pcm[idx] >> 8) & 0xff;
	}

	confessions_ring_queue(&state->playback, ptr);
}

/*
 * Callback from libkyrka when ciphertext is available to be sent.
 * We send it to the currently set peer ip and port.
 */
static void
tunnel_crypto_send(const void *data, size_t len, u_int64_t seq, void *udata)
{
	struct sockaddr_in	sin;
	struct state		*state;

	PRECOND(data != NULL);
	PRECOND(udata != NULL);

	state = udata;

	sin.sin_family = AF_INET;
	sin.sin_port = state->peer_port;
	sin.sin_addr.s_addr = state->peer_ip;

	if (sendto(state->fd,
	    data, len, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("sendto: %s", strerror(errno));

	state->tx_pkt++;
	state->tx_len += len;
}

/*
 * Callback from libkyrka when cathedral data is ready to be sent.
 * We make sure we send it to the correct cathedral ip and port.
 */
static void
tunnel_cathedral_send(const void *data, size_t len, u_int64_t msg, void *udata)
{
	struct sockaddr_in	sin;
	u_int16_t		port;
	struct state		*state;

	PRECOND(data != NULL);
	PRECOND(udata != NULL);

	state = udata;

	port = ntohs(state->cathedral_port);

	if (msg == KYRKA_CATHEDRAL_NAT_MAGIC)
		port++;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = state->cathedral_ip;

	if (sendto(state->fd,
	    data, len, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("sendto: %s", strerror(errno));
}
