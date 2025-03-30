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
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <libkyrka/libkyrka.h>

#include "confession.h"

static void	tunnel_socket_read(struct tunnel *);
static void	tunnel_opus_initialize(struct tunnel *);
static void	tunnel_event(KYRKA *, union kyrka_event *, void *);
static void	tunnel_clear_send(const void *, size_t, u_int64_t, void *);
static void	tunnel_crypto_send(const void *, size_t, u_int64_t, void *);
static void	tunnel_cathedral_send(const void *, size_t, u_int64_t, void *);

/*
 * Allocate and setup the given tunnel context with either the given
 * cathedral options or a direct shared secret to load.
 */
void
confessions_tunnel_alloc(struct state *state, struct kyrka_cathedral_cfg *cfg)
{
	struct tunnel		*tun;

	PRECOND(state != NULL);
	/* cfg is optional. */

	if ((tun = calloc(1, sizeof(*tun))) == NULL)
		fatal("failed to calloc new tunnel");

	if ((tun->ctx = kyrka_ctx_alloc(tunnel_event, tun)) == NULL)
		fatal("failed to allocate new KYRKA context");

	if (cfg != NULL) {
		cfg->udata = tun;
		cfg->send = tunnel_cathedral_send;
		if (kyrka_cathedral_config(tun->ctx, cfg) == -1)
			fatal("cathedral config: %d",
			    kyrka_last_error(tun->ctx));
	} else {
		if (kyrka_secret_load(tun->ctx, state->secret) == -1)
			fatal("kyrka_secret_load: %d",
			    kyrka_last_error(tun->ctx));
	}

	if (kyrka_heaven_ifc(tun->ctx, tunnel_clear_send, tun) == -1)
		fatal("failed to set heaven interface");

	if (kyrka_purgatory_ifc(tun->ctx, tunnel_crypto_send, tun) == -1)
		fatal("failed to set purgatory interface");

	tun->peer_ip = state->cathedral_ip;
	tun->peer_port = state->cathedral_port;

	tun->seq = 0;
	tun->mstate = state;
	tun->last_rx = state->now;
	tun->state = CONFESSIONS_STATE_PENDING;

	if (cfg != NULL)
		tun->id = cfg->tunnel;

	tunnel_opus_initialize(tun);
	confessions_audio_playback(tun);
	confessions_tunnel_socket(state, tun);

	LIST_INSERT_HEAD(&state->tunnels, tun, list);
}

/*
 * Cleanup all tunnel resources.
 */
void
confessions_tunnel_cleanup(struct state *state)
{
	struct tunnel		*tun;

	PRECOND(state != NULL);

	while ((tun = LIST_FIRST(&state->tunnels)) != NULL)
		confessions_tunnel_remove(tun);
}

/*
 * Remove the given tunnel and cleanup its resources.
 */
void
confessions_tunnel_remove(struct tunnel *tun)
{
	PRECOND(tun != NULL);

	LIST_REMOVE(tun, list);

	(void)close(tun->fd);
	kyrka_ctx_free(tun->ctx);

	Pa_CloseStream(tun->stream);
	opus_encoder_destroy(tun->encoder);
	opus_decoder_destroy(tun->decoder);

	free(tun);
}

/*
 * Called every second to manage the tunnel by checking if we need to
 * offer fresh keys or if the peer timed out somehow.
 */
void
confessions_tunnel_manage(struct state *state, struct tunnel *tun)
{
	PRECOND(state != NULL);
	PRECOND(tun != NULL);

	if (state->mode != CONFESSIONS_MODE_DIRECT &&
	    state->now >= tun->cathedral_notify) {
		tun->cathedral_notify = state->now + 1;

		if (kyrka_cathedral_notify(tun->ctx) == -1)
			fatal("failed to notify cathedral");

		if (kyrka_cathedral_nat_detection(tun->ctx) == -1)
			fatal("failed to send NAT detect");
	}

	if (state->now >= tun->key_refresh) {
		tun->key_send = state->now;
		tun->key_refresh = state->now + 120;

		if (kyrka_key_generate(tun->ctx) == -1)
			fatal("failed to generate key offer");
	}

	if (state->now >= tun->key_send) {
		tun->key_send = state->now + 1;

		if (kyrka_key_offer(tun->ctx) == -1 &&
		    kyrka_last_error(tun->ctx) != KYRKA_ERROR_NO_SECRET) {
			fatal("failed to offer key: %d",
			    kyrka_last_error(tun->ctx));
		}
	}

	if (tun->last_rx != 0 && (state->now - tun->last_rx) >= 30) {
		tun->last_rx = state->now;
		kyrka_peer_timeout(tun->ctx);
	}
}

/*
 * Wait for activity on any of our configured tunnels, up to max 10 ms.
 */
void
confessions_tunnel_wait(struct state *state)
{
	int			nfd;
	struct tunnel		*tun;
	size_t			idx, peers;
	struct pollfd		pfd[1 + KYRKA_PEERS_PER_FLOCK];

	PRECOND(state != NULL);

	peers = 0;

	if (state->mode == CONFESSIONS_MODE_LITURGY) {
		pfd[peers].fd = state->liturgy.fd;
		pfd[peers].events = POLLIN;
		peers++;
	}

	LIST_FOREACH(tun, &state->tunnels, list) {
		pfd[peers].fd = tun->fd;
		pfd[peers].events = POLLIN;
		peers++;

		if (peers >= (1 + KYRKA_PEERS_PER_FLOCK))
			fatal("somehow this didn't make sense");
	}

	if ((nfd = poll(pfd, peers, 10)) == -1) {
		if (errno == EINTR)
			return;
		fatal("poll: %s", strerror(errno));
	}

	if (nfd == 0)
		return;

	if (state->mode == CONFESSIONS_MODE_LITURGY) {
		if (pfd[0].revents & POLLIN)
			tunnel_socket_read(&state->liturgy);
		idx = 1;
	} else {
		idx = 0;
	}

	LIST_FOREACH(tun, &state->tunnels, list) {
		if (pfd[idx++].revents & POLLIN)
			tunnel_socket_read(tun);
	}
}

/*
 * Initialize a new socket for the tunnel context.
 */
void
confessions_tunnel_socket(struct state *state, struct tunnel *tun)
{
	struct sockaddr_in	sin;

	PRECOND(state != NULL);
	PRECOND(tun != NULL);

	if ((tun->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", strerror(errno));

	if (state->mode == CONFESSIONS_MODE_DIRECT) {
		sin.sin_family = AF_INET;
		sin.sin_port = state->local_port;
		sin.sin_addr.s_addr = state->local_ip;

		if (bind(tun->fd,
		    (const struct sockaddr *)&sin, sizeof(sin)) == -1)
			fatal("bind: %s", strerror(errno));
	}
}

/*
 * Initialize the OPUS codec state for the given tunnel.
 */
static void
tunnel_opus_initialize(struct tunnel *tun)
{
	int	err;

	PRECOND(tun != NULL);

	tun->decoder = opus_decoder_create(CONFESSIONS_SAMPLE_RATE,
	    CONFESSIONS_CHANNEL_COUNT, &err);
	if (err != OPUS_OK)
		fatal("failed to create opus decoder: %d", err);

	tun->encoder = opus_encoder_create(CONFESSIONS_SAMPLE_RATE,
	    CONFESSIONS_CHANNEL_COUNT, OPUS_APPLICATION_VOIP, &err);
	if (err != OPUS_OK)
		fatal("failed to create opus encoder: %d", err);

	err = opus_encoder_ctl(tun->encoder, OPUS_SET_BITRATE(OPUS_AUTO));
	if (err != OPUS_OK)
		fatal("failed to set bitrate: %d", err);

	err = opus_encoder_ctl(tun->encoder, OPUS_SET_INBAND_FEC(1));
	if (err != OPUS_OK)
		fatal("failed to enable FEC: %d", err);

	err = opus_encoder_ctl(tun->encoder, OPUS_SET_PACKET_LOSS_PERC(5));
	if (err != OPUS_OK)
		fatal("failed to set expected packet loss");
}

/*
 * We received an event from a tunnel context, look at what it is and
 * act upon the event if needed.
 */
static void
tunnel_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	struct in_addr		in;
	struct tunnel		*tun;
	struct state		*state;

	PRECOND(ctx != NULL);
	PRECOND(evt != NULL);
	PRECOND(udata != NULL);

	tun = udata;
	state = tun->mstate;

	switch (evt->type) {
	case KYRKA_EVENT_TX_ACTIVE:
		/*
		 * A bit of an oxymoron maybe, but when we get an TX active
		 * event it means we received a key offer from the peer.
		 */
		tun->last_rx = state->now;
		printf("[%p] [peer]: online - 0x%08x\n", udata, evt->tx.spi);

		if (tun->peer_id != 0 && tun->peer_id != evt->tx.id) {
			printf("[%p] [peer]: restarted, offering new key\n",
			    udata);
			if (kyrka_key_generate(tun->ctx) == -1) {
				fatal("kyrka_key_generate: %d",
				    kyrka_last_error(tun->ctx));
			}
		}

		tun->peer_id = evt->tx.id;
		tun->state = CONFESSIONS_STATE_ONLINE;
		break;
	case KYRKA_EVENT_RX_ACTIVE:
		if (state->debug) {
			printf("[%p] RX SA active 0x%08x\n",
			    udata, evt->rx.spi);
		}
		break;
	case KYRKA_EVENT_TX_EXPIRED:
		printf("[%p] [peer]: key expired - 0x%08x\n",
		    udata, evt->tx.spi);
		break;
	case KYRKA_EVENT_TX_ERASED:
		printf("[%p] [peer]: inactivity detected - 0x%08x\n",
		    udata, evt->tx.spi);
		tun->peer_ip = state->cathedral_ip;
		tun->peer_port = state->cathedral_port;
		tun->state = CONFESSIONS_STATE_PENDING;
		break;
	case KYRKA_EVENT_PEER_UPDATE:
		if (tun->state != CONFESSIONS_STATE_ONLINE) {
			printf("[%p] [peer]: ignoring p2p discovery for now\n",
			    udata);
			break;
		}

		in.s_addr = evt->peer.ip;
		if (tun->peer_ip != evt->peer.ip ||
		    tun->peer_port != evt->peer.port) {
			tun->peer_ip = evt->peer.ip;
			tun->peer_port = evt->peer.port;

			if (tun->peer_ip != state->cathedral_ip &&
			    tun->peer_port != state->cathedral_port) {
				printf("[%p] [peer]: p2p discovery %s:%u\n",
				    udata, inet_ntoa(in), evt->peer.port);
			}
		}
		break;
	case KYRKA_EVENT_AMBRY_RECEIVED:
		printf("[%p] [ambry]: generation 0x%08x active\n",
		    udata, evt->ambry.generation);
		break;
	}
}

/*
 * Attempt to read up to 32 packets on our tunnel socket.
 */
static void
tunnel_socket_read(struct tunnel *tun)
{
	int		idx;
	ssize_t		ret;
	u_int8_t	pkt[1500];

	PRECOND(tun != NULL);

	for (idx = 0; idx < 32; idx++) {
		ret = recv(tun->fd, pkt, sizeof(pkt), MSG_DONTWAIT);
		if (ret == -1) {
			if (errno != EAGAIN)
				fatal("recv failed: %s", strerror(errno));
			break;
		}

		if (ret == 0)
			break;

		tun->rx_pkt++;
		tun->rx_len += ret;

		if (kyrka_purgatory_input(tun->ctx, pkt, ret) == -1) {
			fatal("purgatory input: %d",
			    kyrka_last_error(tun->ctx));
		}
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
	struct tunnel		*tun;
	struct state		*state;
	int			idx, samples;
	opus_int16		pcm[CONFESSIONS_SAMPLE_COUNT];

	PRECOND(data != NULL);
	PRECOND(udata != NULL);

	tun = udata;
	state = tun->mstate;

	tun->last_rx = state->now;

	if (seq != tun->seq + 1) {
		if (state->debug)
			printf("[net]: packet loss detected\n");

		tun->seq = seq;
		if ((samples = opus_decode(tun->decoder,
		    NULL, 0, pcm, CONFESSIONS_SAMPLE_COUNT, 0)) < 0) {
			printf("[net]: opus_decode: %d\n", samples);
			return;
		}
	} else {
		tun->seq = seq;
		if ((samples = opus_decode(tun->decoder,
		    data, len, pcm, CONFESSIONS_SAMPLE_COUNT, 0)) < 0) {
			printf("[net]: opus_decode: %d\n", samples);
			return;
		}
	}

	if ((ptr = confessions_ring_dequeue(&state->buffers)) == NULL) {
		printf("[net]: out of buffers\n");
		return;
	}

	for (idx = 0; idx < samples; idx++) {
		ptr[2 * idx] = pcm[idx] & 0xff;
		ptr[2 * idx + 1] = (pcm[idx] >> 8) & 0xff;
	}

	confessions_ring_queue(&tun->playback, ptr);
}

/*
 * Callback from libkyrka when ciphertext is available to be sent.
 * We send it to the currently set peer ip and port.
 */
static void
tunnel_crypto_send(const void *data, size_t len, u_int64_t seq, void *udata)
{
	struct sockaddr_in	sin;
	struct tunnel		*tun;

	PRECOND(data != NULL);
	PRECOND(udata != NULL);

	tun = udata;

	sin.sin_family = AF_INET;
	sin.sin_port = tun->peer_port;
	sin.sin_addr.s_addr = tun->peer_ip;

	if (sendto(tun->fd,
	    data, len, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("sendto: %s", strerror(errno));

	tun->tx_pkt++;
	tun->tx_len += len;
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
	struct tunnel		*tun;
	struct state		*state;

	PRECOND(data != NULL);
	PRECOND(udata != NULL);

	tun = udata;
	state = tun->mstate;

	port = ntohs(state->cathedral_port);
	if (msg == KYRKA_CATHEDRAL_NAT_MAGIC)
		port++;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = state->cathedral_ip;

	if (sendto(tun->fd,
	    data, len, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("sendto: %s", strerror(errno));
}
