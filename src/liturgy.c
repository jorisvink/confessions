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

#if !defined(PLATFORM_WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libkyrka/libkyrka.h>

#include "confession.h"

static void	liturgy_event(KYRKA *, union kyrka_event *, void *);
static void	liturgy_cathedral_send(const void *, size_t, u_int64_t, void *);

/*
 * Initialize the given tunnel in liturgy mode, configuring a cathedral
 * so we can use autodiscovery to create new tunnels.
 */
void
confessions_liturgy_initialize(struct state *state)
{
	const char		*kek;

	PRECOND(state != NULL);

	state->liturgy.ctx = kyrka_ctx_alloc(liturgy_event, &state->liturgy);
	if (state->liturgy.ctx == NULL)
		fatal("failed to allocate new KYRKA context");

	kek = state->cathedral.kek;
	state->cathedral.kek = NULL;

	state->cathedral.udata = &state->liturgy;
	state->cathedral.send = liturgy_cathedral_send;

	if (kyrka_cathedral_config(state->liturgy.ctx,
	    &state->cathedral) == -1) {
		fatal("cathedral config: %d",
		    kyrka_last_error(state->liturgy.ctx));
	}

	state->cathedral.kek = kek;
	state->liturgy.mstate = state;

	confessions_tunnel_socket(state, &state->liturgy);
}

/*
 * Send a liturgy notification to the cathedral when we have too.
 */
void
confessions_liturgy_manage(struct state *state)
{
	PRECOND(state != NULL);
	PRECOND(state->mode == CONFESSIONS_MODE_LITURGY);

	if (state->now >= state->liturgy.cathedral_notify) {
		state->liturgy.cathedral_notify = state->now + 1;

		if (kyrka_cathedral_liturgy(state->liturgy.ctx, NULL, 0) == -1)
			fatal("failed to send liturgy to cathedral");
	}
}

/*
 * We receive a liturgy response for each time we submit a liturgy request.
 * This response includes a list of all peers that are currently available
 * in our flock. From this list we create new tunnels and get them up
 * and running.
 */
static void
liturgy_event(KYRKA *ctx, union kyrka_event *evt, void *udata)
{
	int				idx;
	struct kyrka_cathedral_cfg	cfg;
	struct tunnel			*tun;
	struct state			*state;

	PRECOND(ctx != NULL);
	PRECOND(evt != NULL);
	PRECOND(udata != NULL);

	tun = udata;
	state = tun->mstate;

	if (evt->type != KYRKA_EVENT_LITURGY_RECEIVED) {
		printf("[liturgy]: ignored event %u\n", evt->type);
		return;
	}

	for (idx = 1; idx < KYRKA_PEERS_PER_FLOCK; idx++) {
		if (state->peers[idx] == 0 && evt->liturgy.peers[idx] == 1) {
			memcpy(&cfg, &state->cathedral, sizeof(cfg));
			cfg.tunnel = (cfg.tunnel << 8) | idx;
			confessions_tunnel_alloc(state, &cfg);
			state->peers[idx] = 1;
		}

		if (state->peers[idx] == 1 && evt->liturgy.peers[idx] == 0) {
			LIST_FOREACH(tun, &state->tunnels, list) {
				if ((tun->id & 0xff) == idx)
					break;
			}

			if (tun == NULL)
				fatal("could not find active tunnel %d", idx);

			confessions_tunnel_remove(tun);
			state->peers[idx] = 0;
		}
	}
}

/*
 * We received an encrypted liturgy message we should submit to our
 * cathedral, so lets do so.
 */
static void
liturgy_cathedral_send(const void *data, size_t len, u_int64_t msg, void *udata)
{
	struct sockaddr_in	sin;
	struct tunnel		*tun;
	struct state		*state;

	PRECOND(data != NULL);
	PRECOND(udata != NULL);

	tun = udata;
	state = tun->mstate;

	sin.sin_family = AF_INET;
	sin.sin_port = state->cathedral_port;
	sin.sin_addr.s_addr = state->cathedral_ip;

	if (sendto(tun->fd,
	    data, len, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("sendto: %s", strerror(errno));
}
