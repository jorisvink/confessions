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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libkyrka/libkyrka.h>

#include "confession.h"

/*
 * Initialize the network goo by setting up our sending and receiving
 * UDP socket we will use for all transport.
 */
void
confessions_network_initialize(struct state *state)
{
	struct sockaddr_in	sin;

	PRECOND(state != NULL);

	state->cathedral_ip = state->peer_ip;
	state->cathedral_port = state->peer_port;

	if ((state->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", strerror(errno));

	if (state->mode == CONFESSIONS_MODE_DIRECT) {
		sin.sin_family = AF_INET;
		sin.sin_port = state->local_port;
		sin.sin_addr.s_addr = state->local_ip;

		if (bind(state->fd,
		    (const struct sockaddr *)&sin, sizeof(sin)) == -1)
			fatal("bind: %s", strerror(errno));
	}
}

/*
 * Attempt to read up to 32 UDP packets, passing them into libkyrka as we go.
 */
void
confessions_network_input(struct state *state)
{
	size_t			idx;
	ssize_t			ret;
	u_int8_t		pkt[1500];

	PRECOND(state != NULL);

	for (idx = 0; idx < 32; idx++) {
		ret = recv(state->fd, pkt, sizeof(pkt), MSG_DONTWAIT);
		if (ret == -1) {
			if (errno != EAGAIN)
				fatal("recv failed: %s", strerror(errno));
			break;
		}

		if (ret == 0)
			break;

		state->rx_pkt++;
		state->rx_len += ret;

		if (kyrka_purgatory_input(state->tunnel, pkt, ret) == -1) {
			fatal("purgatory input: %d",
			    kyrka_last_error(state->tunnel));
		}
	}
}
