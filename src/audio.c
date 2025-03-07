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

#include <stdio.h>
#include <string.h>

#include "confession.h"

/*
 * Initialize portaudio by opening the default devices in full-duplex mode
 * getting both capture and playback.
 */
void
confessions_audio_initialize(struct state *state)
{
	PaError			err;

	PRECOND(state != NULL);
	PRECOND(state->stream == NULL);

	if ((err = Pa_Initialize()) != paNoError)
		fatal("Pa_Initialize: %d", err);

	if ((err = Pa_OpenDefaultStream(&state->stream,
	    CONFESSIONS_CHANNEL_COUNT, CONFESSIONS_CHANNEL_COUNT, paInt16,
	    CONFESSIONS_SAMPLE_RATE, CONFESSIONS_SAMPLE_COUNT,
	    confessions_audio_callback, state)) != paNoError)
		fatal("Pa_OpenDefaultStream: %s", Pa_GetErrorText(err));

	if ((err = Pa_StartStream(state->stream)) != paNoError)
		fatal("Pa_StartStream: %s", Pa_GetErrorText(err));
}

/*
 * The portaudio callback when the library requires data and wants to give
 * us data that we should transport.
 */
int
confessions_audio_callback(const void *input, void *output,
    unsigned long frames, const PaStreamCallbackTimeInfo *info,
    PaStreamCallbackFlags flags, void *udata)
{
	struct state	*state;
	size_t		samples;

	PRECOND(input != NULL);
	PRECOND(output != NULL);
	PRECOND(info != NULL);
	PRECOND(udata != NULL);

	state = udata;
	memset(output, 0, frames * CONFESSIONS_SAMPLE_SIZE);

	if (state->tx_buf == NULL) {
		state->tx_offset = 0;
		state->tx_buf = confessions_ring_dequeue(&state->buffers);
	}

	if (state->tx_buf != NULL) {
		samples = CONFESSIONS_SAMPLE_COUNT -
		    (state->tx_offset / CONFESSIONS_SAMPLE_SIZE);
		if (frames < samples)
			samples = frames;

		memcpy(&state->tx_buf[state->tx_offset], input,
		    samples * CONFESSIONS_SAMPLE_SIZE),
		state->tx_offset += (samples * CONFESSIONS_SAMPLE_SIZE);

		if (state->tx_offset == CONFESSIONS_SAMPLE_BYTES) {
			confessions_ring_queue(&state->encrypt, state->tx_buf);
			state->tx_buf = NULL;
		}
	}

	if (state->rx_buf == NULL) {
		state->rx_offset = 0;
		state->rx_buf = confessions_ring_dequeue(&state->playback);
	}

	if (state->rx_buf != NULL) {
		samples = CONFESSIONS_SAMPLE_COUNT -
		    (state->rx_offset / CONFESSIONS_SAMPLE_SIZE);
		if (frames < samples)
			samples = frames;

		memcpy(output, &state->rx_buf[state->rx_offset],
		    samples * CONFESSIONS_SAMPLE_SIZE);
		state->rx_offset += (samples * CONFESSIONS_SAMPLE_SIZE);

		if (state->rx_offset == CONFESSIONS_SAMPLE_BYTES) {
			confessions_ring_queue(&state->buffers, state->rx_buf);
			state->rx_buf = NULL;
		}
	}

	return (0);
}

/*
 * Processing audio packets from capture and feed them into all tunnels.
 */
void
confessions_audio_process(struct state *state)
{
	u_int8_t		*ptr;
	struct tunnel		*tun;
	u_int8_t		buf[1024];
	int			nbytes, idx;
	opus_int16		opus[CONFESSIONS_SAMPLE_COUNT];

	PRECOND(state != NULL);

	while ((ptr = confessions_ring_dequeue(&state->encrypt)) != NULL) {
		for (idx = 0; idx < CONFESSIONS_SAMPLE_COUNT; idx++)
			opus[idx] = ptr[2 * idx + 1] << 8 | ptr[2 * idx];

		confessions_ring_queue(&state->buffers, ptr);

		LIST_FOREACH(tun, &state->tunnels, list) {
			if ((nbytes = opus_encode(tun->encoder, opus,
			    CONFESSIONS_SAMPLE_COUNT, buf, sizeof(buf))) < 0) {
				printf("opus_encode: %d\n", nbytes);
				continue;
			}

			if (kyrka_heaven_input(tun->ctx, buf, nbytes) == -1) {
				if (kyrka_last_error(tun->ctx) !=
				    KYRKA_ERROR_NO_TX_KEY) {
					fatal("heaven input failed");
				}
			}
		}
	}
}
