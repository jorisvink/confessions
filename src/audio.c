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

static int	audio_capture_callback(const void *, void *,
		    unsigned long, const PaStreamCallbackTimeInfo *,
		    PaStreamCallbackFlags, void *);
static int	audio_playback_callback(const void *, void *,
		    unsigned long, const PaStreamCallbackTimeInfo *,
		    PaStreamCallbackFlags, void *);

/*
 * Initialize portaudio for capture so that we can get audio frames
 * that can be queued up for encryption.
 */
void
confessions_audio_init(struct state *state)
{
	PaError			err;
	PaStreamParameters	params;

	PRECOND(state != NULL);
	PRECOND(state->stream == NULL);

	if ((err = Pa_Initialize()) != paNoError)
		fatal("Pa_Initialize: %d", err);

	params.suggestedLatency = 0;
	params.sampleFormat = paInt16;
	params.hostApiSpecificStreamInfo = NULL;
	params.device = Pa_GetDefaultInputDevice();
	params.channelCount = CONFESSIONS_CHANNEL_COUNT;

	if ((err = Pa_OpenStream(&state->stream, &params, NULL,
	    CONFESSIONS_SAMPLE_RATE, CONFESSIONS_SAMPLE_COUNT, 0,
	    audio_capture_callback, state)) != paNoError)
		fatal("Pa_OpenDefaultStream: %s", Pa_GetErrorText(err));

	if ((err = Pa_StartStream(state->stream)) != paNoError)
		fatal("Pa_StartStream: %s", Pa_GetErrorText(err));

	confessions_ring_init(&state->encrypt, CONFESSIONS_BUF_COUNT);
}

/*
 * Initialize portaudio for the given tunnel object, right now it opens
 * in full-duplex mode getting both capture and playback.
 */
void
confessions_audio_playback(struct tunnel *tun)
{
	PaError			err;
	PaStreamParameters	params;

	PRECOND(tun != NULL);
	PRECOND(tun->stream == NULL);

	params.suggestedLatency = 0;
	params.sampleFormat = paInt16;
	params.hostApiSpecificStreamInfo = NULL;
	params.device = Pa_GetDefaultOutputDevice();
	params.channelCount = CONFESSIONS_CHANNEL_COUNT;

	if ((err = Pa_OpenStream(&tun->stream, NULL, &params,
	    CONFESSIONS_SAMPLE_RATE, CONFESSIONS_SAMPLE_COUNT, 0,
	    audio_playback_callback, tun)) != paNoError)
		fatal("Pa_OpenDefaultStream: %s", Pa_GetErrorText(err));

	if ((err = Pa_StartStream(tun->stream)) != paNoError)
		fatal("Pa_StartStream: %s", Pa_GetErrorText(err));

	confessions_ring_init(&tun->playback, CONFESSIONS_BUF_COUNT);
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

/*
 * Callback for audio capture, we read frames from the input parameter
 * and place them into a buffer that is queued up for encryption by
 * all tunnels.
 */
static int
audio_capture_callback(const void *input, void *output,
    unsigned long frames, const PaStreamCallbackTimeInfo *info,
    PaStreamCallbackFlags flags, void *udata)
{
	struct state		*state;
	size_t			samples;

	PRECOND(input != NULL);
	/* don't care for output. */
	PRECOND(info != NULL);
	PRECOND(udata != NULL);

	state = udata;

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

	return (0);
}

/*
 * Callback for audio playback (per-tunnel). We pop a buffer from the
 * playback queue and write it to the output parameter.
 */
static int
audio_playback_callback(const void *input, void *output,
    unsigned long frames, const PaStreamCallbackTimeInfo *info,
    PaStreamCallbackFlags flags, void *udata)
{
	struct tunnel		*tun;
	struct state		*state;
	size_t			samples;

	/* don't care for input. */
	PRECOND(output != NULL);
	PRECOND(info != NULL);
	PRECOND(udata != NULL);

	tun = udata;
	state = tun->mstate;

	memset(output, 0, frames * CONFESSIONS_SAMPLE_SIZE);

	if (tun->rx_buf == NULL) {
		tun->rx_offset = 0;
		tun->rx_buf = confessions_ring_dequeue(&tun->playback);
	}

	if (tun->rx_buf != NULL) {
		samples = CONFESSIONS_SAMPLE_COUNT -
		    (tun->rx_offset / CONFESSIONS_SAMPLE_SIZE);
		if (frames < samples)
			samples = frames;

		memcpy(output, &tun->rx_buf[tun->rx_offset],
		    samples * CONFESSIONS_SAMPLE_SIZE);
		tun->rx_offset += (samples * CONFESSIONS_SAMPLE_SIZE);

		if (tun->rx_offset == CONFESSIONS_SAMPLE_BYTES) {
			confessions_ring_queue(&state->buffers, tun->rx_buf);
			tun->rx_buf = NULL;
		}
	}

	return (0);
}
