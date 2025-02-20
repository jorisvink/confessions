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
#include <inttypes.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <opus.h>
#include <portaudio.h>
#include <libkyrka/libkyrka.h>

#if defined(__arm64__) || defined(__aarch64__)
#define confessions_cpu_pause()					\
	do {							\
		__asm__ volatile("yield" ::: "memory");		\
	} while (0)
#elif defined(__x86_64__)
#define confessions_cpu_pause()					\
	do {							\
		__asm__ volatile("pause" ::: "memory");		\
	} while (0)
#elif defined(__riscv)
#define confessions_cpu_pause()						\
	do {								\
		__asm__ volatile(".4byte 0x100000F" ::: "memory");	\
	} while (0)
#else
#error "unsupported architecture"
#endif

#define confessions_atomic_read(x)	\
    __atomic_load_n(x, __ATOMIC_SEQ_CST)

#define confessions_atomic_write(x, v)		\
    __atomic_store_n(x, v, __ATOMIC_SEQ_CST)

#define confessions_atomic_cas(x, e, d)		\
    __atomic_compare_exchange(x, e, d, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

#define confessions_atomic_cas_simple(x, e, d)	\
    __sync_bool_compare_and_swap(x, e, d)

#define CONFESSIONS_CHANNEL_COUNT	1
#define CONFESSIONS_SAMPLE_COUNT	960
#define CONFESSIONS_SAMPLE_RATE		48000
#define CONFESSIONS_SAMPLE_SIZE		(sizeof(u_int16_t))

#define CONFESSIONS_RING_MAX		4096
#define CONFESSIONS_BUF_COUNT		1024

#define CONFESSIONS_SAMPLE_BYTES	\
    (CONFESSIONS_SAMPLE_COUNT * CONFESSIONS_SAMPLE_SIZE)
#define CONFESSIONS_BUF_SIZE		\
    (CONFESSIONS_BUF_COUNT * CONFESSIONS_SAMPLE_BYTES)

struct confessions_ring_span {
	volatile u_int32_t	head;
	volatile u_int32_t	tail;
};

struct confessions_ring {
	u_int32_t			elm;
	u_int32_t			mask;
	struct confessions_ring_span	producer;
	struct confessions_ring_span	consumer;
	volatile uintptr_t		data[CONFESSIONS_RING_MAX];
};

void	usage(void) __attribute__((noreturn));
void	fatal(const char *, ...) __attribute__((noreturn));

void	confessions_network_input(void);
void	confessions_tunnel_manage(void);
void	confessions_process_packets(void);
void	confessions_buffers_initialize(void);

void	confessions_opus_initialize(void);
void	confessions_tunnel_initialize(char **);
void	confessions_network_initialize(char **);
void	confessions_tunnel_event(KYRKA *, union kyrka_event *);

void	confessions_clear_output(const void *, size_t, u_int64_t, void *);
void	confessions_crypto_output(const void *, size_t, u_int64_t, void *);
void	confessions_cathedral_output(const void *, size_t, u_int64_t, void *);

void	confessions_audio_initialize(void);
int	confessions_audio_callback(const void *, void *, unsigned long,
	    const PaStreamCallbackTimeInfo *, PaStreamCallbackFlags, void *);

size_t	confessions_ring_pending(struct confessions_ring *);
void	*confessions_ring_dequeue(struct confessions_ring *);
size_t	confessions_ring_available(struct confessions_ring *);
void	confessions_ring_init(struct confessions_ring *, size_t);
int	confessions_ring_queue(struct confessions_ring *, void *);

struct {
	int				fd;

	KYRKA				*tunnel;
	PaStream			*stream;
	OpusEncoder			*encoder;
	OpusDecoder			*decoder;

	time_t				now;
	time_t				last_rx;
	time_t				key_send;
	time_t				key_refresh;
	time_t				cathedral_notify;

	u_int64_t			seq;
	size_t				tx_pkt;
	size_t				tx_len;
	size_t				rx_pkt;
	size_t				rx_len;

	u_int32_t			peer_ip;
	u_int16_t			peer_port;

	u_int32_t			cathedral_ip;
	u_int16_t			cathedral_port;

	size_t				samples_rx;

	u_int8_t			*data;

	struct confessions_ring		buffers;
	struct confessions_ring		encrypt;
	struct confessions_ring		playback;

	u_int8_t			*tx_buf;
	size_t				tx_offset;

	u_int8_t			*rx_buf;
	size_t				rx_offset;
} state;

void
usage(void)
{
	printf("Usage: confessions \\\n");
	printf("          [cathedral ip] [cathedral port] [flock] [tunnel]\n");
	printf("          [identity] [cathedral secret path] [kek path]\n");

	exit(1);
}

int
main(int argc, char **argv)
{
	struct timespec		ts;
	struct pollfd		pfd;
	time_t			stats;

	if (argc != 8)
		usage();

	memset(&state, 0, sizeof(state));

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	state.now = ts.tv_sec;

	confessions_buffers_initialize();
	confessions_audio_initialize();
	confessions_opus_initialize();
	confessions_tunnel_initialize(argv);
	confessions_network_initialize(argv);

	stats = 0;

	pfd.fd = state.fd;
	pfd.events = POLLIN;

	for (;;) {
		(void)clock_gettime(CLOCK_MONOTONIC, &ts);
		state.now = ts.tv_sec;

		if ((state.now - stats) >= 1) {
			stats = state.now;

			printf("rx[%zu, %zu] tx[%zu, %zu]\n",
			    state.rx_pkt, state.rx_len,
			    state.tx_pkt, state.tx_len);

			state.tx_len = 0;
			state.rx_len = 0;
			state.tx_pkt = 0;
			state.rx_pkt = 0;
		}

		confessions_tunnel_manage();

		if (poll(&pfd, 1, 10) == -1)
			fatal("poll: %s", strerror(errno));

		if (pfd.revents & POLLIN)
			confessions_network_input();

		confessions_process_packets();

	}

	(void)close(state.fd);

	opus_encoder_destroy(state.encoder);
	opus_decoder_destroy(state.decoder);

	kyrka_ctx_free(state.tunnel);
	Pa_CloseStream(state.stream);
	Pa_Terminate();

	return (0);
}

void
fatal(const char *fmt, ...)
{
	va_list		args;

	kyrka_emergency_erase();

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

void
confessions_buffers_initialize(void)
{
	size_t			idx;
	u_int8_t		*ptr;

	if ((state.data = malloc(CONFESSIONS_BUF_SIZE)) == NULL)
		fatal("failed to allocate buffer");

	confessions_ring_init(&state.buffers, CONFESSIONS_BUF_COUNT);
	confessions_ring_init(&state.encrypt, CONFESSIONS_BUF_COUNT);
	confessions_ring_init(&state.playback, CONFESSIONS_BUF_COUNT);

	for (idx = 0; idx < CONFESSIONS_BUF_COUNT; idx++) {
		ptr = &state.data[idx * CONFESSIONS_SAMPLE_BYTES];
		confessions_ring_queue(&state.buffers, ptr);
	}
}

void
confessions_audio_initialize(void)
{
	PaError			err;

	if ((err = Pa_Initialize()) != paNoError)
		fatal("Pa_Initialize: %d", err);

	if ((err = Pa_OpenDefaultStream(&state.stream,
	    CONFESSIONS_CHANNEL_COUNT, CONFESSIONS_CHANNEL_COUNT, paInt16,
	    CONFESSIONS_SAMPLE_RATE, CONFESSIONS_SAMPLE_COUNT,
	    confessions_audio_callback, NULL)) != paNoError)
		fatal("Pa_OpenDefaultStream: %s", Pa_GetErrorText(err));

	if ((err = Pa_StartStream(state.stream)) != paNoError)
		fatal("Pa_StartStream: %s", Pa_GetErrorText(err));
}

int
confessions_audio_callback(const void *input, void *output,
    unsigned long frames, const PaStreamCallbackTimeInfo *info,
    PaStreamCallbackFlags flags, void *udata)
{
	size_t		samples;

	memset(output, 0, frames * CONFESSIONS_SAMPLE_SIZE);

	if (state.tx_buf == NULL) {
		state.tx_offset = 0;
		state.tx_buf = confessions_ring_dequeue(&state.buffers);
	}

	if (state.tx_buf != NULL) {
		samples = CONFESSIONS_SAMPLE_COUNT -
		    (state.tx_offset / CONFESSIONS_SAMPLE_SIZE);
		if (frames < samples)
			samples = frames;

		memcpy(&state.tx_buf[state.tx_offset], input,
		    samples * CONFESSIONS_SAMPLE_SIZE),
		state.tx_offset += (samples * CONFESSIONS_SAMPLE_SIZE);

		if (state.tx_offset == CONFESSIONS_SAMPLE_BYTES) {
			confessions_ring_queue(&state.encrypt, state.tx_buf);
			state.tx_buf = NULL;
		}
	}

	if (state.rx_buf == NULL) {
		state.rx_offset = 0;
		state.rx_buf = confessions_ring_dequeue(&state.playback);
	}

	if (state.rx_buf != NULL) {
		samples = CONFESSIONS_SAMPLE_COUNT -
		    (state.rx_offset / CONFESSIONS_SAMPLE_SIZE);
		if (frames < samples)
			samples = frames;

		memcpy(output, &state.rx_buf[state.rx_offset],
		    samples * CONFESSIONS_SAMPLE_SIZE);

		state.rx_offset += (samples * CONFESSIONS_SAMPLE_SIZE);

		if (state.rx_offset == CONFESSIONS_SAMPLE_BYTES) {
			confessions_ring_queue(&state.buffers, state.rx_buf);
			state.rx_buf = NULL;
		}
	}

	return (0);
}

void
confessions_tunnel_initialize(char **argv)
{
	struct kyrka_cathedral_cfg	cfg;

	state.seq = 0;

	if ((state.tunnel = kyrka_ctx_alloc(confessions_tunnel_event)) == NULL)
		fatal("failed to allocate new KYRKA context");

	if (sscanf(argv[3], "%" PRIx64, &cfg.flock) != 1)
		fatal("failed to parse flock '%s'", argv[3]);

	if (sscanf(argv[4], "%hx", &cfg.tunnel) != 1)
		fatal("failed to parse tunnel '%s'", argv[4]);

	if (sscanf(argv[5], "%x", &cfg.identity) != 1)
		fatal("failed to parse identity '%s'", argv[5]);

	cfg.kek = argv[7];
	cfg.secret = argv[6];
	cfg.send = confessions_cathedral_output;

	if (kyrka_cathedral_config(state.tunnel, &cfg) == -1)
		fatal("cathedral config: %d", kyrka_last_error(state.tunnel));

	if (kyrka_heaven_ifc(state.tunnel,
	    confessions_clear_output, NULL) == -1)
		fatal("failed to set heaven interface");

	if (kyrka_purgatory_ifc(state.tunnel,
	    confessions_crypto_output, NULL) == -1)
		fatal("failed to set purgatory interface");

	state.last_rx = state.now;
}

void
confessions_tunnel_event(KYRKA *ctx, union kyrka_event *evt)
{
	struct in_addr		in;

	switch (evt->type) {
	case KYRKA_EVENT_TX_ACTIVE:
		/*
		 * A bit of an oxymoron maybe, but when we get an TX active
		 * event it means we received a key offer from the peer.
		 */
		state.last_rx = state.now;
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
		state.peer_ip = evt->peer.ip;
		state.peer_port = evt->peer.port;
		printf("p2p %s:%u\n", inet_ntoa(in), evt->peer.port);
		break;
	}
}

void
confessions_opus_initialize(void)
{
	int	err;

	state.decoder = opus_decoder_create(CONFESSIONS_SAMPLE_RATE,
	    CONFESSIONS_CHANNEL_COUNT, &err);
	if (err != OPUS_OK)
		fatal("failed to create opus decoder: %d", err);

	state.encoder = opus_encoder_create(CONFESSIONS_SAMPLE_RATE,
	    CONFESSIONS_CHANNEL_COUNT, OPUS_APPLICATION_VOIP, &err);
	if (err != OPUS_OK)
		fatal("failed to create opus encoder: %d", err);

	err = opus_encoder_ctl(state.encoder, OPUS_SET_BITRATE(OPUS_AUTO));
	if (err != OPUS_OK)
		fatal("failed to set bitrate: %d", err);

	err = opus_encoder_ctl(state.encoder, OPUS_SET_INBAND_FEC(1));
	if (err != OPUS_OK)
		fatal("failed to enable FEC: %d", err);

	err = opus_encoder_ctl(state.encoder, OPUS_SET_PACKET_LOSS_PERC(5));
	if (err != OPUS_OK)
		fatal("failed to set expected packet loss");
}

void
confessions_network_initialize(char **argv)
{
	struct sockaddr_in	sin;
	u_int16_t		port;

	if (sscanf(argv[2], "%hu", &port) != 1)
		fatal("failed to parse port '%s'", argv[2]);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(argv[1]);

	state.peer_port = sin.sin_port;
	state.peer_ip = sin.sin_addr.s_addr;

	state.cathedral_port = sin.sin_port;
	state.cathedral_ip = sin.sin_addr.s_addr;

	if ((state.fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", strerror(errno));
}

void
confessions_tunnel_manage(void)
{
	if (state.now >= state.cathedral_notify) {
		state.cathedral_notify = state.now + 5;

		if (kyrka_cathedral_notify(state.tunnel) == -1)
			fatal("failed to notify cathedral");

		if (kyrka_cathedral_nat_detection(state.tunnel) == -1)
			fatal("failed to send NAT detect");
	}

	if (state.now >= state.key_refresh) {
		state.key_send = state.now;
		state.key_refresh = state.now + 120;
		if (kyrka_key_generate(state.tunnel) == -1)
			fatal("failed to generate key offer");
	}

	if (state.now >= state.key_send) {
		state.key_send = state.now + 1;
		if (kyrka_key_offer(state.tunnel) == -1 &&
		    kyrka_last_error(state.tunnel) != KYRKA_ERROR_NO_SECRET) {
			fatal("failed to offer key: %d",
			    kyrka_last_error(state.tunnel));
		}
	}

	if (state.last_rx != 0 && (state.now - state.last_rx) >= 5)
		kyrka_peer_timeout(state.tunnel);
}

void
confessions_process_packets(void)
{
	u_int8_t	*ptr;
	u_int8_t	buf[1024];
	int		nbytes, idx;
	opus_int16	opus[CONFESSIONS_SAMPLE_COUNT];

	while ((ptr = confessions_ring_dequeue(&state.encrypt)) != NULL) {
		for (idx = 0; idx < CONFESSIONS_SAMPLE_COUNT; idx++)
			opus[idx] = ptr[2 * idx + 1] << 8 | ptr[2 * idx];

		confessions_ring_queue(&state.buffers, ptr);

		if ((nbytes = opus_encode(state.encoder,
		    opus, CONFESSIONS_SAMPLE_COUNT, buf, sizeof(buf))) < 0) {
			printf("opus_encode: %d\n", nbytes);
			break;
		}

		if (kyrka_heaven_input(state.tunnel, buf, nbytes) == -1 &&
		    kyrka_last_error(state.tunnel) != KYRKA_ERROR_NO_TX_KEY) {
			fatal("heaven input failed");
		}
	}
}

void
confessions_network_input(void)
{
	size_t			idx;
	ssize_t			ret;
	u_int8_t		pkt[1500];

	for (idx = 0; idx < 32; idx++) {
		if ((ret = recv(state.fd,
		    pkt, sizeof(pkt), MSG_DONTWAIT)) == -1) {
			if (errno != EAGAIN)
				fatal("recv failed: %s", strerror(errno));
			break;
		}

		if (ret == 0)
			break;

		state.rx_pkt++;
		state.rx_len += ret;

		if (kyrka_purgatory_input(state.tunnel, pkt, ret) == -1) {
			fatal("purgatory input: %d",
			    kyrka_last_error(state.tunnel));
		}
	}
}

void
confessions_clear_output(const void *data, size_t len,
    u_int64_t seq, void *udata)
{
	u_int8_t	*ptr;
	int		idx, samples;
	opus_int16	pcm[CONFESSIONS_SAMPLE_COUNT];

	state.last_rx = state.now;

	if (seq != state.seq + 1) {
		printf(">> packet loss detected\n");
		if ((samples = opus_decode(state.decoder,
		    NULL, 0, pcm, CONFESSIONS_SAMPLE_COUNT, 0)) < 0) {
			printf("opus_decode: %d\n", samples);
			return;
		}
	} else {
		if ((samples = opus_decode(state.decoder,
		    data, len, pcm, CONFESSIONS_SAMPLE_COUNT, 0)) < 0) {
			printf("opus_decode: %d\n", samples);
			return;
		}
	}

	if ((ptr = confessions_ring_dequeue(&state.buffers)) == NULL) {
		printf("%s: out of buffers\n", __func__);
		return;
	}

	state.seq = seq;

	for (idx = 0; idx < samples; idx++) {
		ptr[2 * idx] = pcm[idx] & 0xff;
		ptr[2 * idx + 1] = (pcm[idx] >> 8) & 0xff;
	}

	confessions_ring_queue(&state.playback, ptr);
}

void
confessions_crypto_output(const void *data, size_t len,
    u_int64_t seq, void *udata)
{
	struct sockaddr_in		sin;

	sin.sin_family = AF_INET;
	sin.sin_port = state.peer_port;
	sin.sin_addr.s_addr = state.peer_ip;

	if (sendto(state.fd,
	    data, len, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("sendto: %s", strerror(errno));

	state.tx_pkt++;
	state.tx_len += len;
}

void
confessions_cathedral_output(const void *data, size_t len,
    u_int64_t msg, void *udata)
{
	struct sockaddr_in		sin;
	u_int16_t			port;

	port = ntohs(state.cathedral_port);

	if (msg == KYRKA_CATHEDRAL_NAT_MAGIC)
		port++;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = state.cathedral_ip;

	if (sendto(state.fd,
	    data, len, 0, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("sendto: %s", strerror(errno));
}

void
confessions_ring_init(struct confessions_ring *ring, size_t elm)
{
	memset(ring, 0, sizeof(*ring));

	ring->elm = elm;
	ring->mask = elm - 1;
}

size_t
confessions_ring_pending(struct confessions_ring *ring)
{
	u_int32_t	head, tail;

	head = confessions_atomic_read(&ring->consumer.head);
	tail = confessions_atomic_read(&ring->producer.tail);

	return (tail - head);
}

size_t
confessions_ring_available(struct confessions_ring *ring)
{
	u_int32_t	head, tail;

	head = confessions_atomic_read(&ring->producer.head);
	tail = confessions_atomic_read(&ring->consumer.tail);

	return (ring->elm + (tail - head));
}

void *
confessions_ring_dequeue(struct confessions_ring *ring)
{
	uintptr_t	uptr;
	u_int32_t	slot, head, tail, next;

dequeue_again:
	head = confessions_atomic_read(&ring->consumer.head);
	tail = confessions_atomic_read(&ring->producer.tail);

	if ((tail - head) == 0)
		return (NULL);

	next = head + 1;
	if (!confessions_atomic_cas(&ring->consumer.head, &head, &next))
		goto dequeue_again;

	slot = head & ring->mask;
	uptr = confessions_atomic_read(&ring->data[slot]);

	while (!confessions_atomic_cas_simple(&ring->consumer.tail, head, next))
		confessions_cpu_pause();

	return ((void *)uptr);
}

int
confessions_ring_queue(struct confessions_ring *ring, void *ptr)
{
	u_int32_t	slot, head, tail, next;

queue_again:
	head = confessions_atomic_read(&ring->producer.head);
	tail = confessions_atomic_read(&ring->consumer.tail);

	if ((ring->elm + (tail - head)) == 0)
		return (-1);

	next = head + 1;
	if (!confessions_atomic_cas(&ring->producer.head, &head, &next))
		goto queue_again;

	slot = head & ring->mask;
	confessions_atomic_write(&ring->data[slot], (uintptr_t)ptr);

	while (!confessions_atomic_cas_simple(&ring->producer.tail, head, next))
		confessions_cpu_pause();

	return (0);
}
