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

#ifndef __H_CONFESSION_H
#define __H_CONFESSION_H

#include <sys/types.h>
#include <sys/queue.h>

#include <opus.h>
#include <portaudio.h>
#include <libkyrka/libkyrka.h>

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			fatal("precondition failed: "			\
			    "%s:%s:%d\n", __FILE__, __func__,		\
			    __LINE__);					\
		}							\
	} while (0)

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

/* If we're in cathedral, direct or liturgy mode. */
#define CONFESSIONS_MODE_DIRECT		1
#define CONFESSIONS_MODE_CATHEDRAL	2
#define CONFESSIONS_MODE_LITURGY	3

/* Audio settings. */
#define CONFESSIONS_CHANNEL_COUNT	1
#define CONFESSIONS_SAMPLE_COUNT	960
#define CONFESSIONS_SAMPLE_RATE		48000
#define CONFESSIONS_SAMPLE_SIZE		(sizeof(u_int16_t))

/* Ring and buffer count settings. */
#define CONFESSIONS_RING_MAX		4096
#define CONFESSIONS_BUF_COUNT		1024

#define CONFESSIONS_SAMPLE_BYTES	\
    (CONFESSIONS_SAMPLE_COUNT * CONFESSIONS_SAMPLE_SIZE)
#define CONFESSIONS_BUF_SIZE		\
    (CONFESSIONS_BUF_COUNT * CONFESSIONS_SAMPLE_BYTES)

/*
 * A memory ring queue with space for up to 4096 elements.
 * The actual size is given via sanctum_ring_init() and must be <= 4096.
 */
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

#define CONFESSIONS_STATE_PENDING	1
#define CONFESSIONS_STATE_ONLINE	2

/*
 * An active tunnel object.
 */
struct tunnel {
	/* Misc stuff. */
	int			fd;
	u_int16_t		id;
	KYRKA			*ctx;
	int			state;

	/* Incoming sequence number and statistics. */
	u_int64_t		seq;
	size_t			tx_pkt;
	size_t			tx_len;
	size_t			rx_pkt;
	size_t			rx_len;

	/* The playback audio stream. */
	PaStream		*stream;

	/* Queue for playback of this peer its audio. */
	struct confessions_ring	playback;
	u_int8_t		*rx_buf;
	size_t			rx_offset;

	/* Tunnel specific opus encoder and decoder. */
	OpusEncoder		*encoder;
	OpusDecoder		*decoder;

	/* Timers for specific things that should trigger. */
	time_t			last_rx;
	time_t			key_send;
	time_t			key_refresh;
	time_t			cathedral_notify;

	/* Our peer ip:port and its id. */
	u_int64_t		peer_id;
	u_int32_t		peer_ip;
	u_int16_t		peer_port;

	/* Pointer to state. */
	struct state		*mstate;

	LIST_ENTRY(tunnel)	list;
};

/*
 * The confessions main state.
 */
struct state {
	/* Misc stuff. */
	int				mode;
	int				debug;

	/* Path to secret. */
	const char			*secret;

	/* The explicit liturgy tunnel. */
	struct tunnel			liturgy;

	/* For liturgy, the peers last state. */
	u_int8_t			peers[KYRKA_PEERS_PER_FLOCK];

	/* All tunnels that we are handling (except liturgy). */
	LIST_HEAD(, tunnel)		tunnels;

	/* Current time. */
	time_t				now;

	/* Our local ip address and bound port. */
	u_int32_t			local_ip;
	u_int16_t			local_port;

	/* The cathedral its configured ip address and port. */
	u_int32_t			cathedral_ip;
	u_int16_t			cathedral_port;

	/* The cathedral configuration. */
	struct kyrka_cathedral_cfg	cathedral;

	/* The capture audio stream. */
	PaStream			*stream;

	/* The shared capture/playback audio buffers. */
	u_int8_t			*data;

	struct confessions_ring		buffers;
	struct confessions_ring		encrypt;

	u_int8_t			*tx_buf;
	size_t				tx_offset;
};

/* src/kyrka.c */
int	confessions_last_signal(void);
void	fatal(const char *, ...) __attribute__((noreturn));

/* src/audio.c */
void	confessions_audio_init(struct state *);
void	confessions_audio_process(struct state *);
void	confessions_audio_playback(struct tunnel *);

/* src/liturgy.c */
void	confessions_liturgy_manage(struct state *);
void	confessions_liturgy_initialize(struct state *);

/* src/ring.c */
size_t	confessions_ring_pending(struct confessions_ring *);
void	*confessions_ring_dequeue(struct confessions_ring *);
size_t	confessions_ring_available(struct confessions_ring *);
void	confessions_ring_init(struct confessions_ring *, size_t);
int	confessions_ring_queue(struct confessions_ring *, void *);

/* src/tunnel.c */
void	confessions_tunnel_wait(struct state *);
void	confessions_tunnel_remove(struct tunnel *);
void	confessions_tunnel_cleanup(struct state *);
void	confessions_tunnel_manage(struct state *, struct tunnel *);
void	confessions_tunnel_socket(struct state *, struct tunnel *);
void	confessions_tunnel_alloc(struct state *, struct kyrka_cathedral_cfg *);

u_int64_t	confessions_ms(void);

#endif
