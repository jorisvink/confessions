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
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include "confession.h"

static void	usage(void) __attribute__((noreturn));

static void	signal_hdlr(int);
static void	signal_memfault(int);

static void	confessions_signal_trap(int);
static void	confessions_buffers_initialize(struct state *);
static void	confessions_split_ip_port(char *, u_int32_t *, u_int16_t *);

/* The last received signal. */
static volatile sig_atomic_t	sig_recv = -1;

void
usage(void)
{
	printf("Usage: confessions [mode] [opts] [ip:port]\n");
	printf("Mode choices:\n");
	printf("  direct          - Direct tunnel between two peers.\n");
	printf("  cathedral       - Use a cathedral to do peer discovery.\n");
	printf("\n");
	printf("Generic options:\n");
	printf("  -s <path>       - The shared secret or catehdral secret\n");
	printf("\n");
	printf("Direct specific options:\n");
	printf("  -b <ip:port>    - Bind to the given ip:port\n");
	printf("\n");
	printf("Cathedral specific options:\n");
	printf("  -k <path>       - The device KEK\n");
	printf("  -f <flock>      - Hexadecimal flock ID\n");
	printf("  -i <identity>   - Hexadecimal client ID\n");
	printf("  -t <tunnel>     - Hexadecimal tunnel ID\n");
	printf("\n");
	printf("In cathedral mode, the tunnel given specifies who you want\n");
	printf("to talk too. If you have two devices (01 and 02) and you\n");
	printf("want to establish a voice channel between these you use\n");
	printf("tunnel 0x0102 on device 01 and tunnel 0x0201 on device 02.\n");

	exit(1);
}

int
main(int argc, char **argv)
{
	struct timespec			ts;
	struct pollfd			pfd;
	struct state			state;
	time_t				stats;
	sigset_t			sigset;
	int				ch, running;
	struct kyrka_cathedral_cfg	*cathedral, cfg;

	if (argc < 3)
		usage();

	memset(&cfg, 0, sizeof(cfg));
	memset(&state, 0, sizeof(state));

	optind = 2;
	cathedral = NULL;
	state.mode = CONFESSIONS_MODE_DIRECT;

	if (!strcmp(argv[1], "direct")) {
		state.mode = CONFESSIONS_MODE_DIRECT;
	} else if (!strcmp(argv[1], "cathedral")) {
		cathedral = &cfg;
		state.mode = CONFESSIONS_MODE_CATHEDRAL;
	} else {
		fatal("unknown mode '%s'", argv[1]);
	}

	while ((ch = getopt(argc, argv, "b:df:i:k:s:t:")) != -1) {
		switch (ch) {
		case 'b':
			confessions_split_ip_port(optarg,
			    &state.local_ip, &state.local_port);
			break;
		case 'd':
			state.debug = 1;
			break;
		case 'f':
			if (state.mode != CONFESSIONS_MODE_CATHEDRAL)
				fatal("-f is only for cathedral mode");
			if (sscanf(optarg, "%" PRIx64, &cfg.flock) != 1)
				fatal("failed to parse flock '%s'", optarg);
			break;
		case 'i':
			if (state.mode != CONFESSIONS_MODE_CATHEDRAL)
				fatal("-i is only for cathedral mode");
			if (sscanf(optarg, "%x", &cfg.identity) != 1)
				fatal("failed to parse identity '%s'", optarg);
			break;
		case 'k':
			if (state.mode != CONFESSIONS_MODE_CATHEDRAL)
				fatal("-k is only for cathedral mode");
			cfg.kek = optarg;
			break;
		case 's':
			if (state.mode != CONFESSIONS_MODE_CATHEDRAL)
				state.secret = optarg;
			else
				cfg.secret = optarg;
			break;
		case 't':
			if (state.mode != CONFESSIONS_MODE_CATHEDRAL)
				fatal("-t is only for cathedral mode");
			if (sscanf(optarg, "%hx", &cfg.tunnel) != 1)
				fatal("failed to parse tunnel '%s'", optarg);
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	switch (state.mode) {
	case CONFESSIONS_MODE_DIRECT:
		if (state.secret == NULL)
			fatal("no secret (-s) specified");
		if (state.local_ip == 0 && state.local_port == 0)
			fatal("no local ip (-b) specified");
		break;
	case CONFESSIONS_MODE_CATHEDRAL:
		if (cfg.secret == NULL)
			fatal("no secret (-s) specified");
		if (cfg.flock == 0)
			fatal("no flock (-f) specified");
		if (cfg.identity == 0)
			fatal("no identity (-i) specified");
		if (cfg.kek == NULL)
			fatal("no KEK (-k) specified");
		if (cfg.tunnel == 0)
			fatal("no tunnel (-t) specified");
		break;
	default:
		fatal("what is mode?");
	}

	confessions_signal_trap(SIGINT);
	confessions_signal_trap(SIGHUP);
	confessions_signal_trap(SIGQUIT);
	confessions_signal_trap(SIGTERM);
	confessions_signal_trap(SIGSEGV);

	if (sigfillset(&sigset) == -1)
		fatal("sigfillset: %s", strerror(errno));

	sigdelset(&sigset, SIGINT);
	sigdelset(&sigset, SIGHUP);
	sigdelset(&sigset, SIGTERM);
	sigdelset(&sigset, SIGQUIT);
	(void)sigprocmask(SIG_BLOCK, &sigset, NULL);

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);
	state.now = ts.tv_sec;

	confessions_split_ip_port(argv[0], &state.peer_ip, &state.peer_port);

	confessions_audio_initialize(&state);
	confessions_buffers_initialize(&state);
	confessions_tunnel_initialize(&state, cathedral);
	confessions_network_initialize(&state);

	stats = 0;
	running = 1;

	pfd.fd = state.fd;
	pfd.events = POLLIN;

	while (running) {
		switch (confessions_last_signal()) {
		case SIGINT:
		case SIGHUP:
		case SIGTERM:
		case SIGQUIT:
			running = 0;
			continue;
		}

		(void)clock_gettime(CLOCK_MONOTONIC, &ts);
		state.now = ts.tv_sec;

		if (state.debug && (state.now - stats) >= 1) {
			stats = state.now;

			printf("rx[%zu, %zu] tx[%zu, %zu]\n",
			    state.rx_pkt, state.rx_len,
			    state.tx_pkt, state.tx_len);

			state.tx_len = 0;
			state.rx_len = 0;
			state.tx_pkt = 0;
			state.rx_pkt = 0;
		}

		confessions_tunnel_manage(&state);

		if (poll(&pfd, 1, 10) == -1 && errno != EINTR)
			fatal("poll: %s", strerror(errno));

		if (pfd.revents & POLLIN)
			confessions_network_input(&state);

		confessions_network_recv_packets(&state);

	}

	printf("shutting down\n");
	free(state.data);

	(void)close(state.fd);

	opus_encoder_destroy(state.encoder);
	opus_decoder_destroy(state.decoder);

	kyrka_ctx_free(state.tunnel);
	Pa_CloseStream(state.stream);
	Pa_Terminate();

	return (0);
}

/* As always, bad ju-ju happened. */
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

/*
 * Returns the last received signal to the caller and resets sig_recv.
 */
int
confessions_last_signal(void)
{
	int	sig;

	sig = sig_recv;
	sig_recv = -1;

	return (sig);
}

/*
 * Setup the buffers that are going to be used by the different components.
 */
static void
confessions_buffers_initialize(struct state *state)
{
	size_t		idx;
	u_int8_t	*ptr;

	PRECOND(state != NULL);

	if ((state->data = malloc(CONFESSIONS_BUF_SIZE)) == NULL)
		fatal("failed to allocate buffer");

	confessions_ring_init(&state->buffers, CONFESSIONS_BUF_COUNT);
	confessions_ring_init(&state->encrypt, CONFESSIONS_BUF_COUNT);
	confessions_ring_init(&state->playback, CONFESSIONS_BUF_COUNT);

	for (idx = 0; idx < CONFESSIONS_BUF_COUNT; idx++) {
		ptr = &state->data[idx * CONFESSIONS_SAMPLE_BYTES];
		confessions_ring_queue(&state->buffers, ptr);
	}
}

/*
 * A helper function that takes an ip:port combination and splits it
 * into an actual IPv4 IP and port.
 */
static void
confessions_split_ip_port(char *str, u_int32_t *ip, u_int16_t *port)
{
	char		*p;

	PRECOND(str != NULL);
	PRECOND(ip != NULL);
	PRECOND(port != NULL);

	if ((p = strchr(str, ':')) == NULL)
		fatal("invalid ip:port pair (%s)", str);

	*(p)++ = '\0';

	if (inet_pton(AF_INET, str, ip) == -1)
		fatal("invalid ip address '%s'", str);

	if (sscanf(p, "%hu", port) != 1)
		fatal("failed to parse port '%s'", p);

	*port = htons(*port);
}

/*
 * Let the given signal be caught by our signal handler.
 */
static void
confessions_signal_trap(int sig)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));

	if (sig == SIGSEGV)
		sa.sa_handler = signal_memfault;
	else
		sa.sa_handler = signal_hdlr;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", strerror(errno));

	if (sigaction(sig, &sa, NULL) == -1)
		fatal("sigaction: %s", strerror(errno));
}

/*
 * Our signal handler, doesn't do much more than set sig_recv so it can
 * be obtained by confessions_last_signal().
 */
static void
signal_hdlr(int sig)
{
	sig_recv = sig;
}

/*
 * The signal handler for when a segmentation fault occurred, we are
 * catching this so we can just cleanup before dying.
 */
static void
signal_memfault(int sig)
{
	kyrka_emergency_erase();
	abort();
}
