/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/uio.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>

#include "libmctp.h"
#include "libmctp-astlpc.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "utils/mctp-capture.h"
#include "mctp.h"
#include "container_of.h"

#ifndef ETH_P_MCTP
#define ETH_P_MCTP 0x00fa
#endif

static const size_t MAX_MTU = 64 * 1024;

struct mctp_binding_raw {
	struct mctp_binding binding;
	int tun_fd;
	void *tun_buf;
	size_t tun_buf_size;
};

struct ctx {
	struct mctp *mctp;
	struct mctp_binding_astlpc *astlpc;
	struct mctp_binding_raw *tun;
	int tun_fd;
	void *tun_buf;
	size_t tun_buf_size;
	bool verbose;
	struct {
		struct capture ast_binding;
		struct capture raw_binding;
	} pcap;
};

struct mctp_binding *mctp_binding_raw_core(struct mctp_binding_raw *b)
{
	return &b->binding;
}

#define binding_to_raw(b) container_of(b, struct mctp_binding_raw, binding)

static void mctp_raw_init_pollfd(struct mctp_binding_raw *b, struct pollfd *pollfd)
{
	pollfd->fd = b->tun_fd;
	pollfd->events = POLLIN;
}

static int mctp_binding_raw_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_raw *binding = binding_to_raw(b);
	struct tun_pi tun_pi;
	struct iovec iov[2];
	ssize_t wlen = 0;

	tun_pi.flags = 0;
	tun_pi.proto = htobe16(ETH_P_MCTP);

	iov[0].iov_base = &tun_pi;
	iov[0].iov_len = sizeof(tun_pi);
	iov[1].iov_base = mctp_pktbuf_hdr(pkt);
	iov[1].iov_len = mctp_pktbuf_size(pkt);

	wlen = writev(binding->tun_fd, iov, 2);
	if (wlen != (ssize_t)(sizeof(tun_pi) + mctp_pktbuf_size(pkt))) {
		warnx("tun short write (wrote %zd, expected %zu)", wlen,
		      sizeof(tun_pi) + mctp_pktbuf_size(pkt));
		return -1;
	}

	return 0;
}

static struct mctp_binding_raw *mctp_tun_init()
{
	struct mctp_binding_raw *tun;

	tun = __mctp_alloc(sizeof(*tun));
	memset(tun, 0, sizeof(*tun));
	tun->binding.name = "tun";
	tun->binding.pkt_size = MCTP_PACKET_SIZE(32 * 1024);
	tun->binding.version = 1;
	tun->binding.pkt_header = 4;
	tun->binding.pkt_trailer = 4;
	tun->binding.tx = mctp_binding_raw_tx;
	return tun;
}

static int tun_init(struct mctp_binding_raw *tun)
{
	struct ifreq ifreq;
	int fd, rc;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		warn("can't open tun device");
		return -1;
	}

	memset(&ifreq, 0, sizeof(ifreq));
	ifreq.ifr_flags = IFF_TUN;

	rc = ioctl(fd, TUNSETIFF, &ifreq);
	if (rc) {
		warn("ioctl(TUNSETIFF)");
		return -1;
	}

	printf("tun interface created: %s\n", ifreq.ifr_name);

	tun->tun_fd = fd;
	return 0;
}

int tun_read(struct ctx *ctx)
{
	struct mctp_binding_raw *tun = ctx->tun;
	struct tun_pi tun_pi;
	struct iovec iov[2];
	ssize_t rlen;

	iov[0].iov_base = &tun_pi;
	iov[0].iov_len = sizeof(tun_pi);
	iov[1].iov_base = tun->tun_buf;
	iov[1].iov_len = tun->tun_buf_size;

	rlen = readv(tun->tun_fd, iov, 2);
	if (rlen < 0) {
		warn("tun read failed");
		return -1;
	}

	if ((size_t)rlen < sizeof(tun_pi)) {
		warn("tun short read header (%zd bytes)", rlen);
		return -1;
	}

	if (tun_pi.proto != htobe16(ETH_P_MCTP))
		return 0;

	if ((size_t)rlen < sizeof(tun_pi) + 4) {
		warn("tun short read (%zd bytes)", rlen);
		return -1;
	}

	rlen -= sizeof(tun_pi);
	struct mctp_pktbuf *pkt;

	pkt = mctp_pktbuf_alloc(&tun->binding, rlen);
	if (!pkt) {
		warn("couldn't allocate packet of size (%zd bytes)", rlen);
		return -1;
	}
	memcpy(mctp_pktbuf_hdr(pkt), tun->tun_buf, rlen);
	mctp_bus_rx(&tun->binding, pkt);

	// possibly the correct / better way to do this
	//	pkt = mctp_pktbuf_alloc(&tun->binding, 0);
	//	mctp_pktbuf_push(pkt, tun->tun_buf, rlen);

	return 0;
}

//daemon stuff below

static const struct option options[] = {
	{ "capture-astlpc-binding", required_argument, 0, 'b' },
	{ "capture-raw-binding", required_argument, 0, 'r' },
	{ "verbose", no_argument, 0, 'v' },
	{ 0 },
};

int main(int argc, char *const *argv)
{
	struct ctx _ctx, *ctx;
	int rc;

	if (argc < 2) {
		err(EXIT_FAILURE, "Need to specify a KCS device for the ASTLPC binding");
	}

	ctx = &_ctx;

	ctx->mctp = mctp_init();
	ctx->pcap.raw_binding.path = NULL;
	ctx->pcap.ast_binding.path = NULL;
	ctx->verbose = false;

	for (;;) {
		rc = getopt_long(argc, argv, "b:es::v", options, NULL);
		if (rc == -1)
			break;
		switch (rc) {
		case 'b':
			ctx->pcap.ast_binding.path = optarg;
			break;
		case 'r':
			ctx->pcap.raw_binding.path = optarg;
			break;
		case 'v':
			ctx->verbose = true;
			break;
		default:
			fprintf(stderr, "Invalid argument\n");
			return EXIT_FAILURE;
		}
	}
	if (ctx->pcap.ast_binding.path || ctx->pcap.raw_binding.path) {
		if (capture_init()) {
			rc = EXIT_FAILURE;
			goto cleanup_mctp;
		}
	}
	/* Set max message size to something more reasonable than 64k */
	mctp_set_max_message_size(ctx->mctp, 32768 * 10);

	/* Setup astlpc binding */
	ctx->astlpc = mctp_astlpc_init_fileio(argv[1]);
	if (!ctx->astlpc)
		errx(EXIT_FAILURE, "can't init astlpc hardware transport");

	/* Setup raw binding */
	ctx->tun = mctp_tun_init();
	rc = tun_init(ctx->tun);
	if (rc)
		errx(EXIT_FAILURE, "can't init tun device");

	ctx->tun->tun_buf_size = MAX_MTU;
	ctx->tun->tun_buf = malloc(ctx->tun->tun_buf_size);
	if (!ctx->tun->tun_buf)
		errx(EXIT_FAILURE, "malloc");

	/* Connect the two bindings */
	rc = mctp_bridge_busses(ctx->mctp,
				mctp_binding_astlpc_core(ctx->astlpc),
				mctp_binding_raw_core(ctx->tun));
	if (rc)
		errx(EXIT_FAILURE, "can't connect lpc and tun bindings");

	/* Enable bindings */
	mctp_binding_set_tx_enabled(mctp_binding_astlpc_core(ctx->astlpc),
				    true);
	mctp_binding_set_tx_enabled(mctp_binding_raw_core(ctx->tun), true);

	/* Init capture bindings  */
	if (ctx->pcap.ast_binding.path) {
		rc = capture_prepare(&ctx->pcap.ast_binding);
		if (rc == -1) {
			fprintf(stderr,
				"Failed to initialise capture for ast binding: %d\n",
				rc);
			rc = EXIT_FAILURE;
			goto cleanup_mctp;
		}

		mctp_set_capture_handler(mctp_binding_astlpc_core(ctx->astlpc),
					 capture_binding,
					 ctx->pcap.ast_binding.dumper);
	}
	if (ctx->pcap.raw_binding.path) {
		rc = capture_prepare(&ctx->pcap.raw_binding);
		if (rc == -1) {
			fprintf(stderr,
				"Failed to initialise capture for raw binding: %d\n",
				rc);
			rc = EXIT_FAILURE;
			goto cleanup_mctp;
		}

		mctp_set_capture_handler(mctp_binding_raw_core(ctx->tun),
					 capture_binding,
					 ctx->pcap.raw_binding.dumper);
	}

	struct pollfd pollfds[2];
	for (;;) {
		// should these be inside or outside the for loop?
		mctp_raw_init_pollfd(ctx->tun, &pollfds[0]);
		mctp_astlpc_init_pollfd(ctx->astlpc, &pollfds[1]);
		//	pollfds[1].fd = mctp_astlpc_get_fd(ctx->astlpc);
		//	pollfds[1].events = POLLIN | POLLOUT;

		rc = poll(pollfds, 2, -1);
		if (rc < 0)
			err(EXIT_FAILURE, "poll");

		if (!rc)
			continue;

		if (pollfds[0].revents) {
			rc = tun_read(ctx);
			if (rc)
				fprintf(stderr, "tun_read failed \n");
			if (rc)
				break;
		}

		if (pollfds[1].revents) {
			rc = mctp_astlpc_poll(ctx->astlpc);
			if (rc)
				fprintf(stderr, "mctp_astlpc_poll failed \n");
			if (rc)
				break;
		}
	}

	fprintf(stderr, "Shouldn't get here. rc: %d\n", rc);

	if (ctx->pcap.ast_binding.path)
		capture_close(&ctx->pcap.ast_binding);
	if (ctx->pcap.raw_binding.path)
		capture_close(&ctx->pcap.raw_binding);
	mctp_astlpc_destroy(ctx->astlpc);
	//todo write raw destroy

	rc = rc ? EXIT_FAILURE : EXIT_SUCCESS;
cleanup_mctp:

	return rc;
}
