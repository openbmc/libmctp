/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
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

#ifndef ETH_P_MCTP
#define ETH_P_MCTP 0x00fa
#endif

static const size_t MAX_MTU = 64 * 1024;

struct ctx {
	struct mctp *mctp;
	struct mctp_binding_astlpc *astlpc;
	int tun_fd;
	void *tun_buf;
	size_t tun_buf_size;
};

static int tun_init(struct ctx *ctx)
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

	/* todo: set MTU to match astlpc binding? */

	ctx->tun_fd = fd;
	return 0;
}

static void packet_rx(uint8_t src_eid, bool tag_owner, uint8_t tag, void *data,
		      void *pkt, size_t len)
{
	struct ctx *ctx = data;
	struct tun_pi tun_pi;
	struct iovec iov[2];
	ssize_t wlen;

	wlen = 0;

	tun_pi.flags = 0;
	tun_pi.proto = htobe16(ETH_P_MCTP);

	iov[0].iov_base = &tun_pi;
	iov[0].iov_len = sizeof(tun_pi);
	iov[1].iov_base = pkt;
	iov[1].iov_len = len;

	wlen = writev(ctx->tun_fd, iov, 2);
	if (wlen < 0) {
		warn("tun write");
	} else if (wlen != sizeof(tun_pi) + len) {
		warnx("tun short write (wrote %zd, expected %zd)", wlen,
		      sizeof(tun_pi) + len);
	}
}

static int tun_read(struct ctx *ctx)
{
	struct tun_pi tun_pi;
	struct iovec iov[2];
	ssize_t rlen;
	int rc;

	iov[0].iov_base = &tun_pi;
	iov[0].iov_len = sizeof(tun_pi);
	iov[1].iov_base = ctx->tun_buf;
	iov[1].iov_len = ctx->tun_buf_size;

	rlen = readv(ctx->tun_fd, iov, 2);
	if (rlen < 0) {
		warn("tun read failed");
		return -1;
	}

	if (rlen < sizeof(tun_pi) + 4) {
		warn("tun short read (%zd bytes)", rlen);
		return -1;
	}

	rlen -= sizeof(tun_pi);

	if (tun_pi.proto != htobe16(ETH_P_MCTP))
		return 0;

	rc = mctp_packet_raw_tx(mctp_binding_astlpc_core(ctx->astlpc),
				ctx->tun_buf, rlen);
	if (rc)
		warnx("mctp packet tx failed");

	return rc;
}

int main(void)
{
	struct ctx _ctx, *ctx;
	int rc;

	ctx = &_ctx;

	ctx->mctp = mctp_init();

	ctx->astlpc = mctp_astlpc_init_fileio();
	if (!ctx->astlpc)
		errx(EXIT_FAILURE, "can't init astlpc hardware transport");

	rc = tun_init(ctx);
	if (rc)
		return EXIT_FAILURE;

	rc = mctp_register_raw_bus(ctx->mctp,
				   mctp_binding_astlpc_core(ctx->astlpc));
	if (rc)
		errx(EXIT_FAILURE, "can't register MCTP bus");

	rc = mctp_set_rx_all(ctx->mctp, packet_rx, ctx);
	if (rc)
		errx(EXIT_FAILURE, "can't register MCTP rx callback");

	ctx->tun_buf_size = MAX_MTU;
	ctx->tun_buf = malloc(ctx->tun_buf_size);
	if (!ctx->tun_buf)
		errx(EXIT_FAILURE, "malloc");

	for (;;) {
		struct pollfd pollfds[2];

		pollfds[0].fd = ctx->tun_fd;
		pollfds[0].events = POLLIN;
		pollfds[1].fd = mctp_astlpc_get_fd(ctx->astlpc);
		pollfds[1].events = POLLIN | POLLOUT;

		rc = poll(pollfds, 2, -1);
		if (rc < 0)
			err(EXIT_FAILURE, "poll");

		if (!rc)
			continue;

		if (pollfds[0].revents) {
			rc = tun_read(ctx);
			if (rc)
				break;
		}

		if (pollfds[1].revents) {
			rc = mctp_astlpc_poll(ctx->astlpc);
			if (rc)
				break;
		}
	}

	return EXIT_SUCCESS;
}
