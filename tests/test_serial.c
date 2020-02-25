/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#include "config.h"

#include "libmctp-log.h"
#include "libmctp-serial.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct mctp_binding_serial_pipe {
	int ingress;
	int egress;

	struct mctp_binding_serial *serial;
};

static int mctp_binding_serial_pipe_tx(void *data, void *buf, size_t len)
{
	struct mctp_binding_serial_pipe *ctx = data;
	ssize_t rc;

	rc = write(ctx->egress, buf, len);
	assert(rc == len);
}

uint8_t mctp_msg_src[2 * MCTP_BTU];

static bool seen;

static void rx_message(uint8_t eid, void *data, void *msg, size_t len)
{
	uint8_t type;

	type = *(uint8_t *)msg;

	mctp_prdebug("MCTP message received: len %zd, type %d", len, type);

	assert(sizeof(mctp_msg_src) == len);
	assert(!memcmp(mctp_msg_src, msg, len));

	seen = true;
}

struct serial_test {
	struct mctp_binding_serial_pipe binding;
	struct mctp *mctp;
};

int main(void)
{
	struct serial_test scenario[2];

	struct mctp_binding_serial_pipe *a = &scenario[0].binding;
	struct mctp_binding_serial_pipe *b = &scenario[1].binding;
	int p[2][2];
	int rc;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	memset(&mctp_msg_src[0], 0x5a, MCTP_BTU);
	memset(&mctp_msg_src[MCTP_BTU], 0xa5, MCTP_BTU);

	rc = pipe(p[0]);
	assert(!rc);

	rc = pipe(p[1]);
	assert(!rc);

	/* Instantiate the A side of the serial pipe */
	scenario[0].mctp = mctp_init();
	assert(scenario[0].mctp);
	a->serial = mctp_serial_init();
	assert(a->serial);
	a->ingress = p[0][0];
	a->egress = p[1][1];
	mctp_serial_open_fd(a->serial, a->ingress);
	mctp_serial_set_tx_fn(a->serial, mctp_binding_serial_pipe_tx, a);
	mctp_register_bus(scenario[0].mctp, mctp_binding_serial_core(a->serial), 8);

	/* Instantiate the B side of the serial pipe */
	scenario[1].mctp = mctp_init();
	assert(scenario[1].mctp);
	mctp_set_rx_all(scenario[1].mctp, rx_message, NULL);
	b->serial = mctp_serial_init();
	assert(b->serial);
	b->ingress = p[1][0];
	b->egress = p[0][1];
	mctp_serial_open_fd(b->serial, b->ingress);
	mctp_serial_set_tx_fn(b->serial, mctp_binding_serial_pipe_tx, a);
	mctp_register_bus(scenario[1].mctp, mctp_binding_serial_core(b->serial), 9);

	/* Transmit a message from A to B */
	rc = mctp_message_tx(scenario[0].mctp, 9, mctp_msg_src, sizeof(mctp_msg_src));
	assert(rc == 0);

	/* Read the message at B from A */
	seen = false;
	mctp_serial_read(b->serial);
	assert(seen);

	return 0;
}
