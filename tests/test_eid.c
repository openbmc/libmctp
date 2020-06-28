/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <libmctp.h>

#include "test-utils.h"


struct test_ctx {
	struct mctp			*mctp;
	struct mctp_binding_test	*binding;
	int				rx_count;
	mctp_eid_t			src_eid;
};

static void test_rx(mctp_eid_t eid, void *data, void *msg, size_t len)
{
	struct test_ctx *ctx = data;

	(void)msg;
	(void)len;

	ctx->rx_count++;
	ctx->src_eid = eid;
}

static void create_packet(struct mctp_hdr *pkt,
		mctp_eid_t src, mctp_eid_t dest)
{
	memset(pkt, 0, sizeof(*pkt));
	pkt->src = src;
	pkt->dest = dest;
	pkt->flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
}

#include "libmctp-log.h"

void test_eid_rx(void)
{
	struct test_ctx _ctx, *ctx = &_ctx;
	const mctp_eid_t local_eid = MCTP_EID(8);
	const mctp_eid_t remote_eid = MCTP_EID(9);
	const mctp_eid_t other_eid = MCTP_EID(10);
	struct {
		struct mctp_hdr	hdr;
		uint8_t		payload[1];
	} pktbuf;

	mctp_test_stack_init(&ctx->mctp, &ctx->binding, local_eid);

	mctp_set_rx_all(ctx->mctp, test_rx, ctx);

	/* check a message addressed to us is received */
	ctx->rx_count = 0;

	create_packet(&pktbuf.hdr, remote_eid, local_eid);

	mctp_binding_test_rx_raw(ctx->binding, &pktbuf, sizeof(pktbuf));

	assert(ctx->rx_count == 1);
	assert(mctp_eid_equal(ctx->src_eid, remote_eid));

	/* check a message not addressed to us is not received */
	ctx->rx_count = 0;

	create_packet(&pktbuf.hdr, remote_eid, other_eid);

	mctp_binding_test_rx_raw(ctx->binding, &pktbuf, sizeof(pktbuf));

	assert(ctx->rx_count == 0);

	mctp_binding_test_destroy(ctx->binding);
	mctp_destroy(ctx->mctp);
}

static void test_mctp_eid_is_valid(void)
{
	struct mctp *mctp = NULL;

	assert(mctp_eid_is_valid(mctp, MCTP_EID(0)));
	assert(!mctp_eid_is_valid(mctp, MCTP_EID(1)));
	assert(!mctp_eid_is_valid(mctp, MCTP_EID(2)));
	assert(!mctp_eid_is_valid(mctp, MCTP_EID(3)));
	assert(!mctp_eid_is_valid(mctp, MCTP_EID(4)));
	assert(!mctp_eid_is_valid(mctp, MCTP_EID(5)));
	assert(!mctp_eid_is_valid(mctp, MCTP_EID(6)));
	assert(!mctp_eid_is_valid(mctp, MCTP_EID(7)));
	assert(mctp_eid_is_valid(mctp, MCTP_EID(8)));
	assert(mctp_eid_is_valid(mctp, MCTP_EID(254)));
	assert(mctp_eid_is_valid(mctp, MCTP_EID(255)));
}

static void test_mctp_eid_range_is_valid(void)
{
	struct mctp *mctp = NULL;

	assert(mctp_eid_range_is_valid(
		mctp, &(struct mctp_eid_range){ .first = 8, .last = 8 }));
	assert(mctp_eid_range_is_valid(
		mctp, &(struct mctp_eid_range){ .first = 8, .last = 9 }));
	assert(mctp_eid_range_is_valid(
		mctp, &(struct mctp_eid_range){ .first = 8, .last = 254 }));
}

static void test_mctp_eid_range_is_invalid(void)
{
	struct mctp *mctp = NULL;

	assert(!mctp_eid_range_is_valid(
		mctp, &(struct mctp_eid_range){ .first = 0, .last = 0 }));
	assert(!mctp_eid_range_is_valid(
		mctp, &(struct mctp_eid_range){ .first = 255, .last = 255 }));
	assert(!mctp_eid_range_is_valid(
		mctp, &(struct mctp_eid_range){ .first = 9, .last = 8 }));
}

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	test_eid_rx();
	test_mctp_eid_is_valid();
	test_mctp_eid_range_is_valid();
	test_mctp_eid_range_is_invalid();

	return EXIT_SUCCESS;
}
