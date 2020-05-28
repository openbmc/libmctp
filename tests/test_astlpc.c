/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "astlpc.c"

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(x) "test: " x
#endif

#include "libmctp-astlpc.h"
#include "libmctp-log.h"
#include "container_of.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

struct mctp_binding_astlpc_mmio {
	struct mctp_binding_astlpc astlpc;
	bool bmc;

	uint8_t (*kcs)[2];

	size_t lpc_size;
	uint8_t *lpc;
};

struct astlpc_endpoint {
	struct mctp_binding_astlpc_mmio mmio;
	struct mctp_binding_astlpc *astlpc;
	struct mctp *mctp;
};

struct astlpc_test {
	struct astlpc_endpoint bmc;
	struct astlpc_endpoint host;
	uint8_t kcs[2];
	uint8_t *lpc_mem;

	void *msg;
	uint8_t count;
};

#define binding_to_mmio(b)                                                     \
	container_of(b, struct mctp_binding_astlpc_mmio, astlpc)

static int mctp_astlpc_mmio_kcs_read(void *data,
				     enum mctp_binding_astlpc_kcs_reg reg,
				     uint8_t *val)
{
	struct mctp_binding_astlpc_mmio *mmio = binding_to_mmio(data);

	*val = (*mmio->kcs)[reg];

	mctp_prdebug("%s: 0x%hhx from %s", __func__, *val,
		     reg ? "status" : "data");

	if (reg == MCTP_ASTLPC_KCS_REG_DATA) {
		uint8_t flag = mmio->bmc ? KCS_STATUS_IBF : KCS_STATUS_OBF;
		(*mmio->kcs)[MCTP_ASTLPC_KCS_REG_STATUS] &= ~flag;
	}

	return 0;
}

static int mctp_astlpc_mmio_kcs_write(void *data,
				      enum mctp_binding_astlpc_kcs_reg reg,
				      uint8_t val)
{
	struct mctp_binding_astlpc_mmio *mmio = binding_to_mmio(data);
	uint8_t *regp;

	assert(reg == MCTP_ASTLPC_KCS_REG_DATA ||
	       reg == MCTP_ASTLPC_KCS_REG_STATUS);

	if (reg == MCTP_ASTLPC_KCS_REG_DATA) {
		uint8_t flag = mmio->bmc ? KCS_STATUS_OBF : KCS_STATUS_IBF;
		(*mmio->kcs)[MCTP_ASTLPC_KCS_REG_STATUS] |= flag;
	}

	regp = &(*mmio->kcs)[reg];
	if (reg == MCTP_ASTLPC_KCS_REG_STATUS)
		*regp = (val & ~0xbU) | (val & *regp & 1);
	else
		*regp = val;

	mctp_prdebug("%s: 0x%hhx to %s", __func__, val,
		     reg ? "status" : "data");

	return 0;
}
int mctp_astlpc_mmio_lpc_read(void *data, void *buf, long offset, size_t len)
{
	struct mctp_binding_astlpc_mmio *mmio = binding_to_mmio(data);

	mctp_prdebug("%s: %zu bytes from 0x%lx", __func__, len, offset);

	assert(offset >= 0L);
	assert(offset + len < mmio->lpc_size);

	memcpy(buf, mmio->lpc + offset, len);

	return 0;
}

int mctp_astlpc_mmio_lpc_write(void *data, const void *buf, long offset,
			       size_t len)
{
	struct mctp_binding_astlpc_mmio *mmio = binding_to_mmio(data);

	mctp_prdebug("%s: %zu bytes to 0x%lx", __func__, len, offset);

	assert(offset >= 0L);
	assert(offset + len < mmio->lpc_size);

	memcpy(mmio->lpc + offset, buf, len);

	return 0;
}

static void rx_message(uint8_t eid, void *data, void *msg, size_t len)
{
	struct astlpc_test *test = data;
	uint8_t type;

	mctp_prdebug("MCTP message received: msg: %p, len %zd", msg, len);

	assert(len > 0);
	assert(msg);
	type = *(uint8_t *)msg;

	assert(test);
	assert(test->msg);
	assert(!memcmp(test->msg, msg, len));

	test->count++;
}

static const struct mctp_binding_astlpc_ops astlpc_direct_mmio_ops = {
	.kcs_read = mctp_astlpc_mmio_kcs_read,
	.kcs_write = mctp_astlpc_mmio_kcs_write,
};

static const struct mctp_binding_astlpc_ops astlpc_indirect_mmio_ops = {
	.kcs_read = mctp_astlpc_mmio_kcs_read,
	.kcs_write = mctp_astlpc_mmio_kcs_write,
	.lpc_read = mctp_astlpc_mmio_lpc_read,
	.lpc_write = mctp_astlpc_mmio_lpc_write,
};

static void endpoint_init(struct astlpc_endpoint *ep, mctp_eid_t eid,
			  uint8_t mode, uint8_t (*kcs)[2], void *lpc_mem)
{
	/*
	 * Configure the direction of the KCS interface so we know whether to
	 * set or clear IBF or OBF on writes or reads.
	 */
	ep->mmio.bmc = (mode == MCTP_BINDING_ASTLPC_MODE_BMC);

	ep->mctp = mctp_init();
	assert(ep->mctp);

	/* Inject KCS registers */
	ep->mmio.kcs = kcs;

	/* Initialise the binding */
	ep->astlpc = mctp_astlpc_init(mode, MCTP_BTU, lpc_mem,
				      &astlpc_direct_mmio_ops, &ep->mmio);

	mctp_register_bus(ep->mctp, &ep->astlpc->binding, eid);
}

static void endpoint_destroy(struct astlpc_endpoint *ep)
{
	mctp_astlpc_destroy(ep->astlpc);
	mctp_destroy(ep->mctp);
}

static void network_init(struct astlpc_test *ctx)
{
	uint8_t kcs[2] = { 0 };
	int rc;

	ctx->lpc_mem = calloc(1, 1 * 1024 * 1024);
	assert(ctx->lpc_mem);

	/* BMC initialisation */
	endpoint_init(&ctx->bmc, 8, MCTP_BINDING_ASTLPC_MODE_BMC, &ctx->kcs,
		      ctx->lpc_mem);
	assert(ctx->kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_BMC_READY);

	/* Host initialisation */
	endpoint_init(&ctx->host, 9, MCTP_BINDING_ASTLPC_MODE_HOST, &ctx->kcs,
		      ctx->lpc_mem);

	/* BMC processes host channel init request, alerts host */
	mctp_astlpc_poll(ctx->bmc.astlpc);
	assert(ctx->kcs[MCTP_ASTLPC_KCS_REG_STATUS] &
	       KCS_STATUS_CHANNEL_ACTIVE);
	assert(ctx->kcs[MCTP_ASTLPC_KCS_REG_DATA] == 0xff);

	/* Host dequeues channel init result */
	mctp_astlpc_poll(ctx->host.astlpc);
}

static void network_destroy(struct astlpc_test *ctx)
{
	endpoint_destroy(&ctx->bmc);
	endpoint_destroy(&ctx->host);
	free(ctx->lpc_mem);
}

static void astlpc_assert_tx_packet(struct astlpc_endpoint *src,
				    const void *expected, size_t len)
{
	const size_t tx_body = src->astlpc->layout.tx.offset + 4 + 4;
	const void *test = ((char *)src->astlpc->lpc_map) + tx_body;
	assert(!memcmp(test, expected, len));
}

static void astlpc_test_packetised_message_bmc_to_host(void)
{
	struct astlpc_test ctx = { 0 };
	uint8_t msg[2 * MCTP_BTU];
	int rc;

	/* Test harness initialisation */

	network_init(&ctx);

	memset(&msg[0], 0x5a, MCTP_BTU);
	memset(&msg[MCTP_BTU], 0xa5, MCTP_BTU);

	ctx.msg = &msg[0];
	ctx.count = 0;
	mctp_set_rx_all(ctx.host.mctp, rx_message, &ctx);

	/* BMC sends a message */
	rc = mctp_message_tx(ctx.bmc.mctp, 9, msg, sizeof(msg));
	assert(rc == 0);

	/* Host receives the first packet */
	mctp_astlpc_poll(ctx.host.astlpc);

	/* BMC dequeues ownership hand-over and sends the queued packet */
	rc = mctp_astlpc_poll(ctx.bmc.astlpc);
	assert(rc == 0);

	/* Host receives the next packet */
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF);
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_DATA] == 0x01);

	astlpc_assert_tx_packet(&ctx.bmc, &msg[MCTP_BTU], MCTP_BTU);

	/* Host receives final packet */
	mctp_astlpc_poll(ctx.host.astlpc);
	assert(ctx.count == 1);

	network_destroy(&ctx);
}

static void astlpc_test_simple_message_host_to_bmc(void)
{
	struct astlpc_test ctx = { 0 };
	uint8_t msg[MCTP_BTU];
	int rc;

	/* Test harness initialisation */

	network_init(&ctx);

	memset(&msg[0], 0xa5, MCTP_BTU);

	ctx.msg = &msg[0];
	ctx.count = 0;
	mctp_set_rx_all(ctx.bmc.mctp, rx_message, &ctx);

	/* Host sends the single-packet message */
	rc = mctp_message_tx(ctx.host.mctp, 8, msg, sizeof(msg));
	assert(rc == 0);
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_IBF);
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_DATA] == 0x01);

	astlpc_assert_tx_packet(&ctx.host, &msg[0], MCTP_BTU);

	/* BMC receives the single-packet message */
	mctp_astlpc_poll(ctx.bmc.astlpc);
	assert(ctx.count == 1);

	/* BMC returns Tx area ownership to Host */
	assert(!(ctx.kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_IBF));
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_DATA] = 0x02);
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF);

	/* Host dequeues ownership hand-over and sends the queued packet */
	rc = mctp_astlpc_poll(ctx.host.astlpc);
	assert(rc == 0);

	network_destroy(&ctx);
}

static void astlpc_test_simple_message_bmc_to_host(void)
{
	struct astlpc_test ctx = { 0 };
	uint8_t msg[MCTP_BTU];
	int rc;

	/* Test harness initialisation */

	network_init(&ctx);

	memset(&msg[0], 0x5a, MCTP_BTU);

	ctx.msg = &msg[0];
	ctx.count = 0;
	mctp_set_rx_all(ctx.host.mctp, rx_message, &ctx);

	/* BMC sends the single-packet message */
	rc = mctp_message_tx(ctx.bmc.mctp, 9, msg, sizeof(msg));
	assert(rc == 0);
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF);
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_DATA] == 0x01);

	astlpc_assert_tx_packet(&ctx.bmc, &msg[0], MCTP_BTU);

	/* Host receives the single-packet message */
	mctp_astlpc_poll(ctx.host.astlpc);
	assert(ctx.count == 1);

	/* Host returns Rx area ownership to BMC */
	assert(!(ctx.kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF));
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_DATA] = 0x02);
	assert(ctx.kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_IBF);

	/* BMC dequeues ownership hand-over and sends the queued packet */
	rc = mctp_astlpc_poll(ctx.bmc.astlpc);
	assert(rc == 0);

	network_destroy(&ctx);
}

static void astlpc_test_host_before_bmc(void)
{
	struct mctp_binding_astlpc_mmio mmio = { 0 };
	struct mctp_binding_astlpc *astlpc;
	uint8_t kcs[2] = { 0 };
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	/* Inject KCS registers */
	mmio.kcs = &kcs;

	/* Initialise the binding */
	astlpc = mctp_astlpc_init(MCTP_BINDING_ASTLPC_MODE_HOST, MCTP_BTU, NULL,
				  &astlpc_direct_mmio_ops, &mmio);

	/* Register the binding to trigger the start-up sequence */
	rc = mctp_register_bus(mctp, &astlpc->binding, 8);

	/* Start-up should fail as we haven't initialised the BMC */
	assert(rc < 0);

	mctp_astlpc_destroy(astlpc);
	mctp_destroy(mctp);
}

static void astlpc_test_simple_init(void)
{
	struct astlpc_endpoint bmc, host;
	uint8_t kcs[2] = { 0 };
	void *lpc_mem;
	int rc;

	/* Test harness initialisation */
	lpc_mem = calloc(1, 1 * 1024 * 1024);
	assert(lpc_mem);

	/* BMC initialisation */
	endpoint_init(&bmc, 8, MCTP_BINDING_ASTLPC_MODE_BMC, &kcs, lpc_mem);

	/* Verify the BMC binding was initialised */
	assert(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_BMC_READY);

	/* Host initialisation */
	endpoint_init(&host, 9, MCTP_BINDING_ASTLPC_MODE_HOST, &kcs, lpc_mem);

	/* Host sends channel init command */
	assert(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_IBF);
	assert(kcs[MCTP_ASTLPC_KCS_REG_DATA] == 0x00);

	/* BMC receives host channel init request */
	mctp_astlpc_poll(bmc.astlpc);

	/* BMC sends init response */
	assert(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF);
	assert(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_CHANNEL_ACTIVE);
	assert(kcs[MCTP_ASTLPC_KCS_REG_DATA] == 0xff);

	/* Host dequeues data */
	mctp_astlpc_poll(host.astlpc);

	endpoint_destroy(&bmc);
	endpoint_destroy(&host);
	free(lpc_mem);
}

static void astlpc_test_simple_indirect_message_bmc_to_host(void)
{
	struct astlpc_test ctx = { 0 };
	uint8_t kcs[2] = { 0 };
	uint8_t msg[MCTP_BTU];
	int rc;

	ctx.lpc_mem = calloc(1, LPC_WIN_SIZE);
	assert(ctx.lpc_mem);

	/* Test message data */
	memset(&msg[0], 0x5a, MCTP_BTU);

	/* Manually set up the network so we can inject the indirect ops */

	/* BMC initialisation */
	ctx.bmc.mmio.bmc = true;
	ctx.bmc.mctp = mctp_init();
	assert(ctx.bmc.mctp);
	ctx.bmc.mmio.kcs = &kcs;
	ctx.bmc.mmio.lpc = ctx.lpc_mem;
	ctx.bmc.mmio.lpc_size = LPC_WIN_SIZE;
	ctx.bmc.astlpc =
		mctp_astlpc_init(MCTP_BINDING_ASTLPC_MODE_BMC, MCTP_BTU, NULL,
				 &astlpc_indirect_mmio_ops, &ctx.bmc.mmio);
	mctp_register_bus(ctx.bmc.mctp, &ctx.bmc.astlpc->binding, 8);

	/* Host initialisation */
	ctx.host.mmio.bmc = false;
	ctx.host.mctp = mctp_init();
	assert(ctx.host.mctp);
	ctx.host.mmio.kcs = &kcs;
	ctx.host.mmio.lpc = ctx.lpc_mem;
	ctx.host.mmio.lpc_size = LPC_WIN_SIZE;
	ctx.host.astlpc =
		mctp_astlpc_init(MCTP_BINDING_ASTLPC_MODE_HOST, MCTP_BTU, NULL,
				 &astlpc_indirect_mmio_ops, &ctx.host.mmio);
	mctp_register_bus(ctx.host.mctp, &ctx.host.astlpc->binding, 9);

	/* BMC processes host channel init request, alerts host */
	mctp_astlpc_poll(ctx.bmc.astlpc);

	/* Host dequeues channel init result */
	mctp_astlpc_poll(ctx.host.astlpc);

	ctx.msg = &msg[0];
	ctx.count = 0;
	mctp_set_rx_all(ctx.host.mctp, rx_message, &ctx);

	/* BMC sends the single-packet message */
	rc = mctp_message_tx(ctx.bmc.mctp, 9, msg, sizeof(msg));
	assert(rc == 0);

	/* Host receives the single-packet message */
	rc = mctp_astlpc_poll(ctx.host.astlpc);
	assert(rc == 0);
	assert(ctx.count == 1);

	/* BMC dequeues ownership hand-over and sends the queued packet */
	rc = mctp_astlpc_poll(ctx.bmc.astlpc);
	assert(rc == 0);

	/* Can still tear-down the network in the normal fashion */
	network_destroy(&ctx);
}

static void astlpc_test_host_tx_bmc_gone(void)
{
	struct astlpc_test ctx = { 0 };
	uint8_t unwritten[MCTP_BTU];
	uint8_t msg[MCTP_BTU];
	int rc;

	/* Test harness initialisation */

	network_init(&ctx);

	memset(&msg[0], 0x5a, sizeof(msg));
	memset(&unwritten[0], 0, sizeof(unwritten));

	ctx.msg = &msg[0];
	ctx.count = 0;

	/* Clear bmc-ready */
	endpoint_destroy(&ctx.bmc);

	/* Host detects that the BMC is disabled */
	mctp_astlpc_poll(ctx.host.astlpc);

	/* Host attempts to send the single-packet message, but is prevented */
	rc = mctp_message_tx(ctx.host.mctp, 8, msg, sizeof(msg));
	assert(rc == 0);
	assert(!(ctx.kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF));
	astlpc_assert_tx_packet(&ctx.host, &unwritten[0], MCTP_BTU);

	/* BMC comes back */
	endpoint_init(&ctx.bmc, 8, MCTP_BINDING_ASTLPC_MODE_BMC, &ctx.kcs,
		      ctx.lpc_mem);
	mctp_set_rx_all(ctx.bmc.mctp, rx_message, &ctx);

	/* Host triggers channel init */
	mctp_astlpc_poll(ctx.host.astlpc);

	/* BMC handles channel init */
	mctp_astlpc_poll(ctx.bmc.astlpc);

	/* Host completes channel init, flushing the Tx queue */
	mctp_astlpc_poll(ctx.host.astlpc);

	/* BMC receives the single-packet message */
	mctp_astlpc_poll(ctx.bmc.astlpc);
	assert(ctx.count == 1);

	network_destroy(&ctx);
}

static void astlpc_test_poll_not_ready(void)
{
	struct astlpc_endpoint bmc;
	uint8_t kcs[2] = { 0 };
	void *lpc_mem;
	int rc;

	/* Test harness initialisation */
	lpc_mem = calloc(1, 1 * 1024 * 1024);
	assert(lpc_mem);

	/* BMC initialisation */
	endpoint_init(&bmc, 8, MCTP_BINDING_ASTLPC_MODE_BMC, &kcs, lpc_mem);

	/* Check for a command despite none present */
	rc = mctp_astlpc_poll(bmc.astlpc);

	/* Make sure it doesn't fail */
	assert(rc == 0);

	endpoint_destroy(&bmc);
	free(lpc_mem);
}

/* clang-format off */
#define TEST_CASE(test) { #test, test }
static const struct {
	const char *name;
	void (*test)(void);
} astlpc_tests[] = {
	TEST_CASE(astlpc_test_simple_init),
	TEST_CASE(astlpc_test_host_before_bmc),
	TEST_CASE(astlpc_test_simple_message_bmc_to_host),
	TEST_CASE(astlpc_test_simple_message_host_to_bmc),
	TEST_CASE(astlpc_test_packetised_message_bmc_to_host),
	TEST_CASE(astlpc_test_simple_indirect_message_bmc_to_host),
	TEST_CASE(astlpc_test_host_tx_bmc_gone),
	TEST_CASE(astlpc_test_poll_not_ready),
};
/* clang-format on */

int main(void)
{
	int i;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	for (i = 0; i < ARRAY_SIZE(astlpc_tests); i++) {
		mctp_prlog(MCTP_LOG_DEBUG, "begin: %s", astlpc_tests[i].name);
		astlpc_tests[i].test();
		mctp_prlog(MCTP_LOG_DEBUG, "end: %s\n", astlpc_tests[i].name);
	}

	return 0;
}
