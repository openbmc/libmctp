/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp-astlpc.h"
#include "libmctp-log.h"
#include "container_of.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#define RX_BUFFER_DATA	0x100 + 4 + 4

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "astlpc.c"

struct mctp_binding_astlpc_mmio {
	struct mctp_binding_astlpc astlpc;
	bool bmc;

	uint8_t (*kcs)[2];
};

#define binding_to_mmio(b) \
	container_of(b, struct mctp_binding_astlpc_mmio, astlpc)

int mctp_astlpc_mmio_kcs_read(void *data, enum mctp_binding_astlpc_kcs_reg reg,
		uint8_t *val)
{
	struct mctp_binding_astlpc_mmio *mmio = binding_to_mmio(data);

	*val = (*mmio->kcs)[reg];

	mctp_prdebug("%s: 0x%hhx from %s", __func__, *val, reg ? "status" : "data");

	if (reg == MCTP_ASTLPC_KCS_REG_DATA) {
		uint8_t flag = mmio->bmc ? KCS_STATUS_IBF : KCS_STATUS_OBF;
		(*mmio->kcs)[MCTP_ASTLPC_KCS_REG_STATUS] &= ~flag;
	}

	return 0;
}

int mctp_astlpc_mmio_kcs_write(void *data, enum mctp_binding_astlpc_kcs_reg reg,
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

	mctp_prdebug("%s: 0x%hhx to %s", __func__, val, reg ? "status" : "data");

	return 0;
}

static void rx_message(uint8_t eid, void *data, void *msg, size_t len)
{
	uint8_t type;

	type = *(uint8_t *)msg;

	mctp_prdebug("MCTP message received: len %zd, type %d",
			len, type);
}

const struct mctp_binding_astlpc_ops mctp_binding_astlpc_mmio_ops = {
	.kcs_read = mctp_astlpc_mmio_kcs_read,
	.kcs_write = mctp_astlpc_mmio_kcs_write,
};

struct astlpc_test {
	struct mctp_binding_astlpc_mmio mmio;
	struct mctp_binding_astlpc *astlpc;
	struct mctp *mctp;
};

void initialise_endpoint(struct astlpc_test *ep, mctp_eid_t eid,
			 enum mctp_binding_astlpc_mode mode, uint8_t (*kcs)[2],
			 void *lpc_mem)
{
	/*
	 * Configure the direction of the KCS interface so we know whether to
	 * set or clear IBF or OBF on writes or reads. For the moment, conflate
	 * bus owner with the BMC.
	 */
	ep->mmio.bmc = (mode == astlpc_mode_bus_owner);

	ep->mctp = mctp_init();
	assert(ep->mctp);

	mctp_set_rx_all(ep->mctp, rx_message, NULL);

	/* Inject KCS registers */
	ep->mmio.kcs = kcs;

	/* Initialise the binding */
	ep->astlpc = mctp_astlpc_init_ops(mode, &mctp_binding_astlpc_mmio_ops,
					  &ep->mmio, lpc_mem);

	mctp_register_bus(ep->mctp, &ep->astlpc->binding, eid);
}

int main(void)
{
	uint8_t msg[2 * MCTP_BTU];
	struct astlpc_test bmc, host;
	size_t lpc_size;
	uint8_t kcs[2] = { 0 };
	void *lpc_mem;
	int rc;

	/* Test harness initialisation */

	memset(&msg[0], 0x5a, MCTP_BTU);
	memset(&msg[MCTP_BTU], 0xa5, MCTP_BTU);

	lpc_mem = calloc(1, 1 * 1024 * 1024);
	assert(lpc_mem);

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	/* Bus owner (BMC) initialisation */
	initialise_endpoint(&bmc, 8, astlpc_mode_bus_owner, &kcs, lpc_mem);

	/* Verify the BMC binding was initialised */
	assert(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_BMC_READY);

	/* Device (Host) initialisation */
	initialise_endpoint(&host, 9, astlpc_mode_device, &kcs, lpc_mem);

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

	/* BMC sends a message */
	rc = mctp_message_tx(bmc.mctp, 9, msg, sizeof(msg));
	assert(rc == 0);
	assert(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF);
	assert(kcs[MCTP_ASTLPC_KCS_REG_DATA] == 0x01);

	/* Verify it's the packet we expect */
	assert(!memcmp(lpc_mem + RX_BUFFER_DATA, &msg[0], MCTP_BTU));

	/* Host receives a packet */
	mctp_astlpc_poll(host.astlpc);

	/* Host returns Rx area ownership to BMC */
	assert(!(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF));
	assert(kcs[MCTP_ASTLPC_KCS_REG_DATA] = 0x02);
	assert(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_IBF);

	/* BMC dequeues ownership hand-over and sends the queued packet */
	rc = mctp_astlpc_poll(bmc.astlpc);
	assert(rc == 0);

	/* Host receives a message */
	assert(kcs[MCTP_ASTLPC_KCS_REG_STATUS] & KCS_STATUS_OBF);
	assert(kcs[MCTP_ASTLPC_KCS_REG_DATA] == 0x01);

	/* Verify it's the packet we expect */
	assert(!memcmp(lpc_mem + RX_BUFFER_DATA, &msg[MCTP_BTU], MCTP_BTU));

	mctp_astlpc_destroy(bmc.astlpc);
	mctp_destroy(bmc.mctp);
	mctp_astlpc_destroy(host.astlpc);
	mctp_destroy(host.mctp);
	free(lpc_mem);

	return 0;
}
