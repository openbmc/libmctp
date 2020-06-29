/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include "binding.h"

#include "libmctp.h"
#include "libmctp-alloc.h"

#include "test-utils.h"

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct mctp_binding_bridge {
	struct mctp_binding	binding;
	int			rx_count;
	int			tx_count;
	uint8_t			last_pkt_data;
};

struct test_ctx {
	struct mctp			*mctp;
	struct mctp_binding_bridge	*bindings[2];
};

static int mctp_binding_bridge_tx(struct mctp_binding *b,
		struct mctp_pktbuf *pkt)
{
	struct mctp_binding_bridge *binding = container_of(b,
			struct mctp_binding_bridge, binding);

	binding->tx_count++;
	assert(mctp_pktbuf_size(pkt) == sizeof(struct mctp_hdr) + 1);
	binding->last_pkt_data = *(uint8_t *)mctp_pktbuf_data(pkt);

	return 0;
}

struct mctp_pktbuf *mctp_binding_bridge_frame(struct mctp_binding *binding
					      __attribute__((unused)),
					      struct mctp_pktbuf *pkt,
					      const struct mctp_device *dest
					      __attribute__((unused)))
{
	return pkt;
}

static void mctp_binding_bridge_rx(struct mctp_binding_bridge *binding,
				   mctp_eid_t src, mctp_eid_t dest, uint8_t key)
{
	struct mctp_pktbuf *pkt;
	struct mctp_hdr *hdr;
	uint8_t *buf;

	pkt = mctp_pktbuf_alloc(&binding->binding,
			sizeof(struct mctp_hdr) + 1);
	assert(pkt);

	hdr = mctp_pktbuf_hdr(pkt);
	hdr->flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;

	hdr->src = src;
	hdr->dest = dest;

	buf = mctp_pktbuf_data(pkt);
	*buf = key;

	binding->rx_count++;
	mctp_binding_rx(&binding->binding, pkt);
}

static struct mctp_binding_bridge *mctp_binding_bridge_init(void)
{
	struct mctp_binding_bridge *binding;

	binding = __mctp_alloc(sizeof(*binding));
	memset(binding, 0, sizeof(*binding));
	binding->binding.name = "test";
	binding->binding.version = 1;
	binding->binding.tx = mctp_binding_bridge_tx;
	binding->binding.frame = mctp_binding_bridge_frame;
	binding->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	binding->binding.pkt_pad = 0;
	return binding;
}

int main(void)
{
	struct test_ctx _ctx, *ctx = &_ctx;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	mctp_eid_t eid_1 = MCTP_EID(8);
	mctp_eid_t eid_2 = MCTP_EID(9);

	ctx->mctp = mctp_init();
	ctx->bindings[0] = mctp_binding_bridge_init();
	ctx->bindings[1] = mctp_binding_bridge_init();

	mctp_bridge_busses(ctx->mctp, &ctx->bindings[0]->binding, eid_1,
			   &ctx->bindings[1]->binding, eid_2);

	mctp_binding_set_tx_enabled(&ctx->bindings[0]->binding, true);
	mctp_binding_set_tx_enabled(&ctx->bindings[1]->binding, true);

	mctp_binding_bridge_rx(ctx->bindings[0], eid_1, eid_2, 0xaa);
	assert(ctx->bindings[0]->tx_count == 0);
	assert(ctx->bindings[1]->tx_count == 1);
	assert(ctx->bindings[1]->last_pkt_data == 0xaa);

	mctp_binding_bridge_rx(ctx->bindings[1], eid_2, eid_1, 0x55);
	assert(ctx->bindings[1]->tx_count == 1);
	assert(ctx->bindings[0]->tx_count == 1);
	assert(ctx->bindings[0]->last_pkt_data == 0x55);

	__mctp_free(ctx->bindings[1]);
	__mctp_free(ctx->bindings[0]);
	mctp_destroy(ctx->mctp);

	return EXIT_SUCCESS;
}
