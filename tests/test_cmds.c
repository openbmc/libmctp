/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include "test-utils.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <libmctp.h>
#include <libmctp-alloc.h>
#include <libmctp-cmds.h>

#ifdef NDEBUG
#undef NDEBUG
#endif

static const mctp_eid_t eid_1 = 9;
static const mctp_eid_t eid_2 = 10;

struct msg_payload {
	struct mctp_hdr hdr;
	struct mctp_ctrl_msg_hdr ctrl_hdr;
};

struct callback_data {
	uint8_t invoked;
	union {
		uint8_t command_code;
		uint8_t completion_code;
	};
};

void control_message_callback(mctp_eid_t src, void *data, void *buf, size_t len)
{
	struct callback_data *ctx = data;
	struct mctp_ctrl_msg_hdr *msg_hdr = buf;
	printf("Control message received - command code: 0x%x\n",
	       msg_hdr->command_code);
	ctx->invoked++;
	assert(msg_hdr->command_code == ctx->command_code);
}

void control_message_transport_callback(mctp_eid_t src, void *data, void *buf,
					size_t len)
{
	struct callback_data *ctx = data;
	struct mctp_ctrl_msg_hdr *msg_hdr = buf;
	printf("Transport control message received - command code: 0x%X\n",
	       msg_hdr->command_code);
	ctx->invoked++;
	assert(msg_hdr->command_code == ctx->command_code);
}

int mctp_test_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = mctp_pktbuf_data(pkt);
	struct callback_data *ctx = b->control_rx_data;

	printf("Control message response from 0x%X: completion code 0x%X\n",
	       mctp_pktbuf_hdr(pkt)->src, msg_hdr->completion_code);
	assert(msg_hdr->completion_code == ctx->completion_code);
	ctx->invoked++;
	return 0;
}

void rcv_ctrl_msg(struct mctp_binding *b, const void *buf, size_t len)
{
	struct mctp_pktbuf *pkt = mctp_pktbuf_alloc(b, len);
	memcpy(mctp_pktbuf_hdr(pkt), buf, len);
	mctp_bus_rx(b, pkt);
}

void setup_test_binding(struct mctp_binding *test_binding,
			struct mctp *test_endpoint, void *callback_ctx)
{
	assert(test_binding != NULL);
	assert(test_endpoint != NULL);
	assert(callback_ctx != NULL);

	memset(test_binding, 0, sizeof(*test_binding));
	test_binding->name = "test";
	test_binding->version = 1;
	test_binding->tx = mctp_test_tx;
	test_binding->pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	test_binding->pkt_pad = 0;
	test_binding->control_rx = control_message_transport_callback;
	test_binding->control_rx_data = callback_ctx;

	mctp_register_bus(test_endpoint, test_binding, eid_1);
	mctp_binding_set_tx_enabled(test_binding, true);
}

void send_control_message(void)
{
	struct mctp *endpoint = mctp_init();
	struct mctp_binding binding;
	struct callback_data ctx;
	static const struct msg_payload send_control_message_payload = {
		.hdr = {
			.dest = eid_1,
			.src = eid_2,
			.flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM,
		},
		.ctrl_hdr = {
			.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE,
			.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST,
			.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID,
		},
	};
	memset(&ctx, 0, sizeof(ctx));
	setup_test_binding(&binding, endpoint, &ctx);
	mctp_set_rx_ctrl(endpoint, control_message_callback, &ctx);
	ctx.command_code = send_control_message_payload.ctrl_hdr.command_code;
	printf("Sending control message: 0x%X\n",
	       send_control_message_payload.ctrl_hdr.command_code);
	rcv_ctrl_msg(&binding, (void *)&send_control_message_payload,
		     sizeof(send_control_message_payload));
	assert(ctx.invoked == 1);

	__mctp_free(endpoint);
}

void send_control_message_with_reserved_command_code(void)
{
	struct mctp *endpoint = mctp_init();
	struct mctp_binding binding;
	struct callback_data ctx;
	struct msg_payload ctl_msg_to_send;
	static const struct msg_payload send_control_message_payload = {
		.hdr = {
			.dest = eid_1,
			.src = eid_2,
			.flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM,
		},
		.ctrl_hdr = {
			.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE,
			.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST,
			.command_code = MCTP_CTRL_CMD_RESERVED,
		},
	};

	memset(&ctx, 0, sizeof(ctx));
	setup_test_binding(&binding, endpoint, &ctx);
	mctp_set_rx_ctrl(endpoint, control_message_callback, &ctx);
	ctx.completion_code = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
	printf("Sending reserved command code in control message: 0x%X\n",
	       send_control_message_payload.ctrl_hdr.command_code);
	rcv_ctrl_msg(&binding, (void *)&send_control_message_payload,
		     sizeof(send_control_message_payload));
	assert(ctx.invoked == 1);

	__mctp_free(endpoint);
}

void send_transport_control_message(void)
{
	struct mctp *endpoint = mctp_init();
	struct mctp_binding binding;
	struct callback_data ctx;
	static const struct msg_payload send_control_message_payload = {
		.hdr = {
			.dest = eid_1,
			.src = eid_2,
			.flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM,
		},
		.ctrl_hdr = {
			.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE,
			.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST,
			.command_code = 0xF2,
		},
	};

	memset(&ctx, 0, sizeof(ctx));
	setup_test_binding(&binding, endpoint, &ctx);
	ctx.command_code = send_control_message_payload.ctrl_hdr.command_code;
	printf("Sending transport control message: 0x%X\n",
	       send_control_message_payload.ctrl_hdr.command_code);
	rcv_ctrl_msg(&binding, (void *)&send_control_message_payload,
		     sizeof(send_control_message_payload));
	assert(ctx.invoked == 1);

	__mctp_free(endpoint);
}

int main(int argc, char *argv[])
{
	send_control_message();
	send_control_message_with_reserved_command_code();
	send_transport_control_message();
	return EXIT_SUCCESS;
}
