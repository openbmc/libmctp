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

void control_message_callback(mctp_eid_t src, void *data, void *buf, size_t len)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = buf;
	printf("Control message received - command code: 0x%x\n",
	       msg_hdr->command_code);
	assert(msg_hdr->command_code == MCTP_CTRL_CMD_GET_ENDPOINT_ID);
	(*(uint8_t*)data)++;
}

void control_message_transport_callback(mctp_eid_t src, void *data, void *buf,
					 size_t len)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = buf;
	printf("Transport control message received - command code: 0x%X\n",
	       msg_hdr->command_code);
	assert(msg_hdr->command_code == 0xF2);
	(*(uint8_t*)data)++;
}

int mctp_test_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = mctp_pktbuf_data(pkt);
	printf("Control message response sent from 0x%X: completion code 0x%X\n",
	       mctp_pktbuf_hdr(pkt)->src, msg_hdr->completion_code);
	assert(msg_hdr->completion_code == MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD);
	(*(uint8_t*)b->control_rx_data)++;
	return 0;
}

void rcv_ctrl_msg(struct mctp_binding *b, void *buf, size_t len)
{
	struct mctp_pktbuf *pkt = mctp_pktbuf_alloc(b, len);
	memcpy(mctp_pktbuf_hdr(pkt), buf, len);
	mctp_bus_rx(b, pkt);
}

void setup_test_binding(struct mctp_binding *test_binding,
			struct mctp *test_endpoint, uint8_t *callbacks_counter)
{
	assert(test_binding != NULL);
	assert(test_endpoint != NULL);
	assert(callbacks_counter != NULL);

	memset(test_binding, 0, sizeof(*test_binding));
	test_binding->name = "test";
	test_binding->version = 1;
	test_binding->tx = mctp_test_tx;
	test_binding->pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	test_binding->pkt_pad = 0;
	mctp_register_bus(test_endpoint, test_binding, eid_1);
	mctp_binding_set_tx_enabled(test_binding, true);

	mctp_set_rx_ctrl(test_endpoint, control_message_callback, callbacks_counter);
	test_binding->control_rx = control_message_transport_callback;
	test_binding->control_rx_data = callbacks_counter;
}

void send_control_message(struct mctp_binding *bin)
{
	struct msg_payload ctl_msg_to_send;
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctrl_hdr.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctrl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
	printf("Sending control message: 0x%X\n",
	       ctl_msg_to_send.ctrl_hdr.command_code);

	rcv_ctrl_msg(bin, &ctl_msg_to_send, sizeof(ctl_msg_to_send));
}

void send_control_message_with_reserved_command_code(struct mctp_binding *bin)
{
	struct msg_payload ctl_msg_to_send;
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctrl_hdr.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctrl_hdr.command_code = MCTP_CTRL_CMD_RESERVED;
	printf("Sending reserved command code in control message: 0x%X\n",
	       ctl_msg_to_send.ctrl_hdr.command_code);

	rcv_ctrl_msg(bin, &ctl_msg_to_send, sizeof(ctl_msg_to_send));
}

void send_transport_control_message(struct mctp_binding *bin)
{
	struct msg_payload ctl_msg_to_send;
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctrl_hdr.ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctrl_hdr.rq_dgram_inst = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctrl_hdr.command_code = 0xF2;
	printf("Sending transport control message: 0x%X\n",
	       ctl_msg_to_send.ctrl_hdr.command_code);

	rcv_ctrl_msg(bin, &ctl_msg_to_send, sizeof(ctl_msg_to_send));
}

int main(int argc, char *argv[])
{
	struct mctp *test_endpoint = mctp_init();
	struct mctp_binding test_binding;

	uint8_t callback_results = 0;
	const uint8_t expected_callback_results = 3;

	setup_test_binding(&test_binding, test_endpoint, &callback_results);

	send_control_message(&test_binding);

	send_control_message_with_reserved_command_code(&test_binding);

	send_transport_control_message(&test_binding);

	/* Transport control message: */
	assert(callback_results == expected_callback_results);

	__mctp_free(test_endpoint);
}
