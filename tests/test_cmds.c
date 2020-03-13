/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <stdio.h>
#include <string.h>

#include <libmctp.h>
#include <libmctp-alloc.h>
#include <libmctp-cmds.h>

#include "test-utils.h"

struct msg_payload {
  struct mctp_hdr hdr;
  struct mctp_ctrl_msg_hdr ctl_hdr;
};

void control_message_callback(mctp_eid_t src, void* data, void* buf, size_t len)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = (struct mctp_ctrl_msg_hdr*)buf;
	printf("Control message received - command code: 0x%x\n", msg_hdr->command_code);
}

void control_message__transport_callback(mctp_eid_t src, void* data, void* buf, size_t len)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = (struct mctp_ctrl_msg_hdr*)buf;
	printf("Transport control message received - command code: 0x%X\n", msg_hdr->command_code);
}

int mctp_test_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	printf("Control message response sent from 0x%X: completion code 0x%X\n",
		   mctp_pktbuf_hdr(pkt)->src, ((struct mctp_ctrl_msg_hdr*)mctp_pktbuf_data(pkt))->completion_code);
	return 0;
}

void rcv_ctrl_msg(struct mctp_binding *b, void *buf, size_t len)
{
	struct mctp_pktbuf *pkt = mctp_pktbuf_alloc(b, len);
	memcpy(mctp_pktbuf_hdr(pkt), buf, len);
	mctp_bus_rx(b, pkt);
}

int main(int argc, char* argv[])
{
	const mctp_eid_t eid_1 = 9;
	const mctp_eid_t eid_2 = 10;
	struct msg_payload ctl_msg_to_send;
	struct mctp *test_endpoint = mctp_init();

	struct mctp_binding test_binding;
	memset(&test_binding, 0,sizeof(struct mctp_binding));
	test_binding.name = "test";
	test_binding.version = 1;
	test_binding.tx = mctp_test_tx;
	test_binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	test_binding.pkt_pad = 0;
	mctp_register_bus(test_endpoint, &test_binding, eid_1);
	mctp_binding_set_tx_enabled(&test_binding, true);


	/* Connect callbacks: */
	mctp_set_rx_ctrl(test_endpoint, control_message_callback, NULL);
	mctp_set_transport_rx_ctrl(&test_binding, control_message__transport_callback, NULL);

	/* Regular control message: */
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctl_hdr.msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctl_hdr.request = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctl_hdr.command_code = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
	printf("Sending control message: 0x%X\n", ctl_msg_to_send.ctl_hdr.command_code);

	rcv_ctrl_msg(&test_binding, &ctl_msg_to_send, sizeof(ctl_msg_to_send));

	/* Reserved command code: */
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctl_hdr.msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctl_hdr.request = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctl_hdr.command_code = MCTP_CTRL_CMD_RSVD;
	printf("Sending reserved command code in control message: 0x%X\n", ctl_msg_to_send.ctl_hdr.command_code);

	rcv_ctrl_msg(&test_binding, &ctl_msg_to_send, sizeof(ctl_msg_to_send));

	/* Transport control message: */
	memset(&ctl_msg_to_send, 0, sizeof(ctl_msg_to_send));
	ctl_msg_to_send.hdr.dest = eid_1;
	ctl_msg_to_send.hdr.src = eid_2;
	ctl_msg_to_send.hdr.flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;
	ctl_msg_to_send.ctl_hdr.msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	ctl_msg_to_send.ctl_hdr.request = MCTP_CTRL_HDR_FLAG_REQUEST;
	ctl_msg_to_send.ctl_hdr.command_code = 0xF2;
	printf("Sending transport control message: 0x%X\n", ctl_msg_to_send.ctl_hdr.command_code);

	rcv_ctrl_msg(&test_binding, &ctl_msg_to_send, sizeof(ctl_msg_to_send));

	__mctp_free(test_endpoint);

}
