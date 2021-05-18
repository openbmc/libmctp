/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp-log.h"
#include "libmctp-alloc.h"
#include "test-utils.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DEST_EID 9
#define TEST_SRC_EID 10

#define MAX_SIZE_T_SIZE (size_t) - 1

static bool seen;

uint8_t test_payload[2 * MCTP_BTU];

#define __unused __attribute__((unused))

static void rx_message(uint8_t eid __unused, void *data __unused, void *msg,
		       size_t len)
{
	uint8_t type;

	type = *(uint8_t *)msg;

	mctp_prdebug("MCTP message received: len %zd, type %d", len, type);

	seen = true;
}

static uint8_t get_sequence()
{
	static uint8_t pkt_seq = 0;

	return (pkt_seq++ % 4);
}

static void receive_ptkbuf(struct mctp_binding_test *binding, void *buf, size_t len)
{
	struct mctp_pktbuf *rx_pkt;

	rx_pkt = __mctp_alloc(sizeof(*rx_pkt) + sizeof(struct mctp_hdr));

	rx_pkt->size = len;
	rx_pkt->start = 0;
	rx_pkt->end = len;
	rx_pkt->mctp_hdr_off = 0;
	rx_pkt->next = NULL;
	memcpy(rx_pkt->data, buf, sizeof(struct mctp_hdr));

	mctp_bus_rx((struct mctp_binding*)binding, rx_pkt);
}

int main(void)
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	

	mctp_set_log_stdio(MCTP_LOG_DEBUG);
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, NULL);

	memset(&test_payload[0], 0x5a, MCTP_BTU);
	memset(&test_payload[MCTP_BTU], 0xa5, MCTP_BTU);

	struct {
		struct mctp_hdr hdr;
		uint8_t* payload;
	} pktbuf;

	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Receive a single packet payload of 2 fragments*/
	seen = false;
	
	pktbuf.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_SOM | (get_sequence() << MCTP_HDR_SEQ_SHIFT);
	pktbuf.payload = test_payload;	
	receive_ptkbuf(binding, &pktbuf,
				 sizeof(struct mctp_hdr) + MCTP_BTU);

	pktbuf.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_EOM | (get_sequence() << MCTP_HDR_SEQ_SHIFT);
	pktbuf.payload = test_payload + MCTP_BTU;
	receive_ptkbuf(binding, &pktbuf,
				 sizeof(struct mctp_hdr) + MCTP_BTU);

	assert(seen);

	/* Receive a large payload - first fragment with MCTP_BTU bytes, 2nd fragment of MAX_SIZE_T_SIZE */
	seen = false;
	mctp_set_max_message_size(mctp, MAX_SIZE_T_SIZE);

	pktbuf.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_SOM | (get_sequence() << MCTP_HDR_SEQ_SHIFT);
	pktbuf.payload = test_payload;
	receive_ptkbuf(binding, &pktbuf,
				 sizeof(struct mctp_hdr) + MCTP_BTU);

	pktbuf.hdr.flags_seq_tag =
		MCTP_HDR_FLAG_EOM | (get_sequence() << MCTP_HDR_SEQ_SHIFT);
	pktbuf.payload = test_payload;
	receive_ptkbuf(binding, &pktbuf, MAX_SIZE_T_SIZE);
	
	assert(!seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
	return 0;
}
