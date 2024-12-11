/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "compiler.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "range.h"
#include "test-utils.h"

#define TEST_DEST_EID		9
#define TEST_DEST_NULL_EID	0
#define TEST_DEST_BROADCAST_EID 255
#define TEST_SRC_EID		10

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#define MAX_PAYLOAD_SIZE 50000

struct pktbuf {
	struct mctp_hdr hdr;
	uint8_t *payload;
};

struct test_params {
	bool seen;
	size_t message_size;
	uint8_t msg_tag;
	bool tag_owner;
};

static void rx_message(uint8_t eid __unused, bool tag_owner, uint8_t msg_tag,
		       void *data, void *msg __unused, size_t len)
{
	struct test_params *param = (struct test_params *)data;

	mctp_prdebug("MCTP message received: len %zd, tag %u", len, msg_tag);

	param->seen = true;
	param->message_size = len;
	param->msg_tag = msg_tag;
	param->tag_owner = tag_owner;
}

static uint8_t get_sequence()
{
	static uint8_t pkt_seq = 0;

	return (pkt_seq++ % 4);
}

static uint8_t get_tag()
{
	static uint8_t tag = 0;

	return (tag++ % 8);
}

/*
 * receive_pktbuf bypasses all bindings and directly invokes mctp_bus_rx.
 * This is necessary in order invoke test cases on the core functionality.
 * The memory allocated for the mctp packet is capped at MCTP_BTU
 * size, however, the mimiced rx pkt still retains the len parameter.
 * This allows to mimic packets larger than a sane memory allocator can
 * provide.
 */
static void receive_ptkbuf(struct mctp_binding_test *binding,
			   const struct pktbuf *pktbuf, size_t len)
{
	size_t alloc_size = MIN((size_t)MCTP_BTU, len);
	struct mctp_pktbuf *rx_pkt;

	rx_pkt = __mctp_alloc(sizeof(*rx_pkt) + MCTP_PACKET_SIZE(alloc_size));
	assert(rx_pkt);

	/* Preserve passed len parameter */
	rx_pkt->size = MCTP_PACKET_SIZE(len);
	rx_pkt->start = 0;
	rx_pkt->end = MCTP_PACKET_SIZE(len);
	rx_pkt->mctp_hdr_off = 0;
	memcpy(rx_pkt->data, &pktbuf->hdr, sizeof(pktbuf->hdr));
	memcpy(rx_pkt->data + sizeof(pktbuf->hdr), pktbuf->payload, alloc_size);

	mctp_bus_rx((struct mctp_binding *)binding, rx_pkt);
	__mctp_free(rx_pkt);
}

static void receive_one_fragment(struct mctp_binding_test *binding,
				 uint8_t *payload, size_t fragment_size,
				 uint8_t flags_seq_tag, struct pktbuf *pktbuf)
{
	pktbuf->hdr.flags_seq_tag = flags_seq_tag;
	pktbuf->payload = payload;
	receive_ptkbuf(binding, pktbuf, fragment_size);
}

static void receive_two_fragment_message(struct mctp_binding_test *binding,
					 uint8_t *payload,
					 size_t fragment1_size,
					 size_t fragment2_size,
					 struct pktbuf *pktbuf)
{
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	uint8_t flags_seq_tag;

	flags_seq_tag = MCTP_HDR_FLAG_SOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, payload, fragment1_size, flags_seq_tag,
			     pktbuf);

	flags_seq_tag = MCTP_HDR_FLAG_EOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, payload + fragment1_size, fragment2_size,
			     flags_seq_tag, pktbuf);
}

static void mctp_core_test_simple_rx()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[2 * MCTP_BTU];
	struct pktbuf pktbuf;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Receive 2 fragments of equal size */
	receive_two_fragment_message(binding, test_payload, MCTP_BTU, MCTP_BTU,
				     &pktbuf);

	assert(test_param.seen);
	assert(test_param.message_size == 2 * MCTP_BTU);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_equal_length_fragments()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	struct pktbuf pktbuf;
	uint8_t flags_seq_tag;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Receive 3 fragments, each of size MCTP_BTU */
	flags_seq_tag = MCTP_HDR_FLAG_SOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	flags_seq_tag = (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU,
			     flags_seq_tag, &pktbuf);

	flags_seq_tag = MCTP_HDR_FLAG_EOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + (2 * MCTP_BTU), MCTP_BTU,
			     flags_seq_tag, &pktbuf);

	assert(test_param.seen);
	assert(test_param.message_size == 3 * MCTP_BTU);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_unexpected_smaller_middle_fragment()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	struct pktbuf pktbuf;
	uint8_t flags_seq_tag;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Middle fragment with size MCTP_BTU - 1 */
	flags_seq_tag = MCTP_HDR_FLAG_SOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	flags_seq_tag = (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU - 1,
			     flags_seq_tag, &pktbuf);

	flags_seq_tag = MCTP_HDR_FLAG_EOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + (2 * MCTP_BTU), MCTP_BTU,
			     flags_seq_tag, &pktbuf);

	assert(!test_param.seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_unexpected_bigger_middle_fragment()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	struct pktbuf pktbuf;
	uint8_t flags_seq_tag;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Middle fragment with size MCTP_BTU + 1 */
	flags_seq_tag = MCTP_HDR_FLAG_SOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	flags_seq_tag = (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU + 1,
			     flags_seq_tag, &pktbuf);

	flags_seq_tag = MCTP_HDR_FLAG_EOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + (2 * MCTP_BTU), MCTP_BTU,
			     flags_seq_tag, &pktbuf);

	assert(!test_param.seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_smaller_end_fragment()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	uint8_t end_frag_size = MCTP_BTU - 10;
	struct pktbuf pktbuf;
	uint8_t flags_seq_tag;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	flags_seq_tag = MCTP_HDR_FLAG_SOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	flags_seq_tag = (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU,
			     flags_seq_tag, &pktbuf);

	flags_seq_tag = MCTP_HDR_FLAG_EOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + (2 * MCTP_BTU),
			     end_frag_size, flags_seq_tag, &pktbuf);

	assert(test_param.seen);
	assert(test_param.message_size ==
	       (size_t)(2 * MCTP_BTU + end_frag_size));

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_bigger_end_fragment()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	uint8_t end_frag_size = MCTP_BTU + 10;
	struct pktbuf pktbuf;
	uint8_t flags_seq_tag;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	flags_seq_tag = MCTP_HDR_FLAG_SOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	flags_seq_tag = (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU,
			     flags_seq_tag, &pktbuf);

	flags_seq_tag = MCTP_HDR_FLAG_EOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload + (2 * MCTP_BTU),
			     end_frag_size, flags_seq_tag, &pktbuf);

	assert(!test_param.seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_drop_large_fragments()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MAX_PAYLOAD_SIZE];
	struct pktbuf pktbuf;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Receive a large payload - first fragment with MCTP_BTU bytes,
	* 2nd fragment of SIZE_MAX */

	receive_two_fragment_message(binding, test_payload, MCTP_BTU,
				     SIZE_MAX - sizeof(struct mctp_hdr),
				     &pktbuf);

	assert(!test_param.seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_exhaust_context_buffers()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	uint8_t i = 0;
	const uint8_t max_context_buffers = 16;
	struct pktbuf pktbuf;
	uint8_t flags_seq_tag;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Exhaust all 16 context buffers*/
	for (i = 0; i < max_context_buffers; i++) {
		flags_seq_tag = MCTP_HDR_FLAG_SOM |
				(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
		receive_one_fragment(binding, test_payload, MCTP_BTU,
				     flags_seq_tag, &pktbuf);

		/* Change source EID so that different contexts are created */
		pktbuf.hdr.src++;
	}

	/* Send a full message from a different EID */
	pktbuf.hdr.src++;
	receive_two_fragment_message(binding, test_payload, MCTP_BTU, MCTP_BTU,
				     &pktbuf);

	/* Message assembly should fail */
	assert(!test_param.seen);

	/* Complete message assembly for one of the messages */
	pktbuf.hdr.src -= max_context_buffers;
	flags_seq_tag = MCTP_HDR_FLAG_EOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	assert(test_param.seen);
	assert(test_param.message_size == (2 * MCTP_BTU));

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_rx_with_tag()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MCTP_BTU];
	uint8_t tag = get_tag();
	struct pktbuf pktbuf;
	uint8_t flags_seq_tag;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	test_param.msg_tag = 0;
	test_param.tag_owner = false;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Set tag and tag owner fields for a recieve packet */
	flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM |
			(1 << MCTP_HDR_TO_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	assert(test_param.seen);
	assert(test_param.message_size == (MCTP_BTU));
	assert(test_param.msg_tag == tag);
	assert(test_param.tag_owner);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_rx_with_tag_multifragment()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	static uint8_t test_payload[MCTP_BTU];
	uint8_t tag = get_tag();
	struct pktbuf pktbuf;
	uint8_t flags_seq_tag;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	test_param.msg_tag = 0;
	test_param.tag_owner = false;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Set tag and tag owner fields for a 3 fragment packet */
	flags_seq_tag = MCTP_HDR_FLAG_SOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) |
			(1 << MCTP_HDR_TO_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	flags_seq_tag = (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
			(1 << MCTP_HDR_TO_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	flags_seq_tag = MCTP_HDR_FLAG_EOM |
			(get_sequence() << MCTP_HDR_SEQ_SHIFT) |
			(1 << MCTP_HDR_TO_SHIFT) | tag;
	receive_one_fragment(binding, test_payload, MCTP_BTU, flags_seq_tag,
			     &pktbuf);

	assert(test_param.seen);
	assert(test_param.message_size == (3 * MCTP_BTU));
	assert(test_param.msg_tag == tag);
	assert(test_param.tag_owner);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

/*
 * This test case covers null destination eid. MCTP
 * daemon might query endpoint (i.e., Get Endpoint
 * ID command) by physical address requests and
 * destination eid as 0. Endpoint shall accept and
 * handle this request.
 */
static void mctp_core_test_rx_with_null_dst_eid()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[2 * MCTP_BTU];
	struct pktbuf pktbuf;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_NULL_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Receive 2 fragments of equal size */
	receive_two_fragment_message(binding, test_payload, MCTP_BTU, MCTP_BTU,
				     &pktbuf);

	assert(test_param.seen);
	assert(test_param.message_size == 2 * MCTP_BTU);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

/*
 * This test case covers Broadcast Request message (i.e.,
 * `Endpoint Discovery` command). Endpoint shall accept
 * and handle this request.
 */
static void mctp_core_test_rx_with_broadcast_dst_eid()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[2 * MCTP_BTU];
	struct pktbuf pktbuf;

	memset(test_payload, 0, sizeof(test_payload));
	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);
	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_BROADCAST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	/* Receive 2 fragments of equal size */
	receive_two_fragment_message(binding, test_payload, MCTP_BTU, MCTP_BTU,
				     &pktbuf);

	assert(test_param.seen);
	assert(test_param.message_size == 2 * MCTP_BTU);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

/*
 * This test case tests tag allocation. 8 tags
 * are allowed to be pending.
 */
static void mctp_core_test_tx_alloc_tag()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t msg_tag;
	void *msg;
	int rc;
	mctp_eid_t dest_eid1 = 30;
	size_t msg_len = 10;

	mctp_test_stack_init(&mctp, &binding, dest_eid1);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	uint8_t used = 0;
	for (int i = 0; i < 8; i++) {
		test_param.seen = false;
		test_param.msg_tag = 0xff;
		test_param.tag_owner = false;

		msg = __mctp_alloc(msg_len);
		memset(msg, 0x99, msg_len);
		rc = mctp_message_tx_request(mctp, dest_eid1, msg, msg_len,
					     &msg_tag);
		assert(rc == 0);
		assert(test_param.seen == true);
		assert(test_param.msg_tag == msg_tag);
		assert(test_param.tag_owner == true);
		used |= (1 << msg_tag);
	}
	assert(used == 0xff);

	/* Ran out of tags */
	test_param.seen = false;
	msg = __mctp_alloc(msg_len);
	memset(msg, 0x99, msg_len);
	rc = mctp_message_tx_request(mctp, dest_eid1, msg, msg_len, &msg_tag);
	assert(rc == -EBUSY);
	assert(test_param.seen == false);

	/* Send/Receive a response to one of those tags */
	test_param.seen = false;
	msg = __mctp_alloc(msg_len);
	memset(msg, 0x99, msg_len);
	/* Arbitrary one */
	uint8_t replied_tag = 3;
	rc = mctp_message_tx_alloced(mctp, dest_eid1, false, replied_tag, msg,
				     msg_len);
	assert(rc == 0);
	assert(test_param.seen == true);
	assert(test_param.msg_tag == replied_tag);
	assert(test_param.tag_owner == false);

	/* Now sending allocates that tag again, since it is the only spare one */
	test_param.seen = false;
	msg = __mctp_alloc(msg_len);
	memset(msg, 0x99, msg_len);
	rc = mctp_message_tx_request(mctp, dest_eid1, msg, msg_len, &msg_tag);
	assert(rc == 0);
	assert(test_param.seen == true);
	assert(msg_tag == replied_tag);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

/* clang-format off */
#define TEST_CASE(test) { #test, test }
static const struct {
	const char *name;
	void (*test)(void);
} mctp_core_tests[] = {
	TEST_CASE(mctp_core_test_simple_rx),
	TEST_CASE(mctp_core_test_receive_equal_length_fragments),
	TEST_CASE(mctp_core_test_receive_unexpected_smaller_middle_fragment),
	TEST_CASE(mctp_core_test_receive_unexpected_bigger_middle_fragment),
	TEST_CASE(mctp_core_test_receive_smaller_end_fragment),
	TEST_CASE(mctp_core_test_receive_bigger_end_fragment),
	TEST_CASE(mctp_core_test_drop_large_fragments),
	TEST_CASE(mctp_core_test_exhaust_context_buffers),
	TEST_CASE(mctp_core_test_rx_with_tag),
	TEST_CASE(mctp_core_test_rx_with_tag_multifragment),
	TEST_CASE(mctp_core_test_rx_with_null_dst_eid),
	TEST_CASE(mctp_core_test_rx_with_broadcast_dst_eid),
	TEST_CASE(mctp_core_test_tx_alloc_tag),
};
/* clang-format on */

int main(void)
{
	uint8_t i;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	static_assert(ARRAY_SIZE(mctp_core_tests) < SIZE_MAX, "size");
	for (i = 0; i < ARRAY_SIZE(mctp_core_tests); i++) {
		mctp_prlog(MCTP_LOG_DEBUG, "begin: %s",
			   mctp_core_tests[i].name);
		mctp_core_tests[i].test();
		mctp_prlog(MCTP_LOG_DEBUG, "end: %s\n",
			   mctp_core_tests[i].name);
	}

	return 0;
}
