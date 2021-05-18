/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#ifdef NDEBUG
#undef NDEBUG
#endif

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp-log.h"
#include "libmctp-alloc.h"
#include "test-utils.h"

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_DEST_EID 9
#define TEST_SRC_EID  10

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#define __unused __attribute__((unused))

#define MAX_PAYLOAD_SIZE 50000

struct {
	struct mctp_hdr hdr;
	uint8_t *payload;
} pktbuf;

struct test_params {
	bool seen;
	size_t message_size;
};

static void rx_message(uint8_t eid __unused, void *data, void *msg __unused,
		       size_t len)
{
	struct test_params *param = (struct test_params *)data;

	mctp_prdebug("MCTP message received: len %zd", len);

	param->seen = true;
	param->message_size = len;
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

/* This function bypasses all bindings and directly invokes mctp_bus_rx.
 * This is necessary in order invoke test cases on the core functionality */

static void receive_ptkbuf(struct mctp_binding_test *binding, void *buf,
			   size_t len)
{
	struct mctp_pktbuf *rx_pkt;

	rx_pkt = __mctp_alloc(sizeof(*rx_pkt) + sizeof(struct mctp_hdr));

	rx_pkt->size = len;
	rx_pkt->start = 0;
	rx_pkt->end = len;
	rx_pkt->mctp_hdr_off = 0;
	rx_pkt->next = NULL;
	memcpy(rx_pkt->data, buf, sizeof(struct mctp_hdr));

	mctp_bus_rx((struct mctp_binding *)binding, rx_pkt);
}

static void receive_one_fragment(struct mctp_binding_test *binding,
				 uint8_t *payload, size_t fragment_size,
				 uint8_t flags_seq_tag)
{
	pktbuf.hdr.flags_seq_tag = flags_seq_tag;
	pktbuf.payload = payload;
	receive_ptkbuf(binding, &pktbuf,
		       fragment_size + sizeof(struct mctp_hdr));
}

static void receive_two_fragment_message(struct mctp_binding_test *binding,
					 uint8_t *payload,
					 size_t fragment1_size,
					 size_t fragment2_size)
{
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	receive_one_fragment(binding, payload, fragment1_size,
			     MCTP_HDR_FLAG_SOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	receive_one_fragment(binding, payload + fragment1_size, fragment2_size,
			     MCTP_HDR_FLAG_EOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);
}

static void mctp_core_test_simple_rx()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[2 * MCTP_BTU];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();

	test_param.seen = false;
	test_param.message_size = 0;
	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	/* Receive 2 fragments of equal size */
	receive_two_fragment_message(binding, test_payload, MCTP_BTU, MCTP_BTU);

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
	uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();

	test_param.seen = false;
	test_param.message_size = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	/* Receive 3 fragments, each of size MCTP_BTU */
	receive_one_fragment(binding, test_payload, MCTP_BTU,
			     MCTP_HDR_FLAG_SOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU,
			     (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag);

	receive_one_fragment(binding, test_payload + (2 * MCTP_BTU), MCTP_BTU,
			     MCTP_HDR_FLAG_EOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	assert(test_param.seen);
	assert(test_param.message_size == 3 * MCTP_BTU);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_unexpected_middle_fragment_size_test_1()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();

	test_param.seen = false;
	test_param.message_size = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	receive_one_fragment(binding, test_payload, MCTP_BTU,
			     MCTP_HDR_FLAG_SOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU - 1,
			     (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag);

	receive_one_fragment(binding, test_payload + (2 * MCTP_BTU), MCTP_BTU,
			     MCTP_HDR_FLAG_EOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	assert(!test_param.seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_unexpected_middle_fragment_size_test_2()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();

	test_param.seen = false;
	test_param.message_size = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	/* Middle fragment with size MCTP_BTU + 1*/
	receive_one_fragment(binding, test_payload, MCTP_BTU,
			     MCTP_HDR_FLAG_SOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU + 1,
			     (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag);

	receive_one_fragment(binding, test_payload + (2 * MCTP_BTU), MCTP_BTU,
			     MCTP_HDR_FLAG_EOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	assert(!test_param.seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_expected_end_fragment_size()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	uint8_t end_frag_size = MCTP_BTU - 10;

	test_param.seen = false;
	test_param.message_size = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	receive_one_fragment(binding, test_payload, MCTP_BTU,
			     MCTP_HDR_FLAG_SOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU,
			     (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag);

	receive_one_fragment(
		binding, test_payload + (2 * MCTP_BTU), end_frag_size,
		MCTP_HDR_FLAG_EOM | (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
			tag);

	assert(test_param.seen);
	assert(test_param.message_size == (2 * MCTP_BTU + end_frag_size));

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_receive_unexpected_end_fragment_size()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();

	test_param.seen = false;
	test_param.message_size = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	receive_one_fragment(binding, test_payload, MCTP_BTU,
			     MCTP_HDR_FLAG_SOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	receive_one_fragment(binding, test_payload + MCTP_BTU, MCTP_BTU,
			     (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag);

	receive_one_fragment(
		binding, test_payload + (2 * MCTP_BTU), MCTP_BTU + 10,
		MCTP_HDR_FLAG_EOM | (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
			tag);

	assert(!test_param.seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_exhaust_context_buffers()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[MAX_PAYLOAD_SIZE];
	uint8_t tag = MCTP_HDR_FLAG_TO | get_tag();
	uint8_t i = 0;
	const uint8_t max_context_buffers = 16;

	test_param.seen = false;
	test_param.message_size = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	/* Exhaust all 16 context buffers*/
	for (i = 0; i < max_context_buffers; i++) {
		receive_one_fragment(
			binding, test_payload, MCTP_BTU,
			MCTP_HDR_FLAG_SOM |
				(get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag);

		/* Change source EID so that different contexts are created */
		pktbuf.hdr.src++;
	}

	/* Send a full message from a different EID */
	pktbuf.hdr.src++;
	receive_two_fragment_message(binding, test_payload, MCTP_BTU, MCTP_BTU);

	/* Message assemble should fail */
	assert(!test_param.seen);

	/* Complete message assembly for one of the messages */
	pktbuf.hdr.src -= max_context_buffers;
	receive_one_fragment(binding, test_payload, MCTP_BTU,
			     MCTP_HDR_FLAG_EOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);

	assert(test_param.seen);
	assert(test_param.message_size == (2 * MCTP_BTU));

	/* Reset source EID */
	pktbuf.hdr.src = TEST_SRC_EID;

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_test_trigger_ctx_buffer_overflow()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	struct test_params test_param;
	uint8_t test_payload[MAX_PAYLOAD_SIZE];

	test_param.seen = false;
	test_param.message_size = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, &test_param);

	/* Receive a large payload - first fragment with MCTP_BTU bytes,
	 * 2nd fragment of SIZE_MAX */
	mctp_set_max_message_size(mctp, SIZE_MAX);

	receive_two_fragment_message(binding, test_payload, MCTP_BTU,
				     SIZE_MAX - sizeof(struct mctp_hdr));

	assert(!test_param.seen);

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
	TEST_CASE(mctp_core_test_receive_unexpected_middle_fragment_size_test_1),
	TEST_CASE(mctp_core_test_receive_unexpected_middle_fragment_size_test_2),
	TEST_CASE(mctp_core_test_receive_expected_end_fragment_size),
	TEST_CASE(mctp_core_test_receive_unexpected_end_fragment_size),
	TEST_CASE(mctp_core_test_exhaust_context_buffers),
	TEST_CASE(mctp_core_test_trigger_ctx_buffer_overflow)
};
/* clang-format on */

#ifndef BUILD_ASSERT
#define BUILD_ASSERT(x)                                                        \
	do {                                                                   \
		(void)sizeof(char[0 - (!(x))]);                                \
	} while (0)
#endif

int main(void)
{
	uint8_t i;

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	memset(&pktbuf, 0, sizeof(pktbuf));
	pktbuf.hdr.dest = TEST_DEST_EID;
	pktbuf.hdr.src = TEST_SRC_EID;

	BUILD_ASSERT(ARRAY_SIZE(mctp_core_tests) < SIZE_MAX);
	for (i = 0; i < ARRAY_SIZE(mctp_core_tests); i++) {
		mctp_prlog(MCTP_LOG_DEBUG, "begin: %s",
			   mctp_core_tests[i].name);
		mctp_core_tests[i].test();
		mctp_prlog(MCTP_LOG_DEBUG, "end: %s\n",
			   mctp_core_tests[i].name);
	}

	return 0;
}
