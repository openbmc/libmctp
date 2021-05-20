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
#define TEST_SRC_EID  10

#define MAX_SIZE_T_SIZE	 (size_t) - 1
#define MAX_PAYLOAD_SIZE 50000

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

static bool seen;

uint8_t test_payload[MAX_PAYLOAD_SIZE];

struct {
	struct mctp_hdr hdr;
	uint8_t *payload;
} pktbuf;

#define __unused __attribute__((unused))

static void rx_message(uint8_t eid __unused, void *data __unused,
		       void *msg __unused, size_t len)
{
	mctp_prdebug("MCTP message received: len %zd", len);

	seen = true;
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
	receive_ptkbuf(binding, &pktbuf, fragment_size);
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

	receive_one_fragment(
		binding, payload + fragment1_size - sizeof(struct mctp_hdr),
		fragment2_size,
		MCTP_HDR_FLAG_EOM | (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
			tag);
}

static void mctp_core_simple_rx()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, NULL);

	/* Receive a single packet payload of 2 fragments*/
	seen = false;
	receive_two_fragment_message(binding, test_payload,
				     sizeof(struct mctp_hdr) + MCTP_BTU,
				     sizeof(struct mctp_hdr) + MCTP_BTU);
	assert(seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_trigger_ctx_buffer_overflow()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, NULL);

	/* Receive a large payload - first fragment with MCTP_BTU bytes, 2nd fragment of MAX_SIZE_T_SIZE */
	seen = false;
	mctp_set_max_message_size(mctp, MAX_SIZE_T_SIZE);

	receive_two_fragment_message(binding, test_payload,
				     sizeof(struct mctp_hdr) + MCTP_BTU,
				     MAX_SIZE_T_SIZE);
	assert(!seen);

	mctp_prdebug("Test passed.");

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_irregular_fragment_rx_test_1()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, NULL);

	/* Receive a payload where second fragment = (3 * first fragment), assert that we receive the message */
	/* Test 1 - First fragment size less than 4096U */
	mctp_set_max_message_size(mctp, MAX_SIZE_T_SIZE);

	seen = false;
	receive_two_fragment_message(binding, test_payload, 4000U, 4000U * 3);
	assert(seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_irregular_fragment_rx_test_2()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, NULL);

	/* Receive a payload where second fragment = (3 * first fragment), assert that we receive the message */
	/* Test 2 - First fragment size equal to 4096U */
	mctp_set_max_message_size(mctp, MAX_SIZE_T_SIZE);
	seen = false;
	receive_two_fragment_message(binding, test_payload,
				     4096U + sizeof(struct mctp_hdr),
				     (4096U * 3) + sizeof(struct mctp_hdr));
	assert(seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_irregular_fragment_rx_test_3()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, NULL);

	/* Receive a payload where second fragment = (3 * first fragment), assert that we receive the message */
	/* Test 3 - First fragment size greater than 4096U */
	mctp_set_max_message_size(mctp, MAX_SIZE_T_SIZE);

	seen = false;
	receive_two_fragment_message(binding, test_payload, 5000U, 5000U * 3);
	assert(seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_irregular_fragment_rx_test_4()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	uint8_t tag = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, NULL);

	/* Test 4 - Send three fragments where each fragment is 3x size of the previous one */
	mctp_set_max_message_size(mctp, MAX_SIZE_T_SIZE);

	seen = false;
	tag = MCTP_HDR_FLAG_TO | get_tag();
	receive_one_fragment(binding, test_payload, 5000U,
			     MCTP_HDR_FLAG_SOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);
	receive_one_fragment(binding, test_payload, 15000U,
			     (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag);
	receive_one_fragment(binding, test_payload, 45000U,
			     MCTP_HDR_FLAG_EOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);
	assert(seen);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void mctp_core_irregular_fragment_rx_test_5()
{
	struct mctp *mctp = NULL;
	struct mctp_binding_test *binding = NULL;
	uint8_t tag = 0;

	mctp_test_stack_init(&mctp, &binding, TEST_DEST_EID);
	mctp_set_rx_all(mctp, rx_message, NULL);

	/* Test 5 - Send three fragments where each fragment is 3x size of the previous one, 
	* and sum total over flows max packet size. 
	* Assert that message assembly does not go through */
	mctp_set_max_message_size(mctp, 25000U);

	seen = false;
	tag = MCTP_HDR_FLAG_TO | get_tag();

	receive_one_fragment(binding, test_payload, 5000U,
			     MCTP_HDR_FLAG_SOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);
	receive_one_fragment(binding, test_payload, 15000U,
			     (get_sequence() << MCTP_HDR_SEQ_SHIFT) | tag);
	receive_one_fragment(binding, test_payload, 45000U,
			     MCTP_HDR_FLAG_EOM |
				     (get_sequence() << MCTP_HDR_SEQ_SHIFT) |
				     tag);
	assert(!seen);

	mctp_prdebug("Test passed.");
	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

/* clang-format off */
#define TEST_CASE(test) { #test, test }
static const struct {
	const char *name;
	void (*test)(void);
} mctp_core_tests[] = {
	TEST_CASE(mctp_core_simple_rx),
	TEST_CASE(mctp_core_trigger_ctx_buffer_overflow),
	TEST_CASE(mctp_core_irregular_fragment_rx_test_1),
	TEST_CASE(mctp_core_irregular_fragment_rx_test_2),
	TEST_CASE(mctp_core_irregular_fragment_rx_test_3),
	TEST_CASE(mctp_core_irregular_fragment_rx_test_4),
	TEST_CASE(mctp_core_irregular_fragment_rx_test_5),
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

	memset(&test_payload[0], 0x5a, MCTP_BTU);
	memset(&test_payload[MCTP_BTU], 0xa5, MCTP_BTU);

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
