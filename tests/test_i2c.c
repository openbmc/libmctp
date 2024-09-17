/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "compiler.h"
#include "range.h"
#include "libmctp-log.h"
#include "libmctp-i2c.h"
#include "libmctp-sizes.h"
#include "libmctp-alloc.h"

/* For access to mctp_bninding_i2c internals */
#include "i2c-internal.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

struct mctp_binding_serial_pipe {
	int ingress;
	int egress;

	struct mctp_binding_serial *serial;
};

// Sized to test fragmentation and >8 bit length
#define TEST_MSG_LEN 300
static uint8_t mctp_msg_src[TEST_MSG_LEN];

struct i2c_test {
	struct mctp_binding_i2c *i2c;
	struct mctp *mctp;

	uint8_t rx_msg[TEST_MSG_LEN];
	size_t rx_len;

	/* Physical addresses. These get set regardless of whether the packet
	 * is dropped by the stack (no match etc) */
	uint8_t last_rx_i2c_src;
	uint8_t last_tx_i2c_dst;
};

static const uint8_t I2C_ADDR_A = 0x20;
static const uint8_t I2C_ADDR_B = 0x21;
static const uint8_t EID_A = 50;
static const uint8_t EID_B = 51;

static int test_i2c_tx(const void *buf, size_t len, void *ctx)
{
	struct i2c_test *test_pair = ctx;
	struct i2c_test *tx_test = &test_pair[0];
	struct i2c_test *rx_test = &test_pair[1];

	mctp_prdebug("test_i2c_tx len %zu", len);

	const struct mctp_i2c_hdr *hdr = buf;
	tx_test->last_tx_i2c_dst = hdr->dest >> 1;
	rx_test->last_rx_i2c_src = hdr->source >> 1;

	mctp_i2c_rx(rx_test->i2c, buf, len);
	return 0;
}

static void test_i2c_rxmsg(uint8_t src_eid, bool tag_owner, uint8_t msg_tag,
			   void *ctx, void *msg, size_t len)
{
	struct i2c_test *test_pair = ctx;
	// struct i2c_test *tx_test = &test_pair[0];
	struct i2c_test *rx_test = &test_pair[1];

	mctp_prdebug("test_i2c_rx src %d len %zu tag %d owner %d", src_eid, len,
		     msg_tag, tag_owner);

	// Must be cleared by previous test runs
	assert(rx_test->rx_len == 0);
	memcpy(rx_test->rx_msg, msg, len);
	rx_test->rx_len = len;
}

/* Transmits a MCTP message and checks the received message matches */
static void run_tx_test(struct i2c_test *tx_test, uint8_t dest_eid,
			size_t tx_len, struct i2c_test *rx_test)
{
	int rc;
	const uint8_t msg_tag = 2;
	const bool tag_owner = false;

	assert(tx_len <= sizeof(mctp_msg_src));
	rc = mctp_message_tx(tx_test->mctp, dest_eid, tag_owner, msg_tag,
			     mctp_msg_src, tx_len);
	assert(rc == 0);

	while (!mctp_is_tx_ready(tx_test->mctp, dest_eid)) {
		mctp_i2c_tx_poll(tx_test->i2c);
	}

	assert(rx_test->rx_len == tx_len);
	assert(memcmp(rx_test->rx_msg, mctp_msg_src, tx_len) == 0);

	rx_test->rx_len = 0;
}

static void test_neigh_expiry(struct i2c_test *tx_test,
			      struct i2c_test *rx_test)
{
	const uint8_t msg_tag = 2;
	const bool tag_owner = true;
	const size_t msg_len = 5;
	int rc;

	(void)rx_test;

	/* Clear the tx neighbour table */
	memset(tx_test->i2c->neigh, 0x0, sizeof(tx_test->i2c->neigh));

	/* Check that all EIDs fail */
	rx_test->rx_len = 0;
	for (size_t eid = 8; eid < 254; eid++) {
		mctp_message_tx(tx_test->mctp, eid, tag_owner, msg_tag,
				mctp_msg_src, msg_len);
		/* Not received */
		assert(rx_test->rx_len == 0);
	}

	/* Add one entry */
	rc = mctp_i2c_set_neighbour(tx_test->i2c, EID_B,
				    rx_test->i2c->own_addr);
	assert(rc == 0);
	rx_test->rx_len = 0;
	mctp_message_tx(tx_test->mctp, EID_B, tag_owner, msg_tag, mctp_msg_src,
			msg_len);
	assert(rx_test->rx_len == msg_len);
	assert(tx_test->last_tx_i2c_dst == rx_test->i2c->own_addr);

	/* Replace the entry */
	rx_test->i2c->own_addr++;
	rc = mctp_i2c_set_neighbour(tx_test->i2c, EID_B,
				    rx_test->i2c->own_addr);
	assert(rc == 0);
	rx_test->rx_len = 0;
	mctp_message_tx(tx_test->mctp, EID_B, tag_owner, msg_tag, mctp_msg_src,
			msg_len);
	assert(rc == 0);
	assert(rx_test->rx_len == msg_len);
	assert(tx_test->last_tx_i2c_dst == rx_test->i2c->own_addr);

	/* Check only one entry is set */
	size_t count = 0;
	for (size_t i = 0; i < MCTP_I2C_NEIGH_COUNT; i++) {
		struct mctp_i2c_neigh *n = &tx_test->i2c->neigh[i];
		if (n->used) {
			assert(n->eid == EID_B);
			count++;
		}
	}
	assert(count == 1);

	/* Ensure we can iterate without overflow.
	 * If MCTP_I2C_NEIGH_COUNT increases too large this test would need rethinking
	 * (and eviction may become impossible) */
	assert((int)EID_B + MCTP_I2C_NEIGH_COUNT < 254);
	assert((int)I2C_ADDR_B + MCTP_I2C_NEIGH_COUNT < 0x7f);

	/* Fill entries. -1 because one was already filled. */
	for (size_t i = 0; i < MCTP_I2C_NEIGH_COUNT - 1; i++) {
		/* Unused addresses */
		uint8_t addr = rx_test->i2c->own_addr + i + 1;
		uint8_t eid = EID_B + i + 1;
		rc = mctp_i2c_set_neighbour(tx_test->i2c, eid, addr);
		assert(rc == 0);
	}

	/* Check all are used */
	for (size_t i = 0; i < MCTP_I2C_NEIGH_COUNT; i++) {
		struct mctp_i2c_neigh *n = &tx_test->i2c->neigh[i];
		assert(n->used);
	}

	/* Test eviction */
	{
		uint8_t addr =
			rx_test->i2c->own_addr + MCTP_I2C_NEIGH_COUNT + 1;
		uint8_t eid = EID_B + MCTP_I2C_NEIGH_COUNT + 1;
		rc = mctp_i2c_set_neighbour(tx_test->i2c, eid, addr);
		assert(rc == 0);

		/* EID_B got evicted, send should fail */
		rx_test->rx_len = 0;
		mctp_message_tx(tx_test->mctp, EID_B, tag_owner, msg_tag,
				mctp_msg_src, msg_len);
		/* Not received */
		assert(rx_test->rx_len == 0);
	}

	/* Add EID_B again */
	rc = mctp_i2c_set_neighbour(tx_test->i2c, EID_B,
				    rx_test->i2c->own_addr);
	assert(rc == 0);
	rx_test->rx_len = 0;
	mctp_message_tx(tx_test->mctp, EID_B, tag_owner, msg_tag, mctp_msg_src,
			msg_len);
	/* Is received */
	assert(rx_test->rx_len == msg_len);
}

int main(void)
{
	struct i2c_test scenario[2];
	struct i2c_test *tx_test = &scenario[0];
	struct i2c_test *rx_test = &scenario[1];

	mctp_set_log_stdio(MCTP_LOG_DEBUG);

	memset(scenario, 0x0, sizeof(scenario));

	/* Setup a source buffer */
	for (size_t i = 0; i < sizeof(mctp_msg_src); i++) {
		mctp_msg_src[i] = i & 0xff;
	}

	tx_test->mctp = mctp_init();
	assert(tx_test->mctp);
	tx_test->i2c = malloc(MCTP_SIZEOF_BINDING_I2C);
	assert(tx_test->i2c);
	rx_test->mctp = mctp_init();
	assert(rx_test->mctp);
	rx_test->i2c = malloc(MCTP_SIZEOF_BINDING_I2C);
	assert(rx_test->i2c);

	/* TX side */
	mctp_i2c_setup(tx_test->i2c, I2C_ADDR_A, test_i2c_tx, scenario);
	mctp_register_bus(tx_test->mctp, mctp_binding_i2c_core(tx_test->i2c),
			  EID_A);
	mctp_set_rx_all(tx_test->mctp, NULL, NULL);
	mctp_i2c_set_neighbour(tx_test->i2c, EID_B, I2C_ADDR_B);

	/* RX side */
	mctp_i2c_setup(rx_test->i2c, I2C_ADDR_B, NULL, NULL);
	mctp_register_bus(rx_test->mctp, mctp_binding_i2c_core(rx_test->i2c),
			  EID_B);
	mctp_set_rx_all(rx_test->mctp, test_i2c_rxmsg, scenario);
	// mctp_i2c_set_neighbour(rx_test->i2c, EID_A, I2C_ADDR_A);

	/* Try all message sizes */
	for (size_t i = 1; i < sizeof(mctp_msg_src); i++) {
		run_tx_test(tx_test, EID_B, i, rx_test);
	}

	test_neigh_expiry(tx_test, rx_test);

	return 0;
}
