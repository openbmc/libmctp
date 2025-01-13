/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#pragma once

#include <assert.h>
#include "libmctp.h"
#include "libmctp-i2c.h"

/* Limited by bytecount field */
static_assert(I2C_BTU <= 254);

#ifndef MCTP_I2C_NEIGH_COUNT
#define MCTP_I2C_NEIGH_COUNT 4
#endif

struct mctp_i2c_hdr {
	uint8_t dest;
	uint8_t cmd;
	uint8_t bytecount;
	uint8_t source;
};

struct mctp_i2c_neigh {
	bool used;
	/* 7-bit address */
	uint8_t addr;
	uint8_t eid;
	/* from platform_now(), for LRU eviction */
	uint64_t last_seen_timestamp;
};

struct mctp_binding_i2c {
	struct mctp_binding binding;

	struct mctp_i2c_neigh neigh[MCTP_I2C_NEIGH_COUNT];

	uint8_t own_addr;

	uint8_t tx_storage[MCTP_PKTBUF_SIZE(I2C_BTU)] PKTBUF_STORAGE_ALIGN;
	uint8_t rx_storage[MCTP_PKTBUF_SIZE(I2C_BTU)] PKTBUF_STORAGE_ALIGN;

	mctp_i2c_tx_fn tx_fn;
	void *tx_ctx;
};
