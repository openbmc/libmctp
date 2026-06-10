/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "libmctp.h"

struct mctp_binding_i2c;


typedef int (*mctp_i2c_tx_fn)(const void *buf, size_t len, void *ctx);

/**
 * @brief Initialize and set up an MCTP I2C binding.
 *
 * Allocates and initializes a new MCTP I2C binding instance.
 * This function internally calls mctp_i2c_setup() — callers do
 * NOT need to invoke mctp_i2c_setup() separately.
 *
 * @param own_addr  Local device I2C address (7-bit).
 * @param tx_fn     TX callback function. Can be NULL if not yet available.
 * @param tx_ctx    User context pointer passed to tx_fn. Can be NULL.
 *
 * @return Pointer to mctp_binding_i2c on success, NULL on failure.
 */
struct mctp_binding_i2c *mctp_i2c_init( uint8_t own_addr, mctp_i2c_tx_fn tx_fn, void *tx_ctx);

void mctp_i2c_destroy(struct mctp_binding_i2c *i2c);

/* Configures the i2c binding. */
int mctp_i2c_setup(struct mctp_binding_i2c *i2c, uint8_t own_addr,
		   mctp_i2c_tx_fn tx_fn, void *tx_ctx);
void mctp_i2c_cleanup(struct mctp_binding_i2c *i2c);

int mctp_i2c_set_address(struct mctp_binding_i2c *i2c, uint8_t own_addr);

struct mctp_binding *mctp_binding_i2c_core(struct mctp_binding_i2c *i2c);

int mctp_i2c_set_neighbour(struct mctp_binding_i2c *i2c, uint8_t eid,
			   uint8_t addr);

void mctp_i2c_rx(struct mctp_binding_i2c *i2c, const void *data, size_t len);
int mctp_i2c_parse_hdr(const void *data, size_t len, uint8_t *src_addr,
		       uint8_t *dest_addr, uint8_t *bytecount);
void mctp_i2c_tx_poll(struct mctp_binding_i2c *i2c);

/* Can be customised if needed */
#ifndef I2C_BTU
#define I2C_BTU MCTP_BTU
#endif

#define MCTP_I2C_PACKET_SIZE (MCTP_PACKET_SIZE(I2C_BTU) + 4)

#ifdef __cplusplus
}
#endif
