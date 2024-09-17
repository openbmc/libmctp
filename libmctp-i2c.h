#include <stdint.h>

#include "libmctp.h"

struct mctp_binding_i2c;

typedef int (*mctp_i2c_tx_fn)(const void *buf, size_t len, void *ctx);

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
