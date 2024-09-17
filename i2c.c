/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "container_of.h"
#include "libmctp-i2c.h"
#include "i2c-internal.h"

static const uint8_t MCTP_I2C_COMMAND = 0x0f;

#define binding_to_i2c(b) container_of(b, struct mctp_binding_i2c, binding)

static bool mctp_i2c_valid_addr(uint8_t addr)
{
	return addr <= 0x7f;
}

static bool mctp_i2c_valid_eid(uint8_t eid)
{
	/* Disallow reserved range */
	return eid >= 8 && eid < 0xff;
}

static int mctp_i2c_core_start(struct mctp_binding *binding)
{
	mctp_binding_set_tx_enabled(binding, true);
	return 0;
}

/* Returns 0 if an entry is found, or -ENOENT otherwise.
 * The last seen timestamp will be updated for found entries */
static int mctp_i2c_neigh_get(struct mctp_binding_i2c *i2c, uint8_t eid,
			      uint8_t *ret_neigh_addr)
{
	for (size_t i = 0; i < MCTP_I2C_NEIGH_COUNT; i++) {
		struct mctp_i2c_neigh *n = &i2c->neigh[i];
		if (n->used && n->eid == eid) {
			n->last_seen_timestamp = mctp_now(i2c->binding.mctp);
			*ret_neigh_addr = n->addr;
			return 0;
		}
	}
	return -ENOENT;
}

/* Adds a new neighbour entry. If the table is full, the oldest
 * entry will be evicted. If eid already exists, that entry will
 * be replaced. */
static void mctp_i2c_neigh_add(struct mctp_binding_i2c *i2c, uint8_t eid,
			       uint8_t addr)
{
	assert(addr <= 0x7f);
	struct mctp_i2c_neigh *entry = NULL;
	for (size_t i = 0; i < MCTP_I2C_NEIGH_COUNT; i++) {
		struct mctp_i2c_neigh *n = &i2c->neigh[i];
		if (!n->used) {
			/* Spare entry, use it */
			entry = n;
			break;
		}

		if (n->eid == eid) {
			/* Replacing existing entry */
			entry = n;
			break;
		}

		if (!entry ||
		    n->last_seen_timestamp < entry->last_seen_timestamp) {
			/* Use this as the provisional oldest, keep iterating */
			entry = n;
		}
	}
	assert(entry);

	entry->addr = addr;
	entry->eid = eid;
	entry->used = true;
	entry->last_seen_timestamp = mctp_now(i2c->binding.mctp);
}

static int mctp_binding_i2c_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_i2c *i2c = binding_to_i2c(b);
	struct mctp_hdr *hdr = mctp_pktbuf_hdr(pkt);
	int rc;
	uint8_t neigh_addr;

	rc = mctp_i2c_neigh_get(i2c, hdr->dest, &neigh_addr);
	if (rc) {
		return rc;
	}

	struct mctp_i2c_hdr *i2c_hdr =
		mctp_pktbuf_alloc_start(pkt, sizeof(struct mctp_i2c_hdr));
	i2c_hdr->dest = neigh_addr << 1;
	i2c_hdr->cmd = MCTP_I2C_COMMAND;
	size_t bytecount = mctp_pktbuf_size(pkt) -
			   (offsetof(struct mctp_i2c_hdr, bytecount) + 1);
	if (bytecount > 0xff) {
		return -EINVAL;
	}
	i2c_hdr->bytecount = bytecount;
	i2c_hdr->source = i2c->own_addr << 1 | 1;

	rc = i2c->tx_fn(pkt->data + pkt->start, mctp_pktbuf_size(pkt),
			i2c->tx_ctx);
	switch (rc) {
	case -EMSGSIZE:
	case 0:
		break;
	case -EBUSY:
	default:
		mctp_binding_set_tx_enabled(&i2c->binding, false);
	}
	return rc;
}

int mctp_i2c_set_neighbour(struct mctp_binding_i2c *i2c, uint8_t eid,
			   uint8_t addr)
{
	if (!mctp_i2c_valid_eid(eid)) {
		return -EINVAL;
	}
	if (!mctp_i2c_valid_addr(addr)) {
		return -EINVAL;
	}

	mctp_i2c_neigh_add(i2c, eid, addr);
	return 0;
}

int mctp_i2c_setup(struct mctp_binding_i2c *i2c, uint8_t own_addr,
		   mctp_i2c_tx_fn tx_fn, void *tx_ctx)
{
	int rc;

	memset(i2c, 0x0, sizeof(*i2c));

	rc = mctp_i2c_set_address(i2c, own_addr);
	if (rc) {
		return rc;
	}

	i2c->binding.name = "i2c";
	i2c->binding.version = 1;
	i2c->binding.pkt_size = MCTP_PACKET_SIZE(I2C_BTU);
	i2c->binding.pkt_header = sizeof(struct mctp_i2c_hdr);
	i2c->binding.tx_storage = i2c->tx_storage;

	i2c->binding.start = mctp_i2c_core_start;
	i2c->binding.tx = mctp_binding_i2c_tx;

	i2c->tx_fn = tx_fn;
	i2c->tx_ctx = tx_ctx;

	return 0;
}

int mctp_i2c_set_address(struct mctp_binding_i2c *i2c, uint8_t own_addr)
{
	if (!mctp_i2c_valid_addr(own_addr)) {
		return -EINVAL;
	}

	i2c->own_addr = own_addr;
	return 0;
}

struct mctp_binding *mctp_binding_i2c_core(struct mctp_binding_i2c *i2c)
{
	return &i2c->binding;
}

static int mctp_i2c_hdr_validate(const struct mctp_i2c_hdr *hdr)
{
	if (hdr->cmd != MCTP_I2C_COMMAND) {
		return -EINVAL;
	}
	if ((hdr->dest & 1) != 0) {
		return -EINVAL;
	}
	if ((hdr->source & 1) != 1) {
		return -EINVAL;
	}
	return 0;
}

void mctp_i2c_rx(struct mctp_binding_i2c *i2c, const void *data, size_t len)
{
	int rc;

	if (len < sizeof(struct mctp_i2c_hdr)) {
		return;
	}
	const struct mctp_i2c_hdr *hdr = data;
	rc = mctp_i2c_hdr_validate(hdr);
	if (rc) {
		return;
	}

	if (hdr->bytecount != len - 3) {
		return;
	}

	if ((hdr->dest >> 1) != i2c->own_addr) {
		return;
	}

	uint8_t src = hdr->source >> 1;
	if (src == i2c->own_addr) {
		return;
	}

	struct mctp_pktbuf *pkt =
		mctp_pktbuf_init(&i2c->binding, i2c->rx_storage);
	rc = mctp_pktbuf_push(pkt, data + sizeof(struct mctp_i2c_hdr),
			      len - sizeof(struct mctp_i2c_hdr));
	if (rc) {
		// Packet too large for I2C_BTU
		return;
	}

	if (mctp_pktbuf_size(pkt) < sizeof(struct mctp_hdr)) {
		return;
	}

	struct mctp_hdr *mctp_hdr = mctp_pktbuf_hdr(pkt);
	if (mctp_hdr->flags_seq_tag & MCTP_HDR_FLAG_TO) {
		/* Update neighbour entry */
		mctp_i2c_neigh_add(i2c, mctp_hdr->src, src);
	}

	mctp_bus_rx(&i2c->binding, pkt);
}

int mctp_i2c_parse_hdr(const void *data, size_t len, uint8_t *src_addr,
		       uint8_t *dest_addr, uint8_t *bytecount)
{
	int rc;

	if (len < sizeof(struct mctp_i2c_hdr)) {
		return -EINVAL;
	}
	const struct mctp_i2c_hdr *hdr = data;
	rc = mctp_i2c_hdr_validate(hdr);
	if (rc) {
		return rc;
	}

	if (src_addr) {
		*src_addr = hdr->source >> 1;
	}
	if (dest_addr) {
		*dest_addr = hdr->dest >> 1;
	}
	if (bytecount) {
		*bytecount = hdr->bytecount;
	}
	return 0;
}

void mctp_i2c_tx_poll(struct mctp_binding_i2c *i2c)
{
	mctp_binding_set_tx_enabled(&i2c->binding, true);
}
