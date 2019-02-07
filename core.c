/* SPDX-License-Identifier: Apache-2.0 */

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef pr_fmt
#define pr_fmt(fmt) "core: " fmt

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"

/* Internal data structures */

struct mctp_bus {
	mctp_eid_t		eid;
	struct mctp_binding	*binding;

	/* todo: routing */
};

struct mctp {
	/* todo: multiple busses */
	struct mctp_bus	busses[1];

	struct mctp_pktbuf	txbuf;

	/* Message RX callback */
	mctp_rx_fn		message_rx;
	void			*message_rx_data;
};

#ifndef BUILD_ASSERT
#define BUILD_ASSERT(x) \
	do { (void)sizeof(char[0-(!(x))]); } while (0)
#endif

struct mctp_pktbuf *mctp_pktbuf_alloc(uint8_t len)
{
	struct mctp_pktbuf *buf;

	BUILD_ASSERT(MCTP_PKTBUF_SIZE <= 0xff);

	/* todo: pools */
	buf = __mctp_alloc(sizeof(*buf));

	buf->start = MCTP_PKTBUF_BINDING_PAD;
	buf->end = buf->start + len;
	buf->mctp_hdr_off = buf->start;

	return buf;
}

void mctp_pktbuf_free(struct mctp_pktbuf *pkt)
{
	__mctp_free(pkt);
}

struct mctp_hdr *mctp_pktbuf_hdr(struct mctp_pktbuf *pkt)
{
	return (void *)pkt->data + pkt->mctp_hdr_off;
}

void *mctp_pktbuf_data(struct mctp_pktbuf *pkt)
{
	return (void *)pkt->data + pkt->mctp_hdr_off + sizeof(struct mctp_hdr);
}

uint8_t mctp_pktbuf_size(struct mctp_pktbuf *pkt)
{
	return pkt->end - pkt->start;
}

void *mctp_pktbuf_alloc_start(struct mctp_pktbuf *pkt, uint8_t size)
{
	assert(size <= pkt->start);
	pkt->start -= size;
	return pkt->data + pkt->start;
}

void *mctp_pktbuf_alloc_end(struct mctp_pktbuf *pkt, uint8_t size)
{
	void *buf;

	assert(size < (MCTP_PKTBUF_SIZE - pkt->end));
	buf = pkt->data + pkt->end;
	pkt->end += size;
	return buf;
}

int mctp_pktbuf_push(struct mctp_pktbuf *pkt, void *data, uint8_t len)
{
	void *p;

	assert(pkt->end + len <= MCTP_PKTBUF_SIZE);

	if (pkt->end + len > MCTP_PKTBUF_SIZE)
		return -1;

	p = pkt->data + pkt->end;

	pkt->end += len;
	memcpy(p, data, len);

	return 0;
}

struct mctp *mctp_init(void)
{
	struct mctp *mctp;

	mctp = __mctp_alloc(sizeof(*mctp));
	memset(mctp, 0, sizeof(*mctp));

	return mctp;
}

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data)
{
	mctp->message_rx = fn;
	mctp->message_rx_data = data;
	return 0;
}

static struct mctp_bus *find_bus_for_eid(struct mctp *mctp,
		mctp_eid_t dest __attribute__((unused)))
{
	return &mctp->busses[0];
}

unsigned long mctp_register_bus(struct mctp *mctp,
		struct mctp_binding *binding,
		mctp_eid_t eid)
{
	assert(!mctp->busses[0].binding);
	mctp->busses[0].binding = binding;
	mctp->busses[0].eid = eid;
	return 0;
}

void mctp_bus_rx(struct mctp *mctp, unsigned long bus_id,
		struct mctp_pktbuf *pkt)
{
	struct mctp_bus *bus = &mctp->busses[bus_id];
	size_t len;
	void *p;

	len = pkt->end - pkt->mctp_hdr_off - sizeof(struct mctp_hdr);
	p = pkt->data + pkt->mctp_hdr_off + sizeof(struct mctp_hdr),
	mctp->message_rx(bus->eid, mctp->message_rx_data, p, len);
}

static int mctp_packet_tx(struct mctp *mctp __attribute__((unused)),
		struct mctp_bus *bus,
		struct mctp_pktbuf *pkt)
{
	return bus->binding->tx(bus->binding, pkt);
}

int mctp_message_tx(struct mctp *mctp, mctp_eid_t eid,
		void *msg, size_t msg_len)
{
	struct mctp_pktbuf *pkt;
	struct mctp_hdr *hdr;
	struct mctp_bus *bus;
	int rc;

	/* todo: multiple-packet messages, sequence numbers */
	assert(msg_len <= MCTP_MTU);

	bus = find_bus_for_eid(mctp, eid);

	pkt = mctp_pktbuf_alloc(msg_len + sizeof(*hdr));
	hdr = mctp_pktbuf_hdr(pkt);

	/* todo: tags */
	hdr->ver = bus->binding->version & 0xf;
	hdr->dest = eid;
	hdr->src = bus->eid;
	hdr->flags_seq_tag = MCTP_HDR_FLAG_SOM |
		MCTP_HDR_FLAG_EOM |
		(0 << MCTP_HDR_SEQ_SHIFT) |
		MCTP_HDR_FLAG_TO |
		(0 << MCTP_HDR_TAG_SHIFT);

	/* todo: zero copy? */
	memcpy(mctp_pktbuf_data(pkt), msg, msg_len);

	rc = mctp_packet_tx(mctp, bus, pkt);

	return rc;
}
