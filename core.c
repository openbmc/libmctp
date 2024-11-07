/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <errno.h>
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
#include "libmctp-cmds.h"
#include "range.h"
#include "compiler.h"
#include "core-internal.h"
#include "control.h"

#if MCTP_DEFAULT_CLOCK_GETTIME
#include <time.h>
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

static int mctp_message_tx_on_bus(struct mctp_bus *bus, mctp_eid_t src,
				  mctp_eid_t dest, bool tag_owner,
				  uint8_t msg_tag, void *msg, size_t msg_len);
static void mctp_dealloc_tag(struct mctp_bus *bus, mctp_eid_t local,
			     mctp_eid_t remote, uint8_t tag);

struct mctp_pktbuf *mctp_pktbuf_alloc(struct mctp_binding *binding, size_t len)
{
	size_t size =
		binding->pkt_size + binding->pkt_header + binding->pkt_trailer;
	if (len > size) {
		return NULL;
	}

	void *storage = __mctp_alloc(size + sizeof(struct mctp_pktbuf));
	if (!storage) {
		return NULL;
	}
	struct mctp_pktbuf *pkt = mctp_pktbuf_init(binding, storage);
	pkt->alloc = true;
	pkt->end = pkt->start + len;
	return pkt;
}

void mctp_pktbuf_free(struct mctp_pktbuf *pkt)
{
	if (pkt->alloc) {
		__mctp_free(pkt);
	} else {
		mctp_prdebug("pktbuf_free called for non-alloced");
	}
}

struct mctp_pktbuf *mctp_pktbuf_init(struct mctp_binding *binding,
				     void *storage)
{
	size_t size =
		binding->pkt_size + binding->pkt_header + binding->pkt_trailer;
	struct mctp_pktbuf *buf = (struct mctp_pktbuf *)storage;
	buf->size = size;
	buf->start = binding->pkt_header;
	buf->end = buf->start;
	buf->mctp_hdr_off = buf->start;
	buf->alloc = false;

	return buf;
}

struct mctp_hdr *mctp_pktbuf_hdr(struct mctp_pktbuf *pkt)
{
	return (struct mctp_hdr *)(pkt->data + pkt->mctp_hdr_off);
}

void *mctp_pktbuf_data(struct mctp_pktbuf *pkt)
{
	return pkt->data + pkt->mctp_hdr_off + sizeof(struct mctp_hdr);
}

size_t mctp_pktbuf_size(const struct mctp_pktbuf *pkt)
{
	return pkt->end - pkt->start;
}

void *mctp_pktbuf_alloc_start(struct mctp_pktbuf *pkt, size_t size)
{
	assert(size <= pkt->start);
	pkt->start -= size;
	return pkt->data + pkt->start;
}

void *mctp_pktbuf_alloc_end(struct mctp_pktbuf *pkt, size_t size)
{
	void *buf;

	assert(size <= (pkt->size - pkt->end));
	buf = pkt->data + pkt->end;
	pkt->end += size;
	return buf;
}

int mctp_pktbuf_push(struct mctp_pktbuf *pkt, const void *data, size_t len)
{
	void *p;

	if (pkt->end + len > pkt->size)
		return -1;

	p = pkt->data + pkt->end;

	pkt->end += len;
	memcpy(p, data, len);

	return 0;
}

void *mctp_pktbuf_pop(struct mctp_pktbuf *pkt, size_t len)
{
	if (len > mctp_pktbuf_size(pkt))
		return NULL;

	pkt->end -= len;
	return pkt->data + pkt->end;
}

/* Allocate a duplicate of the message and copy it */
static void *mctp_msg_dup(const void *msg, size_t msg_len, struct mctp *mctp)
{
	void *copy = __mctp_msg_alloc(msg_len, mctp);
	if (!copy) {
		mctp_prdebug("msg dup len %zu failed", msg_len);
		return NULL;
	}

	memcpy(copy, msg, msg_len);
	return copy;
}

/* Message reassembly */
static struct mctp_msg_ctx *mctp_msg_ctx_lookup(struct mctp *mctp, uint8_t src,
						uint8_t dest, uint8_t tag)
{
	unsigned int i;

	/* @todo: better lookup, if we add support for more outstanding
	 * message contexts */
	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *ctx = &mctp->msg_ctxs[i];
		if (ctx->buf && ctx->src == src && ctx->dest == dest &&
		    ctx->tag == tag)
			return ctx;
	}

	return NULL;
}

static struct mctp_msg_ctx *mctp_msg_ctx_create(struct mctp *mctp, uint8_t src,
						uint8_t dest, uint8_t tag)
{
	struct mctp_msg_ctx *ctx = NULL;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *tmp = &mctp->msg_ctxs[i];
		if (!tmp->buf) {
			ctx = tmp;
			break;
		}
	}

	if (!ctx)
		return NULL;

	ctx->src = src;
	ctx->dest = dest;
	ctx->tag = tag;

	ctx->buf_size = 0;
	ctx->buf_alloc_size = mctp->max_message_size;
	ctx->buf = __mctp_msg_alloc(ctx->buf_alloc_size, mctp);
	if (!ctx->buf) {
		return NULL;
	}

	return ctx;
}

static void mctp_msg_ctx_drop(struct mctp_bus *bus, struct mctp_msg_ctx *ctx)
{
	/* Free and mark as unused */
	__mctp_msg_free(ctx->buf, bus->mctp);
	ctx->buf = NULL;
}

static void mctp_msg_ctx_reset(struct mctp_msg_ctx *ctx)
{
	ctx->buf_size = 0;
	ctx->fragment_size = 0;
}

static int mctp_msg_ctx_add_pkt(struct mctp_msg_ctx *ctx,
				struct mctp_pktbuf *pkt)
{
	size_t len;

	len = mctp_pktbuf_size(pkt) - sizeof(struct mctp_hdr);

	if (len + ctx->buf_size < ctx->buf_size) {
		return -1;
	}

	if (ctx->buf_size + len > ctx->buf_alloc_size) {
		return -1;
	}

	memcpy((uint8_t *)ctx->buf + ctx->buf_size, mctp_pktbuf_data(pkt), len);
	ctx->buf_size += len;

	return 0;
}

/* Core API functions */
struct mctp *mctp_init(void)
{
	struct mctp *mctp;

	mctp = __mctp_alloc(sizeof(*mctp));

	if (!mctp)
		return NULL;

	mctp_setup(mctp, sizeof(*mctp));
	return mctp;
}

#if MCTP_DEFAULT_CLOCK_GETTIME
static uint64_t mctp_default_now(void *ctx __attribute__((unused)))
{
	struct timespec tp;
	int rc = clock_gettime(CLOCK_MONOTONIC, &tp);
	if (rc) {
		/* Should not be possible */
		return 0;
	}
	return (uint64_t)tp.tv_sec * 1000 + tp.tv_nsec / 1000000;
}
#endif

int mctp_setup(struct mctp *mctp, size_t struct_mctp_size)
{
	if (struct_mctp_size < sizeof(struct mctp)) {
		mctp_prdebug("Mismatching struct mctp");
		return -EINVAL;
	}
	memset(mctp, 0, sizeof(*mctp));
	mctp->max_message_size = MCTP_MAX_MESSAGE_SIZE;

#if MCTP_DEFAULT_CLOCK_GETTIME
	mctp->platform_now = mctp_default_now;
#endif
#if MCTP_CONTROL_HANDLER
	mctp_control_add_type(mctp, MCTP_CTRL_HDR_MSG_TYPE);
#endif
	return 0;
}

void mctp_set_max_message_size(struct mctp *mctp, size_t message_size)
{
	mctp->max_message_size = message_size;
}

void mctp_set_capture_handler(struct mctp *mctp, mctp_capture_fn fn, void *user)
{
	mctp->capture = fn;
	mctp->capture_data = user;
}

static void mctp_bus_destroy(struct mctp_bus *bus, struct mctp *mctp)
{
	if (bus->tx_msg) {
		__mctp_msg_free(bus->tx_msg, mctp);
		bus->tx_msg = NULL;
	}
}

void mctp_cleanup(struct mctp *mctp)
{
	size_t i;

	/* Cleanup message assembly contexts */
	static_assert(ARRAY_SIZE(mctp->msg_ctxs) < SIZE_MAX, "size");
	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *tmp = &mctp->msg_ctxs[i];
		if (tmp->buf)
			__mctp_msg_free(tmp->buf, mctp);
	}

	while (mctp->n_busses--)
		mctp_bus_destroy(&mctp->busses[mctp->n_busses], mctp);
}

void mctp_destroy(struct mctp *mctp)
{
	mctp_cleanup(mctp);
	__mctp_free(mctp);
}

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data)
{
	mctp->message_rx = fn;
	mctp->message_rx_data = data;
	return 0;
}

static struct mctp_bus *find_bus_for_eid(struct mctp *mctp, mctp_eid_t dest
					 __attribute__((unused)))
{
	if (mctp->n_busses == 0)
		return NULL;

	/* for now, just use the first bus. For full routing support,
	 * we will need a table of neighbours */
	return &mctp->busses[0];
}

int mctp_register_bus(struct mctp *mctp, struct mctp_binding *binding,
		      mctp_eid_t eid)
{
	int rc = 0;

	/* todo: multiple busses */
	static_assert(MCTP_MAX_BUSSES >= 1, "need a bus");
	assert(mctp->n_busses == 0);
	mctp->n_busses = 1;

	assert(binding->tx_storage);

	memset(mctp->busses, 0, sizeof(struct mctp_bus));
	mctp->busses[0].mctp = mctp;
	mctp->busses[0].binding = binding;
	mctp->busses[0].eid = eid;
	binding->bus = &mctp->busses[0];
	binding->mctp = mctp;
	mctp->route_policy = ROUTE_ENDPOINT;

	if (binding->start) {
		rc = binding->start(binding);
		if (rc < 0) {
			mctp_prerr("Failed to start binding: %d", rc);
			binding->bus = NULL;
			mctp->n_busses = 0;
		}
	}

	return rc;
}

int mctp_bus_set_eid(struct mctp_binding *binding, mctp_eid_t eid)
{
	if (eid < 8 || eid == 0xff) {
		return -EINVAL;
	}

	binding->bus->eid = eid;
	return 0;
}

void mctp_unregister_bus(struct mctp *mctp, struct mctp_binding *binding)
{
	/*
	 * We only support one bus right now; once the call completes we will
	 * have no more busses
	 */
	mctp->n_busses = 0;
	binding->mctp = NULL;
	binding->bus = NULL;
}

int mctp_bridge_busses(struct mctp *mctp, struct mctp_binding *b1,
		       struct mctp_binding *b2)
{
	int rc = 0;

	assert(b1->tx_storage);
	assert(b2->tx_storage);

	assert(mctp->n_busses == 0);
	assert(MCTP_MAX_BUSSES >= 2);
	memset(mctp->busses, 0, 2 * sizeof(struct mctp_bus));
	mctp->n_busses = 2;
	mctp->busses[0].binding = b1;
	b1->bus = &mctp->busses[0];
	b1->mctp = mctp;
	mctp->busses[1].binding = b2;
	b2->bus = &mctp->busses[1];
	b2->mctp = mctp;

	mctp->route_policy = ROUTE_BRIDGE;

	if (b1->start) {
		rc = b1->start(b1);
		if (rc < 0) {
			mctp_prerr("Failed to start bridged bus %s: %d",
				   b1->name, rc);
			goto done;
		}
	}

	if (b2->start) {
		rc = b2->start(b2);
		if (rc < 0) {
			mctp_prerr("Failed to start bridged bus %s: %d",
				   b2->name, rc);
			goto done;
		}
	}

done:
	return rc;
}

static inline bool mctp_ctrl_cmd_is_transport(struct mctp_ctrl_msg_hdr *hdr)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
	return ((hdr->command_code >= MCTP_CTRL_CMD_FIRST_TRANSPORT) &&
		(hdr->command_code <= MCTP_CTRL_CMD_LAST_TRANSPORT));
#pragma GCC diagnostic pop
}

static bool mctp_ctrl_handle_msg(struct mctp_bus *bus, mctp_eid_t src,
				 uint8_t msg_tag, bool tag_owner, void *buffer,
				 size_t length)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = buffer;

	/*
	 * Control message is received. If a transport control message handler
	 * is provided, it will called. If there is no dedicated handler, this
	 * function returns false and data can be handled by the generic
	 * message handler. The transport control message handler will be
	 * provided with messages in the command range 0xF0 - 0xFF.
	 */
	if (mctp_ctrl_cmd_is_transport(msg_hdr)) {
		if (bus->binding->control_rx != NULL) {
			/* MCTP bus binding handler */
			bus->binding->control_rx(src, msg_tag, tag_owner,
						 bus->binding->control_rx_data,
						 buffer, length);
			return true;
		}
	} else {
#if MCTP_CONTROL_HANDLER
		/* libmctp will handle control requests */
		return mctp_control_handler(bus, src, tag_owner, msg_tag,
					    buffer, length);
#endif
	}

	/*
	 * Command was not handled, due to lack of specific callback.
	 * It will be passed to regular message_rx handler.
	 */
	return false;
}

static inline bool mctp_rx_dest_is_local(struct mctp_bus *bus, mctp_eid_t dest)
{
	return dest == bus->eid || dest == MCTP_EID_NULL ||
	       dest == MCTP_EID_BROADCAST;
}

static inline bool mctp_ctrl_cmd_is_request(struct mctp_ctrl_msg_hdr *hdr)
{
	return hdr->ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE &&
	       hdr->rq_dgram_inst & MCTP_CTRL_HDR_FLAG_REQUEST;
}

/*
 * Receive the complete MCTP message and route it.
 * Asserts:
 *     'buf' is not NULL.
 */
static void mctp_rx(struct mctp *mctp, struct mctp_bus *bus, mctp_eid_t src,
		    mctp_eid_t dest, bool tag_owner, uint8_t msg_tag, void *buf,
		    size_t len)
{
	assert(buf != NULL);

	if (mctp->route_policy == ROUTE_ENDPOINT &&
	    mctp_rx_dest_is_local(bus, dest)) {
		/* Note responses to allocated tags */
		if (!tag_owner) {
			mctp_dealloc_tag(bus, dest, src, msg_tag);
		}

		/* Handle MCTP Control Messages: */
		if (len >= sizeof(struct mctp_ctrl_msg_hdr)) {
			struct mctp_ctrl_msg_hdr *msg_hdr = buf;

			/*
			 * Identify if this is a control request message.
			 * See DSP0236 v1.3.0 sec. 11.5.
			 */
			if (mctp_ctrl_cmd_is_request(msg_hdr)) {
				bool handled;
				handled = mctp_ctrl_handle_msg(
					bus, src, msg_tag, tag_owner, buf, len);
				if (handled)
					return;
			}
		}

		if (mctp->message_rx)
			mctp->message_rx(src, tag_owner, msg_tag,
					 mctp->message_rx_data, buf, len);
	}

	if (mctp->route_policy == ROUTE_BRIDGE) {
		int i;

		for (i = 0; i < mctp->n_busses; i++) {
			struct mctp_bus *dest_bus = &mctp->busses[i];
			if (dest_bus == bus)
				continue;

			void *copy = mctp_msg_dup(buf, len, mctp);
			if (!copy) {
				return;
			}

			mctp_message_tx_on_bus(dest_bus, src, dest, tag_owner,
					       msg_tag, copy, len);
		}
	}
}

void mctp_bus_rx(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	struct mctp_bus *bus = binding->bus;
	struct mctp *mctp = binding->mctp;
	uint8_t flags, exp_seq, seq, tag;
	struct mctp_msg_ctx *ctx;
	struct mctp_hdr *hdr;
	bool tag_owner;
	size_t len;
	void *p;
	int rc;

	assert(bus);

	/* Drop packet if it was smaller than mctp hdr size */
	if (mctp_pktbuf_size(pkt) < sizeof(struct mctp_hdr))
		goto out;

	if (mctp->capture)
		mctp->capture(pkt, MCTP_MESSAGE_CAPTURE_INCOMING,
			      mctp->capture_data);

	hdr = mctp_pktbuf_hdr(pkt);

	/* small optimisation: don't bother reassembly if we're going to
	 * drop the packet in mctp_rx anyway */
	if (mctp->route_policy == ROUTE_ENDPOINT &&
	    !mctp_rx_dest_is_local(bus, hdr->dest))
		goto out;

	flags = hdr->flags_seq_tag & (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM);
	tag = (hdr->flags_seq_tag >> MCTP_HDR_TAG_SHIFT) & MCTP_HDR_TAG_MASK;
	seq = (hdr->flags_seq_tag >> MCTP_HDR_SEQ_SHIFT) & MCTP_HDR_SEQ_MASK;
	tag_owner = (hdr->flags_seq_tag >> MCTP_HDR_TO_SHIFT) &
		    MCTP_HDR_TO_MASK;

	switch (flags) {
	case MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM:
		/* single-packet message - send straight up to rx function,
		 * no need to create a message context */
		len = pkt->end - pkt->mctp_hdr_off - sizeof(struct mctp_hdr);
		p = mctp_msg_dup(pkt->data + pkt->mctp_hdr_off +
					 sizeof(struct mctp_hdr),
				 len, mctp);
		if (p) {
			mctp_rx(mctp, bus, hdr->src, hdr->dest, tag_owner, tag,
				p, len);
			__mctp_msg_free(p, mctp);
		}
		break;

	case MCTP_HDR_FLAG_SOM:
		/* start of a new message - start the new context for
		 * future message reception. If an existing context is
		 * already present, drop it. */
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag);
		if (ctx) {
			mctp_msg_ctx_reset(ctx);
		} else {
			ctx = mctp_msg_ctx_create(mctp, hdr->src, hdr->dest,
						  tag);
			/* If context creation fails due to exhaution of contexts we
			* can support, drop the packet */
			if (!ctx) {
				mctp_prdebug("Context buffers exhausted.");
				goto out;
			}
		}

		/* Save the fragment size, subsequent middle fragments
		 * should of the same size */
		ctx->fragment_size = mctp_pktbuf_size(pkt);

		rc = mctp_msg_ctx_add_pkt(ctx, pkt);
		if (rc) {
			mctp_msg_ctx_drop(bus, ctx);
		} else {
			ctx->last_seq = seq;
		}

		break;

	case MCTP_HDR_FLAG_EOM:
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag);
		if (!ctx)
			goto out;

		exp_seq = (ctx->last_seq + 1) % 4;

		if (exp_seq != seq) {
			mctp_prdebug(
				"Sequence number %d does not match expected %d",
				seq, exp_seq);
			mctp_msg_ctx_drop(bus, ctx);
			goto out;
		}

		len = mctp_pktbuf_size(pkt);

		if (len > ctx->fragment_size) {
			mctp_prdebug("Unexpected fragment size. Expected"
				     " less than %zu, received = %zu",
				     ctx->fragment_size, len);
			mctp_msg_ctx_drop(bus, ctx);
			goto out;
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt);
		if (!rc)
			mctp_rx(mctp, bus, ctx->src, ctx->dest, tag_owner, tag,
				ctx->buf, ctx->buf_size);

		mctp_msg_ctx_drop(bus, ctx);
		break;

	case 0:
		/* Neither SOM nor EOM */
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag);
		if (!ctx)
			goto out;

		exp_seq = (ctx->last_seq + 1) % 4;
		if (exp_seq != seq) {
			mctp_prdebug(
				"Sequence number %d does not match expected %d",
				seq, exp_seq);
			mctp_msg_ctx_drop(bus, ctx);
			goto out;
		}

		len = mctp_pktbuf_size(pkt);

		if (len != ctx->fragment_size) {
			mctp_prdebug("Unexpected fragment size. Expected = %zu "
				     "received = %zu",
				     ctx->fragment_size, len);
			mctp_msg_ctx_drop(bus, ctx);
			goto out;
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt);
		if (rc) {
			mctp_msg_ctx_drop(bus, ctx);
			goto out;
		}
		ctx->last_seq = seq;

		break;
	}
out:
	return;
}

static int mctp_packet_tx(struct mctp_bus *bus, struct mctp_pktbuf *pkt)
{
	struct mctp *mctp = bus->binding->mctp;

	if (bus->state != mctp_bus_state_tx_enabled) {
		mctp_prdebug("tx with bus disabled");
		return -1;
	}

	if (mctp->capture)
		mctp->capture(pkt, MCTP_MESSAGE_CAPTURE_OUTGOING,
			      mctp->capture_data);

	return bus->binding->tx(bus->binding, pkt);
}

/* Returns a pointer to the binding's tx_storage */
static struct mctp_pktbuf *mctp_next_tx_pkt(struct mctp_bus *bus)
{
	if (!bus->tx_msg) {
		return NULL;
	}

	size_t p = bus->tx_msgpos;
	size_t msg_len = bus->tx_msglen;
	size_t payload_len = msg_len - p;
	size_t max_payload_len = MCTP_BODY_SIZE(bus->binding->pkt_size);
	if (payload_len > max_payload_len)
		payload_len = max_payload_len;

	struct mctp_pktbuf *pkt =
		mctp_pktbuf_init(bus->binding, bus->binding->tx_storage);
	struct mctp_hdr *hdr = mctp_pktbuf_hdr(pkt);

	hdr->ver = bus->binding->version & 0xf;
	hdr->dest = bus->tx_dest;
	hdr->src = bus->tx_src;
	hdr->flags_seq_tag = (bus->tx_to << MCTP_HDR_TO_SHIFT) |
			     (bus->tx_tag << MCTP_HDR_TAG_SHIFT);

	if (p == 0)
		hdr->flags_seq_tag |= MCTP_HDR_FLAG_SOM;
	if (p + payload_len >= msg_len)
		hdr->flags_seq_tag |= MCTP_HDR_FLAG_EOM;
	hdr->flags_seq_tag |= bus->tx_seq << MCTP_HDR_SEQ_SHIFT;

	memcpy(mctp_pktbuf_data(pkt), (uint8_t *)bus->tx_msg + p, payload_len);
	pkt->end = pkt->start + sizeof(*hdr) + payload_len;
	bus->tx_pktlen = payload_len;

	mctp_prdebug(
		"tx dst %d tag %d payload len %zu seq %d. msg pos %zu len %zu",
		hdr->dest, bus->tx_tag, payload_len, bus->tx_seq, p, msg_len);

	return pkt;
}

/* Called when a packet has successfully been sent */
static void mctp_tx_complete(struct mctp_bus *bus)
{
	if (!bus->tx_msg) {
		mctp_prdebug("tx complete no message");
		return;
	}

	bus->tx_seq = (bus->tx_seq + 1) & MCTP_HDR_SEQ_MASK;
	bus->tx_msgpos += bus->tx_pktlen;

	if (bus->tx_msgpos >= bus->tx_msglen) {
		__mctp_msg_free(bus->tx_msg, bus->binding->mctp);
		bus->tx_msg = NULL;
	}
}

static void mctp_send_tx_queue(struct mctp_bus *bus)
{
	struct mctp_pktbuf *pkt;

	while (bus->tx_msg && bus->state == mctp_bus_state_tx_enabled) {
		int rc;

		pkt = mctp_next_tx_pkt(bus);

		rc = mctp_packet_tx(bus, pkt);
		switch (rc) {
		/* If transmission succeded */
		case 0:
			/* Drop the packet */
			mctp_tx_complete(bus);
			break;

		/* If the binding was busy */
		case -EBUSY:
			/* Keep the packet for next try */
			mctp_prdebug("tx EBUSY");
			return;

		/* Some other unknown error occurred */
		default:
			/* Drop the packet */
			mctp_prdebug("tx drop %d", rc);
			mctp_tx_complete(bus);
			return;
		};
	}
}

void mctp_binding_set_tx_enabled(struct mctp_binding *binding, bool enable)
{
	struct mctp_bus *bus = binding->bus;

	switch (bus->state) {
	case mctp_bus_state_constructed:
		if (!enable)
			return;

		if (binding->pkt_size < MCTP_PACKET_SIZE(MCTP_BTU)) {
			mctp_prerr(
				"Cannot start %s binding with invalid MTU: %zu",
				binding->name,
				MCTP_BODY_SIZE(binding->pkt_size));
			return;
		}

		bus->state = mctp_bus_state_tx_enabled;
		mctp_prinfo("%s binding started", binding->name);
		return;
	case mctp_bus_state_tx_enabled:
		if (enable)
			return;

		bus->state = mctp_bus_state_tx_disabled;
		mctp_prdebug("%s binding Tx disabled", binding->name);
		return;
	case mctp_bus_state_tx_disabled:
		if (!enable)
			return;

		bus->state = mctp_bus_state_tx_enabled;
		mctp_prdebug("%s binding Tx enabled", binding->name);
		mctp_send_tx_queue(bus);
		return;
	}
}

static int mctp_message_tx_on_bus(struct mctp_bus *bus, mctp_eid_t src,
				  mctp_eid_t dest, bool tag_owner,
				  uint8_t msg_tag, void *msg, size_t msg_len)
{
	size_t max_payload_len;
	int rc;

	if (bus->state == mctp_bus_state_constructed) {
		rc = -ENXIO;
		goto err;
	}

	if ((msg_tag & MCTP_HDR_TAG_MASK) != msg_tag) {
		rc = -EINVAL;
		goto err;
	}

	max_payload_len = MCTP_BODY_SIZE(bus->binding->pkt_size);

	{
		const bool valid_mtu = max_payload_len >= MCTP_BTU;
		assert(valid_mtu);
		if (!valid_mtu) {
			rc = -EINVAL;
			goto err;
		}
	}

	mctp_prdebug(
		"%s: Generating packets for transmission of %zu byte message from %hhu to %hhu",
		__func__, msg_len, src, dest);

	if (bus->tx_msg) {
		mctp_prdebug("Bus busy");
		rc = -EBUSY;
		goto err;
	}

	/* Take the message to send */
	bus->tx_msg = msg;
	bus->tx_msglen = msg_len;
	bus->tx_msgpos = 0;
	/* bus->tx_seq is allowed to continue from previous message */
	bus->tx_src = src;
	bus->tx_dest = dest;
	bus->tx_to = tag_owner;
	bus->tx_tag = msg_tag;

	mctp_send_tx_queue(bus);
	return 0;

err:
	__mctp_msg_free(msg, bus->binding->mctp);
	return rc;
}

int mctp_message_tx_alloced(struct mctp *mctp, mctp_eid_t eid, bool tag_owner,
			    uint8_t msg_tag, void *msg, size_t msg_len)
{
	struct mctp_bus *bus;

	/* TODO: Protect against same tag being used across
	 * different callers */
	if ((msg_tag & MCTP_HDR_TAG_MASK) != msg_tag) {
		mctp_prerr("Incorrect message tag %u passed.", msg_tag);
		__mctp_msg_free(msg, mctp);
		return -EINVAL;
	}

	bus = find_bus_for_eid(mctp, eid);
	if (!bus) {
		__mctp_msg_free(msg, mctp);
		return 0;
	}

	return mctp_message_tx_on_bus(bus, bus->eid, eid, tag_owner, msg_tag,
				      msg, msg_len);
}

int mctp_message_tx(struct mctp *mctp, mctp_eid_t eid, bool tag_owner,
		    uint8_t msg_tag, const void *msg, size_t msg_len)
{
	void *copy = mctp_msg_dup(msg, msg_len, mctp);
	if (!copy) {
		return -ENOMEM;
	}

	return mctp_message_tx_alloced(mctp, eid, tag_owner, msg_tag, copy,
				       msg_len);
}

void mctp_set_now_op(struct mctp *mctp, uint64_t (*now)(void *), void *ctx)
{
	assert(now);
	mctp->platform_now = now;
	mctp->platform_now_ctx = ctx;
}

uint64_t mctp_now(struct mctp *mctp)
{
	assert(mctp->platform_now);
	return mctp->platform_now(mctp->platform_now_ctx);
}

static void mctp_dealloc_tag(struct mctp_bus *bus, mctp_eid_t local,
			     mctp_eid_t remote, uint8_t tag)
{
	struct mctp *mctp = bus->binding->mctp;
	if (local == 0) {
		return;
	}

	for (size_t i = 0; i < ARRAY_SIZE(mctp->req_tags); i++) {
		struct mctp_req_tag *r = &mctp->req_tags[i];
		if (r->local == local && r->remote == remote && r->tag == tag) {
			r->local = 0;
			r->remote = 0;
			r->tag = 0;
			r->expiry = 0;
			return;
		}
	}
}

static int mctp_alloc_tag(struct mctp *mctp, mctp_eid_t local,
			  mctp_eid_t remote, uint8_t *ret_tag)
{
	assert(local != 0);
	uint64_t now = mctp_now(mctp);

	uint8_t used = 0;
	struct mctp_req_tag *spare = NULL;
	/* Find which tags and slots are used/spare */
	for (size_t i = 0; i < ARRAY_SIZE(mctp->req_tags); i++) {
		struct mctp_req_tag *r = &mctp->req_tags[i];
		if (r->local == 0 || r->expiry < now) {
			spare = r;
		} else {
			if (r->local == local && r->remote == remote) {
				used |= 1 << r->tag;
			}
		}
	}

	if (spare == NULL) {
		// All req_tag slots are in-use
		return -EBUSY;
	}

	for (uint8_t tag = 0; tag < 8; tag++) {
		tag = (tag + mctp->tag_round_robin) % 8;
		if ((used & 1 << tag) == 0) {
			spare->local = local;
			spare->remote = remote;
			spare->tag = tag;
			spare->expiry = now + MCTP_TAG_TIMEOUT;
			*ret_tag = tag;
			mctp->tag_round_robin = (tag + 1) % 8;
			return 0;
		}
	}

	// All 8 tags are used for this src/dest pair
	return -EBUSY;
}

int mctp_message_tx_request(struct mctp *mctp, mctp_eid_t eid, void *msg,
			    size_t msg_len, uint8_t *ret_alloc_msg_tag)
{
	int rc;
	struct mctp_bus *bus;

	bus = find_bus_for_eid(mctp, eid);
	if (!bus) {
		__mctp_msg_free(msg, mctp);
		return 0;
	}

	uint8_t alloc_tag;
	rc = mctp_alloc_tag(mctp, bus->eid, eid, &alloc_tag);
	if (rc) {
		mctp_prdebug("Failed allocating tag");
		__mctp_msg_free(msg, mctp);
		return rc;
	}

	if (ret_alloc_msg_tag) {
		*ret_alloc_msg_tag = alloc_tag;
	}

	return mctp_message_tx_alloced(mctp, eid, true, alloc_tag, msg,
				       msg_len);
}

bool mctp_is_tx_ready(struct mctp *mctp, mctp_eid_t eid)
{
	struct mctp_bus *bus;

	bus = find_bus_for_eid(mctp, eid);
	if (!bus) {
		return true;
	}
	return bus->tx_msg == NULL;
}

void *mctp_get_alloc_ctx(struct mctp *mctp)
{
	return mctp->alloc_ctx;
}

void mctp_set_alloc_ctx(struct mctp *mctp, void *ctx)
{
	mctp->alloc_ctx = ctx;
}
