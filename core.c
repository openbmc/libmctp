/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
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

#include "container_of.h"

/* Internal data structures */

struct mctp_bus {
	struct mctp_binding *binding;
	uint8_t id;
	bool tx_enabled;

	struct mctp_pktbuf *tx_queue_head;
	struct mctp_pktbuf *tx_queue_tail;
};

struct mctp_msg_ctx {
	uint8_t		src;
	uint8_t		dest;
	uint8_t		tag;
	uint8_t		last_seq;
	void		*buf;
	size_t		buf_size;
	size_t		buf_alloc_size;
};

struct mctp {
	int n_busses;
	struct mctp_bus *busses;

	/* Message RX callback */
	mctp_rx_fn message_rx;
	void *message_rx_data;

	/* Route notify callback */
	mctp_route_notify_fn route_notify;
	void *route_notify_data;

	/* Message reassembly.
	 * @todo: flexible context count
	 */
	struct mctp_msg_ctx msg_ctxs[16];

	size_t max_message_size;

	struct mctp_route_entry *routes;
	struct mctp_eid_range dynamic_pool;
	uint8_t dynamic;
};

#ifndef BUILD_ASSERT
#define BUILD_ASSERT(x) \
	do { (void)sizeof(char[0-(!(x))]); } while (0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

/* 64kb should be sufficient for a single message. Applications
 * requiring higher sizes can override by setting max_message_size.*/
#ifndef MCTP_MAX_MESSAGE_SIZE
#define MCTP_MAX_MESSAGE_SIZE 65536
#endif

static int mctp_message_tx_on_bus(struct mctp_bus *bus, mctp_eid_t src,
				  mctp_eid_t dest, void *msg, size_t msg_len);

struct mctp_pktbuf *mctp_pktbuf_alloc(struct mctp_binding *binding, size_t len)
{
	struct mctp_pktbuf *buf;
	size_t size;

	size = binding->pkt_size + binding->pkt_pad;

	/* todo: pools */
	buf = __mctp_alloc(sizeof(*buf) + size);

	buf->size = size;
	buf->start = binding->pkt_start;
	buf->end = buf->start + len;
	buf->mctp_hdr_off = buf->start;
	buf->next = NULL;

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

size_t mctp_pktbuf_size(struct mctp_pktbuf *pkt)
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

int mctp_pktbuf_push(struct mctp_pktbuf *pkt, void *data, size_t len)
{
	void *p;

	if (pkt->end + len > pkt->size)
		return -1;

	p = pkt->data + pkt->end;

	pkt->end += len;
	memcpy(p, data, len);

	return 0;
}

/* Message reassembly */
static struct mctp_msg_ctx *mctp_msg_ctx_lookup(struct mctp *mctp,
		uint8_t src, uint8_t dest, uint8_t tag)
{
	unsigned int i;

	/* @todo: better lookup, if we add support for more outstanding
	 * message contexts */
	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *ctx = &mctp->msg_ctxs[i];
		if (ctx->src == src && ctx->dest == dest && ctx->tag == tag)
			return ctx;
	}

	return NULL;
}

static struct mctp_msg_ctx *mctp_msg_ctx_create(struct mctp *mctp,
		uint8_t src, uint8_t dest, uint8_t tag)
{
	struct mctp_msg_ctx *ctx = NULL;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *tmp = &mctp->msg_ctxs[i];
		if (!tmp->src) {
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

	return ctx;
}

static void mctp_msg_ctx_drop(struct mctp_msg_ctx *ctx)
{
	ctx->src = 0;
}

static void mctp_msg_ctx_reset(struct mctp_msg_ctx *ctx)
{
	ctx->buf_size = 0;
}

static int mctp_msg_ctx_add_pkt(struct mctp_msg_ctx *ctx,
		struct mctp_pktbuf *pkt, size_t max_size)
{
	size_t len;

	len = mctp_pktbuf_size(pkt) - sizeof(struct mctp_hdr);

	if (ctx->buf_size + len > ctx->buf_alloc_size) {
		size_t new_alloc_size;
		void *lbuf;

		/* @todo: finer-grained allocation */
		if (!ctx->buf_alloc_size) {
			new_alloc_size = MAX(len, 4096UL);
		} else {
			new_alloc_size = ctx->buf_alloc_size * 2;
		}

		/* Don't allow heap to grow beyond a limit */
		if (new_alloc_size > max_size)
			return -1;


		lbuf = __mctp_realloc(ctx->buf, new_alloc_size);
		if (lbuf) {
			ctx->buf = lbuf;
			ctx->buf_alloc_size = new_alloc_size;
		} else {
			__mctp_free(ctx->buf);
			return -1;
		}
	}

	memcpy(ctx->buf + ctx->buf_size, mctp_pktbuf_data(pkt), len);
	ctx->buf_size += len;

	return 0;
}

/* Endpoint ID and Routing APIs */
bool mctp_eid_equal(mctp_eid_t a, mctp_eid_t b)
{
	return a == b;
}

bool mctp_eid_is_valid(const struct mctp *mctp, mctp_eid_t eid)
{
	if (!mctp)
		return false;

	return eid == MCTP_EID_NULL || eid >= 8;
}

bool mctp_eid_is_special(const struct mctp *mctp, mctp_eid_t eid)
{
	if (!mctp)
		return false;

	return mctp_eid_equal(eid, MCTP_EID_NULL) ||
	       mctp_eid_equal(eid, MCTP_EID_BROADCAST);
}

bool mctp_eid_range_is_routable(const struct mctp *mctp,
				const struct mctp_eid_range *range)
{
	bool valid, special;

	if (!(mctp && range))
		return false;

	valid = mctp_eid_is_valid(mctp, MCTP_EID(range->first));
	special = mctp_eid_is_special(mctp, MCTP_EID(range->first)) ||
		  mctp_eid_is_special(mctp, MCTP_EID(range->last));

	return range->first <= range->last && valid && !special;
}

bool mctp_eid_range_equal(const struct mctp *mctp,
			  const struct mctp_eid_range *a,
			  const struct mctp_eid_range *b)
{
	if (!(mctp && a && b))
		return false;

	return a->first == b->first && a->last == b->last;
}

bool mctp_eid_range_contains(const struct mctp *mctp,
			    const struct mctp_eid_range *range, mctp_eid_t eid)
{
	if (!(mctp && range))
		return false;

	if (!mctp_eid_range_is_routable(mctp, range))
		return false;

	return eid >= range->first && eid <= range->last;
}

int mctp_eid_range_intersects(const struct mctp *mctp,
			      const struct mctp_eid_range *a,
			      const struct mctp_eid_range *b)
{
	if (!(mctp && a && b))
		return false;

	return mctp_eid_range_contains(mctp, a, MCTP_EID(b->first)) ||
	       mctp_eid_range_contains(mctp, a, MCTP_EID(b->last)) ||
	       mctp_eid_range_contains(mctp, b, MCTP_EID(a->first)) ||
	       mctp_eid_range_contains(mctp, b, MCTP_EID(a->last));
}

bool mctp_device_equal(const struct mctp_device *a, const struct mctp_device *b)
{
	return a->bus == b->bus && a->address == b->address;
}

static struct mctp_route_entry *
mctp_route_list_add(struct mctp_route_entry *head,
		    struct mctp_route_entry *entry)
{
	if (!entry)
		return head;

	if (head)
		head->prev = entry;

	entry->next = head;
	entry->prev = NULL;

	return entry;
}

static struct mctp_route_entry *
mctp_route_list_remove(struct mctp_route_entry *head,
		       struct mctp_route_entry *entry)
{
	struct mctp_route_entry *next;

	if (!entry)
		return head;

	if (entry->next)
		entry->next->prev = entry->prev;

	if (entry->prev)
		entry->prev->next = entry->next;

	next = (head == entry) ? head->next : head;

	/* Prevent traversal from the removed node */
	entry->next = NULL;
	entry->prev = NULL;

	return next;
}

static void mctp_route_entry_get(struct mctp_route_entry *entry)
{
	assert(entry);
	assert(entry->refs > 0);

	if (entry->refs == 0) {
		mctp_prerr(
			"%s: Route entry reference count is zero, expect instability",
			__func__);
	}

	if (entry->refs == ULONG_MAX) {
		mctp_prerr(
			"%s: Route entry reference count is saturated for { [ %" PRIu8
			", %" PRIu8 " ] } ",
			__func__, entry->route.range.first,
			entry->route.range.last);
		return;
	}

	/* XXX: improve safety */
	entry->refs++;
}

static void mctp_route_entry_put(struct mctp_route_entry *entry)
{
	assert(entry->refs > 0);
	if (entry->refs == 0) {
		mctp_prerr(
			"%s: Route entry reference count is zero, expect instability",
			__func__);
		return;
	}

	if (entry->refs == ULONG_MAX) {
		mctp_prerr(
			"%s: Route entry reference count is saturated for { [ %" PRIu8
			", %" PRIu8 " ] } ",
			__func__, entry->route.range.first,
			entry->route.range.last);
		return;
	}

	/* XXX: improve safety */
	entry->refs--;

	if (!entry->refs) {
		assert(entry->prev == NULL);
		assert(entry->next == NULL);
		__mctp_free(entry);
	}
}

void mctp_route_put(const struct mctp_route *route)
{
	struct mctp_route_entry *entry;

	if (!route)
		return;

	entry = container_of(route, struct mctp_route_entry, route);

	mctp_route_entry_put(entry);
}

static struct mctp_route_entry *
__mctp_route_list_match(const struct mctp *mctp, struct mctp_route_entry *head,
			const struct mctp_route *route, uint32_t mode)
{
	struct mctp_route_entry *cur;
	uint32_t mask;

	assert(mctp);
	assert(route);

	if (!mode)
		return NULL;

	/* Mutually exclusive */
	mask = (MCTP_ROUTE_MATCH_EID | MCTP_ROUTE_MATCH_RANGE);
	if ((mode & mask) == mask)
		return NULL;

	cur = head;
	while (cur) {
		if (mode & MCTP_ROUTE_MATCH_ROUTE) {
			bool range, device, type;

			range = mctp_eid_range_equal(mctp, &cur->route.range,
						     &route->range);
			device = mctp_device_equal(&cur->route.device,
						   &route->device);
			type = cur->route.type == route->type;
			if (range && device && type)
				break;
		}

		if (mode & MCTP_ROUTE_MATCH_RANGE) {
			bool range;

			range = mctp_eid_range_equal(mctp, &cur->route.range,
						     &route->range);
			if (range)
				break;
		}

		if (mode & MCTP_ROUTE_MATCH_DEVICE) {
			if (mctp_device_equal(&cur->route.device,
					      &route->device))
				break;
		}

		if (mode & MCTP_ROUTE_MATCH_EID) {
			if (mctp_eid_range_intersects(mctp, &cur->route.range,
						      &route->range))
				break;
		}

		if (mode & MCTP_ROUTE_MATCH_TYPE) {
			if (cur->route.type == route->type)
				break;
		}

		cur = cur->next;
	}

	return cur;
}

const struct mctp_route_entry *
mctp_route_list_match(const struct mctp *mctp,
		      const struct mctp_route_entry *head,
		      const struct mctp_route *route, uint32_t flags)
{
	if (!mctp)
		return NULL;

	return __mctp_route_list_match(mctp, (struct mctp_route_entry *)head,
				       route, flags);
}

static void mctp_route_list_destroy(struct mctp_route_entry *head)
{
	while (head) {
		struct mctp_route_entry *next;

		next = mctp_route_list_remove(head, head);
		mctp_route_entry_put(head);
		head = next;
	}
}

const struct mctp_route *mctp_route_match(struct mctp *mctp,
					  const struct mctp_route *route,
					  uint32_t flags)
{
	struct mctp_route_entry *entry;

	if (!(mctp && route))
		return NULL;

	entry = __mctp_route_list_match(mctp, mctp->routes, route, flags);

	if (!entry)
		return NULL;

	mctp_route_entry_get(entry);

	return &entry->route;
}

const struct mctp_route *mctp_route_get_by_eid(struct mctp *mctp,
					       mctp_eid_t eid)
{
	struct mctp_route route = { 0 };

	if (!mctp)
		return NULL;

	if (!mctp_eid_is_valid(mctp, eid) || mctp_eid_is_special(mctp, eid))
		return NULL;

	route.range.first = eid;
	route.range.last = eid;

	return mctp_route_match(mctp, &route, MCTP_ROUTE_MATCH_EID);
}

const struct mctp_route *mctp_route_get_by_type(struct mctp *mctp, uint8_t type)
{
	struct mctp_route route = { 0 };

	if (!mctp)
		return NULL;

	if (!(type == MCTP_ROUTE_TYPE_ENDPOINT ||
	      type == MCTP_ROUTE_TYPE_UPSTREAM ||
	      type == MCTP_ROUTE_TYPE_DOWNSTREAM ||
	      type == MCTP_ROUTE_TYPE_LOCAL))
		return NULL;

	route.type = type;

	return mctp_route_match(mctp, &route, MCTP_ROUTE_MATCH_TYPE);
}

const struct mctp_route *mctp_route_get_by_device(struct mctp *mctp,
						  const struct mctp_device *dev)
{
	struct mctp_route route = { 0 };

	if (!(mctp && dev))
		return NULL;

	route.device = *dev;

	return mctp_route_match(mctp, &route, MCTP_ROUTE_MATCH_DEVICE);
}

bool mctp_route_is_local(const struct mctp_route *route)
{
	if (!route)
		return false;

	/* Local routes must be their own entry */
	if (route->range.first == route->range.last)
		return false;

	return route->type == MCTP_ROUTE_TYPE_LOCAL;
}

/* Pre-condition: `mctp_route_is_local(route) == true` */
mctp_eid_t mctp_route_as_eid(const struct mctp_route *route)
{
	assert(route);
	assert(route->type == MCTP_ROUTE_TYPE_LOCAL ||
			route->type == MCTP_ROUTE_TYPE_ENDPOINT);
	assert(route->range.first == route->range.last);

	return MCTP_EID(route->range.first);
}

static struct mctp_route_entry *__mctp_route_add(struct mctp_route_entry **head,
						 const struct mctp_route *route)
{
	struct mctp_route_entry *entry;

	assert(route);

	entry = __mctp_alloc(sizeof(*entry));
	if (!entry)
		return NULL;
	memset(entry, 0, sizeof(*entry));

	entry->route = *route;
	entry->refs = 1;
	*head = mctp_route_list_add(*head, entry);

	return entry;
}

static void __mctp_route_remove(struct mctp_route_entry **head,
				struct mctp_route_entry *entry)
{
	assert(entry);

	*head = mctp_route_list_remove(*head, entry);

	mctp_route_entry_put(entry);
}

/* Caller steals ownership */
static struct mctp_route_entry *
mctp_route_event_add(struct mctp_route_entry **eventp,
		     struct mctp_route_entry **tablep,
		     const struct mctp_route *route)
{
	struct mctp_route_entry *ee, *te;

	if (eventp) {
		ee = __mctp_route_add(eventp, route);
		if (!ee)
			return NULL;

		ee->flags |= MCTP_ROUTE_ENTRY_NOTIFY_ADD;
	}

	te = __mctp_route_add(tablep, route);
	if (eventp && !te) {
		__mctp_route_remove(eventp, ee);
		return NULL;
	}

	return te;
}

static void mctp_route_event_remove(struct mctp_route_entry **eventp,
				    struct mctp_route_entry **tablep,
				    struct mctp_route_entry *entry)
{
	if (!eventp) {
		__mctp_route_remove(tablep, entry);
		return;
	}

	/* Reuse the entry being removed */
	*tablep = mctp_route_list_remove(*tablep, entry);

	assert(!(entry->flags & MCTP_ROUTE_ENTRY_NOTIFY_ADD));
	assert(!(entry->flags & MCTP_ROUTE_ENTRY_NOTIFY_REMOVE));

	entry->flags |= MCTP_ROUTE_ENTRY_NOTIFY_REMOVE;
	*eventp = mctp_route_list_add(*eventp, entry);
}

static int mctp_route_event_delete(struct mctp *mctp,
				   struct mctp_route_entry **eventp,
				   struct mctp_route_entry **tablep,
				   const struct mctp_route *route)
{
	struct mctp_route_entry *match;
	uint32_t flags;

	flags = MCTP_ROUTE_MATCH_EID;

	while ((match = __mctp_route_list_match(mctp, *tablep, route, flags))) {
		struct mctp_route entry;

		assert(mctp_eid_range_is_routable(mctp, &match->route.range));

		entry = match->route;

		mctp_route_event_remove(eventp, &mctp->routes, match);
		match = NULL;

		if (entry.range.first < route->range.first &&
		    entry.range.last > route->range.last) {
			struct mctp_route left, right;

			/* Punch a hole in the entry */
			left = entry;
			left.range.last = route->range.first - 1;
			assert(mctp_eid_range_is_routable(mctp, &left.range));
			if (!mctp_route_event_add(eventp, &mctp->routes,
						  &left)) {
				return -ENOMEM;
			}

			right = entry;
			right.range.first = route->range.last + 1;
			assert(mctp_eid_range_is_routable(mctp, &right.range));
			if (!mctp_route_event_add(eventp, &mctp->routes,
						  &right))
				return -ENOMEM;

			return 0;
		}

		if (entry.range.first >= route->range.first &&
		    entry.range.last <= route->range.last) {
			/* Entry is a strict subset, remove it completely */
			continue;
		}

		/* Ensure entry's last EID is less than route's first */
		if (entry.range.last <= route->range.last) {
			assert(entry.range.first < route->range.first);

			entry.range.last = route->range.first - 1;
		}

		/* Ensure entry's first EID is greater than route's last */
		if (entry.range.first >= route->range.first) {
			assert(entry.range.last > route->range.last);

			entry.range.first = route->range.last + 1;
		}

		assert(mctp_eid_range_is_routable(mctp, &entry.range));

		if (!mctp_route_event_add(eventp, &mctp->routes, &entry))
			return -ENOMEM;
	}

	return 0;
}

static void mctp_route_notify(struct mctp *mctp, struct mctp_route_entry *event)
{
	if (!event)
		return;

	if (!mctp->route_notify)
		return;

	mctp->route_notify(mctp->route_notify_data, event);
	mctp_route_list_destroy(event);
}

int mctp_route_set_notify(struct mctp *mctp, mctp_route_notify_fn fn,
			  void *data)
{
	if (!mctp)
		return -EINVAL;

	mctp->route_notify = fn;
	mctp->route_notify_data = data;

	return 0;
}

#define MCTP_ROUTE_EVENT(mctp, event) ((mctp)->route_notify ? &event : NULL)

/*
 * Pre-condition: The route is not present in the route table
 * Post-condition: The route is present in the route table
 */
int mctp_route_add(struct mctp *mctp, const struct mctp_route *route)
{
	struct mctp_route_entry *event = NULL;
	struct mctp_route_entry *entry;
	uint32_t flags;

	if (!(mctp && route))
		return -EINVAL;

	if (!mctp_eid_range_is_routable(mctp, &route->range))
		return -EINVAL;

	flags = MCTP_ROUTE_MATCH_EID | MCTP_ROUTE_MATCH_DEVICE;
	if (__mctp_route_list_match(mctp, mctp->routes, route, flags))
		return -EEXIST;

	entry = mctp_route_event_add(MCTP_ROUTE_EVENT(mctp, event),
				     &mctp->routes, route);
	if (!entry)
		return -ENOMEM;

	mctp_route_notify(mctp, event);

	return 0;
}

/*
 * Pre-condition: The route may be present in the route table.
 * Post-condition: The route is not present in the route table.
 */
int mctp_route_remove(struct mctp *mctp, const struct mctp_route *route)
{
	struct mctp_route_entry *event = NULL;
	struct mctp_route_entry *match;
	uint32_t flags;

	if (!(mctp && route))
		return -EINVAL;

	if (!mctp_eid_range_is_routable(mctp, &route->range))
		return -EINVAL;

	flags = MCTP_ROUTE_MATCH_ROUTE;
	match = __mctp_route_list_match(mctp, mctp->routes, route, flags);
	if (!match)
		return 0;

	mctp_route_event_remove(MCTP_ROUTE_EVENT(mctp, event), &mctp->routes,
				match);

	mctp_route_notify(mctp, event);

	return 0;
}

/*
 * Pre-condition: Entries covering the provided route may exist in the route
 * 		  table
 * Post-condition: The provided route is present in the route table
 */
int mctp_route_insert(struct mctp *mctp, const struct mctp_route *route)
{
	struct mctp_route_entry **eventp, *event = NULL;
	int rc;

	if (!(mctp && route))
		return -EINVAL;

	if (!mctp_eid_range_is_routable(mctp, &route->range))
		return -EINVAL;

	eventp = MCTP_ROUTE_EVENT(mctp, event);

	/* Punch a route-shaped hole in the table */
	rc = mctp_route_event_delete(mctp, eventp, &mctp->routes, route);
	if (rc < 0)
		return rc;

	/* Fill the hole with route */
	rc = mctp_route_event_add(eventp, &mctp->routes, route) ? 0 : -ENOMEM;

	mctp_route_notify(mctp, event);

	return rc;
}

/*
 * Pre-condition: Entries covering the route may exist in the route table
 * Post-condition: The provided route is not present in the route table
 */
int mctp_route_delete(struct mctp *mctp, const struct mctp_route *route)
{
	struct mctp_route_entry *event = NULL;
	int rc;

	if (!(mctp && route))
		return -EINVAL;

	if (!mctp_eid_range_is_routable(mctp, &route->range))
		return -EINVAL;

	rc = mctp_route_event_delete(mctp, MCTP_ROUTE_EVENT(mctp, event),
				     &mctp->routes, route);

	mctp_route_notify(mctp, event);

	return rc;
}

int mctp_route_set_dynamic_pool(struct mctp *mctp,
				const struct mctp_eid_range *range)
{
	if (!(mctp && range))
		return -EINVAL;

	if (!mctp_eid_range_is_routable(mctp, range))
		return -EINVAL;

	mctp->dynamic_pool = *range;
	mctp->dynamic = range->first;

	return 0;
}

/* Caller steals ownership of the route */
const struct mctp_route *mctp_route_allocate(struct mctp *mctp,
					     const struct mctp_route *route,
					     uint8_t len)
{
	struct mctp_route_entry *match;
	struct mctp_eid_range range;
	struct mctp_route alloc;
	int rc;

	if (!(mctp && route && len))
		return NULL;

	if (!(route->type == MCTP_ROUTE_TYPE_LOCAL ||
	      route->type == MCTP_ROUTE_TYPE_DOWNSTREAM))
		return NULL;

	if (route->type == MCTP_ROUTE_TYPE_LOCAL && len != 1)
		return NULL;

	if (!(route->range.first == 0 && route->range.last == 0)) {
		mctp_prerr("Route range must be zeroed");
		return NULL;
	}

	alloc = *route;

	/* XXX: Implement a proper allocation and re-use policy: 8.17.6 */

	if (!mctp_eid_range_is_routable(mctp, &mctp->dynamic_pool)) {
		mctp_prerr(
			"Failed to allocate %" PRIu8
			" dynamic endpoint ID%s: Dynamic endpoint ID pool is invalid",
			len, len > 1 ? "s" : "");
		return NULL;
	}

	if ((uint8_t)(mctp->dynamic + len) < mctp->dynamic) {
		mctp_prerr("Failed to allocate %" PRIu8
			   " dynamic endpoint ID%s: Out of range request",
			   len, len > 1 ? "s" : "");
		return NULL;
	}

	if (mctp->dynamic + (len - 1) > mctp->dynamic_pool.last) {
		mctp_prerr("Failed to allocate %" PRIu8
			   " dynamic endpoint ID%s: Request exceeds pool limit",
			   len, len > 1 ? "s" : "");
		return NULL;
	}

	range = (struct mctp_eid_range){
		.first = mctp->dynamic,
		.last = mctp->dynamic + len - 1,
	};

	if (!mctp_eid_range_is_routable(mctp, &range)) {
		mctp_prerr("Failed to allocate %" PRIu8
			   " dynamic endpoint ID%s: Proposed range [%" PRIu8
			   ", %" PRIu8 "] is invalid",
			   len, len > 1 ? "s" : "", range.first, range.last);
		return NULL;
	}

	mctp->dynamic += len;

	alloc.range = range;

	rc = mctp_route_insert(mctp, &alloc);
	if (rc < 0) {
		mctp_prerr("Failed to insert allocated route: %d", rc);
		return NULL;
	}

	/* Maybe mctp_route_insert() should return a pointer? */
	match = __mctp_route_list_match(mctp, mctp->routes, &alloc,
					MCTP_ROUTE_MATCH_ROUTE);
	return match ? &match->route : NULL;
}

void mctp_route_table_dump(const struct mctp *mctp, int level)
{
	struct mctp_route_entry *cur;

	if (!mctp) {
		mctp_prwarn("Can't dump route table from NULL context");
		return;
	}

	if (!mctp->routes) {
		mctp_prlog(level, "Route table is empty");
		return;
	}

	cur = mctp->routes;

	mctp_prlog(level, "|  Range  | Type | Device | Refs |");
	mctp_prlog(level, "+---------+------+--------+------+");
	do {
		if (cur->route.range.first == cur->route.range.last) {
			mctp_prlog(level,
				   "|   %3" PRIu8 "   | %4" PRIu8 " | %3" PRIu8
				   ":%-2" PRIx64 " |  %3lu |",
				   cur->route.range.first, cur->route.type,
				   cur->route.device.bus,
				   cur->route.device.address, cur->refs);
		} else {
			mctp_prlog(level,
				   "| %3" PRIu8 "-%-3" PRIu8 " | %4" PRIu8
				   " | %3" PRIu8 ":%-2" PRIx64 " |  %3lu |",
				   cur->route.range.first,
				   cur->route.range.last, cur->route.type,
				   cur->route.device.bus,
				   cur->route.device.address, cur->refs);
		}
	} while ((cur = cur->next));
}

/* Core API functions */
struct mctp *mctp_init(void)
{
	struct mctp *mctp;

	mctp = __mctp_alloc(sizeof(*mctp));

	if(!mctp)
		return NULL;

	memset(mctp, 0, sizeof(*mctp));
	mctp->max_message_size = MCTP_MAX_MESSAGE_SIZE;

	return mctp;
}

void mctp_set_max_message_size(struct mctp *mctp, size_t message_size)
{
	mctp->max_message_size = message_size;
}

void mctp_destroy(struct mctp *mctp)
{
	size_t i;

	/* Cleanup message assembly contexts */
	BUILD_ASSERT(ARRAY_SIZE(mctp->msg_ctxs) < SIZE_MAX);
	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *tmp = &mctp->msg_ctxs[i];
		if (tmp->buf)
			__mctp_free(tmp->buf);
	}

	mctp_route_list_destroy(mctp->routes);
	__mctp_free(mctp->busses);
	__mctp_free(mctp);
}

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data)
{
	mctp->message_rx = fn;
	mctp->message_rx_data = data;
	return 0;
}

static struct mctp_bus *find_bus_for_eid(struct mctp *mctp, mctp_eid_t dest)
{
	const struct mctp_route *match;
	struct mctp_bus *bus;

	match = mctp_route_get_by_eid(mctp, dest);
	if (!match)
		return NULL;

	if (match->device.bus < mctp->n_busses) {
		bus = &mctp->busses[match->device.bus];
	} else {
		mctp_prerr("Invalid bus ID %" PRIu8
			   " (of %d) in route for endpoint %" PRIu8,
			   match->device.bus, mctp->n_busses, dest);
		bus = NULL;
	}

	mctp_route_put(match);

	return bus;
}

int mctp_register_binding(struct mctp *mctp, struct mctp_binding *binding)
{
	int bid = 0;
	int rc = 0;

	if (!(mctp && binding))
		return -EINVAL;

	bid = mctp->n_busses;
	mctp->n_busses += 1;

	if (!mctp->busses) {
		mctp->busses = __mctp_alloc(sizeof(struct mctp_bus));
		if (!mctp->busses)
			return -ENOMEM;

		memset(mctp->busses, 0, sizeof(struct mctp_bus));
	}

	mctp->busses[bid].id = bid;
	mctp->busses[bid].binding = binding;
	binding->bus = &mctp->busses[bid];
	binding->mctp = mctp;

	if (binding->start) {
		rc = binding->start(binding);
		if (rc < 0) {
			mctp_prerr("Failed to start binding: %d", rc);
			__mctp_free(mctp->busses);
			mctp->busses = NULL;
			return rc;
		}
	}

	return bid;
}

int mctp_register_endpoint(struct mctp *mctp, struct mctp_binding *binding,
			   mctp_eid_t eid)
{
	struct mctp_route route;
	int bid;
	int rc;

	if (!(mctp && binding))
		return -EINVAL;

	if (!mctp_eid_is_valid(mctp, eid) || mctp_eid_is_special(mctp, eid))
		return -EINVAL;

	bid = mctp_register_binding(mctp, binding);
	if (bid < 0)
		return bid;

	/* Locally deliver packets destined for the provided endpoint */
	route = (struct mctp_route){
		.range = { .first = eid, .last = eid },
		.type = MCTP_ROUTE_TYPE_ENDPOINT,
		.device = { .bus = bid, .address = 0 },
	};
	rc = mctp_route_insert(mctp, &route);
	if (rc < 0) {
		mctp_prerr("Failed to insert endpoint route in route table: %d",
			   rc);
		__mctp_free(mctp->busses);
		return rc;
	}

	return bid;
}

int mctp_bridge_busses(struct mctp *mctp, struct mctp_binding *b1,
		       mctp_eid_t eid1, struct mctp_binding *b2,
		       mctp_eid_t eid2)
{
	struct mctp_route route;
	int rc;

	assert(mctp->n_busses == 0);
	mctp->busses = __mctp_alloc(2 * sizeof(struct mctp_bus));
	memset(mctp->busses, 0, 2 * sizeof(struct mctp_bus));
	mctp->n_busses = 2;
	mctp->busses[0].binding = b1;
	b1->bus = &mctp->busses[0];
	b1->mctp = mctp;
	mctp->busses[1].binding = b2;
	b2->bus = &mctp->busses[1];
	b2->mctp = mctp;

	route = (struct mctp_route){
		.range = { .first = eid1, .last = eid1 },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.device = { .bus = 0, .address = 0, },
	};
	rc = mctp_route_insert(mctp, &route);
	if (rc < 0)
		goto cleanup;

	route = (struct mctp_route){
		.range = { .first = eid2, .last = eid2 },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.device = { .bus = 1, .address = 0, },
	};
	rc = mctp_route_insert(mctp, &route);
	if (rc < 0)
		goto cleanup;

	if (b1->start) {
		rc = b1->start(b1);
		if (rc < 0)
			goto cleanup;
	}

	if (b2->start) {
		rc = b2->start(b2);
		if (rc < 0)
			goto cleanup;
	}

	return 0;

cleanup:
	__mctp_free(mctp->busses);
	mctp->busses = NULL;
	mctp->n_busses = 0;
	return rc;
}

static inline bool mctp_ctrl_cmd_is_transport(struct mctp_ctrl_msg_hdr *hdr)
{
	return ((hdr->command_code >= MCTP_CTRL_CMD_FIRST_TRANSPORT) &&
		(hdr->command_code <= MCTP_CTRL_CMD_LAST_TRANSPORT));
}

static bool mctp_ctrl_handle_msg(struct mctp_bus *bus, mctp_eid_t src,
				 void *buffer, size_t length)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = buffer;

	/*
	 * Control message is received. If a transport control message handler
	 * is provided, it will called. If there is no dedicated handler, this
	 * function returns false and data can be handled by the generic
	 * message handler. The transport control message handler will be
	 * provided with messages in the command range 0xF0 - 0xFF.
	 */
	if (!mctp_ctrl_cmd_is_transport(msg_hdr))
		return false;

	if (bus->binding->control_rx == NULL)
		return false;

	/* MCTP bus binding handler */
	bus->binding->control_rx(src, bus->binding->control_rx_data, buffer,
				 length);

	return true;
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
		    void *buf, size_t len)
{
	assert(buf != NULL);

	/* Handle MCTP Control Messages: */
	if (len >= sizeof(struct mctp_ctrl_msg_hdr)) {
		struct mctp_ctrl_msg_hdr *msg_hdr = buf;

		/*
		 * Identify if this is a control request message.
		 * See DSP0236 v1.3.0 sec. 11.5.
		 */
		if (mctp_ctrl_cmd_is_request(msg_hdr) &&
		    mctp_ctrl_handle_msg(bus, src, buf, len))
			return;
	}

	if (mctp->message_rx)
		mctp->message_rx(src, mctp->message_rx_data, buf, len);
}

static void mctp_packet_tx_enqueue(struct mctp_bus *bus,
				   struct mctp_pktbuf *pkt)
{
	/* add to tx queue */
	if (bus->tx_queue_tail)
		bus->tx_queue_tail->next = pkt;
	else
		bus->tx_queue_head = pkt;

	bus->tx_queue_tail = pkt;
}

static int mctp_packet_tx(struct mctp_bus *bus, struct mctp_pktbuf *pkt)
{
	if (!bus->tx_enabled)
		return -1;

	return bus->binding->tx(bus->binding, pkt);
}

static void mctp_send_tx_queue(struct mctp_bus *bus)
{
	struct mctp_pktbuf *pkt;

	while ((pkt = bus->tx_queue_head)) {
		int rc;

		rc = mctp_packet_tx(bus, pkt);
		if (rc)
			break;

		bus->tx_queue_head = pkt->next;
		mctp_pktbuf_free(pkt);
	}

	if (!bus->tx_queue_head)
		bus->tx_queue_tail = NULL;
}

static void mctp_binding_route(struct mctp_binding *binding,
			       const struct mctp_route *route,
			       struct mctp_pktbuf *rx_pkt)
{
	struct mctp_pktbuf *tx_pkt, *framed;
	struct mctp *mctp = binding->mctp;
	struct mctp_hdr *rx_hdr, *tx_hdr;
	struct mctp_bus *bus;
	size_t len;

	if (route->device.bus >= mctp->n_busses) {
		mctp_prerr("Dropping packet, invalid bus ID in route: %" PRIu8
			   " (%" PRIu8 ")",
			   route->device.bus, mctp->n_busses);
		goto out;
	}
	bus = &mctp->busses[route->device.bus];

	if (!bus->binding->frame) {
		/* Binding frames the packet on tx */
		mctp_packet_tx_enqueue(bus, rx_pkt);

		/* pkt is freed once it has been sent */
		mctp_send_tx_queue(bus);

		return;
	}

	rx_hdr = mctp_pktbuf_hdr(rx_pkt);

	/* rx_pkt size includes MCTP header */
	tx_pkt = mctp_pktbuf_alloc(bus->binding, mctp_pktbuf_size(rx_pkt));
	if (!tx_pkt) {
		mctp_prerr("Failed to allocate packet for transmission");
		goto out;
	}

	tx_hdr = mctp_pktbuf_hdr(tx_pkt);
	tx_hdr->ver = bus->binding->version & 0xf;
	tx_hdr->dest = rx_hdr->dest;
	tx_hdr->src = rx_hdr->src;
	tx_hdr->flags_seq_tag = rx_hdr->flags_seq_tag;

	/* Payload length */
	len = mctp_pktbuf_size(rx_pkt) - sizeof(*tx_hdr);
	memcpy(mctp_pktbuf_data(tx_pkt), mctp_pktbuf_data(rx_pkt), len);

	framed = bus->binding->frame(bus->binding, tx_pkt, &route->device);
	if (!framed) {
		mctp_prerr("Failed to frame packet for transmission");
		goto out;
	}

	mctp_packet_tx_enqueue(bus, framed);

	/* pkt is freed once it has been sent */
	mctp_send_tx_queue(bus);

out:
	mctp_pktbuf_free(rx_pkt);
	return;
}

static void mctp_binding_assemble(struct mctp_binding *binding,
				  struct mctp_pktbuf *pkt)
{
	struct mctp_bus *bus = binding->bus;
	struct mctp *mctp = binding->mctp;
	uint8_t flags, exp_seq, seq, tag;
	struct mctp_msg_ctx *ctx;
	struct mctp_hdr *hdr;
	size_t len;
	void *p;
	int rc;

	assert(bus);

	/* Drop packet if it was smaller than mctp hdr size */
	if (mctp_pktbuf_size(pkt) <= sizeof(struct mctp_hdr))
		goto out;

	hdr = mctp_pktbuf_hdr(pkt);

	flags = hdr->flags_seq_tag & (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM);
	tag = (hdr->flags_seq_tag >> MCTP_HDR_TAG_SHIFT) & MCTP_HDR_TAG_MASK;
	seq = (hdr->flags_seq_tag >> MCTP_HDR_SEQ_SHIFT) & MCTP_HDR_SEQ_MASK;

	switch (flags) {
	case MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM:
		/* single-packet message - send straight up to rx function,
		 * no need to create a message context */
		len = pkt->end - pkt->mctp_hdr_off - sizeof(struct mctp_hdr);
		p = pkt->data + pkt->mctp_hdr_off + sizeof(struct mctp_hdr);
		mctp_rx(mctp, bus, MCTP_EID(hdr->src), p, len);
		break;

	case MCTP_HDR_FLAG_SOM:
		/* start of a new message - start the new context for
		 * future message reception. If an existing context is
		 * already present, drop it. */
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag);
		if (ctx) {
			mctp_msg_ctx_reset(ctx);
		} else {
			ctx = mctp_msg_ctx_create(mctp,
					hdr->src, hdr->dest, tag);
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt, mctp->max_message_size);
		if (rc) {
			mctp_msg_ctx_drop(ctx);
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
			mctp_msg_ctx_drop(ctx);
			goto out;
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt, mctp->max_message_size);
		if (!rc)
			mctp_rx(mctp, bus, MCTP_EID(ctx->src), ctx->buf,
				ctx->buf_size);

		mctp_msg_ctx_drop(ctx);
		break;

	case 0:
		/* Neither SOM nor EOM */
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src,hdr->dest, tag);
		if (!ctx)
			goto out;

		exp_seq = (ctx->last_seq + 1) % 4;
		if (exp_seq != seq) {
			mctp_prdebug(
				"Sequence number %d does not match expected %d",
				seq, exp_seq);
			mctp_msg_ctx_drop(ctx);
			goto out;
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt, mctp->max_message_size);
		if (rc) {
			mctp_msg_ctx_drop(ctx);
			goto out;
		}
		ctx->last_seq = seq;

		break;
	}
out:
	mctp_pktbuf_free(pkt);
}

void mctp_binding_rx(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	struct mctp *mctp = binding->mctp;
	const struct mctp_route *match;
	struct mctp_hdr *hdr;
	mctp_eid_t dest;

	hdr = mctp_pktbuf_hdr(pkt);

	dest = MCTP_EID(hdr->dest);
	/* Both broadcast and NULL EIDs must be locally delivered */
	if (mctp_eid_is_special(mctp, dest)) {
		mctp_binding_assemble(binding, pkt);
		return;
	}

	match = mctp_route_get_by_eid(mctp, dest);
	if (!match) {
		/* If we can't route the packet in any way then drop it */
		mctp_pktbuf_free(pkt);
		return;
	}

	if (match->type == MCTP_ROUTE_TYPE_ENDPOINT)
		mctp_binding_assemble(binding, pkt);
	else
		mctp_binding_route(binding, match, pkt);

	mctp_route_put(match);
}

void mctp_binding_set_tx_enabled(struct mctp_binding *binding, bool enable)
{
	struct mctp_bus *bus = binding->bus;
	bus->tx_enabled = enable;
	if (enable)
		mctp_send_tx_queue(bus);
}

static int mctp_message_tx_on_bus(struct mctp_bus *bus, mctp_eid_t src,
				  mctp_eid_t dest, void *msg, size_t msg_len)
{
	size_t max_payload_len, payload_len, p;
	const struct mctp_route *route;
	struct mctp_pktbuf *pkt;
	struct mctp_hdr *hdr;
	int i;

	max_payload_len = bus->binding->pkt_size - sizeof(*hdr);

	mctp_prdebug("%s: Generating packets for transmission of %zu byte message from %hhu to %hhu",
		     __func__, msg_len, src, dest);

	route = mctp_route_get_by_eid(bus->binding->mctp, dest);
	if (!route) {
		mctp_prerr("Failed to find route for endpoint %" PRIu8, dest);
		return -ENXIO;
	}

	/* queue up packets, each of max MCTP_MTU size */
	for (p = 0, i = 0; p < msg_len; i++) {
		payload_len = msg_len - p;
		if (payload_len > max_payload_len)
			payload_len = max_payload_len;

		pkt = mctp_pktbuf_alloc(bus->binding,
				payload_len + sizeof(*hdr));
		hdr = mctp_pktbuf_hdr(pkt);

		/* todo: tags */
		hdr->ver = bus->binding->version & 0xf;
		hdr->dest = dest;
		hdr->src = src;
		hdr->flags_seq_tag = MCTP_HDR_FLAG_TO |
			(0 << MCTP_HDR_TAG_SHIFT);

		if (i == 0)
			hdr->flags_seq_tag |= MCTP_HDR_FLAG_SOM;
		if (p + payload_len >= msg_len)
			hdr->flags_seq_tag |= MCTP_HDR_FLAG_EOM;
		hdr->flags_seq_tag |=
			(i & MCTP_HDR_SEQ_MASK) << MCTP_HDR_SEQ_SHIFT;

		memcpy(mctp_pktbuf_data(pkt), msg + p, payload_len);

		if (bus->binding->frame) {
			struct mctp_pktbuf *framed;

			framed = bus->binding->frame(bus->binding, pkt,
						     &route->device);
			if (!framed) {
				mctp_prerr(
					"Failed to frame packet for transmission");
				mctp_pktbuf_free(pkt);
				return -EBADMSG;
			}

			pkt = framed;
		}

		mctp_packet_tx_enqueue(bus, pkt);

		p += payload_len;
	}

	mctp_prdebug("%s: Enqueued %d packets", __func__, i);

	mctp_route_put(route);

	mctp_send_tx_queue(bus);

	return 0;
}

int mctp_message_tx(struct mctp *mctp, mctp_eid_t dest, void *msg, size_t len)
{
	const struct mctp_route *match;
	struct mctp_bus *bus;
	mctp_eid_t src;
	int rc;

	bus = find_bus_for_eid(mctp, dest);
	mctp_prdebug("Got bus: %p", bus);
	if (!bus)
		return -ENODEV;

	/* Determine the source EID */
	/* XXX: Do this by deriving the local port from the bus? */
	match = mctp_route_get_by_type(mctp, MCTP_ROUTE_TYPE_ENDPOINT);
	if (match) {
		src = mctp_route_as_eid(match);
	} else {
		/* Fall back to the NULL EID if we're sending locally */
		match = mctp_route_get_by_eid(mctp, dest);
		assert(match);
		if (match->type != MCTP_ROUTE_TYPE_LOCAL) {
			/* Can't use a NULL EID for a non-local device */
			rc = -ENXIO;
			goto out;
		}

		src = MCTP_EID_NULL;
	}

	rc = mctp_message_tx_on_bus(bus, src, dest, msg, len);

out:
	mctp_route_put(match);

	return rc;
}
