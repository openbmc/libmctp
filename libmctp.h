/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_H
#define _LIBMCTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct mctp;
struct mctp_bus;
typedef uint8_t mctp_eid_t;
#define MCTP_EID(id) (id)

/* Special Endpoint ID values */
#define MCTP_EID_NULL	   MCTP_EID(0)
#define MCTP_EID_BROADCAST MCTP_EID(255)

bool mctp_eid_equal(mctp_eid_t a, mctp_eid_t b);

/* Inclusive range */
struct mctp_eid_range {
	mctp_eid_t first;
	mctp_eid_t last;
};

bool mctp_eid_is_valid(const struct mctp *mctp, mctp_eid_t eid);
bool mctp_eid_is_special(const struct mctp *mctp, mctp_eid_t eid);
bool mctp_eid_range_is_valid(const struct mctp *mctp,
			     const struct mctp_eid_range *range);
int mctp_eid_range_contains(const struct mctp *mctp,
			    const struct mctp_eid_range *range, mctp_eid_t eid);
int mctp_eid_range_equal(const struct mctp *mctp,
			 const struct mctp_eid_range *a,
			 const struct mctp_eid_range *b);
int mctp_eid_range_intersects(const struct mctp *mctp,
			      const struct mctp_eid_range *a,
			      const struct mctp_eid_range *b);

/* MCTP packet definitions */
struct mctp_hdr {
	uint8_t	ver;
	uint8_t	dest;
	uint8_t	src;
	uint8_t	flags_seq_tag;
};

/* Definitions for flags_seq_tag field */
#define MCTP_HDR_FLAG_SOM	(1<<7)
#define MCTP_HDR_FLAG_EOM	(1<<6)
#define MCTP_HDR_FLAG_TO	(1<<3)
#define MCTP_HDR_SEQ_SHIFT	(4)
#define MCTP_HDR_SEQ_MASK	(0x3)
#define MCTP_HDR_TAG_SHIFT	(0)
#define MCTP_HDR_TAG_MASK	(0x7)

/* Baseline Transmission Unit and packet size */
#define MCTP_BTU		64
#define MCTP_PACKET_SIZE(unit)	((unit) + sizeof(struct mctp_hdr))
#define MCTP_BODY_SIZE(unit)	((unit) - sizeof(struct mctp_hdr))

/* packet buffers */

struct mctp_pktbuf {
	size_t		start, end, size;
	size_t		mctp_hdr_off;
	struct mctp_pktbuf *next;
	unsigned char	data[];
};

struct mctp_binding;

struct mctp_pktbuf *mctp_pktbuf_alloc(struct mctp_binding *hw, size_t len);
void mctp_pktbuf_free(struct mctp_pktbuf *pkt);
struct mctp_hdr *mctp_pktbuf_hdr(struct mctp_pktbuf *pkt);
void *mctp_pktbuf_data(struct mctp_pktbuf *pkt);
size_t mctp_pktbuf_size(struct mctp_pktbuf *pkt);
void *mctp_pktbuf_alloc_start(struct mctp_pktbuf *pkt, size_t size);
void *mctp_pktbuf_alloc_end(struct mctp_pktbuf *pkt, size_t size);
int mctp_pktbuf_push(struct mctp_pktbuf *pkt, void *data, size_t len);

/* MCTP core */
struct mctp *mctp_init(void);
void mctp_destroy(struct mctp *mctp);

/* Register a binding to the MCTP core, and creates a bus (populating
 * binding->bus).
 *
 * If this function is called with a valid endpoint ID any packets destined for
 * the provided endpoint will be delivered locally - see `mctp_set_rx_all()`
 * below. Pass eid as MCTP_EID_NULL to disable local delivery for the bus.
 *
 * Returns the bus ID of the registered binding for the mctp instance.
 */
int mctp_register_bus(struct mctp *mctp,
		struct mctp_binding *binding,
		mctp_eid_t eid);

/* Create a simple bidirectional bridge between busses.
 *
 * In this mode, the MCTP stack is initialised as a bridge. There is no EID
 * defined for the bridge itself, so no packets are considered local. The
 * supplied endpoint IDs should map to the device context associated with each
 * binding. The route table is configured such that all messages from one
 * binding are forwarded to the other.
 */
int mctp_bridge_busses(struct mctp *mctp, struct mctp_binding *b1,
		       mctp_eid_t eid1, struct mctp_binding *b2,
		       mctp_eid_t eid2);

/* Routing */
struct mctp_device {
	uint8_t bus; /* If you have more busses than endpoints... */
	uint64_t address; /* Surely enough for everyone... */
};

bool mctp_device_equal(const struct mctp_device *a,
		       const struct mctp_device *b);

struct mctp_route {
	struct mctp_eid_range range;
	struct mctp_device device;

#define MCTP_ROUTE_TYPE_ENDPOINT   0
#define MCTP_ROUTE_TYPE_UPSTREAM   1
#define MCTP_ROUTE_TYPE_DOWNSTREAM 2
#define MCTP_ROUTE_TYPE_LOCAL	   3
	uint8_t type;
};

struct mctp_route_entry {
	struct mctp_route_entry *prev;
	struct mctp_route_entry *next;

	unsigned long refs;

#define MCTP_ROUTE_ENTRY_NOTIFY_ADD    (1UL << 0)
#define MCTP_ROUTE_ENTRY_NOTIFY_REMOVE (1UL << 1)
	uint32_t flags;

	struct mctp_route route;
};

#define MCTP_ROUTE_MATCH_ROUTE	(1 << 0)
#define MCTP_ROUTE_MATCH_RANGE	(1 << 1)
#define MCTP_ROUTE_MATCH_DEVICE (1 << 2)
#define MCTP_ROUTE_MATCH_EID	(1 << 3)
#define MCTP_ROUTE_MATCH_TYPE	(1 << 4)
const struct mctp_route_entry *
mctp_route_list_match(const struct mctp *mctp,
		      const struct mctp_route_entry *head,
		      const struct mctp_route *route, uint32_t flags);

void mctp_route_put(const struct mctp_route *route);
const struct mctp_route *mctp_route_match(struct mctp *mctp,
					  const struct mctp_route *route,
					  uint32_t flags);
void mctp_route_put(const struct mctp_route *route);
const struct mctp_route *mctp_route_get_by_eid(struct mctp *mctp,
					       mctp_eid_t eid);
const struct mctp_route *mctp_route_get_by_type(struct mctp *mctp,
						uint8_t type);
const struct mctp_route *
mctp_route_get_by_device(struct mctp *mctp, const struct mctp_device *dev);
mctp_eid_t mctp_route_as_eid(const struct mctp_route *route);

int mctp_route_add(struct mctp *mctp, const struct mctp_route *route);
int mctp_route_remove(struct mctp *mctp, const struct mctp_route *route);
int mctp_route_insert(struct mctp *mctp, const struct mctp_route *route);
int mctp_route_delete(struct mctp *mctp, const struct mctp_route *route);

int mctp_route_set_dynamic_pool(struct mctp *mctp,
				const struct mctp_eid_range *range);
const struct mctp_route *mctp_route_allocate(struct mctp *mctp,
					     const struct mctp_route *route,
					     uint8_t len);

void mctp_route_table_dump(const struct mctp *mctp, int level);

typedef void (*mctp_route_notify_fn)(void *data,
				     const struct mctp_route_entry *event);

int mctp_route_set_notify(struct mctp *mctp, mctp_route_notify_fn fn,
			  void *data);

typedef void (*mctp_rx_fn)(mctp_eid_t src, void *data, void *msg, size_t len);

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data);

int mctp_message_tx(struct mctp *mctp, mctp_eid_t eid,
		void *msg, size_t msg_len);

/* hardware bindings */

void mctp_binding_set_tx_enabled(struct mctp_binding *binding, bool enable);

/*
 * Receive a packet from binding to core. Takes ownership of pkt, free()-ing it
 * after use.
 */
void mctp_bus_rx(struct mctp_binding *binding, struct mctp_pktbuf *pkt);

/* environment-specific allocation */
void mctp_set_alloc_ops(void *(*alloc)(size_t),
		void (*free)(void *),
		void *(realloc)(void *, size_t));

/* environment-specific logging */

void mctp_set_log_stdio(int level);
void mctp_set_log_syslog(void);
void mctp_set_log_custom(void (*fn)(int, const char *, va_list));

/* these should match the syslog-standard LOG_* definitions, for
 * easier use with syslog */
#define MCTP_LOG_ERR		3
#define MCTP_LOG_WARNING	4
#define MCTP_LOG_NOTICE		5
#define MCTP_LOG_INFO		6
#define MCTP_LOG_DEBUG		7


#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_H */
