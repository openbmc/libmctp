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
bool mctp_eid_range_is_routable(const struct mctp *mctp,
				const struct mctp_eid_range *range);
bool mctp_eid_range_contains(const struct mctp *mctp,
			     const struct mctp_eid_range *range,
			     mctp_eid_t eid);
bool mctp_eid_range_equal(const struct mctp *mctp,
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
void mctp_set_max_message_size(struct mctp *mctp, size_t message_size);
void mctp_destroy(struct mctp *mctp);

/* Register a binding to the MCTP core.
 *
 * Returns the bus ID of the registered binding.
 */
int mctp_register_binding(struct mctp *mctp, struct mctp_binding *binding);

/* Register a binding to the MCTP core, and associate an EID with the binding's
 * bus port. The provided EID must be a routable EID.
 *
 * Returns the bus ID of the registered binding.
 */
int mctp_register_endpoint(struct mctp *mctp, struct mctp_binding *binding,
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

/*
 * Represent a device by its physical address parameters to assist route
 * table representation and route resolution.
 */
struct mctp_device {
	uint8_t bus; /* If you have more busses than endpoints... */
	uint64_t address; /* Surely enough for everyone... */
};

bool mctp_device_equal(const struct mctp_device *a,
		       const struct mctp_device *b);

struct mctp_route {
	struct mctp_eid_range range;
	struct mctp_device device;

/*
 * Route types.
 *
 * MCTP_ROUTE_TYPE_UPSTREAM, MCTP_ROUTE_TYPE_DOWNSTREAM and
 * MCTP_ROUTE_TYPE_LOCAL are the "upstream", "downstream and "local" route
 * types as defined by DSP0236 v1.3.1 section 9.1.6.
 *
 * MCTP_ROUTE_TYPE_ENDPOINT is libmctp-specific. It represents a route for an
 * endpoint attached to the current libmctp context, i.e. EIDs that will cause
 * a packet to be delivered to the context rather than routed to another device
 * in the network. Resolving EIDs attached to the context via the route table
 * is necessary because a bridge context can have a number of EIDs assigned
 * that is not equal to the number of ports it bridges.
 *
 * See DSP0236 v1.3.1 section 9.1.2 for the various bridge EID configurations.
 *
 * Note that MCTP_ROUTE_TYPE_LOCAL _does not_ refer to routes for ports that
 * are attached to the libmctp context; rather, it refers to routes for devices
 * that are _attached to the buses associated with the ports of the context_.
 *
 * See DSP0236 v1.3.1 sections 9.1.6, 9.1.7.1 and 12.9 for further explanation
 * of the local route type.
 */
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
bool mctp_route_is_local(const struct mctp_route *route);
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
struct mctp_binding {
	const char *name;
	uint8_t version;
	struct mctp_bus *bus;
	struct mctp *mctp;
	int pkt_size;
	int pkt_pad;
	int (*start)(struct mctp_binding *binding);
	int (*tx)(struct mctp_binding *binding, struct mctp_pktbuf *pkt);
	mctp_rx_fn control_rx;
	void *control_rx_data;
};

void mctp_binding_set_tx_enabled(struct mctp_binding *binding, bool enable);

/*
 * Receive a packet from binding to core. Takes ownership of pkt, free()-ing it
 * after use.
 */
void mctp_binding_rx(struct mctp_binding *binding, struct mctp_pktbuf *pkt);

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
