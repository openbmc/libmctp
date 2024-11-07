/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#pragma once

#include "libmctp.h"

/* 64kb should be sufficient for a single message. Applications
 * requiring higher sizes can override by setting max_message_size.*/
#ifndef MCTP_MAX_MESSAGE_SIZE
#define MCTP_MAX_MESSAGE_SIZE 65536
#endif

/* Must be >= 2 for bridge busses */
#ifndef MCTP_MAX_BUSSES
#define MCTP_MAX_BUSSES 2
#endif

/* Concurrent reassembly contexts. */
#ifndef MCTP_REASSEMBLY_CTXS
#define MCTP_REASSEMBLY_CTXS 16
#endif

/* Outbound request tags */
#ifndef MCTP_REQ_TAGS
#define MCTP_REQ_TAGS MCTP_REASSEMBLY_CTXS
#endif

#ifndef MCTP_DEFAULT_CLOCK_GETTIME
#define MCTP_DEFAULT_CLOCK_GETTIME 1
#endif

#ifndef MCTP_CONTROL_HANDLER
#define MCTP_CONTROL_HANDLER 1
#endif

/* Tag expiry timeout, in milliseconds */
static const uint64_t MCTP_TAG_TIMEOUT = 6000;

/* Internal data structures */

enum mctp_bus_state {
	mctp_bus_state_constructed = 0,
	mctp_bus_state_tx_enabled,
	mctp_bus_state_tx_disabled,
};

struct mctp_bus {
	mctp_eid_t eid;
	struct mctp_binding *binding;
	enum mctp_bus_state state;
	struct mctp *mctp;

	/* Current message to transmit */
	void *tx_msg;
	/* Position in tx_msg */
	size_t tx_msgpos;
	/* Length of tx_msg */
	size_t tx_msglen;
	/* Length of current packet payload */
	size_t tx_pktlen;
	uint8_t tx_seq;
	uint8_t tx_src;
	uint8_t tx_dest;
	bool tx_to;
	uint8_t tx_tag;

	/* todo: routing */
};

struct mctp_msg_ctx {
	/* NULL buf indicates an unused mctp_msg_ctx */
	void *buf;

	uint8_t src;
	uint8_t dest;
	uint8_t tag;
	uint8_t last_seq;
	size_t buf_size;
	size_t buf_alloc_size;
	size_t fragment_size;
};

struct mctp_req_tag {
	/* 0 is an unused entry */
	mctp_eid_t local;
	mctp_eid_t remote;
	uint8_t tag;
	/* time of tag expiry */
	uint64_t expiry;
};

#define MCTP_CONTROL_MAX_TYPES 10

struct mctp_control {
	/* Types to report from Get MCTP Version Support */
	uint8_t msg_types[MCTP_CONTROL_MAX_TYPES];
	size_t num_msg_types;
};

struct mctp {
	int n_busses;
	struct mctp_bus busses[MCTP_MAX_BUSSES];

	/* Message RX callback */
	mctp_rx_fn message_rx;
	void *message_rx_data;

	/* Packet capture callback */
	mctp_capture_fn capture;
	void *capture_data;

	/* Message reassembly. */
	struct mctp_msg_ctx msg_ctxs[MCTP_REASSEMBLY_CTXS];

	/* Allocated outbound TO tags */
	struct mctp_req_tag req_tags[MCTP_REQ_TAGS];
	/* used to avoid always allocating tag 0 */
	uint8_t tag_round_robin;

	enum {
		ROUTE_ENDPOINT,
		ROUTE_BRIDGE,
	} route_policy;
	size_t max_message_size;

#if MCTP_CONTROL_HANDLER
	struct mctp_control control;
#endif

	void *alloc_ctx;

	uint64_t (*platform_now)(void *);
	void *platform_now_ctx;
};
