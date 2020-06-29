/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _BINDING_H
#define _BINDING_H

#include "libmctp.h"

#include <stdbool.h>
#include <stdint.h>

struct mctp_binding {
	const char *name;
	uint8_t version;
	struct mctp_bus *bus;
	struct mctp *mctp;
	int pkt_size;
	int pkt_pad;
	int pkt_start;
	int (*start)(struct mctp_binding *binding);
	struct mctp_pktbuf *(*frame)(struct mctp_binding *binding,
				     struct mctp_pktbuf *pkt,
				     const struct mctp_device *dest);
	int (*tx)(struct mctp_binding *binding, struct mctp_pktbuf *pkt);
	mctp_rx_fn control_rx;
	void *control_rx_data;
};

struct mctp_bus {
	struct mctp_binding *binding;
	uint8_t id;
	bool tx_enabled;

	struct mctp_pktbuf *tx_queue_head;
	struct mctp_pktbuf *tx_queue_tail;
};
#endif
