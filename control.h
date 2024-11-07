#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "libmctp.h"

/* Handle a MCTP control message. Returns true for control requests,
 * false otherwise */
bool mctp_control_handler(struct mctp_bus *bus, uint8_t src_eid, bool tag_owner,
			  uint8_t msg_tag, const void *data, size_t len);
