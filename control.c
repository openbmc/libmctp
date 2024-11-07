#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include "libmctp-cmds.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "core-internal.h"

#include "control.h"

static void fill_resp(const void *req, struct mctp_ctrl_msg_hdr *hdr)
{
	const struct mctp_ctrl_msg_hdr *req_hdr = req;
	hdr->ic_msg_type = MCTP_CTRL_HDR_MSG_TYPE;
	hdr->rq_dgram_inst = req_hdr->rq_dgram_inst &
			     MCTP_CTRL_HDR_INSTANCE_ID_MASK;
	hdr->command_code = req_hdr->command_code;
}

static uint8_t mctp_ctrl_set_endpoint_id(struct mctp_bus *bus, uint8_t src_eid,
					 uint8_t msg_tag, const void *data,
					 size_t len)
{
	if (len != sizeof(struct mctp_ctrl_cmd_set_endpoint_id_req)) {
		return MCTP_CTRL_CC_ERROR_INVALID_LENGTH;
	}
	const struct mctp_ctrl_cmd_set_endpoint_id_req *req = data;

	uint8_t op = req->operation & MCTP_CTRL_SET_EID_OP_MASK;
	if (!(op == MCTP_CTRL_SET_EID_OP_SET ||
	      op == MCTP_CTRL_SET_EID_OP_FORCE)) {
		return MCTP_CTRL_CC_ERROR_INVALID_DATA;
	}

	if (mctp_bus_set_eid(bus->binding, req->eid)) {
		return MCTP_CTRL_CC_ERROR_INVALID_DATA;
	}

	struct mctp_ctrl_cmd_set_endpoint_id_resp *resp =
		__mctp_msg_alloc(sizeof(*resp), bus->mctp);
	if (!resp) {
		mctp_prdebug("no response buffer");
		return MCTP_CTRL_CC_ERROR;
	}
	memset(resp, 0x00, sizeof(*resp));
	fill_resp(data, &resp->hdr);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->status = MCTP_CTRL_SET_EID_STATUS_ACCEPTED;
	resp->eid = req->eid;
	resp->pool_size = 0;

	int rc = mctp_message_tx_alloced(bus->mctp, src_eid, false, msg_tag,
					 resp, sizeof(*resp));
	if (!rc) {
		mctp_prdebug("set_endpoint_id response send failed: %d", rc);
	}
	return MCTP_CTRL_CC_SUCCESS;
}

static uint8_t mctp_ctrl_get_endpoint_id(struct mctp_bus *bus, uint8_t src_eid,
					 uint8_t msg_tag, const void *data,
					 size_t len)
{
	if (len != sizeof(struct mctp_ctrl_msg_hdr)) {
		/* Expect empty request */
		return MCTP_CTRL_CC_ERROR_INVALID_LENGTH;
	}
	(void)data;

	struct mctp_ctrl_cmd_get_endpoint_id_resp *resp =
		__mctp_msg_alloc(sizeof(*resp), bus->mctp);
	if (!resp) {
		mctp_prdebug("no response buffer");
		return MCTP_CTRL_CC_ERROR;
	}
	memset(resp, 0x00, sizeof(*resp));
	fill_resp(data, &resp->hdr);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->endpoint_id = bus->eid;
	resp->endpoint_type = MCTP_CTRL_ENDPOINT_TYPE_SIMPLE |
			      MCTP_CTRL_ENDPOINT_ID_TYPE_STATIC;
	resp->medium_specific = 0x00;

	int rc = mctp_message_tx_alloced(bus->mctp, src_eid, false, msg_tag,
					 resp, sizeof(*resp));
	if (!rc) {
		mctp_prdebug("get_endpoint_id response send failed: %d", rc);
	}
	return MCTP_CTRL_CC_SUCCESS;
}

#define MCTP_PROTOCOL_COUNT 4
/* Big endian */
const uint8_t MCTP_PROTOCOL_VERSIONS[MCTP_PROTOCOL_COUNT * 4] = {
	// 1.0
	0xf1,
	0xf0,
	0xff,
	0x00,
	// 1.1
	0xf1,
	0xf1,
	0xff,
	0x00,
	// 1.2
	0xf1,
	0xf2,
	0xff,
	0x00,
	// 1.3.3
	0xf1,
	0xf3,
	0xf3,
	0x00,
};

static uint8_t mctp_ctrl_get_version(struct mctp_bus *bus, uint8_t src_eid,
				     uint8_t msg_tag, const void *data,
				     size_t len)
{
	if (len != sizeof(struct mctp_ctrl_cmd_get_version_req)) {
		return MCTP_CTRL_CC_ERROR_INVALID_LENGTH;
	}
	const struct mctp_ctrl_cmd_get_version_req *req = data;

	switch (req->msg_type) {
	case 0x00:
	case 0xff:
		/* Only have versions for MCTP base or control */
		break;
	default:
		return MCTP_CTRL_VERSIONS_NOT_SUPPORTED;
	}

	/* Return only the versions for MCTP */
	size_t total_sz = sizeof(struct mctp_ctrl_cmd_get_version_resp) +
			  sizeof(MCTP_PROTOCOL_VERSIONS);

	struct mctp_ctrl_cmd_get_version_resp *resp =
		__mctp_msg_alloc(total_sz, bus->mctp);
	if (!resp) {
		mctp_prdebug("no response buffer");
		return MCTP_CTRL_CC_ERROR;
	}
	memset(resp, 0x00, total_sz);
	fill_resp(data, &resp->hdr);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->version_count = MCTP_PROTOCOL_COUNT;
	memcpy(resp->versions, MCTP_PROTOCOL_VERSIONS,
	       sizeof(MCTP_PROTOCOL_VERSIONS));

	int rc = mctp_message_tx_alloced(bus->mctp, src_eid, false, msg_tag,
					 resp, total_sz);
	if (!rc) {
		mctp_prdebug("mctp get_version response send failed: %d", rc);
	}
	return MCTP_CTRL_CC_SUCCESS;
}

static uint8_t mctp_ctrl_get_types(struct mctp_bus *bus, uint8_t src_eid,
				   uint8_t msg_tag, const void *data,
				   size_t len)
{
	if (len != sizeof(struct mctp_ctrl_msg_hdr)) {
		return MCTP_CTRL_CC_ERROR_INVALID_LENGTH;
	}
	(void)data;

	size_t total_sz = sizeof(struct mctp_ctrl_cmd_get_types_resp) +
			  bus->mctp->control.num_msg_types;

	struct mctp_ctrl_cmd_get_types_resp *resp =
		__mctp_msg_alloc(total_sz, bus->mctp);
	if (!resp) {
		mctp_prdebug("no response buffer");
		return MCTP_CTRL_CC_ERROR;
	}
	memset(resp, 0x00, total_sz);
	fill_resp(data, &resp->hdr);
	resp->completion_code = MCTP_CTRL_CC_SUCCESS;
	resp->type_count = bus->mctp->control.num_msg_types;
	memcpy(resp->types, bus->mctp->control.msg_types,
	       bus->mctp->control.num_msg_types);

	int rc = mctp_message_tx_alloced(bus->mctp, src_eid, false, msg_tag,
					 resp, total_sz);
	if (!rc) {
		mctp_prdebug("mctp get_types response send failed: %d", rc);
	}
	return MCTP_CTRL_CC_SUCCESS;
}

static void reply_error(struct mctp *mctp, uint8_t src_eid, uint8_t msg_tag,
			const struct mctp_ctrl_msg_hdr *ctrl_hdr, uint8_t ccode)
{
	struct mctp_ctrl_cmd_empty_resp *resp =
		__mctp_msg_alloc(sizeof(*resp), mctp);
	if (!resp) {
		mctp_prdebug("no response buffer");
		return;
	}
	memset(resp, 0x00, sizeof(*resp));
	fill_resp(ctrl_hdr, &resp->hdr);
	resp->completion_code = ccode;

	int rc = mctp_message_tx_alloced(mctp, src_eid, false, msg_tag, resp,
					 sizeof(*resp));
	if (!rc) {
		mctp_prdebug("error response send failed: %d", rc);
	}
}

/* Control message request handler. This will respond to the mandatory MCTP control
 * commands */
bool mctp_control_handler(struct mctp_bus *bus, mctp_eid_t src_eid,
			  bool tag_owner, uint8_t msg_tag, const void *data,
			  size_t len)
{
	if (!tag_owner) {
		// Not a request
		return false;
	}

	if (len < 1) {
		// No type byte
		return false;
	}

	const struct mctp_ctrl_msg_hdr *ctrl_hdr = data;
	if (ctrl_hdr->ic_msg_type != MCTP_CTRL_HDR_MSG_TYPE) {
		// Not Control type
		return false;
	}

	if (len < sizeof(struct mctp_ctrl_msg_hdr)) {
		// Drop short messages, but treat as handled
		return true;
	}

	if ((ctrl_hdr->rq_dgram_inst &
	     (MCTP_CTRL_HDR_FLAG_REQUEST | MCTP_CTRL_HDR_FLAG_DGRAM)) !=
	    MCTP_CTRL_HDR_FLAG_REQUEST) {
		// Drop message, isn't a request.
		// Treat as handled since TO bit was set.
		return true;
	}

	// A valid MCTP Control request has been received, process it

	uint8_t cc = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
	switch (ctrl_hdr->command_code) {
	case MCTP_CTRL_CMD_SET_ENDPOINT_ID:
		cc = mctp_ctrl_set_endpoint_id(bus, src_eid, msg_tag, data,
					       len);
		break;
	case MCTP_CTRL_CMD_GET_ENDPOINT_ID:
		cc = mctp_ctrl_get_endpoint_id(bus, src_eid, msg_tag, data,
					       len);
		break;
	case MCTP_CTRL_CMD_GET_VERSION_SUPPORT:
		cc = mctp_ctrl_get_version(bus, src_eid, msg_tag, data, len);
		break;
	case MCTP_CTRL_CMD_GET_MESSAGE_TYPE_SUPPORT:
		cc = mctp_ctrl_get_types(bus, src_eid, msg_tag, data, len);
		break;
	default:
		cc = MCTP_CTRL_CC_ERROR_UNSUPPORTED_CMD;
		break;
	}

	if (cc) {
		reply_error(bus->mctp, src_eid, msg_tag, ctrl_hdr, cc);
	}

	// No further handling required.
	return true;
}

int mctp_control_add_type(struct mctp *mctp, uint8_t msg_type)
{
	/* Check for existing */
	for (size_t i = 0; i < mctp->control.num_msg_types; i++) {
		if (mctp->control.msg_types[i] == msg_type) {
			return 0;
		}
	}

	if (mctp->control.num_msg_types == MCTP_CONTROL_MAX_TYPES) {
		return -ENOSPC;
	}

	mctp->control.msg_types[mctp->control.num_msg_types] = msg_type;
	mctp->control.num_msg_types++;
	return 0;
}

void mctp_control_remove_type(struct mctp *mctp, uint8_t msg_type)
{
	for (size_t i = 0; i < mctp->control.num_msg_types; i++) {
		if (mctp->control.msg_types[i] == msg_type) {
			memmove(&mctp->control.msg_types[i],
				&mctp->control.msg_types[i + 1],
				mctp->control.num_msg_types - (i + 1));
			mctp->control.num_msg_types--;
		}
	}
}
