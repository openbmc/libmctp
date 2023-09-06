/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_ENDIAN_H
#include <endian.h>
#endif

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define pr_fmt(x) "kcs: " x

#include "container_of.h"
#include "crc32.h"
#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-kcs.h"
#include "range.h"

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

//
// IPMI KCS Interface Status Bits
//
#define IPMI_KCS_OBF	      (1 << 0)
#define IPMI_KCS_IBF	      (1 << 1)
#define IPMI_KCS_SMS_ATN      (1 << 2)
#define IPMI_KCS_COMMAND_DATA (1 << 3)
#define IPMI_KCS_OEM1	      (1 << 4)
#define IPMI_KCS_OEM2	      (1 << 5)
#define IPMI_KCS_S0	      (1 << 6)
#define IPMI_KCS_S1	      (1 << 7)

//
// IPMI KCS Interface Control Codes
//
#define IPMI_KCS_CONTROL_CODE_GET_STATUS_ABORT 0x60
#define IPMI_KCS_CONTROL_CODE_WRITE_START      0x61
#define IPMI_KCS_CONTROL_CODE_WRITE_END	       0x62
#define IPMI_KCS_CONTROL_CODE_READ	       0x68

//
// Status Codes
//
#define IPMI_KCS_STATUS_NO_ERROR     0x00
#define IPMI_KCS_STATUS_ABORT	     0x01
#define IPMI_KCS_STATUS_ILLEGAL	     0x02
#define IPMI_KCS_STATUS_LENGTH_ERROR 0x06
#define IPMI_KCS_STATUS_UNSPECIFIED  0xFF

//
// KCS Interface State Bit
//
typedef enum {
	IpmiKcsIdleState = 0,
	IpmiKcsReadState,
	IpmiKcsWriteState,
	IpmiKcsErrorState
} IPMI_KCS_STATE;

#define IPMI_KCS_GET_STATE(s) (s >> 6)
#define IPMI_KCS_SET_STATE(s) (s << 6)

// According to SMBUS spec, the polynomial is:
// C(x) = X^8 + X^2 + X^1 + 1, which is 0x107,
// just ignore bit8 in definition.
#define MCTP_KCS_PACKET_ERROR_CODE_POLY 0x07

#define MCTP_KCS_NETFN_LUN			0xb0
#define DEFINING_BODY_DMTF_PRE_OS_WORKING_GROUP 0x01

#define IPMI_KCS_TIMEOUT_US	 1000
#define IPMI_KCS_FULL_TIMEOUT_US 5000000

struct mctp_binding_kcs {
	struct mctp_binding binding;
	int fd;
};

enum mctp_binding_kcs_reg {
	MCTP_KCS_REG_DATA = 0,
	MCTP_KCS_REG_STATUS = 1,
};

struct mctp_kcs_header {
	uint8_t netFnAndLUN;
	uint8_t definingBody;
	uint8_t len;
} __attribute__((packed));

struct mctp_kcs_trailer {
	uint8_t PEC;
} __attribute__((packed));

#define binding_to_kcs(b) container_of(b, struct mctp_binding_kcs, binding)

#define kcs_prlog(ctx, lvl, fmt, ...)                                          \
	do {                                                                   \
		mctp_prlog(lvl, pr_fmt("%s: " fmt), "kcs", ##__VA_ARGS__);     \
	} while (0)

#define kcs_prerr(ctx, fmt, ...)                                               \
	kcs_prlog(ctx, MCTP_LOG_ERR, fmt, ##__VA_ARGS__)
#define kcs_prwarn(ctx, fmt, ...)                                              \
	kcs_prlog(ctx, MCTP_LOG_WARNING, fmt, ##__VA_ARGS__)
#define kcs_prinfo(ctx, fmt, ...)                                              \
	kcs_prlog(ctx, MCTP_LOG_INFO, fmt, ##__VA_ARGS__)
#define kcs_prdebug(ctx, fmt, ...)                                             \
	kcs_prlog(ctx, MCTP_LOG_DEBUG, fmt, ##__VA_ARGS__)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

static int mctp_kcs_read(void *arg, enum mctp_binding_kcs_reg reg, uint8_t *val)
{
	struct mctp_binding_kcs *kcs = arg;
	off_t offset = reg;
	int rc;

	rc = pread(kcs->fd, val, 1, offset);

	kcs_prdebug(kcs, "%s: offset=%d, val=0x%02x, rc=%d", __func__, reg,
		    *val, rc);
	return rc == 1 ? 0 : -1;
}

static int mctp_kcs_write(void *arg, enum mctp_binding_kcs_reg reg, uint8_t val)
{
	struct mctp_binding_kcs *kcs = arg;
	off_t offset = reg;
	int rc;

	rc = pwrite(kcs->fd, &val, 1, offset);
	kcs_prdebug(kcs, "%s: offset=%d, val=0x%02x, rc=%d", __func__, reg, val,
		    rc);
	return rc == 1 ? 0 : -1;
}

static int mctp_kcs_read_status(struct mctp_binding_kcs *kcs, uint8_t *status)
{
	int rc;
	rc = mctp_kcs_read(kcs, MCTP_KCS_REG_STATUS, status);
	if (rc) {
		kcs_prerr(kcs, "KCS status read failed");
		return rc;
	}
	return 0;
}

static int mctp_kcs_write_command(struct mctp_binding_kcs *kcs, uint8_t command)
{
	int rc;
	rc = mctp_kcs_write(kcs, MCTP_KCS_REG_STATUS, command);
	if (rc) {
		kcs_prerr(kcs, "KCS command write failed");
		return rc;
	}
	return 0;
}

static int mctp_kcs_read_data(struct mctp_binding_kcs *kcs, uint8_t *data)
{
	int rc;
	rc = mctp_kcs_read(kcs, MCTP_KCS_REG_DATA, data);
	if (rc) {
		kcs_prerr(kcs, "KCS data read failed");
		return rc;
	}
	return 0;
}

static int mctp_kcs_write_data(struct mctp_binding_kcs *kcs, uint8_t data)
{
	int rc;
	rc = mctp_kcs_write(kcs, MCTP_KCS_REG_DATA, data);
	if (rc) {
		kcs_prerr(kcs, "KCS data write failed");
		return rc;
	}
	return 0;
}

static int wait_status_set(struct mctp_binding_kcs *kcs, uint8_t flag,
			   uint8_t *status)
{
	uint64_t timeout = 0;
	int rc;

	while (true) {
		rc = mctp_kcs_read_status(kcs, status);
		if (rc) {
			return rc;
		}
		if (*status & flag) {
			break;
		}

		usleep(IPMI_KCS_TIMEOUT_US);
		timeout += IPMI_KCS_TIMEOUT_US;
		if (timeout >= IPMI_KCS_FULL_TIMEOUT_US) {
			kcs_prerr(
				kcs,
				"%s: error - timeout; flag = 0x%02x, status = 0x%02x",
				__func__, flag, *status);
			return -1;
		}
	}
	return 0;
}

static int wait_status_clear(struct mctp_binding_kcs *kcs, uint8_t flag,
			     uint8_t *status)
{
	uint64_t timeout = 0;
	int rc;

	while (true) {
		rc = mctp_kcs_read_status(kcs, status);
		if (rc) {
			return rc;
		}
		if (!(*status & flag)) {
			break;
		}

		usleep(IPMI_KCS_TIMEOUT_US);
		timeout += IPMI_KCS_TIMEOUT_US;
		if (timeout >= IPMI_KCS_FULL_TIMEOUT_US) {
			kcs_prerr(
				kcs,
				"%s: error - timeout; flag = 0x%02x, status = 0x%02x",
				__func__, flag, *status);
			return -1;
		}
	}
	return 0;
}

static int clear_ibf(struct mctp_binding_kcs *kcs)
{
	uint8_t val;
	int rc;
	rc = mctp_kcs_read_status(kcs, &val);
	if (rc) {
		return rc;
	}
	if (val & IPMI_KCS_IBF) {
		rc = mctp_kcs_read_data(kcs, &val);
		if (rc) {
			return rc;
		}
		rc = mctp_kcs_read_status(kcs, &val);
		if (rc) {
			return rc;
		}
		if (val & IPMI_KCS_IBF) {
			kcs_prerr(kcs, "%s: error - can't clear ibf", __func__);
			return -1;
		}
	}
	return 0;
}

static uint8_t generateCrc8(uint8_t polynomial, uint8_t crcInitialValue,
			    uint8_t *buffer, uint32_t len)
{
	uint8_t bitIndex;
	uint32_t bufferIndex;
	uint8_t crc = crcInitialValue;

	bufferIndex = 0;
	while (bufferIndex < len) {
		crc = crc ^ *(buffer + bufferIndex);
		bufferIndex++;

		for (bitIndex = 0; bitIndex < 8; bitIndex++) {
			if ((crc & 0x80) != 0) {
				crc = (crc << 1) ^ polynomial;
			} else {
				crc <<= 1;
			}
		}
	}
	return crc;
}

static uint8_t generatePEC(uint8_t *buffer, uint32_t len)
{
	return generateCrc8(MCTP_KCS_PACKET_ERROR_CODE_POLY, 0, buffer, len);
}

static int mctp_binding_kcs_start(struct mctp_binding *b)
{
	kcs_prinfo(kcs, "%s", __func__);
	mctp_binding_set_tx_enabled(b, true);
	return 0;
}

static int mctp_binding_kcs_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_kcs *kcs = binding_to_kcs(b);
	struct mctp_kcs_trailer *tlr;
	struct mctp_hdr *mctp_hdr;
	size_t len;
	int rc;

	struct mctp_kcs_header kcs_hdr;
	kcs_hdr.netFnAndLUN = MCTP_KCS_NETFN_LUN;
	kcs_hdr.definingBody = DEFINING_BODY_DMTF_PRE_OS_WORKING_GROUP;
	kcs_hdr.len = mctp_pktbuf_size(pkt);

	struct mctp_kcs_trailer kcs_tlr;
	mctp_hdr = mctp_pktbuf_hdr(pkt);
	kcs_tlr.PEC = generatePEC((uint8_t *)mctp_hdr, kcs_hdr.len);

	mctp_hdr = mctp_pktbuf_hdr(pkt);

	uint8_t send_buf[256 + sizeof(struct mctp_kcs_header) +
			 sizeof(struct mctp_kcs_trailer)];

	memcpy(send_buf, &kcs_hdr, sizeof(struct mctp_kcs_header));
	memcpy(send_buf + sizeof(struct mctp_kcs_header), mctp_hdr,
	       kcs_hdr.len);
	memcpy(send_buf + sizeof(struct mctp_kcs_header) + kcs_hdr.len,
	       &(kcs_tlr.PEC), sizeof(struct mctp_kcs_trailer));
	int write_len = sizeof(struct mctp_kcs_header) + kcs_hdr.len +
			sizeof(struct mctp_kcs_trailer);

	kcs_prdebug(kcs, "%s: send buffer", __func__);
	for (int i = 0; i < write_len; i++) {
		kcs_prdebug(kcs, "%s: data[%d]=0x%02x", __func__, i,
			    send_buf[i]);
	}

	uint8_t status, data;
	for (int k = 0; k < write_len; k++) {
		rc = wait_status_clear(kcs, IPMI_KCS_OBF, &status);
		if (rc) {
			return rc;
		}

		rc = mctp_kcs_write_data(kcs, send_buf[k]);
		if (rc) {
			return rc;
		}

		rc = wait_status_set(kcs, IPMI_KCS_IBF, &status);
		if (rc) {
			return rc;
		}

		if (k == (write_len - 1)) {
			rc = wait_status_clear(kcs, IPMI_KCS_OBF, &status);
			if (rc) {
				return rc;
			}
			// Write IDLE state
			rc = mctp_kcs_write_command(
				kcs,
				(status & 0x3F) |
					IPMI_KCS_SET_STATE(IpmiKcsIdleState) |
					IPMI_KCS_OBF);
			if (rc) {
				return rc;
			}
		}

		if (status & IPMI_KCS_COMMAND_DATA) {
			kcs_prerr(kcs, "%s: returned data is not DATA",
				  __func__);
			return -1;
		}
		rc = mctp_kcs_read_data(kcs, &data);
		if (rc) {
			return rc;
		}
		if (data != IPMI_KCS_CONTROL_CODE_READ) {
			kcs_prerr(
				kcs,
				"%s: received command is not IPMI_KCS_CONTROL_CODE_READ",
				__func__);
			return -1;
		}
	}

	rc = wait_status_clear(kcs, IPMI_KCS_OBF, &status);
	if (rc) {
		return rc;
	}

	// Write dummy byte
	rc = mctp_kcs_write_data(kcs, 0x55);
	if (rc) {
		return rc;
	}

	rc = wait_status_clear(kcs, IPMI_KCS_OBF, &status);
	if (rc) {
		return rc;
	}

	kcs_prdebug(kcs, "%s: success", __func__);
	return 0;
}

static int mctp_kcs_validate_data(struct mctp_kcs_header *hdr, int len)
{
	if (hdr->netFnAndLUN != MCTP_KCS_NETFN_LUN) {
		kcs_prerr(
			kcs,
			"%s: KCS binding header error! netFnAndLUN = 0x%02x, but should be 0x%02x",
			__func__, hdr->netFnAndLUN, MCTP_KCS_NETFN_LUN);
		return -1;
	}
	if (hdr->definingBody != DEFINING_BODY_DMTF_PRE_OS_WORKING_GROUP) {
		kcs_prerr(
			kcs,
			"%s: KCS binding header error! definingBody = 0x%02x, but should be 0x%02x",
			__func__, hdr->definingBody,
			DEFINING_BODY_DMTF_PRE_OS_WORKING_GROUP);
		return -1;
	}
	if (hdr->len != (len - sizeof(struct mctp_kcs_header) -
			 sizeof(struct mctp_kcs_trailer))) {
		kcs_prerr(
			kcs,
			"%s: KCS binding header error! len = 0x%02x, but should be 0x%02x",
			__func__, hdr->len,
			(len - sizeof(struct mctp_kcs_header) -
			 sizeof(struct mctp_kcs_trailer)));
		return -1;
	}

	uint8_t PEC = generatePEC((uint8_t *)(hdr + 1), hdr->len);
	struct mctp_kcs_trailer *tlr =
		(struct mctp_kcs_trailer *)((uint8_t *)(hdr + 1) + hdr->len);
	if (PEC != tlr->PEC) {
		kcs_prerr(
			kcs,
			"%s: PEC error! Packet value=0x%02x, calculated value=0x%02x",
			__func__, tlr->PEC, PEC);
		return -1;
	}
	return 0;
}

int mctp_kcs_poll(struct mctp_binding_kcs *kcs)
{
	uint8_t status, data;
	int rc;

	kcs_prdebug(kcs, "%s", __func__);

	uint8_t buf[256 + sizeof(struct mctp_kcs_header) +
		    sizeof(struct mctp_kcs_trailer)];
	int read_len = 0;

	rc = wait_status_clear(kcs, IPMI_KCS_OBF, &status);
	if (rc) {
		return rc;
	}
	rc = wait_status_set(kcs, IPMI_KCS_IBF, &status);
	if (rc) {
		return rc;
	}

	if (status & IPMI_KCS_COMMAND_DATA) {
		// According to spec we need to immediately write WRITE_START after receiving any control code in the command register
		// and read incoming data only after that
		rc = mctp_kcs_write_command(
			kcs, (status & 0x3F) |
				     IPMI_KCS_SET_STATE(IpmiKcsWriteState) |
				     IPMI_KCS_OBF);
		if (rc) {
			return rc;
		}
	} else {
		kcs_prerr(kcs, "%s: returned data is not CMD", __func__);
		return -1;
	}

	rc = mctp_kcs_read_data(kcs, &data);
	if (rc) {
		return rc;
	}

	if (data != IPMI_KCS_CONTROL_CODE_WRITE_START) {
		kcs_prerr(
			kcs,
			"%s: received command is not IPMI_KCS_CONTROL_CODE_WRITE_START",
			__func__);
		return -1;
	}

	while (true) {
		bool cmd;
		rc = wait_status_clear(kcs, IPMI_KCS_OBF, &status);
		if (rc) {
			return rc;
		}
		rc = wait_status_set(kcs, IPMI_KCS_IBF, &status);
		if (rc) {
			return rc;
		}
		// According to the spec we need to immediately update status after receiving the data byte
		rc = mctp_kcs_write_command(
			kcs, (status & 0x3F) |
				     IPMI_KCS_SET_STATE(IpmiKcsWriteState) |
				     IPMI_KCS_OBF);
		if (rc) {
			return rc;
		}

		rc = mctp_kcs_read_data(kcs, &data);
		if (rc) {
			return rc;
		}

		if (status & IPMI_KCS_COMMAND_DATA) {
			kcs_prdebug(kcs, "%s: received CMD=0x%02x", __func__,
				    data);
			if (data != IPMI_KCS_CONTROL_CODE_WRITE_END) {
				kcs_prerr(
					kcs,
					"%s: received command is not IPMI_KCS_CONTROL_CODE_WRITE_END",
					__func__);
				return -1;
			}
			break;
		} else {
			kcs_prdebug(kcs, "%s: received DATA; buf[%d]=0x%02x",
				    __func__, read_len, data);
			buf[read_len] = data;
			read_len++;
		}
	}

	rc = wait_status_clear(kcs, IPMI_KCS_OBF, &status);
	if (rc) {
		return rc;
	}

	rc = wait_status_set(kcs, IPMI_KCS_IBF, &status);
	if (rc) {
		return rc;
	}

	if (status & IPMI_KCS_COMMAND_DATA) {
		kcs_prerr(kcs, "%s: returned data is not DATA", __func__);
		return -1;
	}

	rc = mctp_kcs_write_command(
		kcs, (status & 0x3F) | IPMI_KCS_SET_STATE(IpmiKcsReadState) |
			     IPMI_KCS_OBF);
	if (rc) {
		return rc;
	}

	rc = mctp_kcs_read_data(kcs, &data);
	if (rc) {
		return rc;
	}

	kcs_prdebug(kcs, "%s: received DATA; buf[%d]=0x%02x", __func__,
		    read_len, data);
	buf[read_len] = data;
	read_len++;

	struct mctp_kcs_header *kcs_header = (struct mctp_kcs_header *)buf;
	rc = mctp_kcs_validate_data(kcs_header, read_len);
	if (rc) {
		return rc;
	}

	struct mctp_pktbuf *pkt;
	struct mctp_hdr *hdr;
	pkt = mctp_pktbuf_alloc(&kcs->binding, kcs_header->len);
	if (!pkt) {
		kcs_prerr(kcs, "%s: unable to allocate pktbuf len 0x%x",
			  __func__, kcs_header->len);
	}
	memcpy(mctp_pktbuf_hdr(pkt), (uint8_t *)(kcs_header + 1),
	       kcs_header->len);
	mctp_bus_rx(&kcs->binding, pkt);

	return 0;
}

static struct mctp_binding_kcs *__mctp_kcs_init(void)
{
	struct mctp_binding_kcs *kcs;
	kcs = __mctp_alloc(sizeof(*kcs));
	if (!kcs)
		return NULL;

	memset(kcs, 0, sizeof(*kcs));
	kcs->binding.name = "kcs";
	kcs->binding.version = 1;
	kcs->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	kcs->binding.pkt_header = 3;
	kcs->binding.pkt_trailer = 1;
	kcs->binding.tx = mctp_binding_kcs_tx;
	kcs->binding.start = mctp_binding_kcs_start;

	return kcs;
}

struct mctp_binding *mctp_binding_kcs_core(struct mctp_binding_kcs *kcs)
{
	return &kcs->binding;
}

void mctp_kcs_destroy(struct mctp_binding_kcs *kcs)
{
	mctp_kcs_write_command(kcs, 0);
	clear_ibf(kcs);
	__mctp_free(kcs);
}

int mctp_kcs_init_pollfd(struct mctp_binding_kcs *kcs, struct pollfd *pollfd)
{
	pollfd->fd = kcs->fd;
	pollfd->events = POLLIN;

	return 0;
}

struct mctp_binding_kcs *mctp_kcs_init_fileio(const char *path)
{
	struct mctp_binding_kcs *kcs;

	kcs = __mctp_kcs_init();
	if (!kcs)
		return NULL;

	kcs->fd = open(path, O_RDWR);
	if (kcs->fd < 0) {
		free(kcs);
		return NULL;
	}
	mctp_kcs_write_command(kcs, 0);
	clear_ibf(kcs);

	return kcs;
}
