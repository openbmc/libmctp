/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_ENDIAN_H
#include <endian.h>
#endif

#include <assert.h>
#include <err.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define pr_fmt(x) "astlpc: " x

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-astlpc.h"
#include "container_of.h"

#ifdef MCTP_HAVE_FILEIO

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/aspeed-lpc-ctrl.h>

/* kernel interface */
static const char *kcs_path = "/dev/mctp0";
static const char *lpc_path = "/dev/aspeed-lpc-ctrl";

#endif

struct mctp_binding_astlpc {
	struct mctp_binding binding;

	uint32_t rx_offset;
	uint32_t rx_size;
	uint32_t tx_offset;
	uint32_t tx_size;

	union {
		void *lpc_map;
		struct mctp_lpcmap_hdr *lpc_hdr;
	};

	enum mctp_binding_astlpc_mode mode;

	/* direct ops data */
	struct mctp_binding_astlpc_ops ops;
	void *ops_data;

	/* fileio ops data */
	void *lpc_map_base;
	int kcs_fd;
	uint8_t kcs_status;

	bool running;

	/* temporary transmit buffer */
	uint8_t txbuf[256];
};

#define binding_to_astlpc(b)                                                   \
	container_of(b, struct mctp_binding_astlpc, binding)

#define astlpc_prlog(ctx, lvl, fmt, ...)                                       \
	do {                                                                   \
		bool __owner = ((ctx)->mode == astlpc_mode_bus_owner);         \
		mctp_prlog(lvl, pr_fmt("%s: " fmt),                            \
			   __owner ? "owner" : "device", ##__VA_ARGS__);       \
	} while (0)

#define astlpc_prerr(ctx, fmt, ...)                                            \
	astlpc_prlog(ctx, MCTP_LOG_ERR, fmt, ##__VA_ARGS__)
#define astlpc_prwarn(ctx, fmt, ...)                                           \
	astlpc_prlog(ctx, MCTP_LOG_WARNING, fmt, ##__VA_ARGS__)
#define astlpc_prinfo(ctx, fmt, ...)                                           \
	astlpc_prlog(ctx, MCTP_LOG_INFO, fmt, ##__VA_ARGS__)
#define astlpc_prdebug(ctx, fmt, ...)                                          \
	astlpc_prlog(ctx, MCTP_LOG_DEBUG, fmt, ##__VA_ARGS__)

/* clang-format off */
#define ASTLPC_MCTP_MAGIC	0x4d435450
#define ASTLPC_VER_MIN	1
#define ASTLPC_VER_CUR	1
/* clang-format on */

struct mctp_lpcmap_hdr {
	uint32_t	magic;

	uint16_t	bmc_ver_min;
	uint16_t	bmc_ver_cur;
	uint16_t	host_ver_min;
	uint16_t	host_ver_cur;
	uint16_t	negotiated_ver;
	uint16_t	pad0;

	uint32_t	rx_offset;
	uint32_t	rx_size;
	uint32_t	tx_offset;
	uint32_t	tx_size;
} __attribute__((packed));

/* layout of TX/RX areas */
static const uint32_t	rx_offset = 0x100;
static const uint32_t	rx_size   = 0x100;
static const uint32_t	tx_offset = 0x200;
static const uint32_t	tx_size   = 0x100;

#define LPC_WIN_SIZE                (1 * 1024 * 1024)

enum {
	KCS_REG_DATA = 0,
	KCS_REG_STATUS = 1,
};

#define KCS_STATUS_BMC_READY		0x80
#define KCS_STATUS_CHANNEL_ACTIVE	0x40
#define KCS_STATUS_IBF			0x02
#define KCS_STATUS_OBF			0x01

static inline int mctp_astlpc_lpc_write(struct mctp_binding_astlpc *astlpc,
					const void *buf, long offset,
					size_t len)
{
	astlpc_prdebug(astlpc, "%s: %zu bytes to 0x%lx", __func__, len, offset);

	assert(offset >= 0);

	/* Indirect access */
	if (astlpc->ops.lpc_write) {
		void *data = astlpc->ops_data;

		return astlpc->ops.lpc_write(data, buf, offset, len);
	}

	/* Direct mapping */
	assert(astlpc->lpc_map);
	memcpy(&((char *)astlpc->lpc_map)[offset], buf, len);

	return 0;
}

static inline int mctp_astlpc_lpc_read(struct mctp_binding_astlpc *astlpc,
				       void *buf, long offset, size_t len)
{
	astlpc_prdebug(astlpc, "%s: %zu bytes from 0x%lx", __func__, len,
		       offset);

	assert(offset >= 0);

	/* Indirect access */
	if (astlpc->ops.lpc_read) {
		void *data = astlpc->ops_data;

		return astlpc->ops.lpc_read(data, buf, offset, len);
	}

	/* Direct mapping */
	assert(astlpc->lpc_map);
	memcpy(buf, &((char *)astlpc->lpc_map)[offset], len);

	return 0;
}

static int mctp_astlpc_init_bus_owner(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_lpcmap_hdr hdr = { 0 };
	uint8_t status;
	int rc;

	/* Flip the buffers as the names are defined in terms of the host */
	astlpc->rx_offset = tx_offset;
	astlpc->rx_size = tx_size;
	astlpc->tx_offset = rx_offset;
	astlpc->tx_size = rx_size;

	hdr = (struct mctp_lpcmap_hdr){
		.magic = htobe32(ASTLPC_MCTP_MAGIC),
		.bmc_ver_min = htobe16(ASTLPC_VER_MIN),
		.bmc_ver_cur = htobe16(ASTLPC_VER_CUR),

		/* Flip the buffers back as we're now describing the host's
		 * configuration to the host */
		.rx_offset = htobe32(astlpc->tx_offset),
		.rx_size = htobe32(astlpc->tx_size),
		.tx_offset = htobe32(astlpc->rx_offset),
		.tx_size = htobe32(astlpc->rx_size),
	};

	mctp_astlpc_lpc_write(astlpc, &hdr, 0, sizeof(hdr));

	/* set status indicating that the BMC is now active */
	status = KCS_STATUS_BMC_READY | KCS_STATUS_OBF;
	/* XXX: Should we be calling mctp_astlpc_kcs_set_status() instead? */
	rc = astlpc->ops.kcs_write(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_STATUS,
				   status);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS write failed");
	}

	return rc;
}

static int mctp_binding_astlpc_start_bus_owner(struct mctp_binding *b)
{
	struct mctp_binding_astlpc *astlpc =
		container_of(b, struct mctp_binding_astlpc, binding);

	return mctp_astlpc_init_bus_owner(astlpc);
}

static int mctp_astlpc_init_device(struct mctp_binding_astlpc *astlpc)
{
	const uint16_t ver_min_be = htobe16(ASTLPC_VER_MIN);
	const uint16_t ver_cur_be = htobe16(ASTLPC_VER_CUR);
	struct mctp_lpcmap_hdr hdr;
	int rc;

	mctp_astlpc_lpc_read(astlpc, &hdr, 0, sizeof(hdr));

	astlpc->rx_offset = be32toh(hdr.rx_offset);
	astlpc->rx_size = be32toh(hdr.rx_size);
	astlpc->tx_offset = be32toh(hdr.tx_offset);
	astlpc->tx_size = be32toh(hdr.tx_size);

	mctp_astlpc_lpc_write(astlpc, &ver_min_be,
			      offsetof(struct mctp_lpcmap_hdr, host_ver_min),
			      sizeof(ver_min_be));

	mctp_astlpc_lpc_write(astlpc, &ver_cur_be,
			      offsetof(struct mctp_lpcmap_hdr, host_ver_cur),
			      sizeof(ver_cur_be));

	/* Send channel init command */
	rc = astlpc->ops.kcs_write(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_DATA,
				   0x0);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS write failed");
	}

	return rc;
}

static int mctp_binding_astlpc_start_device(struct mctp_binding *b)
{
	struct mctp_binding_astlpc *astlpc =
		container_of(b, struct mctp_binding_astlpc, binding);

	return mctp_astlpc_init_device(astlpc);
}

static bool __mctp_astlpc_kcs_ready(struct mctp_binding_astlpc *astlpc,
				    uint8_t status, bool is_write)
{
	bool is_bus_owner;
	bool ready_state;
	uint8_t flag;

	is_bus_owner = (astlpc->mode == astlpc_mode_bus_owner);

	/* XXX: Conflate bus owner with the BMC for the moment */
	flag = (is_bus_owner ^ is_write) ? KCS_STATUS_IBF : KCS_STATUS_OBF;
	ready_state = is_write ? 0 : 1;

	return !!(status & flag) == ready_state;
}

static inline bool
mctp_astlpc_kcs_read_ready(struct mctp_binding_astlpc *astlpc, uint8_t status)
{
	return __mctp_astlpc_kcs_ready(astlpc, status, false);
}

static inline bool
mctp_astlpc_kcs_write_ready(struct mctp_binding_astlpc *astlpc, uint8_t status)
{
	return __mctp_astlpc_kcs_ready(astlpc, status, true);
}

static int mctp_astlpc_kcs_set_status(struct mctp_binding_astlpc *astlpc,
		uint8_t status)
{
	uint8_t data;
	int rc;

	/* Since we're setting the status register, we want the other endpoint
	 * to be interrupted. However, some hardware may only raise a host-side
	 * interrupt on an ODR event.
	 * So, write a dummy value of 0xff to ODR, which will ensure that an
	 * interrupt is triggered, and can be ignored by the host.
	 */
	data = 0xff;
	status |= KCS_STATUS_OBF;

	rc = astlpc->ops.kcs_write(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_STATUS,
			status);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS status write failed");
		return -1;
	}

	rc = astlpc->ops.kcs_write(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_DATA,
			data);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS dummy data write failed");
		return -1;
	}

	return 0;
}

static int mctp_astlpc_kcs_send(struct mctp_binding_astlpc *astlpc,
		uint8_t data)
{
	uint8_t status;
	int rc;

	for (;;) {
		rc = astlpc->ops.kcs_read(astlpc->ops_data,
				MCTP_ASTLPC_KCS_REG_STATUS, &status);
		if (rc) {
			astlpc_prwarn(astlpc, "KCS status read failed");
			return -1;
		}
		if (mctp_astlpc_kcs_write_ready(astlpc, status))
			break;
		/* todo: timeout */
	}

	rc = astlpc->ops.kcs_write(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_DATA,
			data);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS data write failed");
		return -1;
	}

	return 0;
}

static int mctp_binding_astlpc_tx(struct mctp_binding *b,
		struct mctp_pktbuf *pkt)
{
	struct mctp_binding_astlpc *astlpc = binding_to_astlpc(b);
	uint32_t len, len_be;
	struct mctp_hdr *hdr;

	hdr = mctp_pktbuf_hdr(pkt);
	len = mctp_pktbuf_size(pkt);

	astlpc_prdebug(astlpc,
		       "%s: Transmitting %" PRIu32
		       "-byte packet (%hhu, %hhu, 0x%hhx)",
		       __func__, len, hdr->src, hdr->dest, hdr->flags_seq_tag);

	if (len > rx_size - 4) {
		astlpc_prwarn(astlpc, "invalid TX len 0x%x", len);
		return -1;
	}

	len_be = htobe32(len);
	mctp_astlpc_lpc_write(astlpc, &len_be, astlpc->tx_offset,
			      sizeof(len_be));
	mctp_astlpc_lpc_write(astlpc, hdr, astlpc->tx_offset + 4, len);

	mctp_binding_set_tx_enabled(b, false);

	mctp_astlpc_kcs_send(astlpc, 0x1);
	return 0;
}

static void mctp_astlpc_init_channel(struct mctp_binding_astlpc *astlpc)
{
	/* todo: actual version negotiation */
	uint16_t negotiated = htobe16(1);
	mctp_astlpc_lpc_write(astlpc, &negotiated,
			      offsetof(struct mctp_lpcmap_hdr, negotiated_ver),
			      sizeof(negotiated));

	mctp_astlpc_kcs_set_status(astlpc, KCS_STATUS_BMC_READY |
						   KCS_STATUS_CHANNEL_ACTIVE |
						   KCS_STATUS_OBF);

	mctp_binding_set_tx_enabled(&astlpc->binding, true);
}

static void mctp_astlpc_rx_start(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_pktbuf *pkt;
	uint32_t len;

	mctp_astlpc_lpc_read(astlpc, &len, astlpc->rx_offset, sizeof(len));
	len = be32toh(len);

	if (len > tx_size - 4) {
		astlpc_prwarn(astlpc, "invalid RX len 0x%x", len);
		return;
	}

	if (len > astlpc->binding.pkt_size) {
		astlpc_prwarn(astlpc, "invalid RX len 0x%x", len);
		return;
	}

	pkt = mctp_pktbuf_alloc(&astlpc->binding, len);
	if (!pkt)
		goto out_complete;

	mctp_astlpc_lpc_read(astlpc, mctp_pktbuf_hdr(pkt),
			     astlpc->rx_offset + 4, len);

	mctp_bus_rx(&astlpc->binding, pkt);

out_complete:
	mctp_astlpc_kcs_send(astlpc, 0x2);
}

static void mctp_astlpc_tx_complete(struct mctp_binding_astlpc *astlpc)
{
	mctp_binding_set_tx_enabled(&astlpc->binding, true);
}

int mctp_astlpc_poll(struct mctp_binding_astlpc *astlpc)
{
	uint8_t status, data;
	int rc;

	rc = astlpc->ops.kcs_read(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_STATUS,
			&status);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS read error");
		return -1;
	}

	astlpc_prdebug(astlpc, "%s: status: 0x%hhx", __func__, status);

	if (!mctp_astlpc_kcs_read_ready(astlpc, status))
		return 0;

	rc = astlpc->ops.kcs_read(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_DATA,
			&data);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS data read error");
		return -1;
	}

	astlpc_prdebug(astlpc, "%s: data: 0x%hhx", __func__, data);

	switch (data) {
	case 0x0:
		mctp_astlpc_init_channel(astlpc);
		break;
	case 0x1:
		mctp_astlpc_rx_start(astlpc);
		break;
	case 0x2:
		mctp_astlpc_tx_complete(astlpc);
		break;
	case 0xff:
		/* reserved value for dummy data writes; do nothing */
		break;
	default:
		astlpc_prwarn(astlpc, "unknown message 0x%x", data);
	}
	return 0;
}

/* allocate and basic initialisation */
static struct mctp_binding_astlpc *
__mctp_astlpc_init(enum mctp_binding_astlpc_mode mode)
{
	struct mctp_binding_astlpc *astlpc;

	assert((mode == astlpc_mode_bus_owner) || (mode == astlpc_mode_device));

	astlpc = __mctp_alloc(sizeof(*astlpc));
	if (!astlpc)
		return NULL;

	memset(astlpc, 0, sizeof(*astlpc));
	astlpc->mode = mode;
	astlpc->lpc_map = NULL;
	astlpc->binding.name = "astlpc";
	astlpc->binding.version = 1;
	astlpc->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	astlpc->binding.pkt_pad = 0;
	astlpc->binding.tx = mctp_binding_astlpc_tx;
	if (mode == astlpc_mode_bus_owner)
		astlpc->binding.start = mctp_binding_astlpc_start_bus_owner;
	else if (mode == astlpc_mode_device)
		astlpc->binding.start = mctp_binding_astlpc_start_device;
	else {
		astlpc_prerr(astlpc, "%s: Invalid mode: %d\n", __func__, mode);
		__mctp_free(astlpc);
		return NULL;
	}

	return astlpc;
}

struct mctp_binding *mctp_binding_astlpc_core(struct mctp_binding_astlpc *b)
{
	return &b->binding;
}

struct mctp_binding_astlpc *
mctp_astlpc_init_ops(enum mctp_binding_astlpc_mode mode,
		     const struct mctp_binding_astlpc_ops *ops, void *ops_data,
		     void *lpc_map)
{
	struct mctp_binding_astlpc *astlpc;

	astlpc = __mctp_astlpc_init(mode);
	if (!astlpc)
		return NULL;

	memcpy(&astlpc->ops, ops, sizeof(astlpc->ops));
	astlpc->ops_data = ops_data;
	astlpc->lpc_map = lpc_map;

	return astlpc;
}

void mctp_astlpc_destroy(struct mctp_binding_astlpc *astlpc)
{
	__mctp_free(astlpc);
}

#ifdef MCTP_HAVE_FILEIO

static int mctp_astlpc_init_fileio_lpc(struct mctp_binding_astlpc *astlpc)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY,
		.window_id = 0, /* There's only one */
		.flags = 0,
		.addr = 0,
		.offset = 0,
		.size = 0
	};
	int fd, rc;

	fd = open(lpc_path, O_RDWR | O_SYNC);
	if (fd < 0) {
		astlpc_prwarn(astlpc, "LPC open (%s) failed", lpc_path);
		return -1;
	}

	rc = ioctl(fd, ASPEED_LPC_CTRL_IOCTL_GET_SIZE, &map);
	if (rc) {
		astlpc_prwarn(astlpc, "LPC GET_SIZE failed");
		close(fd);
		return -1;
	}

	astlpc->lpc_map_base = mmap(NULL, map.size, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (astlpc->lpc_map_base == MAP_FAILED) {
		astlpc_prwarn(astlpc, "LPC mmap failed");
		rc = -1;
	} else {
		astlpc->lpc_map = astlpc->lpc_map_base +
			map.size - LPC_WIN_SIZE;
	}

	close(fd);

	return rc;
}

static int mctp_astlpc_init_fileio_kcs(struct mctp_binding_astlpc *astlpc)
{
	astlpc->kcs_fd = open(kcs_path, O_RDWR);
	if (astlpc->kcs_fd < 0)
		return -1;

	return 0;
}

static int __mctp_astlpc_fileio_kcs_read(void *arg,
		enum mctp_binding_astlpc_kcs_reg reg, uint8_t *val)
{
	struct mctp_binding_astlpc *astlpc = arg;
	off_t offset = reg;
	int rc;

	rc = pread(astlpc->kcs_fd, val, 1, offset);

	return rc == 1 ? 0 : -1;
}

static int __mctp_astlpc_fileio_kcs_write(void *arg,
		enum mctp_binding_astlpc_kcs_reg reg, uint8_t val)
{
	struct mctp_binding_astlpc *astlpc = arg;
	off_t offset = reg;
	int rc;

	rc = pwrite(astlpc->kcs_fd, &val, 1, offset);

	return rc == 1 ? 0 : -1;
}

int mctp_astlpc_get_fd(struct mctp_binding_astlpc *astlpc)
{
	return astlpc->kcs_fd;
}

struct mctp_binding_astlpc *mctp_astlpc_init_fileio(void)
{
	struct mctp_binding_astlpc *astlpc;
	int rc;

	/*
	 * If we're doing file IO then we're very likely not running
	 * freestanding, so lets assume that we're on the BMC (bus-owner) side
	 */
	astlpc = __mctp_astlpc_init(astlpc_mode_bus_owner);
	if (!astlpc)
		return NULL;

	/* Set internal operations for kcs. We use direct accesses to the lpc
	 * map area */
	astlpc->ops.kcs_read = __mctp_astlpc_fileio_kcs_read;
	astlpc->ops.kcs_write = __mctp_astlpc_fileio_kcs_write;
	astlpc->ops_data = astlpc;

	rc = mctp_astlpc_init_fileio_lpc(astlpc);
	if (rc) {
		free(astlpc);
		return NULL;
	}

	rc = mctp_astlpc_init_fileio_kcs(astlpc);
	if (rc) {
		free(astlpc);
		return NULL;
	}

	return astlpc;
}
#else
struct mctp_binding_astlpc * __attribute__((const))
	mctp_astlpc_init_fileio(void)
{
	astlpc_prerr(astlpc, "Missing support for file IO");
	return NULL;
}

int __attribute__((const)) mctp_astlpc_get_fd(
		struct mctp_binding_astlpc *astlpc __attribute__((unused)))
{
	astlpc_prerr(astlpc, "Missing support for file IO");
	return -1;
}
#endif
