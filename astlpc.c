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

struct mctp_astlpc_buffer {
	uint32_t offset;
	uint32_t size;
};

struct mctp_astlpc_layout {
	struct mctp_astlpc_buffer rx;
	struct mctp_astlpc_buffer tx;
};

struct mctp_binding_astlpc {
	struct mctp_binding	binding;

	void *lpc_map;
	struct mctp_astlpc_layout layout;

	uint8_t mode;

	/* direct ops data */
	struct mctp_binding_astlpc_ops ops;
	void *ops_data;

	/* fileio ops data */
	int kcs_fd;
	uint8_t kcs_status;

	bool			running;
};

#define binding_to_astlpc(b) \
	container_of(b, struct mctp_binding_astlpc, binding)

#define astlpc_prlog(ctx, lvl, fmt, ...)                                       \
	do {                                                                   \
		bool __bmc = ((ctx)->mode == MCTP_BINDING_ASTLPC_MODE_BMC);    \
		mctp_prlog(lvl, pr_fmt("%s: " fmt), __bmc ? "bmc" : "host",    \
			   ##__VA_ARGS__);                                     \
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

#define ASTLPC_BODY_SIZE(sz)	((sz) - 4)
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

#define KCS_STATUS_BMC_READY		0x80
#define KCS_STATUS_CHANNEL_ACTIVE	0x40
#define KCS_STATUS_IBF			0x02
#define KCS_STATUS_OBF			0x01

static inline int mctp_astlpc_kcs_write(struct mctp_binding_astlpc *astlpc,
					enum mctp_binding_astlpc_kcs_reg reg,
					uint8_t val)
{
	return astlpc->ops.kcs_write(astlpc->ops_data, reg, val);
}

static inline int mctp_astlpc_kcs_read(struct mctp_binding_astlpc *astlpc,
				       enum mctp_binding_astlpc_kcs_reg reg,
				       uint8_t *val)
{
	return astlpc->ops.kcs_read(astlpc->ops_data, reg, val);
}

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

	rc = mctp_astlpc_kcs_write(astlpc, MCTP_ASTLPC_KCS_REG_STATUS, status);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS status write failed");
		return -1;
	}

	rc = mctp_astlpc_kcs_write(astlpc, MCTP_ASTLPC_KCS_REG_DATA, data);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS dummy data write failed");
		return -1;
	}

	return 0;
}

static int mctp_astlpc_init_bmc(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_lpcmap_hdr hdr = { 0 };
	uint8_t status;

	/* Flip the buffers as the names are defined in terms of the host */
	astlpc->layout.rx.offset = tx_offset;
	astlpc->layout.rx.size = tx_size;
	astlpc->layout.tx.offset = rx_offset;
	astlpc->layout.tx.size = rx_size;

	hdr = (struct mctp_lpcmap_hdr){
		.magic = htobe32(ASTLPC_MCTP_MAGIC),
		.bmc_ver_min = htobe16(ASTLPC_VER_MIN),
		.bmc_ver_cur = htobe16(ASTLPC_VER_CUR),

		/* Flip the buffers back as we're now describing the host's
		 * configuration to the host */
		.rx_offset = htobe32(astlpc->layout.tx.offset),
		.rx_size = htobe32(astlpc->layout.tx.size),
		.tx_offset = htobe32(astlpc->layout.rx.offset),
		.tx_size = htobe32(astlpc->layout.rx.size),
	};

	mctp_astlpc_lpc_write(astlpc, &hdr, 0, sizeof(hdr));

	/* set status indicating that the BMC is now active */
	status = KCS_STATUS_BMC_READY | KCS_STATUS_OBF;
	return mctp_astlpc_kcs_set_status(astlpc, status);
}

static int mctp_binding_astlpc_start_bmc(struct mctp_binding *b)
{
	struct mctp_binding_astlpc *astlpc =
		container_of(b, struct mctp_binding_astlpc, binding);

	return mctp_astlpc_init_bmc(astlpc);
}

static int mctp_astlpc_init_host(struct mctp_binding_astlpc *astlpc)
{
	const uint16_t ver_min_be = htobe16(ASTLPC_VER_MIN);
	const uint16_t ver_cur_be = htobe16(ASTLPC_VER_CUR);
	struct mctp_lpcmap_hdr hdr;
	uint8_t status;
	int rc;

	rc = mctp_astlpc_kcs_read(astlpc, MCTP_ASTLPC_KCS_REG_STATUS, &status);
	if (rc) {
		mctp_prwarn("KCS status read failed");
		return rc;
	}

	astlpc->kcs_status = status;

	if (!(status & KCS_STATUS_BMC_READY))
		return -EHOSTDOWN;

	mctp_astlpc_lpc_read(astlpc, &hdr, 0, sizeof(hdr));

	astlpc->layout.rx.offset = be32toh(hdr.rx_offset);
	astlpc->layout.rx.size = be32toh(hdr.rx_size);
	astlpc->layout.tx.offset = be32toh(hdr.tx_offset);
	astlpc->layout.tx.size = be32toh(hdr.tx_size);

	mctp_astlpc_lpc_write(astlpc, &ver_min_be,
			      offsetof(struct mctp_lpcmap_hdr, host_ver_min),
			      sizeof(ver_min_be));

	mctp_astlpc_lpc_write(astlpc, &ver_cur_be,
			      offsetof(struct mctp_lpcmap_hdr, host_ver_cur),
			      sizeof(ver_cur_be));

	/* Send channel init command */
	rc = mctp_astlpc_kcs_write(astlpc, MCTP_ASTLPC_KCS_REG_DATA, 0x0);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS write failed");
	}

	return rc;
}

static int mctp_binding_astlpc_start_host(struct mctp_binding *b)
{
	struct mctp_binding_astlpc *astlpc =
		container_of(b, struct mctp_binding_astlpc, binding);

	return mctp_astlpc_init_host(astlpc);
}

static bool __mctp_astlpc_kcs_ready(struct mctp_binding_astlpc *astlpc,
				    uint8_t status, bool is_write)
{
	bool is_bmc;
	bool ready_state;
	uint8_t flag;

	is_bmc = (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_BMC);
	flag = (is_bmc ^ is_write) ? KCS_STATUS_IBF : KCS_STATUS_OBF;
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

static int mctp_astlpc_kcs_send(struct mctp_binding_astlpc *astlpc,
		uint8_t data)
{
	uint8_t status;
	int rc;

	for (;;) {
		rc = mctp_astlpc_kcs_read(astlpc, MCTP_ASTLPC_KCS_REG_STATUS,
					  &status);
		if (rc) {
			astlpc_prwarn(astlpc, "KCS status read failed");
			return -1;
		}
		if (mctp_astlpc_kcs_write_ready(astlpc, status))
			break;
		/* todo: timeout */
	}

	rc = mctp_astlpc_kcs_write(astlpc, MCTP_ASTLPC_KCS_REG_DATA, data);
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

	if (len > ASTLPC_BODY_SIZE(astlpc->layout.tx.size)) {
		astlpc_prwarn(astlpc, "invalid TX len 0x%x", len);
		return -1;
	}

	len_be = htobe32(len);
	mctp_astlpc_lpc_write(astlpc, &len_be, astlpc->layout.tx.offset,
			      sizeof(len_be));
	mctp_astlpc_lpc_write(astlpc, hdr, astlpc->layout.tx.offset + 4, len);

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

	mctp_astlpc_lpc_read(astlpc, &len, astlpc->layout.rx.offset,
			     sizeof(len));
	len = be32toh(len);

	if (len > ASTLPC_BODY_SIZE(astlpc->layout.rx.size)) {
		astlpc_prwarn(astlpc, "invalid RX len 0x%x", len);
		return;
	}

	assert(astlpc->binding.pkt_size >= 0);
	if (len > (uint32_t)astlpc->binding.pkt_size) {
		mctp_prwarn("invalid RX len 0x%x", len);
		astlpc_prwarn(astlpc, "invalid RX len 0x%x", len);
		return;
	}

	pkt = mctp_pktbuf_alloc(&astlpc->binding, len);
	if (!pkt)
		goto out_complete;

	mctp_astlpc_lpc_read(astlpc, mctp_pktbuf_hdr(pkt),
			     astlpc->layout.rx.offset + 4, len);

	mctp_bus_rx(&astlpc->binding, pkt);

out_complete:
	mctp_astlpc_kcs_send(astlpc, 0x2);
}

static void mctp_astlpc_tx_complete(struct mctp_binding_astlpc *astlpc)
{
	mctp_binding_set_tx_enabled(&astlpc->binding, true);
}

static int mctp_astlpc_update_channel(struct mctp_binding_astlpc *astlpc,
				      uint8_t status)
{
	uint8_t updated;
	int rc = 0;

	assert(astlpc->mode == MCTP_BINDING_ASTLPC_MODE_HOST);

	updated = astlpc->kcs_status ^ status;

	astlpc_prdebug(astlpc, "%s: status: 0x%x, update: 0x%x", __func__,
		       status, updated);

	if (updated & KCS_STATUS_BMC_READY) {
		if (status & KCS_STATUS_BMC_READY) {
			astlpc->kcs_status = status;
			return astlpc->binding.start(&astlpc->binding);
		} else {
			mctp_binding_set_tx_enabled(&astlpc->binding, false);
		}
	}

	if (updated & KCS_STATUS_CHANNEL_ACTIVE)
		mctp_binding_set_tx_enabled(&astlpc->binding,
					    status & KCS_STATUS_CHANNEL_ACTIVE);

	astlpc->kcs_status = status;

	return rc;
}

int mctp_astlpc_poll(struct mctp_binding_astlpc *astlpc)
{
	uint8_t status, data;
	int rc;

	rc = mctp_astlpc_kcs_read(astlpc, MCTP_ASTLPC_KCS_REG_STATUS, &status);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS read error");
		return -1;
	}

	astlpc_prdebug(astlpc, "%s: status: 0x%hhx", __func__, status);

	if (!mctp_astlpc_kcs_read_ready(astlpc, status))
		return 0;

	rc = mctp_astlpc_kcs_read(astlpc, MCTP_ASTLPC_KCS_REG_DATA, &data);
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
		/* No responsibilities for the BMC on 0xff */
		if (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_HOST) {
			rc = mctp_astlpc_update_channel(astlpc, status);
			if (rc < 0)
				return rc;
		}
		break;
	default:
		astlpc_prwarn(astlpc, "unknown message 0x%x", data);
	}

	/* Handle silent loss of bmc-ready */
	if (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_HOST) {
		if (!(status & KCS_STATUS_BMC_READY && data == 0xff))
			return mctp_astlpc_update_channel(astlpc, status);
	}

	return rc;
}

/* allocate and basic initialisation */
static struct mctp_binding_astlpc *__mctp_astlpc_init(uint8_t mode,
						      uint32_t mtu)
{
	struct mctp_binding_astlpc *astlpc;

	assert((mode == MCTP_BINDING_ASTLPC_MODE_BMC) ||
	       (mode == MCTP_BINDING_ASTLPC_MODE_HOST));

	astlpc = __mctp_alloc(sizeof(*astlpc));
	if (!astlpc)
		return NULL;

	memset(astlpc, 0, sizeof(*astlpc));
	astlpc->mode = mode;
	astlpc->lpc_map = NULL;
	astlpc->binding.name = "astlpc";
	astlpc->binding.version = 1;
	astlpc->binding.pkt_size = MCTP_PACKET_SIZE(mtu);
	astlpc->binding.pkt_pad = 0;
	astlpc->binding.tx = mctp_binding_astlpc_tx;
	if (mode == MCTP_BINDING_ASTLPC_MODE_BMC)
		astlpc->binding.start = mctp_binding_astlpc_start_bmc;
	else if (mode == MCTP_BINDING_ASTLPC_MODE_HOST)
		astlpc->binding.start = mctp_binding_astlpc_start_host;
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
mctp_astlpc_init(uint8_t mode, uint32_t mtu, void *lpc_map,
		 const struct mctp_binding_astlpc_ops *ops, void *ops_data)
{
	struct mctp_binding_astlpc *astlpc;

	if (!(mode == MCTP_BINDING_ASTLPC_MODE_BMC ||
	      mode == MCTP_BINDING_ASTLPC_MODE_HOST)) {
		mctp_prerr("Unknown binding mode: %u", mode);
		return NULL;
	}

	if (mtu != MCTP_BTU) {
		mctp_prwarn("Unable to negotiate the MTU, using %u instead",
			    MCTP_BTU);
		mtu = MCTP_BTU;
	}

	astlpc = __mctp_astlpc_init(mode, mtu);
	if (!astlpc)
		return NULL;

	memcpy(&astlpc->ops, ops, sizeof(astlpc->ops));
	astlpc->ops_data = ops_data;
	astlpc->lpc_map = lpc_map;
	astlpc->mode = mode;

	return astlpc;
}

struct mctp_binding_astlpc *
mctp_astlpc_init_ops(const struct mctp_binding_astlpc_ops *ops, void *ops_data,
		     void *lpc_map)
{
	return mctp_astlpc_init(MCTP_BINDING_ASTLPC_MODE_BMC, MCTP_BTU, lpc_map,
				ops, ops_data);
}

void mctp_astlpc_destroy(struct mctp_binding_astlpc *astlpc)
{
	/* Clear channel-active and bmc-ready */
	mctp_astlpc_kcs_set_status(astlpc, KCS_STATUS_OBF);
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
	void *lpc_map_base;
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

	lpc_map_base =
		mmap(NULL, map.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (lpc_map_base == MAP_FAILED) {
		astlpc_prwarn(astlpc, "LPC mmap failed");
		rc = -1;
	} else {
		astlpc->lpc_map = lpc_map_base + map.size - LPC_WIN_SIZE;
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
	 * freestanding, so lets assume that we're on the BMC side
	 */
	astlpc = __mctp_astlpc_init(MCTP_BINDING_ASTLPC_MODE_BMC, MCTP_BTU);
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
