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

	union {
		void *lpc_map;
		struct mctp_lpcmap_hdr *lpc_hdr;
	};

	/* direct ops data */
	struct mctp_binding_astlpc_ops ops;
	void *ops_data;
	struct mctp_lpcmap_hdr *priv_hdr;

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

#define MCTP_MAGIC 0x4d435450
#define BMC_VER_MIN 1
#define BMC_VER_CUR 1

struct mctp_lpcmap_hdr {
	uint32_t magic;

	uint16_t bmc_ver_min;
	uint16_t bmc_ver_cur;
	uint16_t host_ver_min;
	uint16_t host_ver_cur;
	uint16_t negotiated_ver;
	uint16_t pad0;

	uint32_t rx_offset;
	uint32_t rx_size;
	uint32_t tx_offset;
	uint32_t tx_size;
} __attribute__((packed));

/* layout of TX/RX areas */
static const uint32_t rx_offset = 0x100;
static const uint32_t rx_size = 0x100;
static const uint32_t tx_offset = 0x200;
static const uint32_t tx_size = 0x100;

#define LPC_WIN_SIZE (1 * 1024 * 1024)

enum { KCS_REG_DATA = 0,
       KCS_REG_STATUS = 1,
};

#define KCS_STATUS_BMC_READY 0x80
#define KCS_STATUS_CHANNEL_ACTIVE 0x40
#define KCS_STATUS_IBF 0x02
#define KCS_STATUS_OBF 0x01

static bool lpc_direct(struct mctp_binding_astlpc *astlpc)
{
	return astlpc->lpc_map != NULL;
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
		mctp_prwarn("KCS status write failed");
		return -1;
	}

	rc = astlpc->ops.kcs_write(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_DATA,
				   data);
	if (rc) {
		mctp_prwarn("KCS dummy data write failed");
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
			mctp_prwarn("KCS status read failed");
			return -1;
		}
		if (!(status & KCS_STATUS_OBF))
			break;
		/* todo: timeout */
	}

	rc = astlpc->ops.kcs_write(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_DATA,
				   data);
	if (rc) {
		mctp_prwarn("KCS data write failed");
		return -1;
	}

	return 0;
}

static int mctp_binding_astlpc_tx(struct mctp_binding *b,
				  struct mctp_pktbuf *pkt)
{
	struct mctp_binding_astlpc *astlpc = binding_to_astlpc(b);
	uint32_t len;
	struct mctp_hdr *hdr;

	hdr = mctp_pktbuf_hdr(pkt);
	len = mctp_pktbuf_size(pkt);

	mctp_prdebug("%s: Transmitting %" PRIu32
		     "-byte packet (%hhu, %hhu, 0x%hhx)",
		     __func__, len, hdr->src, hdr->dest, hdr->flags_seq_tag);

	if (len > rx_size - 4) {
		mctp_prwarn("invalid TX len 0x%x", len);
		return -1;
	}

	if (lpc_direct(astlpc)) {
		*(uint32_t *)(astlpc->lpc_map + rx_offset) = htobe32(len);
		memcpy(astlpc->lpc_map + rx_offset + 4, mctp_pktbuf_hdr(pkt),
		       len);
	} else {
		uint32_t tmp = htobe32(len);
		astlpc->ops.lpc_write(astlpc->ops_data, &tmp, rx_offset,
				      sizeof(tmp));
		astlpc->ops.lpc_write(astlpc->ops_data, mctp_pktbuf_hdr(pkt),
				      rx_offset + 4, len);
	}

	mctp_binding_set_tx_enabled(b, false);

	mctp_astlpc_kcs_send(astlpc, 0x1);
	return 0;
}

static void mctp_astlpc_init_channel(struct mctp_binding_astlpc *astlpc)
{
	/* todo: actual version negotiation */
	if (lpc_direct(astlpc)) {
		astlpc->lpc_hdr->negotiated_ver = htobe16(1);
	} else {
		uint16_t ver = htobe16(1);
		astlpc->ops.lpc_write(astlpc->ops_data, &ver,
				      offsetof(struct mctp_lpcmap_hdr,
					       negotiated_ver),
				      sizeof(ver));
	}
	mctp_astlpc_kcs_set_status(astlpc, KCS_STATUS_BMC_READY |
						   KCS_STATUS_CHANNEL_ACTIVE |
						   KCS_STATUS_OBF);

	mctp_binding_set_tx_enabled(&astlpc->binding, true);
}

static void mctp_astlpc_rx_start(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_pktbuf *pkt;
	uint32_t len;

	if (lpc_direct(astlpc)) {
		len = *(uint32_t *)(astlpc->lpc_map + tx_offset);
	} else {
		astlpc->ops.lpc_read(astlpc->ops_data, &len, tx_offset,
				     sizeof(len));
	}
	len = be32toh(len);

	if (len > tx_size - 4) {
		mctp_prwarn("invalid RX len 0x%x", len);
		return;
	}

	if (len > astlpc->binding.pkt_size) {
		mctp_prwarn("invalid RX len 0x%x", len);
		return;
	}

	pkt = mctp_pktbuf_alloc(&astlpc->binding, len);
	if (!pkt)
		goto out_complete;

	if (lpc_direct(astlpc)) {
		memcpy(mctp_pktbuf_hdr(pkt), astlpc->lpc_map + tx_offset + 4,
		       len);
	} else {
		astlpc->ops.lpc_read(astlpc->ops_data, mctp_pktbuf_hdr(pkt),
				     tx_offset + 4, len);
	}

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
		mctp_prwarn("KCS read error");
		return -1;
	}

	mctp_prdebug("%s: status: 0x%hhx", __func__, status);

	if (!(status & KCS_STATUS_IBF))
		return 0;

	rc = astlpc->ops.kcs_read(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_DATA,
				  &data);
	if (rc) {
		mctp_prwarn("KCS data read error");
		return -1;
	}

	mctp_prdebug("%s: data: 0x%hhx", __func__, data);

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
		mctp_prwarn("unknown message 0x%x", data);
	}
	return 0;
}

static int mctp_astlpc_init_bmc(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_lpcmap_hdr *hdr;
	uint8_t status;
	int rc;

	if (lpc_direct(astlpc))
		hdr = astlpc->lpc_hdr;
	else
		hdr = astlpc->priv_hdr;

	hdr->magic = htobe32(MCTP_MAGIC);
	hdr->bmc_ver_min = htobe16(BMC_VER_MIN);
	hdr->bmc_ver_cur = htobe16(BMC_VER_CUR);

	hdr->rx_offset = htobe32(rx_offset);
	hdr->rx_size = htobe32(rx_size);
	hdr->tx_offset = htobe32(tx_offset);
	hdr->tx_size = htobe32(tx_size);

	if (!lpc_direct(astlpc))
		astlpc->ops.lpc_write(astlpc->ops_data, hdr, 0, sizeof(*hdr));

	/* set status indicating that the BMC is now active */
	status = KCS_STATUS_BMC_READY | KCS_STATUS_OBF;
	rc = astlpc->ops.kcs_write(astlpc->ops_data, MCTP_ASTLPC_KCS_REG_STATUS,
				   status);
	if (rc) {
		mctp_prwarn("KCS write failed");
	}

	return rc;
}

static int mctp_binding_astlpc_start(struct mctp_binding *b)
{
	struct mctp_binding_astlpc *astlpc =
		container_of(b, struct mctp_binding_astlpc, binding);

	return mctp_astlpc_init_bmc(astlpc);
}

/* allocate and basic initialisation */
static struct mctp_binding_astlpc *__mctp_astlpc_init(void)
{
	struct mctp_binding_astlpc *astlpc;

	astlpc = __mctp_alloc(sizeof(*astlpc));
	memset(astlpc, 0, sizeof(*astlpc));
	astlpc->binding.name = "astlpc";
	astlpc->binding.version = 1;
	astlpc->binding.tx = mctp_binding_astlpc_tx;
	astlpc->binding.start = mctp_binding_astlpc_start;
	astlpc->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	astlpc->binding.pkt_pad = 0;
	astlpc->lpc_map = NULL;

	return astlpc;
}

struct mctp_binding *mctp_binding_astlpc_core(struct mctp_binding_astlpc *b)
{
	return &b->binding;
}

struct mctp_binding_astlpc *
mctp_astlpc_init_ops(const struct mctp_binding_astlpc_ops *ops, void *ops_data,
		     void *lpc_map)
{
	struct mctp_binding_astlpc *astlpc;

	astlpc = __mctp_astlpc_init();
	if (!astlpc)
		return NULL;

	memcpy(&astlpc->ops, ops, sizeof(astlpc->ops));
	astlpc->ops_data = ops_data;
	astlpc->lpc_map = lpc_map;

	/* In indirect mode, we keep a separate buffer of header data.
	 * We need to sync this through the lpc_read/lpc_write ops.
	 */
	if (!astlpc->lpc_map)
		astlpc->priv_hdr = __mctp_alloc(sizeof(*astlpc->priv_hdr));

	return astlpc;
}

void mctp_astlpc_destroy(struct mctp_binding_astlpc *astlpc)
{
	if (astlpc->priv_hdr)
		__mctp_free(astlpc->priv_hdr);
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
		mctp_prwarn("LPC open (%s) failed", lpc_path);
		return -1;
	}

	rc = ioctl(fd, ASPEED_LPC_CTRL_IOCTL_GET_SIZE, &map);
	if (rc) {
		mctp_prwarn("LPC GET_SIZE failed");
		close(fd);
		return -1;
	}

	astlpc->lpc_map_base =
		mmap(NULL, map.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (astlpc->lpc_map_base == MAP_FAILED) {
		mctp_prwarn("LPC mmap failed");
		rc = -1;
	} else {
		astlpc->lpc_map =
			astlpc->lpc_map_base + map.size - LPC_WIN_SIZE;
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
					 enum mctp_binding_astlpc_kcs_reg reg,
					 uint8_t *val)
{
	struct mctp_binding_astlpc *astlpc = arg;
	off_t offset = reg;
	int rc;

	rc = pread(astlpc->kcs_fd, val, 1, offset);

	return rc == 1 ? 0 : -1;
}

static int __mctp_astlpc_fileio_kcs_write(void *arg,
					  enum mctp_binding_astlpc_kcs_reg reg,
					  uint8_t val)
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

	astlpc = __mctp_astlpc_init();
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
struct mctp_binding_astlpc *__attribute__((const)) mctp_astlpc_init_fileio(void)
{
	mctp_prerr("Missing support for file IO");
	return NULL;
}

int __attribute__((const))
mctp_astlpc_get_fd(struct mctp_binding_astlpc *astlpc __attribute__((unused)))
{
	mctp_prerr("Missing support for file IO");
	return -1;
}
#endif
