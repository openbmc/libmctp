/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "binding.h"

#ifdef MCTP_HAVE_FILEIO
#include <unistd.h>
#include <fcntl.h>
#else
static const size_t write(int fd, void *buf, size_t len)
{
	return -1;
}
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define pr_fmt(x) "serial: " x

/* Post-condition: All bytes written or an error has occurred */
#define mctp_write_all(fn, dst, src, len)				\
({									\
	ssize_t wrote;							\
	while (len) {							\
		wrote = fn(dst, src, len);				\
		if (wrote < 0)						\
			break;						\
		len -= wrote;						\
	}								\
	len ? -1 : 0;							\
})

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-serial.h"
#include "container_of.h"

struct mctp_binding_serial {
	struct mctp_binding	binding;
	int			fd;
	unsigned long		bus_id;

	mctp_serial_tx_fn	tx_fn;
	void			*tx_fn_data;

	/* receive buffer and state */
	uint8_t			rxbuf[1024];
	struct mctp_pktbuf	*rx_pkt;
	uint8_t			rx_exp_len;
	uint16_t		rx_fcs;
	enum {
		STATE_WAIT_SYNC_START,
		STATE_WAIT_REVISION,
		STATE_WAIT_LEN,
		STATE_DATA,
		STATE_DATA_ESCAPED,
		STATE_WAIT_FCS1,
		STATE_WAIT_FCS2,
		STATE_WAIT_SYNC_END,
	} rx_state;

	/* temporary transmit buffer */
	uint8_t			txbuf[256];
};

#define binding_to_serial(b) \
	container_of(b, struct mctp_binding_serial, binding)

#define MCTP_SERIAL_REVISION		0x01
#define MCTP_SERIAL_FRAMING_FLAG	0x7e
#define MCTP_SERIAL_ESCAPE		0x7d

struct mctp_serial_header {
	uint8_t	flag;
	uint8_t revision;
	uint8_t	len;
};

struct mctp_serial_trailer {
	uint8_t	fcs_msb;
	uint8_t fcs_lsb;
	uint8_t	flag;
};

static size_t mctp_serial_pkt_escape(struct mctp_pktbuf *pkt, uint8_t *buf)
{
	uint8_t total_len;
	uint8_t *p;
	int i, j;

	total_len = pkt->end - pkt->mctp_hdr_off;

	p = (void *)mctp_pktbuf_hdr(pkt);

	for (i = 0, j = 0; i < total_len; i++, j++) {
		uint8_t c = p[i];
		if (c == 0x7e || c == 0x7d) {
			if (buf)
				buf[j] = 0x7d;
			j++;
			c ^= 0x20;
		}
		if (buf)
			buf[j] = c;
	}

	return j;
}

static struct mctp_pktbuf *
mctp_binding_serial_frame(struct mctp_binding *b, struct mctp_pktbuf *pkt,
			  const struct mctp_device *dest
			  __attribute__((unused)))
{
	struct mctp_binding_serial *serial = binding_to_serial(b);
	struct mctp_serial_header *hdr;
	struct mctp_serial_trailer *tlr;
	uint8_t *buf;
	size_t provided, required;

	/* the length field in the header excludes serial framing
	 * and escape sequences */
	provided = mctp_pktbuf_size(pkt);

	required = mctp_serial_pkt_escape(pkt, NULL);
	if (required + sizeof(*hdr) + sizeof(*tlr) > sizeof(serial->txbuf)) {
		mctp_prerr(
			"Escaped packet size exceeded allocated bounce buffer");
		return NULL;
	}

	if (required != provided) {
		/* Use the bounce buffer to inject escaping */
		hdr = (void *)serial->txbuf;
	} else {
		/* Otherwise inject the metadata straight into the packet */
		hdr = mctp_pktbuf_alloc_start(pkt, sizeof(*hdr));
	}

	hdr->flag = MCTP_SERIAL_FRAMING_FLAG;
	hdr->revision = MCTP_SERIAL_REVISION;
	hdr->len = provided;

	buf = (void *)(hdr + 1);

	if (required != provided) {
		mctp_serial_pkt_escape(pkt, buf);
		buf += required;
		tlr = (void *)buf;
	} else {
		tlr = mctp_pktbuf_alloc_end(pkt, sizeof(*tlr));
	}

	tlr->flag = MCTP_SERIAL_FRAMING_FLAG;
	/* todo: trailer FCS */
	tlr->fcs_msb = 0;
	tlr->fcs_lsb = 0;

	if (required != provided) {
		required += sizeof(*hdr) + sizeof(*tlr);

		if (required > pkt->size) {
			struct mctp_pktbuf *escaped;

			escaped = __mctp_alloc(sizeof(*escaped) + required);
			if (!escaped) {
				mctp_prerr("Failed to allocate packet");
				return NULL;
			}

			mctp_pktbuf_free(pkt);
			pkt = escaped;
			pkt->size = required;
			pkt->start = b->pkt_start;
			pkt->end = required;
			pkt->mctp_hdr_off = pkt->start;
			pkt->next = NULL;
		}

		buf = mctp_pktbuf_alloc_start(pkt, sizeof(*hdr));
		memcpy(buf, serial->txbuf, required);
	}

	return pkt;
}

static int mctp_binding_serial_tx(struct mctp_binding *b,
				  struct mctp_pktbuf *pkt)
{
	struct mctp_binding_serial *serial = binding_to_serial(b);
	size_t len;
	int rc;

	len = mctp_pktbuf_size(pkt);

	if (!serial->tx_fn)
		return mctp_write_all(write, serial->fd, pkt->data, len);

	rc = mctp_write_all(serial->tx_fn, serial->tx_fn_data, pkt->data, len);
	return rc;
}

static void mctp_serial_finish_packet(struct mctp_binding_serial *serial,
		bool valid)
{
	struct mctp_pktbuf *pkt = serial->rx_pkt;
	assert(pkt);

	if (valid)
		mctp_binding_rx(&serial->binding,
				&(struct mctp_device){ serial->binding.bus->id,
						       1 },
				pkt);

	serial->rx_pkt = NULL;
}

static void mctp_serial_start_packet(struct mctp_binding_serial *serial,
		uint8_t len)
{
	serial->rx_pkt = mctp_pktbuf_alloc(&serial->binding, len);
}

static void mctp_rx_consume_one(struct mctp_binding_serial *serial,
		uint8_t c)
{
	struct mctp_pktbuf *pkt = serial->rx_pkt;

	mctp_prdebug("state: %d, char 0x%02x", serial->rx_state, c);

	assert(!pkt == (serial->rx_state == STATE_WAIT_SYNC_START ||
			serial->rx_state == STATE_WAIT_REVISION ||
			serial->rx_state == STATE_WAIT_LEN));

	switch (serial->rx_state) {
	case STATE_WAIT_SYNC_START:
		if (c != MCTP_SERIAL_FRAMING_FLAG) {
			mctp_prdebug("lost sync, dropping packet");
			if (pkt)
				mctp_serial_finish_packet(serial, false);
		} else {
			serial->rx_state = STATE_WAIT_REVISION;
		}
		break;

	case STATE_WAIT_REVISION:
		if (c == MCTP_SERIAL_REVISION) {
			serial->rx_state = STATE_WAIT_LEN;
		} else {
			mctp_prdebug("invalid revision 0x%02x", c);
			serial->rx_state = STATE_WAIT_SYNC_START;
		}
		break;
	case STATE_WAIT_LEN:
		if (c > serial->binding.pkt_size ||
				c < sizeof(struct mctp_hdr)) {
			mctp_prdebug("invalid size %d", c);
			serial->rx_state = STATE_WAIT_SYNC_START;
		} else {
			mctp_serial_start_packet(serial, 0);
			pkt = serial->rx_pkt;
			serial->rx_exp_len = c;
			serial->rx_state = STATE_DATA;
		}
		break;

	case STATE_DATA:
		if (c == MCTP_SERIAL_ESCAPE) {
			serial->rx_state = STATE_DATA_ESCAPED;
		} else {
			mctp_pktbuf_push(pkt, &c, 1);
			if (pkt->end - pkt->mctp_hdr_off == serial->rx_exp_len)
				serial->rx_state = STATE_WAIT_FCS1;
		}
		break;

	case STATE_DATA_ESCAPED:
		c ^= 0x20;
		mctp_pktbuf_push(pkt, &c, 1);
		if (pkt->end - pkt->mctp_hdr_off == serial->rx_exp_len)
			serial->rx_state = STATE_WAIT_FCS1;
		else
			serial->rx_state = STATE_DATA;
		break;

	case STATE_WAIT_FCS1:
		serial->rx_fcs = c << 8;
		serial->rx_state = STATE_WAIT_FCS2;
		break;
	case STATE_WAIT_FCS2:
		serial->rx_fcs |= c;
		/* todo: check fcs */
		serial->rx_state = STATE_WAIT_SYNC_END;
		break;

	case STATE_WAIT_SYNC_END:
		if (c == MCTP_SERIAL_FRAMING_FLAG) {
			mctp_serial_finish_packet(serial, true);
		} else {
			mctp_prdebug("missing end frame marker");
			mctp_serial_finish_packet(serial, false);
		}
		serial->rx_state = STATE_WAIT_SYNC_START;
		break;
	}

	mctp_prdebug(" -> state: %d", serial->rx_state);
}
static void mctp_rx_consume(struct mctp_binding_serial *serial,
		const void *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		mctp_rx_consume_one(serial, *(uint8_t *)(buf + i));
}

#ifdef MCTP_HAVE_FILEIO
int mctp_serial_read(struct mctp_binding_serial *serial)
{
	ssize_t len;

	len = read(serial->fd, serial->rxbuf, sizeof(serial->rxbuf));
	if (len == 0)
		return -1;

	if (len < 0) {
		mctp_prerr("can't read from serial device: %m");
		return -1;
	}

	mctp_rx_consume(serial, serial->rxbuf, len);

	return 0;
}

int mctp_serial_get_fd(struct mctp_binding_serial *serial)
{
	return serial->fd;
}

int mctp_serial_open_path(struct mctp_binding_serial *serial,
		const char *device)
{
	serial->fd = open(device, O_RDWR);
	if (serial->fd < 0)
		mctp_prerr("can't open device %s: %m", device);

	return 0;
}

void mctp_serial_open_fd(struct mctp_binding_serial *serial, int fd)
{
	serial->fd = fd;
}
#endif

void mctp_serial_set_tx_fn(struct mctp_binding_serial *serial,
		mctp_serial_tx_fn fn, void *data)
{
	serial->tx_fn = fn;
	serial->tx_fn_data = data;
}

int mctp_serial_rx(struct mctp_binding_serial *serial,
		const void *buf, size_t len)
{
	mctp_rx_consume(serial, buf, len);
	return 0;
}

static int mctp_serial_core_start(struct mctp_binding *binding)
{
	mctp_binding_set_tx_enabled(binding, true);
	return 0;
}

struct mctp_binding *mctp_binding_serial_core(struct mctp_binding_serial *b)
{
	return &b->binding;
}

struct mctp_binding_serial *mctp_serial_init(void)
{
	struct mctp_binding_serial *serial;

	serial = __mctp_alloc(sizeof(*serial));
	memset(serial, 0, sizeof(*serial));
	serial->fd = -1;
	serial->rx_state = STATE_WAIT_SYNC_START;
	serial->rx_pkt = NULL;
	serial->binding.name = "serial";
	serial->binding.version = 1;
	serial->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	serial->binding.pkt_pad = sizeof(struct mctp_serial_header) +
				  sizeof(struct mctp_serial_trailer);
	serial->binding.pkt_start = sizeof(struct mctp_serial_header);
	serial->binding.start = mctp_serial_core_start;
	serial->binding.frame = mctp_binding_serial_frame;
	serial->binding.tx = mctp_binding_serial_tx;

	return serial;
}

void mctp_serial_destroy(struct mctp_binding_serial *serial)
{
	__mctp_free(serial);
}
