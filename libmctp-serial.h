/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_SERIAL_H
#define _LIBMCTP_SERIAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libmctp.h>

struct mctp_binding_serial;

struct mctp_binding_serial *mctp_serial_init(void);

void mctp_serial_register_bus(struct mctp_binding_serial *serial,
		struct mctp *mctp, mctp_eid_t eid);

/* file-based IO */
int mctp_serial_get_fd(struct mctp_binding_serial *serial);
int mctp_serial_read(struct mctp_binding_serial *serial);
int mctp_serial_open_path(struct mctp_binding_serial *serial,
		const char *path);
void mctp_serial_open_fd(struct mctp_binding_serial *serial, int fd);

/* direct function call IO */
typedef int (*mctp_serial_tx_fn)(void *data, void *buf, size_t len);
void mctp_serial_set_tx_fn(struct mctp_binding_serial *serial,
		mctp_serial_tx_fn fn, void *data);
int mctp_serial_rx(struct mctp_binding_serial *serial,
		const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_SERIAL_H */
