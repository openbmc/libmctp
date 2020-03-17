/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_ASTLPCL_H
#define _LIBMCTP_ASTLPCL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libmctp.h>

struct mctp_binding_astlpc;

enum mctp_binding_astlpc_kcs_reg {
	MCTP_ASTLPC_KCS_REG_DATA = 0,
	MCTP_ASTLPC_KCS_REG_STATUS = 1,
};

struct mctp_binding_astlpc_ops {
	int	(*kcs_read)(void *data, enum mctp_binding_astlpc_kcs_reg reg,
			uint8_t *val);
	int	(*kcs_write)(void *data, enum mctp_binding_astlpc_kcs_reg reg,
			uint8_t val);
	int	(*lpc_read)(void *data, void *buf, long offset, size_t len);
	int	(*lpc_write)(void *data, void *buf, long offset, size_t len);
};

struct mctp_binding_astlpc *mctp_astlpc_init_ops(
		const struct mctp_binding_astlpc_ops *ops,
		void *ops_data, void *lpc_map);
void mctp_astlpc_destroy(struct mctp_binding_astlpc *astlpc);

struct mctp_binding *mctp_binding_astlpc_core(struct mctp_binding_astlpc *b);

int mctp_astlpc_poll(struct mctp_binding_astlpc *astlpc);

/* fileio-based interface */
struct mctp_binding_astlpc *mctp_astlpc_init_fileio(void);
int mctp_astlpc_get_fd(struct mctp_binding_astlpc *astlpc);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTLPCL_H */
