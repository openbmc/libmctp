
/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_KCS_H
#define _LIBMCTP_KCS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libmctp.h>

#include <stdint.h>

struct mctp_binding_kcs;

struct mctp_binding_kcs *mctp_kcs_init(void);

void mctp_kcs_destroy(struct mctp_binding_kcs *kcs);

struct mctp_binding *mctp_binding_kcs_core(struct mctp_binding_kcs *b);

int mctp_kcs_poll(struct mctp_binding_kcs *kcs);

struct mctp_binding_kcs *mctp_kcs_init_fileio(const char *path);

struct pollfd;
int mctp_kcs_init_pollfd(struct mctp_binding_kcs *kcs, struct pollfd *pollfd);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_KCS_H */
