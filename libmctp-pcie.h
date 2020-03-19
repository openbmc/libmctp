/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_PCIE_H
#define _LIBMCTP_PCIE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp.h"
#include "libmctp-alloc.h"

#define MCTP_PCIE_BINDING_DEFAULT_BUF  1024

struct mctp_binding_pcie;

struct mctp_binding_pcie *mctp_binding_pcie_init(void);

struct mctp_binding *mctp_binding_pcie_core(struct mctp_binding_pcie *b);

void mctp_binding_pcie_free(struct mctp_binding_pcie *b);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_PCIE_H */
