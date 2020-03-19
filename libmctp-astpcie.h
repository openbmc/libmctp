/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_ASTPCIE_H
#define _LIBMCTP_ASTPCIE_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp.h"
#include "libmctp-alloc.h"

#define MCTP_ASTPCIE_BINDING_DEFAULT_BUF  1024

struct mctp_binding_astpcie;

struct mctp_binding_astpcie *mctp_binding_astpcie_init(void);

struct mctp_binding *mctp_binding_astpcie_core(struct mctp_binding_astpcie *b);

void mctp_binding_astpcie_free(struct mctp_binding_astpcie *b);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_ASTPCIE_H */
