/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_ASTPCIE_BIND_H
#define _LIBMCTP_ASTPCIE_BIND_H

#include "libmctp.h"

struct mctp_binding_astpcie {
    struct mctp_binding binding;
    int fd;

    struct mctp_pktbuf *rx_pkt;

    /* placeholder for buffer */
    uint8_t rxbuf[MCTP_ASTPCIE_BINDING_DEFAULT_BUF];
};

#endif // _LIBMCTP_ASTPCIE_BIND_H
