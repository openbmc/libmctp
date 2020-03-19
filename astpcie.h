/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

/* This is a private header file defining binding structure for PCIe binding */

#ifndef _ASTPCIE_H
#define _ASTPCIE_H

#include "libmctp.h"

#define MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER     1024

struct mctp_binding_astpcie {
    struct mctp_binding binding;
    int fd;

    struct mctp_pktbuf *rx_pkt;

    /* placeholder for buffer */
    uint8_t rxbuf[MCTP_ASTPCIE_BINDING_DEFAULT_BUFFER];
};

#endif
