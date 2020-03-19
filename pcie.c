/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-pcie.h"

struct mctp_binding_pcie {
    struct mctp_binding binding;
    int fd;

    /* placeholder for buffer */
    uint8_t rxbuf[MCTP_PCIE_BINDING_DEFAULT_BUF];

    struct mctp_pktbuf *rx_pkt;
};

#ifndef container_of
#define container_of(ptr, type, member)                                        \
    (type *)((char *)(ptr) - (char *)&((type *)0)->member)
#endif

#define binding_to_pcie(b) container_of(b, struct mctp_binding_pcie, binding)

/* dummy start function */
int mctp_binding_pcie_start(struct mctp_binding *binding) {
    return -1;
}

/* dummy tx function */
int mctp_binding_pcie_tx(struct mctp_binding *binding,
                         struct mctp_pktbuf *pkt) {
    return -1;
}

struct mctp_binding_pcie *mctp_binding_pcie_init(void)
{
    struct mctp_binding_pcie *pcie;
    pcie = __mctp_alloc(sizeof(*pcie));
    memset(pcie, 0, sizeof(*pcie));

    pcie->binding.name = "pcie";
    pcie->binding.version = 1;
    pcie->binding.tx = mctp_binding_pcie_tx;
    pcie->binding.start = mctp_binding_pcie_start;
    pcie->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
    pcie->binding.pkt_pad = 0;

    return pcie;
}

void mctp_binding_pcie_free(struct mctp_binding_pcie *b) {
    __mctp_free(b);
}

struct mctp_binding *mctp_binding_pcie_core(struct mctp_binding_pcie *b) {
    return &b->binding;
}
