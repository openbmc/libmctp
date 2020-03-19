/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-astpcie.h"
#include "container_of.h"

#include "astpcie.h"

#define binding_to_astpcie(b) \
    container_of(b, struct mctp_binding_astpcie, binding)

/* dummy start function */
int mctp_binding_astpcie_start(struct mctp_binding *binding) {
    return -1;
}

/* dummy tx function */
int mctp_binding_astpcie_tx(struct mctp_binding *binding,
                         struct mctp_pktbuf *pkt) {
    return -1;
}

struct mctp_binding_astpcie *mctp_binding_astpcie_init(void)
{
    struct mctp_binding_astpcie *pcie;
    pcie = __mctp_alloc(sizeof(*pcie));
    memset(pcie, 0, sizeof(*pcie));

    pcie->binding.name = "astpcie";
    pcie->binding.version = 1;
    pcie->binding.tx = mctp_binding_astpcie_tx;
    pcie->binding.start = mctp_binding_astpcie_start;
    pcie->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
    pcie->binding.pkt_pad = 0;

    return pcie;
}

void mctp_binding_astpcie_free(struct mctp_binding_astpcie *b) {
    __mctp_free(b);
}

struct mctp_binding *mctp_binding_astpcie_core(struct mctp_binding_astpcie *b) {
    return &b->binding;
}
