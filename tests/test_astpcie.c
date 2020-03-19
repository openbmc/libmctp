/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "libmctp-astpcie.h"
#include "libmctp-log.h"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libmctp-astpcie-bind.h"

#define TEST_EID   10

int main(void)
{
    int res;
    struct mctp *mctp;
    struct mctp_binding *binding;
    struct mctp_binding_astpcie *pcie;

    mctp_set_log_stdio(MCTP_LOG_DEBUG);

    mctp = mctp_init();
    assert(mctp);

    pcie = mctp_binding_astpcie_init();
    assert(pcie);

    binding = mctp_binding_astpcie_core(pcie);
    assert(binding);

    assert(strcmp(pcie->binding.name, "astpcie") == 0);
    assert(pcie->binding.version == 1);
    assert(pcie->binding.tx != NULL);
    assert(pcie->binding.start != NULL);

    res = mctp_register_bus(mctp, &pcie->binding, TEST_EID);
    assert(res == 0);

    /* cleanup */
    mctp_binding_astpcie_free(pcie);
    __mctp_free(mctp);

    return 0;
}
