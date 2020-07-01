/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include "test-utils.h"

#include "binding.h"
#include "container_of.h"

#include "libmctp.h"
#include "libmctp-alloc.h"

#include <string.h>
#include <assert.h>

static int mctp_binding_test_tx(struct mctp_binding *b, struct mctp_pktbuf *pkt)
{
	struct mctp_binding_test *test = binding_to_test(b);
	size_t len;

	len = sizeof(*test->pkt) + mctp_pktbuf_size(pkt);
	test->pkt = __mctp_alloc(len);
	assert(test->pkt);
	memcpy(test->pkt, pkt, len);

	return 0;
}

static struct mctp_pktbuf *
mctp_binding_test_frame(struct mctp_binding *b __attribute__((unused)),
			struct mctp_pktbuf *pkt, const struct mctp_device *dest)
{
	uint8_t *hdr;

	hdr = mctp_pktbuf_alloc_start(pkt, 1);
	*hdr = dest->address & 0xff;

	return pkt;
}

struct mctp_binding_test *mctp_binding_test_init(void)
{
	struct mctp_binding_test *test;

	test = __mctp_alloc(sizeof(*test));
	memset(test, '\0', sizeof(*test));
	test->binding.name = "test";
	test->binding.version = 1;
	test->binding.frame = mctp_binding_test_frame;
	test->binding.tx = mctp_binding_test_tx;
	test->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	test->binding.pkt_pad = 1;
	test->binding.pkt_start = 1;
	return test;
}

void mctp_binding_test_destroy(struct mctp_binding_test *test)
{
	__mctp_free(test);
}

void mctp_binding_test_rx_raw(struct mctp_binding_test *test,
			      const struct mctp_device *dsrc, void *buf,
			      size_t len)
{
	struct mctp_pktbuf *pkt;

	pkt = mctp_pktbuf_alloc(&test->binding, len);
	assert(pkt);
	memcpy(mctp_pktbuf_hdr(pkt), buf, len);
	mctp_bus_rx(&test->binding, dsrc, pkt);
}

void mctp_binding_test_register_bus(struct mctp_binding_test *binding,
		struct mctp *mctp, mctp_eid_t eid)
{
	mctp_register_bus(mctp, &binding->binding, eid);
	binding->binding.bus->tx_enabled = 1;
}

void mctp_test_stack_init(struct mctp **mctp,
		struct mctp_binding_test **binding,
		mctp_eid_t eid)
{
	*mctp = mctp_init();
	assert(*mctp);

	*binding = mctp_binding_test_init();
	assert(*binding);

	mctp_binding_test_register_bus(*binding, *mctp, eid);
}
