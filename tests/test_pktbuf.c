/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */
#include "test-utils.h"

#include <libmctp.h>

#include <assert.h>
#include <stdlib.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

struct test_ctx {
	struct mctp			*mctp;
	struct mctp_binding_test	*binding;
};

struct test_case {
	int (*fn)(struct mctp_binding *binding);
	struct mctp_binding binding;
};

static int test_mctp_pktbuf_alloc(struct mctp_binding *binding)
{
	struct mctp_pktbuf *pkt;

	pkt = mctp_pktbuf_alloc(binding, binding->pkt_size);
	assert(pkt);
	assert(mctp_pktbuf_size(pkt) >= binding->pkt_size);
	mctp_pktbuf_free(pkt);

	return EXIT_SUCCESS;
}

static const struct test_case tests[] = {
	{ .fn = test_mctp_pktbuf_alloc, },
};

int main(void)
{
	struct test_ctx _ctx, *ctx = &_ctx;
	const mctp_eid_t local_eid = 8;
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		mctp_test_stack_init(&ctx->mctp, &ctx->binding, local_eid);

		tests[i].fn(&ctx->binding->binding);

		mctp_test_stack_destroy(ctx->mctp, ctx->binding);
	}

	exit(EXIT_SUCCESS);
}
