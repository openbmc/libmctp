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
	void (*fn)(struct mctp_binding *binding);
	struct mctp_binding_test binding;
};

static void test_mctp_pktbuf_alloc(struct mctp_binding *binding)
{
	struct mctp_pktbuf *pkt;

	pkt = mctp_pktbuf_alloc(binding, binding->pkt_size);
	assert(pkt);
	assert(mctp_pktbuf_size(pkt) >= binding->pkt_size);
	mctp_pktbuf_free(pkt);
}

static void test_mctp_pktbuf_size(struct mctp_binding *binding)
{
	struct mctp_pktbuf *pkt;

	pkt = mctp_pktbuf_alloc(binding, binding->pkt_size);
	assert(mctp_pktbuf_size(pkt) == binding->pkt_size);
	mctp_pktbuf_free(pkt);
}

#include <stdio.h>
static void test_mctp_pktbuf_alloc_start(struct mctp_binding *binding)
{
	struct mctp_pktbuf *pkt;
	void *a, *b;

	printf("pkt_pad: %d, start: %d\n", binding->pkt_pad);
	pkt = mctp_pktbuf_alloc(binding, binding->pkt_size);

	a = mctp_pktbuf_data(pkt);
	b = mctp_pktbuf_alloc_start(pkt, 1);
	printf("a: %p, b: %p, d: %td\n", a, b, a-b);
	assert(1 == (a - b));

	mctp_pktbuf_free(pkt);
}

static void test_mctp_pktbuf_alloc_end(struct mctp_binding *binding)
{
}

static const struct test_case tests[] = {
	{ .fn = test_mctp_pktbuf_alloc, },
	{ .fn = test_mctp_pktbuf_size, },
	{
		.fn = test_mctp_pktbuf_alloc_start,
		.binding.binding = {
			.pkt_pad = 1,
		},
	},
};

int main(void)
{
	struct test_ctx _ctx, *ctx = &_ctx;
	const mctp_eid_t local_eid = 8;
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		const struct test_case *t = &tests[i];
		struct mctp_binding_test *b =
			(struct mctp_binding_test *)&t->binding;

		mctp_test_stack_init(&ctx->mctp, &b, local_eid);

		ctx->binding = b;

		tests[i].fn(&ctx->binding->binding);

		mctp_test_stack_destroy(ctx->mctp, ctx->binding);
	}

	exit(EXIT_SUCCESS);
}
