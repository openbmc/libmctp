/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "libmctp.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

static void construct_route_table_from_static(struct mctp *mctp,
					      const struct mctp_route *entries,
					      size_t n)
{
	size_t i;
	int rc;

	for (i = 0; i < n; i++) {
		rc = mctp_route_add(mctp, &entries[i]);
		assert(!rc);
	}
}

static const struct mctp_route test_add_one[] = {
	{ .range = { .first = 8, .last = 8 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL }
};

static void test_mctp_route_table_add_one(void)
{
	const struct mctp_route *match;
	struct mctp *mctp;

	mctp = mctp_init();
	assert(mctp);

	construct_route_table_from_static(mctp, &test_add_one[0],
					  ARRAY_SIZE(test_add_one));

	match = mctp_route_match(mctp, &test_add_one[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	mctp_destroy(mctp);
}

static const struct mctp_route test_add_two[] = {
	{ .range = { .first = 8, .last = 8 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 9, .last = 9 },
	  .bus = 0,
	  .address = 1,
	  .type = MCTP_ROUTE_TYPE_LOCAL }
};

static void test_mctp_route_table_add_two(void)
{
	const struct mctp_route *match;
	struct mctp *mctp;

	mctp = mctp_init();
	assert(mctp);

	construct_route_table_from_static(mctp, &test_add_two[0],
					  ARRAY_SIZE(test_add_two));

	match = mctp_route_match(mctp, &test_add_two[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	match = mctp_route_match(mctp, &test_add_two[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	mctp_destroy(mctp);
}

static const struct mctp_route test_add_eid_conflict[] = {
	{ .range = { .first = 9, .last = 11 },
	  .bus = 0,
	  .address = 1,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 8, .last = 10 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 10, .last = 12 },
	  .bus = 0,
	  .address = 1,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 8, .last = 12 },
	  .bus = 0,
	  .address = 1,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 10, .last = 10 },
	  .bus = 0,
	  .address = 1,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
};

static void test_mctp_route_table_add_eid_conflict(void)
{
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	rc = mctp_route_add(mctp, &test_add_eid_conflict[0]);
	assert(!rc);

	rc = mctp_route_add(mctp, &test_add_eid_conflict[1]);
	assert(rc);

	rc = mctp_route_add(mctp, &test_add_eid_conflict[2]);
	assert(rc);

	rc = mctp_route_add(mctp, &test_add_eid_conflict[3]);
	assert(rc);

	rc = mctp_route_add(mctp, &test_add_eid_conflict[4]);
	assert(rc);

	mctp_destroy(mctp);
}

static const struct mctp_route test_add_bus_addr_conflict[] = {
	{ .range = { .first = 8, .last = 8 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 9, .last = 9 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL }
};

static void test_mctp_route_table_add_bus_addr_conflict(void)
{
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	rc = mctp_route_add(mctp, &test_add_bus_addr_conflict[0]);
	assert(!rc);

	rc = mctp_route_add(mctp, &test_add_bus_addr_conflict[1]);
	assert(rc);

	mctp_destroy(mctp);
}

static void test_mctp_route_table_remove_only(void)
{
	const struct mctp_route *route;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	rc = mctp_route_add(mctp, &test_add_one[0]);
	assert(!rc);

	rc = mctp_route_remove(mctp, &test_add_one[0]);
	assert(!rc);

	route = mctp_route_match(mctp, &test_add_one[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(!route);

	mctp_destroy(mctp);
}

static void test_mctp_route_table_remove_first(void)
{
	const struct mctp_route *route;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	construct_route_table_from_static(mctp, &test_add_two[0],
					  ARRAY_SIZE(test_add_two));

	rc = mctp_route_remove(mctp, &test_add_two[0]);
	assert(!rc);

	route = mctp_route_match(mctp, &test_add_two[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(!route);

	route = mctp_route_match(mctp, &test_add_two[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(route);

	mctp_destroy(mctp);
}

static void test_mctp_route_table_remove_last(void)
{
	const struct mctp_route *route;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	construct_route_table_from_static(mctp, &test_add_two[0],
					  ARRAY_SIZE(test_add_two));

	rc = mctp_route_remove(mctp, &test_add_two[1]);
	assert(!rc);

	route = mctp_route_match(mctp, &test_add_two[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(route);

	route = mctp_route_match(mctp, &test_add_two[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(!route);

	mctp_destroy(mctp);
}

static const struct mctp_route test_remove_middle[] = {
	{ .range = { .first = 8, .last = 8 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 9, .last = 9 },
	  .bus = 0,
	  .address = 1,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 10, .last = 10 },
	  .bus = 0,
	  .address = 2,
	  .type = MCTP_ROUTE_TYPE_LOCAL }
};

static void test_mctp_route_table_remove_middle(void)
{
	const struct mctp_route *route;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	construct_route_table_from_static(mctp, &test_remove_middle[0],
					  ARRAY_SIZE(test_remove_middle));

	rc = mctp_route_remove(mctp, &test_remove_middle[1]);
	assert(!rc);

	route = mctp_route_match(mctp, &test_remove_middle[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(route);

	route = mctp_route_match(mctp, &test_remove_middle[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(!route);

	route = mctp_route_match(mctp, &test_remove_middle[2],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(route);

	mctp_destroy(mctp);
}

static void test_mctp_route_table_insert_two_disjoint(void)
{
	const struct mctp_route *match;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	rc = mctp_route_insert(mctp, &test_add_two[0]);
	assert(!rc);

	rc = mctp_route_insert(mctp, &test_add_two[1]);
	assert(!rc);

	match = mctp_route_match(mctp, &test_add_two[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	match = mctp_route_match(mctp, &test_add_two[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	mctp_destroy(mctp);
}

static const struct mctp_route test_intersect[] = {
	{ .range = { .first = 8, .last = 254 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 8, .last = 130 },
	  .bus = 0,
	  .address = 1,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 131, .last = 254 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 70, .last = 191 },
	  .bus = 0,
	  .address = 2,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 8, .last = 69 },
	  .bus = 0,
	  .address = 1,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
	{ .range = { .first = 192, .last = 254 },
	  .bus = 0,
	  .address = 0,
	  .type = MCTP_ROUTE_TYPE_LOCAL },
};

static void test_mctp_route_table_insert_delete_intersect(void)
{
	const struct mctp_route *match;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	rc = mctp_route_insert(mctp, &test_intersect[0]);
	assert(!rc);

	match = mctp_route_match(mctp, &test_intersect[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	rc = mctp_route_insert(mctp, &test_intersect[1]);
	assert(!rc);

	match = mctp_route_match(mctp, &test_intersect[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	match = mctp_route_match(mctp, &test_intersect[2],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	rc = mctp_route_insert(mctp, &test_intersect[3]);
	assert(!rc);

	match = mctp_route_match(mctp, &test_intersect[3],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	match = mctp_route_match(mctp, &test_intersect[4],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	match = mctp_route_match(mctp, &test_intersect[5],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);

	rc = mctp_route_delete(mctp, &test_intersect[3]);
	assert(!rc);

	match = mctp_route_match(mctp, &test_intersect[3],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(!match);

	mctp_destroy(mctp);
}

int main(void)
{
	test_mctp_route_table_add_one();
	test_mctp_route_table_add_two();
	test_mctp_route_table_add_eid_conflict();
	test_mctp_route_table_add_bus_addr_conflict();
	test_mctp_route_table_remove_only();
	test_mctp_route_table_remove_first();
	test_mctp_route_table_remove_last();
	test_mctp_route_table_remove_middle();
	test_mctp_route_table_insert_two_disjoint();
	test_mctp_route_table_insert_delete_intersect();

	return 0;
}
