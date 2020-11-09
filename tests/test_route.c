/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "test-utils.h"

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
	  .device = { .bus = 0, .address = 0, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0, }
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
	mctp_route_put(match);

	mctp_destroy(mctp);
}

static const struct mctp_route test_add_two[] = {
	{ .range = { .first = 8, .last = 8 },
	  .device = { .bus = 0, .address = 0, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
	{ .range = { .first = 9, .last = 9 },
	  .device = { .bus = 0, .address = 1, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 }
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
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_add_two[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	mctp_destroy(mctp);
}

static const struct mctp_route test_add_eid_conflict[] = {
	{ .range = { .first = 9, .last = 11 },
	  .device = { .bus = 0, .address = 1, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
	{ .range = { .first = 8, .last = 10 },
	  .device = { .bus = 0, .address = 0, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
	{ .range = { .first = 10, .last = 12 },
	  .device = { .bus = 0, .address = 1, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
	{ .range = { .first = 8, .last = 12 },
	  .device = { .bus = 0, .address = 1, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
	{ .range = { .first = 10, .last = 10 },
	  .device = { .bus = 0, .address = 1, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
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
	  .device = { .bus = 0, .address = 0, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
	{ .range = { .first = 9, .last = 9 },
	  .device = { .bus = 0, .address = 0, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 }
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
	mctp_route_put(route);

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
	mctp_route_put(route);

	route = mctp_route_match(mctp, &test_add_two[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(!route);

	mctp_destroy(mctp);
}

static const struct mctp_route test_remove_middle[] = {
	{ .range = { .first = 8, .last = 8 },
	  .device = { .bus = 0, .address = 0, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
	{ .range = { .first = 9, .last = 9 },
	  .device = { .bus = 0, .address = 1, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 },
	{ .range = { .first = 10, .last = 10 },
	  .device = { .bus = 0, .address = 2, },
	  .type = MCTP_ROUTE_TYPE_LOCAL,
	  .flags = 0 }
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
	mctp_route_put(route);

	route = mctp_route_match(mctp, &test_remove_middle[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(!route);

	route = mctp_route_match(mctp, &test_remove_middle[2],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(route);
	mctp_route_put(route);

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
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_add_two[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	mctp_destroy(mctp);
}

static const struct mctp_route test_intersect[] = {
	/* Insert a route covering the normal EID range */
	[0] = { .range = { .first = 8, .last = 254 },
		.device = { .bus = 0, .address = 0, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },

	/* Insert a route covering the first half, truncating the first route */
	[1] = { .range = { .first = 8, .last = 130 },
		.device = { .bus = 0, .address = 1, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },
	[2] = { .range = { .first = 131, .last = 254 },
		.device = { .bus = 0, .address = 0, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },

	/* Insert a route intersecting both existing routes */
	[3] = { .range = { .first = 70, .last = 191 },
		.device = { .bus = 0, .address = 2, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },
	[4] = { .range = { .first = 8, .last = 69 },
		.device = { .bus = 0, .address = 1, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },
	[5] = { .range = { .first = 192, .last = 254 },
		.device = { .bus = 0, .address = 0, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },

	/* Insert a route in a subset of the third route's range */
	[6] = { .range = { .first = 100, .last = 130 },
		.device = { .bus = 0, .address = 3, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },
	[7] = { .range = { .first = 8, .last = 69 },
		.device = { .bus = 0, .address = 1, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },
	[8] = { .range = { .first = 70, .last = 99 },
		.device = { .bus = 0, .address = 2, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },
	[9] = { .range = { .first = 131, .last = 191 },
		.device = { .bus = 0, .address = 2, },
		.type = MCTP_ROUTE_TYPE_LOCAL,
		.flags = 0 },
	[10] = { .range = { .first = 192, .last = 254 },
		 .device = { .bus = 0, .address = 0, },
		 .type = MCTP_ROUTE_TYPE_LOCAL,
		 .flags = 0 },
};

static void test_mctp_route_table_insert_delete_intersect(void)
{
	const struct mctp_route *match;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	/* Insert a route covering the normal EID range */
	rc = mctp_route_insert(mctp, &test_intersect[0]);
	assert(!rc);

	match = mctp_route_match(mctp, &test_intersect[0],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	/* Insert a route covering the first half, truncating the first route */
	rc = mctp_route_insert(mctp, &test_intersect[1]);
	assert(!rc);

	match = mctp_route_match(mctp, &test_intersect[1],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_intersect[2],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	/* Insert a route intersecting both existing routes */
	rc = mctp_route_insert(mctp, &test_intersect[3]);
	assert(!rc);

	match = mctp_route_match(mctp, &test_intersect[3],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_intersect[4],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_intersect[5],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	rc = mctp_route_insert(mctp, &test_intersect[6]);
	assert(!rc);

	/* Insert a route in a subset of the third route's range */
	match = mctp_route_match(mctp, &test_intersect[6],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_intersect[7],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_intersect[8],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_intersect[9],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	match = mctp_route_match(mctp, &test_intersect[10],
				 MCTP_ROUTE_MATCH_ROUTE);
	assert(match);
	mctp_route_put(match);

	mctp_route_table_dump(mctp, MCTP_LOG_DEBUG);

	rc = mctp_route_delete(mctp, &test_intersect[0]);

	match = mctp_route_match(mctp, &test_intersect[10],
				 MCTP_ROUTE_MATCH_EID);
	assert(!match);

	mctp_route_table_dump(mctp, MCTP_LOG_DEBUG);

	mctp_destroy(mctp);
}

struct test_mctp_notify {
	struct mctp *mctp;
	struct mctp_route_entry *entry;
	uint8_t count;
};

static void mctp_route_notify_cb(void *data,
				 const struct mctp_route_entry *event)
{
	const struct mctp_route_entry *match;
	struct test_mctp_notify *test;

	test = data;

	match = mctp_route_list_match(test->mctp, event, &test->entry->route,
				      MCTP_ROUTE_MATCH_ROUTE);
	if (match) {
		if (test->entry->flags == match->flags)
			test->count++;
	}
}

static void test_mctp_route_table_add_notify(void)
{
	struct mctp_route_entry entry;
	struct test_mctp_notify test;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	entry = (struct mctp_route_entry){
		.flags = MCTP_ROUTE_ENTRY_NOTIFY_ADD,
		.route = {
			.range = { .first = 8, .last = 8 },
			.device = { .bus = 0, .address = 0, },
			.type = MCTP_ROUTE_TYPE_ENDPOINT,
			.flags = 0,
		},
	};

	test.mctp = mctp;
	test.entry = &entry;
	test.count = 0;

	rc = mctp_route_set_notify(mctp, mctp_route_notify_cb, &test);
	assert(!rc);

	rc = mctp_route_add(mctp, &entry.route);
	assert(!rc);

	assert(test.count == 1);

	mctp_destroy(mctp);
}

static void test_mctp_route_table_remove_notify(void)
{
	struct mctp_route_entry entry;
	struct test_mctp_notify test;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	entry = (struct mctp_route_entry){
		.flags = MCTP_ROUTE_ENTRY_NOTIFY_REMOVE,
		.route = {
			.range = { .first = 8, .last = 8 },
			.type = MCTP_ROUTE_TYPE_ENDPOINT,
			.device = { .bus = 0, .address = 0, },
			.flags = 0,
		},
	};

	test.mctp = mctp;
	test.entry = &entry;
	test.count = 0;

	rc = mctp_route_set_notify(mctp, mctp_route_notify_cb, &test);
	assert(!rc);

	rc = mctp_route_add(mctp, &entry.route);
	assert(!rc);

	assert(test.count == 0);

	rc = mctp_route_remove(mctp, &entry.route);
	assert(!rc);

	assert(test.count == 1);

	mctp_destroy(mctp);
}

static void test_mctp_route_table_allocate_one(void)
{
	const struct mctp_route *alloc;
	struct mctp_route route = { 0 };
	struct mctp_eid_range range;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	range = (struct mctp_eid_range){ .first = 9, .last = 9 };
	rc = mctp_route_set_dynamic_pool(mctp, &range);
	assert(!rc);
	route.type = MCTP_ROUTE_TYPE_LOCAL;
	alloc = mctp_route_allocate(mctp, &route, 1);
	assert(alloc);
	assert(alloc->type == MCTP_ROUTE_TYPE_LOCAL);
	assert(alloc->range.first == 9);
	assert(alloc->range.last == 9);

	mctp_destroy(mctp);
}

static void test_mctp_route_table_allocate_one_provisional(void)
{
	const struct mctp_route *alloc;
	struct mctp_route route = { 0 };
	struct mctp *mctp;

	mctp = mctp_init();
	assert(mctp);

	route.flags = MCTP_ROUTE_FLAG_PROVISIONAL;
	route.type = MCTP_ROUTE_TYPE_LOCAL;
	alloc = mctp_route_allocate(mctp, &route, 1);
	assert(alloc);
	assert(alloc->type == MCTP_ROUTE_TYPE_LOCAL);
	assert(alloc->range.first == 254);
	assert(alloc->range.last == 254);

	mctp_destroy(mctp);
}

void test_mctp_route_query_provisional_one(void)
{
	struct mctp_binding_test *binding;
	const struct mctp_route *alloc;
	struct mctp_route route = { 0 };
	uint8_t data = 0x5a;
	struct mctp *mctp;
	mctp_eid_t dest;
	int rc;

	mctp_test_stack_init(&mctp, &binding, MCTP_EID(8));
	assert(mctp);

	route.flags = MCTP_ROUTE_FLAG_PROVISIONAL;
	route.type = MCTP_ROUTE_TYPE_LOCAL;
	alloc = mctp_route_allocate(mctp, &route, 1);
	assert(alloc);
	dest = mctp_route_as_eid(alloc);
	rc = mctp_message_tx(mctp, dest, &data, sizeof(data));
	assert(!rc);

	assert(binding->pkt);
	assert(((uint8_t *)binding->pkt->data)[0] == 0);
	__mctp_free(binding->pkt);

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void test_rx(mctp_eid_t eid, void *data, void *msg, size_t len)
{
	struct mctp *mctp = data;

	(void)msg;
	(void)len;
	assert(mctp_eid_is_valid(mctp, eid) && !mctp_eid_is_special(mctp, eid));
	assert(eid.flags & MCTP_EID_FLAG_PROVISIONAL);
}

void test_mctp_route_respond_provisional_one(void)
{
	struct mctp_device dev = { .bus = 0, .address = 1 };
	struct mctp_binding_test *binding;
	struct mctp *mctp;

	struct {
		struct mctp_hdr hdr;
		uint8_t payload[1];
	} pktbuf;

	mctp_test_stack_init(&mctp, &binding, MCTP_EID(8));
	assert(mctp);

	mctp_set_rx_all(mctp, test_rx, mctp);

	memset(&pktbuf.hdr, 0, sizeof(pktbuf.hdr));
	pktbuf.hdr.src = 0;
	pktbuf.hdr.dest = 0;
	pktbuf.hdr.flags_seq_tag = MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM;

	mctp_binding_test_rx_raw(binding, &dev, &pktbuf, sizeof(pktbuf));

	mctp_binding_test_destroy(binding);
	mctp_destroy(mctp);
}

static void test_mctp_route_table_allocate_invalid(void)
{
	const struct mctp_route *alloc;
	struct mctp_route route = { 0 };
	struct mctp_eid_range range;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	/* Attempt allocation before dynamic pool is configured */
	alloc = mctp_route_allocate(mctp, &route, 1);
	assert(!alloc);

	/* Configure a single-EID dynamic pool */
	range = (struct mctp_eid_range){ .first = 9, .last = 9 };
	rc = mctp_route_set_dynamic_pool(mctp, &range);
	assert(!rc);

	/* Dynamic pool starts at 9, so overflow the last EID calculation */
	alloc = mctp_route_allocate(mctp, &route, UINT8_MAX);
	assert(!alloc);

	/* Request exceeds the dynamic pool size */
	alloc = mctp_route_allocate(mctp, &route, range.last - range.first + 2);
	assert(!alloc);

	mctp_destroy(mctp);
}

static void test_mctp_route_table_allocate_provisional_overlap(void)
{
	const struct mctp_route *alloc;
	struct mctp_route route = { 0 };
	struct mctp_eid_range range;
	mctp_eid_t peid, feid;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	/* Configure the dynamic pool to cover the first provisional EID */
	range = (struct mctp_eid_range){ .first = 254, .last = 254 };
	rc = mctp_route_set_dynamic_pool(mctp, &range);
	assert(!rc);

	/* Allocate a provisional EID */
	route.flags = MCTP_ROUTE_FLAG_PROVISIONAL;
	route.type = MCTP_ROUTE_TYPE_LOCAL;
	alloc = mctp_route_allocate(mctp, &route, 1);
	assert(alloc);
	peid = mctp_route_as_eid(alloc);
	assert(mctp_eid_is_valid(mctp, peid) &&
	       !mctp_eid_is_special(mctp, peid));
	assert(peid.flags & MCTP_EID_FLAG_PROVISIONAL);

	/* Allocate a formal EID */
	route.flags = 0;
	alloc = mctp_route_allocate(mctp, &route, 1);
	assert(alloc);
	feid = mctp_route_as_eid(alloc);
	assert(mctp_eid_is_valid(mctp, feid) &&
	       !mctp_eid_is_special(mctp, feid));
	assert(!(feid.flags & MCTP_EID_FLAG_PROVISIONAL));

	/* Make sure both coexist and are not equal */
	assert(peid.id == feid.id);
	assert(!mctp_eid_equal(peid, feid));

	mctp_destroy(mctp);
}

static void test_mctp_route_get_by_device_overlap(void)
{
	const struct mctp_route *alloc, *match;
	struct mctp_route route = { 0 };
	struct mctp_eid_range range;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	/* Configure the dynamic pool to cover the first provisional EID */
	range = (struct mctp_eid_range){ .first = 254, .last = 254 };
	rc = mctp_route_set_dynamic_pool(mctp, &range);
	assert(!rc);

	/* Allocate a provisional EID */
	route.flags = MCTP_ROUTE_FLAG_PROVISIONAL;
	route.type = MCTP_ROUTE_TYPE_LOCAL;
	alloc = mctp_route_allocate(mctp, &route, 1);
	assert(alloc);
	assert(mctp_device_equal(&route.device, &alloc->device));
	match = mctp_route_get_by_device(mctp, &route.device);
	assert(mctp_device_equal(&route.device, &match->device));
	assert(match->flags & MCTP_ROUTE_FLAG_PROVISIONAL);
	mctp_route_put(match);

	/* Allocate a formal EID */
	route.flags = 0;
	route.type = MCTP_ROUTE_TYPE_LOCAL;
	alloc = mctp_route_allocate(mctp, &route, 1);
	assert(mctp_device_equal(&route.device, &alloc->device));
	assert(alloc);
	match = mctp_route_get_by_device(mctp, &route.device);
	assert(mctp_device_equal(&route.device, &match->device));
	assert(!(match->flags & MCTP_ROUTE_FLAG_PROVISIONAL));

	/* Assert the provisional route still exists, shadowed by formal */
	route = *match;
	mctp_route_put(match);

	route.flags = MCTP_ROUTE_FLAG_PROVISIONAL;
	match = mctp_route_match(mctp, &route, MCTP_ROUTE_MATCH_ROUTE);
	mctp_route_table_dump(mctp, MCTP_LOG_DEBUG);
	assert(match);
	mctp_route_put(match);

	mctp_destroy(mctp);
}

int main(void)
{
	mctp_set_log_stdio(MCTP_LOG_DEBUG);

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
	test_mctp_route_table_add_notify();
	test_mctp_route_table_remove_notify();
	test_mctp_route_table_allocate_one();
	test_mctp_route_table_allocate_invalid();
	test_mctp_route_table_allocate_one_provisional();
	test_mctp_route_query_provisional_one();
	test_mctp_route_respond_provisional_one();
	test_mctp_route_table_allocate_provisional_overlap();
	test_mctp_route_get_by_device_overlap();

	return 0;
}
