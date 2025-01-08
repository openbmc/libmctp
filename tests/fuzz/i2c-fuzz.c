#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <endian.h>

#include "compiler.h"
#include "libmctp.h"
#include "libmctp-i2c.h"
#include "libmctp-sizes.h"
#include "libmctp-alloc.h"

#if NDEBUG
static_assert(0, "fuzzing shouldn't build with NDEBUG");
#endif

/* Limits memory used in tx path */
#define MAX_SEND 600

/* Avoids wasting time traversing unreachable sizes */
#define MAX_RECEIVE 30

static const size_t FUZZCTRL_SIZE = 0x400;

static const uint8_t RX_CHANCE = 90;
static const uint8_t TX_BUSY_CHANCE = 3;

static const uint8_t OWN_I2C_ADDR = 0x20;
static const uint8_t OWN_EID = 123;

/* time step in milliseconds */
static const uint32_t MAX_TIME_STEP = 15000;

struct fuzz_buf {
	size_t len;
	size_t pos;
	const uint8_t *data;
};

struct fuzz_ctx {
	struct fuzz_buf *ctrl;
	struct fuzz_buf *input;

	struct mctp_binding_i2c *i2c;
	struct mctp *mctp;

	uint64_t now;

	bool done;
};

static struct fuzz_buf *fuzz_buf_new(const void *data, size_t len)
{
	struct fuzz_buf *buf = malloc(sizeof(struct fuzz_buf));
	buf->pos = 0;
	buf->len = len;
	buf->data = data;
	return buf;
}

static const void *fuzz_buf_extract(struct fuzz_buf *buf, size_t len)
{
	if (buf->pos + len > buf->len) {
		return NULL;
	}

	const void *ret = &buf->data[buf->pos];
	buf->pos += len;
	return ret;
}

/* Returns true on success */
static bool fuzz_buf_extract_u32(struct fuzz_buf *buf, uint32_t *ret)
{
	const void *r = fuzz_buf_extract(buf, sizeof(uint32_t));
	if (!r) {
		return false;
	}

	uint32_t v;
	memcpy(&v, r, sizeof(v));
	*ret = be32toh(v);
	return true;
}

/* Returns true with roughly `percent` chance */
static bool fuzz_chance(struct fuzz_ctx *ctx, uint8_t percent)
{
	assert(percent <= 100);

	const uint8_t *v = fuzz_buf_extract(ctx->ctrl, sizeof(uint8_t));
	if (!v) {
		return false;
	}

	uint8_t cutoff = (uint32_t)percent * UINT8_MAX / 100;
	return *v <= cutoff;
}

static int fuzz_i2c_tx(const void *buf, size_t len, void *c)
{
	struct fuzz_ctx *ctx = c;
	(void)buf;
	(void)len;

	if (fuzz_chance(ctx, TX_BUSY_CHANCE)) {
		return -EBUSY;
	}

	return 0;
}

static void fuzz_i2c_rxmsg(uint8_t src_eid, bool tag_owner, uint8_t msg_tag,
			   void *c, void *msg, size_t len)
{
	struct fuzz_ctx *ctx = c;
	(void)ctx;
	(void)src_eid;
	(void)tag_owner;
	(void)msg_tag;
	(void)msg;
	(void)len;
}

static void do_rx(struct fuzz_ctx *ctx)
{
	uint32_t len;
	if (!fuzz_buf_extract_u32(ctx->ctrl, &len)) {
		ctx->done = true;
		return;
	}

	if (len > MAX_RECEIVE) {
		ctx->done = true;
		return;
	}

	const uint8_t *data = fuzz_buf_extract(ctx->input, len);
	if (!data) {
		ctx->done = true;
		return;
	}

	mctp_i2c_rx(ctx->i2c, data, len);
}

static void do_tx(struct fuzz_ctx *ctx)
{
	int rc;

	const uint8_t *e = fuzz_buf_extract(ctx->ctrl, sizeof(uint8_t));
	if (!e) {
		ctx->done = true;
		return;
	}
	mctp_eid_t eid = *e;

	bool tag_owner = fuzz_chance(ctx, 50);
	/* `t` generates the dest eid in owner case, or tag in non-owner case */
	const uint8_t *t = fuzz_buf_extract(ctx->ctrl, sizeof(uint8_t));
	if (!t) {
		ctx->done = true;
		return;
	}

	uint32_t len;
	if (!fuzz_buf_extract_u32(ctx->ctrl, &len)) {
		ctx->done = true;
		return;
	}
	len = len % (MAX_SEND + 1);

	uint8_t *fake_send_data = __mctp_msg_alloc(len, ctx->mctp);

	mctp_i2c_tx_poll(ctx->i2c);

	if (tag_owner) {
		/* Random destination from a small set, reuse `t` */
		mctp_eid_t dest = 10 + (*t % 5);
		uint8_t tag;
		rc = mctp_message_tx_request(ctx->mctp, dest, fake_send_data,
					     len, &tag);
		if (rc == 0) {
			assert((tag & MCTP_HDR_TAG_MASK) == tag);
		}
	} else {
		uint8_t tag = *t % 8;
		mctp_message_tx_alloced(ctx->mctp, eid, tag_owner, tag,
					fake_send_data, len);
	}
}

static uint64_t fuzz_now(void *c)
{
	struct fuzz_ctx *ctx = c;

	uint32_t step = 10;
	uint32_t s;
	if (fuzz_buf_extract_u32(ctx->ctrl, &s)) {
		step = s % (MAX_TIME_STEP + 1);
	}

	uint64_t prev = ctx->now;
	ctx->now += step;
	/* Notice if overflow occurs */
	assert(ctx->now >= prev);
	return ctx->now;
}

int LLVMFuzzerTestOneInput(uint8_t *input, size_t len)
{
	/* Split input into two parts. First FUZZCTRL_SIZE (0x400 bytes currently)
     * is used for fuzzing control (random choices etc).
     * The remainder is a PLDM packet stream, of length:data */
	if (len < FUZZCTRL_SIZE) {
		return 0;
	}

	struct fuzz_ctx _ctx = {
		.ctrl = fuzz_buf_new(input, FUZZCTRL_SIZE),
		.input = fuzz_buf_new(&input[FUZZCTRL_SIZE],
				      len - FUZZCTRL_SIZE),
		.now = 0,
		.done = false,
	};
	struct fuzz_ctx *ctx = &_ctx;

	/* Instantiate the MCTP stack */
	ctx->i2c = malloc(MCTP_SIZEOF_BINDING_I2C);
	mctp_i2c_setup(ctx->i2c, OWN_I2C_ADDR, fuzz_i2c_tx, ctx);
	ctx->mctp = mctp_init();
	mctp_register_bus(ctx->mctp, mctp_binding_i2c_core(ctx->i2c), OWN_EID);
	mctp_set_rx_all(ctx->mctp, fuzz_i2c_rxmsg, ctx);
	mctp_set_now_op(ctx->mctp, fuzz_now, ctx);

	while (!ctx->done) {
		if (fuzz_chance(ctx, RX_CHANCE)) {
			do_rx(ctx);
		} else {
			do_tx(ctx);
		}
	}

	mctp_destroy(ctx->mctp);
	free(ctx->i2c);
	free(ctx->ctrl);
	free(ctx->input);

	return 0;
}

int LLVMFuzzerInitialize(int *argc __unused, char ***argv __unused)
{
	return 0;
}

#ifdef HFND_FUZZING_ENTRY_FUNCTION
#define USING_HONGGFUZZ 1
#else
#define USING_HONGGFUZZ 0
#endif

#ifdef __AFL_FUZZ_TESTCASE_LEN
#define USING_AFL 1
#else
#define USING_AFL 0
#endif

#if USING_AFL
__AFL_FUZZ_INIT();
#endif

#if !USING_AFL && !USING_HONGGFUZZ
/* Let it build without AFL taking stdin instead */
static void run_standalone()
{
	while (true) {
		unsigned char buf[1024000];
		ssize_t len = read(STDIN_FILENO, buf, sizeof(buf));
		if (len <= 0) {
			break;
		}
		LLVMFuzzerTestOneInput(buf, len);
	}
}
#endif

#if !USING_HONGGFUZZ
int main(int argc, char **argv)
{
	LLVMFuzzerInitialize(&argc, &argv);

#if USING_AFL
	__AFL_INIT();
	uint8_t *buf = __AFL_FUZZ_TESTCASE_BUF;

	while (__AFL_LOOP(100000)) {
		size_t len = __AFL_FUZZ_TESTCASE_LEN;
		LLVMFuzzerTestOneInput(buf, len);
	}
#else
	run_standalone();
#endif

	return 0;
}
#endif // !USING_HONGGFUZZ
