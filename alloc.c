/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>

#include "libmctp.h"
#include "libmctp-alloc.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "compiler.h"

#if defined(MCTP_DEFAULT_ALLOC) && defined(MCTP_CUSTOM_ALLOC)
#error Default and Custom alloc are incompatible
#endif

#ifdef MCTP_DEFAULT_ALLOC
static void *default_msg_malloc(size_t size, void *ctx __unused)
{
	void *ptr = __mctp_alloc(size);
	return ptr;
}

static void default_msg_free(void *msg, void *ctx __unused)
{
	__mctp_free(msg);
}
#endif

/* Allocators provided as functions to call */
#ifdef MCTP_CUSTOM_ALLOC
extern void *mctp_custom_malloc(size_t size);
extern void mctp_custom_free(void *ptr);
extern void *mctp_custom_msg_alloc(size_t size, void *ctx);
extern void mctp_custom_msg_free(void *msg, void *ctx);
#endif

#ifdef MCTP_CUSTOM_ALLOC
const
#endif
	struct {
	void *(*m_alloc)(size_t);
	void (*m_free)(void *);
	/* Final argument is ctx */
	void *(*m_msg_alloc)(size_t, void *);
	void (*m_msg_free)(void *, void *);
} alloc_ops = {
#ifdef MCTP_DEFAULT_ALLOC
	malloc,
	free,
	default_msg_malloc,
	default_msg_free,
#endif
#ifdef MCTP_CUSTOM_ALLOC
	mctp_custom_malloc,
	mctp_custom_free,
	mctp_custom_msg_alloc,
	mctp_custom_msg_free,
#endif
};

/* internal-only allocation functions */
void *__mctp_alloc(size_t size)
{
	if (alloc_ops.m_alloc)
		return alloc_ops.m_alloc(size);
	assert(0);
	return NULL;
}

void __mctp_free(void *ptr)
{
	if (alloc_ops.m_free)
		alloc_ops.m_free(ptr);
	else
		assert(0);
}

void *__mctp_msg_alloc(size_t size, struct mctp *mctp)
{
	void *ctx = mctp_get_alloc_ctx(mctp);
	if (alloc_ops.m_msg_alloc)
		return alloc_ops.m_msg_alloc(size, ctx);
	assert(0);
	return NULL;
}

void __mctp_msg_free(void *ptr, struct mctp *mctp)
{
	void *ctx = mctp_get_alloc_ctx(mctp);
	if (alloc_ops.m_msg_free)
		alloc_ops.m_msg_free(ptr, ctx);
}

#ifndef MCTP_CUSTOM_ALLOC
void mctp_set_alloc_ops(void *(*m_alloc)(size_t), void (*m_free)(void *),
			void *(*m_msg_alloc)(size_t, void *),
			void (*m_msg_free)(void *, void *))
{
	alloc_ops.m_alloc = m_alloc;
	alloc_ops.m_free = m_free;
	alloc_ops.m_msg_alloc = m_msg_alloc;
	alloc_ops.m_msg_free = m_msg_free;
}
#endif // MCTP_CUSTOM_ALLOC
