/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_LOG_H
#define _LIBMCTP_LOG_H

/* libmctp-internal logging */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef MCTP_NOLOG

__attribute__((format(printf, 2, 3))) static inline void
mctp_prlog(int level __unused, const char *fmt __unused, ...)
{
}

#else

void mctp_prlog(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

#endif

#ifndef pr_fmt
#define pr_fmt(x) x
#endif

#define mctp_prerr(fmt, ...)                                                   \
	mctp_prlog(MCTP_LOG_ERR, pr_fmt(fmt), ##__VA_ARGS__)
#define mctp_prwarn(fmt, ...)                                                  \
	mctp_prlog(MCTP_LOG_WARNING, pr_fmt(fmt), ##__VA_ARGS__)
#define mctp_prinfo(fmt, ...)                                                  \
	mctp_prlog(MCTP_LOG_INFO, pr_fmt(fmt), ##__VA_ARGS__)
#define mctp_prdebug(fmt, ...)                                                 \
	mctp_prlog(MCTP_LOG_DEBUG, pr_fmt(fmt), ##__VA_ARGS__)

#endif /* _LIBMCTP_LOG_H */
