/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_ALLOC_H
#define _LIBMCTP_ALLOC_H

#include <stdlib.h>

struct mctp;

void *__mctp_alloc(size_t size);
void __mctp_free(void *ptr);

void *__mctp_msg_alloc(size_t size, struct mctp *mctp);
void __mctp_msg_free(void *ptr, struct mctp *mctp);

#endif /* _LIBMCTP_ALLOC_H */
