#ifndef _CONTAINER_OF_H
#define _CONTAINER_OF_H

#ifndef container_of
#define container_of(ptr, type, member)                                        \
	(type *)((char *)(ptr) - offsetof(type, member))
#endif

#endif
