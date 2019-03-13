
CC = gcc
AR = ar
CFLAGS = -Wall -Wextra -Werror -ggdb
CPPFLAGS = -DMCTP_LOG_STDERR -DMCTP_FILEIO -I$(LIBMCTP_DIR)

LIBMCTP_DIR=./

include Makefile.inc

all: $(LIBMCTP)

libmctp.a:
	$(AR) rcsTPD $@ $^

utils/%: utils/%.o libmctp.a
	$(LINK.o) -o $@ $^

clean:
	rm -f $(LIBMCTP)
	rm -f $(LIBMCTP_OBJS)
	rm -f tests/*.o
