
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

test_util_objs = tests/test-utils.o

tests = test_eid test_seq

test_targets = $(tests:%=tests/%)

$(test_targets): $(test_util_objs) libmctp.a

$(test_targets): %: %.o
	$(LINK.o) -o $@ $^

check: $(test_targets)
	for t in $(test_targets); do echo $$t; $$t || exit 1; done

.PHONY: check

clean:
	rm -f $(LIBMCTP)
	rm -f $(LIBMCTP_OBJS)
	rm -f tests/*.o
