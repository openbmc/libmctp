LIBMCTP_DIR ?= libmctp/
LIBMCTP_OBJS = core.o alloc.o serial.o

LIBMCTP = $(LIBMCTP_DIR)libmctp.a

$(LIBMCTP): $(LIBMCTP_OBJS:%=$(LIBMCTP_DIR)%)
