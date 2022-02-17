/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include "libmctp.h"
#include "libmctp-serial.h"

static void rx_message(uint8_t eid, void *data, void *msg, size_t len)
{
	ssize_t rc;
	(void)eid;
	(void)data;

	rc = write(STDOUT_FILENO, msg, len);
	if (rc < 0)
		warn("Write failed");
	else if ((size_t)rc < len)
		warnx("Short write of length %zd, requested %zd", rc, len);
}

int main(void)
{
	struct mctp_binding_serial *serial;
	struct mctp *mctp;
	int rc;

	mctp = mctp_init();
	assert(mctp);

	serial = mctp_serial_init();
	assert(serial);

	mctp_serial_open_fd(serial, STDIN_FILENO);

	mctp_register_bus(mctp, mctp_binding_serial_core(serial), 8);

	mctp_set_rx_all(mctp, rx_message, NULL);

	for (;;) {
		rc = mctp_serial_read(serial);
		if (rc)
			break;
	}

	return EXIT_SUCCESS;

}
