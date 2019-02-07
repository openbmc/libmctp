
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
	(void)eid;
	(void)data;
	write(STDOUT_FILENO, msg, len);
}

int main(void)
{
	struct mctp_binding_serial *serial[2];
	mctp_eid_t eids[] = {8, 9};
	struct pollfd pollfds[3];
	struct mctp *mctp[2];
	int rc, mctp_fds[2];

	mctp[0] = mctp_init();
	mctp[1] = mctp_init();

	assert(mctp[0] && mctp[1]);

	serial[0] = mctp_serial_init();
	serial[1] = mctp_serial_init();

	assert(serial[0] && serial[1]);

	rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, mctp_fds);
	if (rc)
		err(EXIT_FAILURE, "Can't create sockets");

	mctp_serial_open_fd(serial[0], mctp_fds[0]);
	mctp_serial_open_fd(serial[1], mctp_fds[1]);

	mctp_serial_register_bus(serial[0], mctp[0], eids[0]);
	mctp_serial_register_bus(serial[1], mctp[1], eids[1]);

	mctp_set_rx_all(mctp[1], rx_message, NULL);

	pollfds[0].fd = mctp_fds[0];
	pollfds[0].events = POLLIN;
	pollfds[1].fd = mctp_fds[1];
	pollfds[1].events = POLLIN;
	pollfds[2].fd = STDIN_FILENO;
	pollfds[2].events = POLLIN;

	for (;;) {
		uint8_t buf[1024];

		rc = poll(pollfds, 3, 0);
		if (rc < 0)
			return EXIT_FAILURE;

		if (pollfds[0].revents)
			mctp_serial_read(serial[0]);
		if (pollfds[1].revents)
			mctp_serial_read(serial[1]);
		if (pollfds[2].revents) {
			rc = read(STDIN_FILENO, buf, sizeof(buf));
			if (rc == 0)
				break;
			else if (rc < 0)
				err(EXIT_FAILURE, "read");
			mctp_message_tx(mctp[0], eids[1], buf, rc);
		}
	}

	return EXIT_SUCCESS;

}
