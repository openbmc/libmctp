libmctp: Implementation of MCTP (DTMF DSP0236)
==============================================

This library is intended to be a portable implementation of the Management
Component Transport Protocol (MCTP), as defined by DMTF standard "DSP0236",
plus transport binding specifications.

Currently, the library is is only at prototyping stage. Interfaces will likely
change, and are missing lots of components of the standard.

Core API
--------

To initialise the MCTP stack with a single hardware bus:

 * `mctp = mctp_init()`: Initialise the MCTP core
 * `binding = mctp_<binding>_init()`: Initialise a hardware binding
 * `mctp_register_bus(mctp, binding, eid)`: Register the hardware binding with
   the core, using a predefined EID

Then, register a function call to be invoked when a message is received:

 * `mctp_set_rx_all(mctp, function)`: Provide a callback to be invoked when a
   MCTP message is received

Or transmit a message:

 * `mctp_message_tx(mctp, message, len)`: Transmit a MCTP message

The binding may require you to notify it to receive packets. For example,
for the serial binding, the `mctp_serial_read()` function should be invoked
when the file-descriptor for the serial device has data available.

Environment configuration
-------------------------

This library is intended to be portable to be used in a range of environments,
but the main targets are:

  - Linux userspace, typically for BMC use-cases
  - Low-level firmware environments

For the latter, we need to support customisation of the functions that libmctp
uses (for example, POSIX file IO is not available).

In order to support these, we have a couple of compile-time definitions:

 - `MCTP_FILEIO`: define if POSIX file io is available, allowing the
   serial hardware binding to access char devices for IO.

 - `MCTP_LOG_`: allows selection of a logging backend. Currently available
   are:

    - `MCTP_LOG_STDERR`: use `fprintf(stderr, ...)` for log output

    - `MCTP_LOG_SYSLOG`: use `syslog()` for log output

    - `MCTP_LOG_CUSTOM`: provide your own macro for logging, of
      the format: ```#define mctp_prlog(level, fmt, ...) (....)```

TODO
----

 - Partial packet queue transmit
 - Control messages
 - Message- and packet-buffer pools and preallocation
 - C++ API
 - Non-file-based serial binding
