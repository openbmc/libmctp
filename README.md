# libmctp: Implementation of MCTP (DTMF DSP0236)

This library is intended to be a portable implementation of the Management
Component Transport Protocol (MCTP), as defined by DMTF standard "DSP0236", plus
transport binding specifications.

## Target usage

`libmctp` is a library that implements a straightforward MCTP stack. It will be
useful in a two main scenarios:

- where you are implementing MCTP in an embedded device; or
- where you have Linux system:
  - with no kernel MCTP support,
  - need a single application implementing all of the MCTP stack; and
  - you are providing your own hardware drivers for MCTP transports.

Notably, if you are implementing an MCTP application on Linux, you _almost
certainly_ want to use the in-kernel MCTP support, which gives you a standard
sockets-based interface to transmit and receive MCTP messages. When using the
Linux kernel MCTP support, you do not need to use `libmctp` at all, and can use
the sockets directly. `libmctp` does not provide functions to interact with the
kernel MCTP sockets.

There is an overview and example code for the in-kernel support in the [MCTP
kernel docs][kernel-mctp], and a general guide in an [introduction to MCTP on
Linux][mctp-linux-intro] document.

[kernel-mctp]: https://docs.kernel.org/networking/mctp.html
[mctp-linux-intro]:
  https://codeconstruct.com.au/docs/mctp-on-linux-introduction/

## Contact

- Email: See [OWNERS](OWNERS). Please also Cc <openbmc@lists.ozlabs.org>
- Discord: #mctp on <https://discord.gg/69Km47zH98>
- IRC: #openbmc on Freenode

## API/ABI Stability

The APIs and ABI of libmctp are not yet stablised as we continue to explore ways
to present the MCTP protocol to firmware and applications. Please bear with us!

When we approach a complete implementation of DSP0236 we will consider the
suitability of the API/ABI for stabilisation.

In the mean time, we'd like your feedback on the library's suitability for your
environment.

## Core API

To initialise the MCTP stack with a single hardware bus:

- `mctp = mctp_init()`: Initialise the MCTP core
- `binding = mctp_<binding>_init()`: Initialise a hardware binding
- `mctp_register_bus(mctp, binding, eid)`: Register the hardware binding with
  the core, using a predefined EID

Then, register a function call to be invoked when a message is received:

- `mctp_set_rx_all(mctp, function)`: Provide a callback to be invoked when a
  MCTP message is received

Or transmit a message:

- `mctp_message_tx(mctp, message, len)`: Transmit a MCTP message

The binding may require you to notify it to receive packets. For example, for
the serial binding, the `mctp_serial_read()` function should be invoked when the
file-descriptor for the serial device has data available.

### Bridging

libmctp implements basic support for bridging between two hardware bindings. In
this mode, bindings may have different MTUs, so packets are reassembled into
their messages, then the messages are re-packetised for the outgoing binding.

For bridging between two endpoints, use the `mctp_bridge_busses()` function:

- `mctp = mctp_init()`: Initialise the MCTP core
- `b1 = mctp_<binding>_init(); b2 = mctp_<binding>_init()`: Initialise two
  hardware bindings
- `mctp_bridge_busses(mctp, b1, b2)`: Setup bridge

Note that no EIDs are defined here; the bridge does not deliver any messages to
a local rx callback, and messages are bridged as-is.

## Binding API

Hardware bindings provide a method for libmctp to send and receive packets
to/from hardware. A binding defines a hardware specific structure
(`struct mctp_binding_<name>`), which wraps the generic binding
(`struct mctp_binding`):

    struct mctp_binding_foo {
        struct mctp_binding binding;
        /* hardware-specific members here... */
    };

The binding code then provides a method (`_init`) to allocate and initialise the
binding; this may be of any prototype (calling code will know what arguments to
pass):

    struct mctp_binding_foo *mctp_binding_foo_init(void);

or maybe the `foo` binding needs a path argument:

    struct mctp_binding_foo *mctp_binding_foo_init(const char *path);

The binding then needs to provide a function (`_core`) to convert the
hardware-specific struct to the libmctp generic core struct

    struct mctp_binding *mctp_binding_foo_core(struct mctp_binding_foo *b);

(Implementations of this will usually be fairly consistent, just returning
`b->binding`). Callers can then use that generic pointer to register the binding
with the core:

    struct mctp_binding *binding = mctp_binding_foo_core(foo);
    mctp_register_bus(mctp, binding, 8);

## Integration

The libmctp code is intended to be integrated into other codebases by two
methods:

1. as a simple library (`libmctp.{a,so}`) which can be compiled separately and
   linked into the containing project

2. as a set of sources to be included into the containing project (either
   imported, or as a git subtree/submodule)

For (1), you can use the top-level makefile to produce `libmctp.a`.

For (2), the `Makefile.inc` file provides the minimum set of dependencies to
either build libmctp.a, or just the actual object files (`LIBMCTP_OBS`), which
you can include into your existing make definitions. You'll want to set
`LIBMTCP_DIR` to refer to the subdirectory that contains that makefile, so we
can set the correct paths to sources.

## Environment configuration

This library is intended to be portable to be used in a range of environments,
but the main targets are:

- Linux userspace, typically for BMC use-cases
- Low-level firmware environments

For the latter, we need to support customisation of the functions that libmctp
uses (for example, POSIX file IO is not available).

In order to support these, we have a few compile-time definitions:

- `MCTP_HAVE_FILEIO`: define if POSIX file io is available, allowing the serial
  hardware binding to access char devices for IO.

- `MCTP_HAVE_SYSLOG`: allow logging to syslog, through the `vsyslog` call.

- `MCTP_DEFAULT_ALLOC`: set default allocator functions (malloc, free, realloc),
  so that applications do not have to provide their own.

## TODO

- Partial packet queue transmit
- Control messages
- Message- and packet-buffer pools and preallocation
- C++ API
- Non-file-based serial binding
