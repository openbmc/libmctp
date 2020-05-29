# Management Component Transport Protocol (MCTP) LPC Transport Binding Specification for ASPEED BMC Systems

## Scope

This design provides an efficient method to transfer MCTP packets between the
host and BMC over the LPC bus on ASPEED BMC platforms.

## Normative References

The following referenced documents are indispensable for the application of
this document.

DMTF DSP0236, Management Component Transport Protocol (MCTP) Base Specification
1.0,
http://www.dmtf.org/standards/published_documents/DSP0236_1.0.pdf

Intel (R) Low Pin Count (LPC) Interface Specification 1.1,
https://www.intel.com/content/dam/www/program/design/us/en/documents/low-pin-count-interface-specification.pdf

IPMI Consortium, Intelligent Platform Management Interface Specification, v1.5
Revision 1.1 February 20, 2002,
http://download.intel.com/design/servers/ipmi/IPMIv1_5rev1_1.pdf

## Terms and Definitions

### Keyboard Controller Style Interface (KCS)

A set of bit definitions, and operation of the registers typically used in
keyboard microcontrollers and embedded controllers. The term "Keyboard
Controller Style" reflects that the register definition was originally used as
the legacy "8742" keyboard controller interface in PC architecture computer
systems.  This interface is available built-in to several commercially
available microcontrollers. Data is transferred across the KCS interface using
a per-byte handshake.

### Low Pin Count (LPC)

A bus specification that implements ISA bus in a reduced physical form while
extending ISA's capabilities.

### LPC Firmware Cycles (LPC FW)

LPC firmware cycles allow separate boot BIOS firmware memory cycles and
application memory cycles with respect to the LPC bus. The ASPEED BMCs allow
remapping of the LPC firmware cycles onto arbitrary regions of the BMC's
physical address space, including RAM.

## MCTP over LPC Transport

The basic components used for the transfer are:

* A window of the LPC FW address space, where reads and writes are forwarded to
  BMC memory, using the LPC2AHB hardware
* An interrupt mechanism using the IPMI KCS interface

In order to transfer a packet, either side of the channel (BMC or host) will:

1. Write the packet to the LPC FW window
   * The BMC will perform writes by writing to the memory backing the LPC
     window
   * The host will perform writes by writing to the LPC bus, at predefined
     addresses
2. Trigger an interrupt on the remote side, by writing to the KCS data buffer

On this indication, the remote side will:

1. Read from the KCS status register, which shows that the single-byte KCS data
   buffer is full
2. Read the MCTP packet from the LPC FW window
3. Read from the KCS buffer, to clear the 'buffer full' state.

### Scope

The document limits itself to describing the operation of the binding protocol.
The following issues of protocol ABI are considered out of scope:

1. The LPC IO address and Serial IRQ parameters of the KCS device
2. The concrete location of the control region in the LPC FW address space

### LPC FW Window Layout

The window of BMC-memory-backed LPC FW address space has a predefined format,
consisting of:

* A control descriptor, describing static data about the rest of the window
* A receive area for BMC-to-host packets
* A transmit area, for host-to-BMC packets

The control descriptor contains a version, and offset and size data for the
transmit and receive areas. These offsets are relative to the start of the LPC
FW window.

Full definition of the control area is defined below, and it will be the base
for all future versions.

```
struct mctp_lpcmap_hdr {
   uint32_t magic;

   uint16_t bmc_ver_min;
   uint16_t bmc_ver_cur;
   uint16_t host_ver_min;
   uint16_t host_ver_cur;
   uint16_t negotiated_ver;
   uint16_t pad0;

   uint32_t rx_offset;
   uint32_t rx_size;
   uint32_t tx_offset;
   uint32_t tx_size;
} __attribute__((packed));
```

Where the magic value marking the beginning of the control area is the ASCII
encoding of "MCTP":

```
#define LPC_MAGIC 0x4d435450
```

The transmit and receive areas contain a length field, followed by the actual
MCTP packet to be transferred. At version 1, only a single MCTP packet is
present in the Rx and Tx areas. This may change for future versions of the
protocol.

All control data is in big-endian format. MCTP packet data is transferred
exactly as is presented, and no data escaping is performed.

### KCS Control

The KCS hardware on the ASPEED BMCs is used as a method of indicating, to the
remote side, that a packet is ready to be transferred through the LPC FW
mapping.

The KCS hardware consists of two single-byte buffers: the Output Data Register
(ODR) and the Input Data Register (IDR). The ODR is written by the BMC and read
by the host. The IDR is the obverse.

The KCS unit also contains a status register, allowing both host and BMC to
determine if there is data in the ODR or IDR. These are single-bit flags,
designated Input/Output Buffer Full (IBF/OBF), and are automatically set by
hardware when data has been written to the corresponding ODR/IDR buffer (and
cleared when data has been read).

We use these flags to determine whether data in the LPC window is available to
be consumed.

#### KCS Status Register Layout

| Bit | Managed By | Description |
|-----|------------|-------------|
|  7  |  Software  | (MSB) BMC Active  |
|  6  |  Software  | Channel active, version negotiated |
|  5  |  Software  | Unused      |
|  4  |  Software  | Unused      |
|  3  |  Hardware  | Command / Data |
|  2  |  Software  | Unused      |
|  1  |  Hardware  | Input Buffer Full |
|  0  |  Hardware  | (LSB) Output Buffer Full |

#### KCS Data Register Commands

| Command | Description |
|---------|-------------|
|  0x00   | Initialise  |
|  0x01   | Tx Begin    |
|  0x02   | Rx Complete |
|  0xff   | Dummy Value |

### General Protocol Behaviours

* The BMC writes to the status register
  * The hardware triggers a host interrupt
  * The host reads the status register for BMC operating state transitions
* The host writes to the data register
  * The hardware triggers a BMC interrupt
  * The BMC reads the status register for IBF (this is the only bit that may
    change)
  * If IBF is set, the BMC reads the data register for buffer state transitions
* The BMC writes to the data register
  * The hardware triggers a Host interrupt
  * The host reads the status register for OBF (this is the only bit that may
    change)
  * If OBF is set, the host reads the data register for buffer state
    transitions
* Some KCS hardware implementations may only trigger an interrupt from ODR
  events (and not status update). The `0xff` dummy value allows either side of
  the KCS interface to trigger a data-register interrupt by performing a dummy
  write

#### LPC Window Ownership and Synchronisation

Because the LPC FW window is shared between the host and the BMC we need
strict rules on which entity is allowed to access it at specific times.

Firstly, we have rules for modification:

* The control data is only written during initialisation. Only the BMC may
  write to the control area, except the host-version fields. The control area
  is never modified once the channel is active.
* Only the BMC may write to the Rx buffer described in the control area
* Only the host may write to the Tx buffer described in the control area

During packet transmission, the follow sequence occurs:

* The Tx side writes the packet to its Tx buffer
* The Tx side sends a `Tx Begin` message, indicating that the buffer ownership
  is transferred
* The Rx side now owns the buffer, and reads the message from its Rx area
* The Rx side sends a `Rx Complete` once done, indicating that the buffer
  ownership is transferred back to the Tx side.

### LPC Binding Operation

The binding operation is not symmetric as the BMC is the only side that can
drive the status register. Each side's initialisation sequence is outlined
below.

#### BMC Initialisation Sequence

| Step | Description                                                      |
|------|------------------------------------------------------------------|
|  1   | The BMC initialises the control area: magic value, BMC versions and buffer parameters |
|  2   | The BMC sets the BMC active bit and triggers the host interrupt  |

#### Host initialisation Sequence

| Step | Description                                                      |
|------|------------------------------------------------------------------|
|  1   | Wait for the BMC to indicate active via the KCS status register  |
|  2   | Populate the host version fields                                 |
|  3   | Send the `Initialise` message via KCS                            |
|  4   | The hardware sets the IBF flag in the status register            |
|  5   | The KCS interrupt is triggered on the BMC                        |
|  6   | The BMC reads the KCS status and data registers                  |
|  7   | The hardware clears IBF and de-asserts the KCS IRQ               |
|  8   | The BMC calculates the negotiated version                        |
|  9   | The BMC sets the `Channel Active` bit in the KCS status register |
|  10  | The KCS interrupt is triggered on the host                       |
|  11  | The host reads the KCS status and data registers                 |
|  12  | The hardware clears OBF and de-asserts the host KCS IRQ          |
|  13  | The host observes that `Channel Active` is set in the KCS status register |
|  14  | The host reads the negotiated version                            |

#### Host Packet Transmission Sequence

| Step | Description                                                      |
|------|------------------------------------------------------------------|
|  1   | The host waits on the previous `Rx Complete` message             |
|  2   | The host waits on `BMC Active` and `Channel Active` in the KCS status register |
|  3   | The host writes the packet to its Tx area (BMC Rx area)          |
|  4   | The host sends the `Tx Begin` command via the KCS interface, transferring ownership of its Tx buffer to the BMC |
|  5   | The hardware sets the IBF flag in the KCS status register        |
|  6   | The KCS interrupt is triggered on the BMC                        |
|  7   | The BMC reads the KCS status and data registers                  |
|  8   | The hardware clears IBF and de-asserts the KCS IRQ               |
|  9   | The BMC observes IBF is set and the command is `Tx Begin`        |
|  10  | The BMC reads the packet from the BMC Rx area (host Tx area)     |
|  11  | The BMC sends the `Rx Complete` command via the KCS interface    |
|  12  | The hardware sets the OBF flag in the KCS status register        |
|  13  | The KCS interrupt is triggered on the host                       |
|  14  | The host reads the KCS status and data registers                 |
|  15  | The hardware clears OBF and de-asserts the host KCS IRQ          |
|  16  | The host observes OBF is set and the command is `Rx Complete`    |
|  17  | The host regains ownership of its Tx buffer                      |

#### BMC Packet Transmission Sequence

| Step | Description                                                      |
|------|------------------------------------------------------------------|
|  1   | The BMC waits on the previous `Rx Complete` message              |
|  2   | The BMC writes the packet to its Tx area (host Rx area)          |
|  3   | The BMC sends the `Tx Begin` command via the KCS interface, transferring ownership of its Tx buffer to the host |
|  4   | The hardware sets the OBF flag in the KCS status register        |
|  5   | The KCS interrupt is triggered on the host                       |
|  6   | The host reads the KCS status and data registers                 |
|  7   | The hardware clears OBF and de-asserts the KCS IRQ               |
|  8   | The host observes OBF is set and the command is `Tx Begin`       |
|  9   | The host reads the packet from the host Rx area (BMC Tx area)    |
|  10  | The host sends the `Rx Complete` command via the KCS interface   |
|  11  | The hardware sets the IBF flag in the KCS status register        |
|  12  | The KCS interrupt is triggered on the BMC                        |
|  13  | The BMC reads the KCS status and data registers                  |
|  14  | The hardware clears IBF and de-asserts the BMC KCS IRQ           |
|  15  | The BMC observes IBF is set and the command is `Rx Complete`.    |
|  16  | The BMC regains ownership of its Tx buffer                       |

## Alternatives Considered

### The KCS MCTP Binding (DSP0254)

The KCS hardware (used as the full transfer channel) can be used to transfer
arbitrarily-sized MCTP messages. However, there are much larger overheads in
synchronisation between host and BMC for every byte transferred.

### The MCTP Serial Binding (DSP0253)

We could use the VUART hardware to transfer the MCTP packets according to the
existing MCTP Serial Binding. However, the VUART device is already used for
console data. Multiplexing both MCTP and console would be an alternative, but
the complexity introduced would make low-level debugging both more difficult
and less reliable.

### The BT interface

The BT interface allows for block-at-time transfers. However, the BT buffer
size is only 64 bytes on the AST2500 hardware, which does not allow us to
comply with the MCTP Base Specification (DSP0236) that requires a 64-byte
payload size as the minimum. The 64-byte BT buffer does not allow for MCTP and
transport headers.

Additionally, we would like to develop the MCTP channel alongside the existing
IPMI interfaces, to allow a gradual transition from IPMI to MCTP. As the BT
channel is already used on OpenPOWER systems for IPMI transfers, we would not
be able to support both in parallel.

### Using the AST2500 LPC Mailbox

This would require enabling the SuperIO interface, which allows the host to
access the entire BMC address space, and so introduces security
vulnerabilities.
