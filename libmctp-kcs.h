
/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_KCS_H
#define _LIBMCTP_KCS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libmctp.h>

#include <stdint.h>

//
// IPMI KCS Interface Status Bits
//
#define IPMI_KCS_OBF	      (1 << 0)
#define IPMI_KCS_IBF	      (1 << 1)
#define IPMI_KCS_SMS_ATN      (1 << 2)
#define IPMI_KCS_COMMAND_DATA (1 << 3)
#define IPMI_KCS_OEM1	      (1 << 4)
#define IPMI_KCS_OEM2	      (1 << 5)
#define IPMI_KCS_S0	      (1 << 6)
#define IPMI_KCS_S1	      (1 << 7)

//
// IPMI KCS Interface Control Codes
//
#define IPMI_KCS_CONTROL_CODE_GET_STATUS_ABORT 0x60
#define IPMI_KCS_CONTROL_CODE_WRITE_START      0x61
#define IPMI_KCS_CONTROL_CODE_WRITE_END	       0x62
#define IPMI_KCS_CONTROL_CODE_READ	       0x68

//
// Status Codes
//
#define IPMI_KCS_STATUS_NO_ERROR     0x00
#define IPMI_KCS_STATUS_ABORT	     0x01
#define IPMI_KCS_STATUS_ILLEGAL	     0x02
#define IPMI_KCS_STATUS_LENGTH_ERROR 0x06
#define IPMI_KCS_STATUS_UNSPECIFIED  0xFF

//
// KCS Interface State Bit
//
typedef enum {
	IpmiKcsIdleState = 0,
	IpmiKcsReadState,
	IpmiKcsWriteState,
	IpmiKcsErrorState
} IPMI_KCS_STATE;

#define IPMI_KCS_GET_STATE(s) (s >> 6)
#define IPMI_KCS_SET_STATE(s) (s << 6)

// According to SMBUS spec, the polynomial is:
// C(x) = X^8 + X^2 + X^1 + 1, which is 0x107,
// just ignore bit8 in definition.
#define MCTP_KCS_PACKET_ERROR_CODE_POLY 0x07

#define MCTP_KCS_NETFN_LUN			0xb0
#define DEFINING_BODY_DMTF_PRE_OS_WORKING_GROUP 0x01

#define IPMI_KCS_TIMEOUT_US	 1000
#define IPMI_KCS_FULL_TIMEOUT_US 5000000

struct mctp_binding_kcs;

enum mctp_binding_kcs_reg {
	MCTP_KCS_REG_DATA = 0,
	MCTP_KCS_REG_STATUS = 1,
};

struct mctp_binding_kcs *mctp_kcs_init(void);

void mctp_kcs_destroy(struct mctp_binding_kcs *kcs);

struct mctp_binding *mctp_binding_kcs_core(struct mctp_binding_kcs *b);

int mctp_kcs_poll(struct mctp_binding_kcs *kcs);

struct mctp_binding_kcs *mctp_kcs_init_fileio(void);

struct pollfd;
int mctp_kcs_init_pollfd(struct mctp_binding_kcs *kcs, struct pollfd *pollfd);

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_KCS_H */
