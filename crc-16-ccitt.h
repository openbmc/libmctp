/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _CRC_16_CCITT_H
#define _CRC_16_CCITT_H

#include <stdint.h>

#define FCS_INIT_16 0xFFFF /* Initial FCS value */

uint16_t crc_16_ccitt(uint16_t fcs, const uint8_t *cp, uint32_t len);

uint16_t crc_16_ccitt_byte(uint16_t fcs, const uint8_t c);

#endif
