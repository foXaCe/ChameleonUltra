/**
 * @file crc_utils.h
 * @brief CRC calculation utilities optimized for Chameleon Ultra
 * @author Chameleon Ultra Team
 * 
 * This file provides CRC calculation utilities for ISO14443A protocol
 */

#ifndef __CRC_UTILS_H
#define __CRC_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Calculate CRC16 for ISO14443A protocol using lookup table method
 * 
 * This function calculates the CRC16 checksum according to ISO14443A standard.
 * It uses a lookup table implementation optimized for Chameleon Ultra hardware.
 *
 * @param data Pointer to input data buffer
 * @param length Length of data in bytes
 * @param output Pointer to output buffer (must be at least 2 bytes)
 * @note Output is written in little-endian format
 */
void calc_14a_crc_lut(uint8_t *data, int length, uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif /* __CRC_UTILS_H */
