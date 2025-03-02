/**
 * @file hex_utils.h
 * @brief Hex conversion utilities optimized for Chameleon Ultra
 * @author Chameleon Ultra Team
 * 
 * Utilities for converting between numbers and byte arrays
 */

#ifndef __HEX_UTILS_H
#define __HEX_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Convert uint64_t value to byte array in big-endian format
 * 
 * @param n Value to convert
 * @param len Number of bytes to write (1-8)
 * @param dest Destination buffer (must be at least len bytes)
 */
void num_to_bytes(uint64_t n, uint8_t len, uint8_t *dest);

/**
 * @brief Convert byte array in big-endian format to uint64_t value
 * 
 * @param src Source buffer to read from
 * @param len Number of bytes to read (1-8)
 * @return Converted uint64_t value
 */
uint64_t bytes_to_num(uint8_t *src, uint8_t len);

#ifdef __cplusplus
}
#endif

#endif /* __HEX_UTILS_H */
