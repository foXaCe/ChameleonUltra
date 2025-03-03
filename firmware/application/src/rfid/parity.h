/**
 * @file parity.h
 * @brief Parity calculation functions and tables
 * 
 * This header provides optimized functions for calculating odd and even 
 * parity of bytes and 32-bit words. It uses lookup tables for byte-level
 * operations and optimized bit manipulation for 32-bit operations.
 * 
 * This code is licensed under the terms of the GNU GPL, version 2 or later.
 */

#ifndef __PARITY_H
#define __PARITY_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Lookup table for odd parity calculation
 * Returns 1 if the number of 1-bits in the index is even (need to add 1 for odd parity)
 * Returns 0 if the number of 1-bits in the index is odd (already has odd parity)
 */
extern const uint8_t OddByteParity[256];

/**
 * Lookup table for even parity calculation
 * Returns 0 if the number of 1-bits in the index is even (already has even parity)
 * Returns 1 if the number of 1-bits in the index is odd (need to add 1 for even parity)
 */
extern const uint8_t EvenByteParity[256];

/**
 * @brief Calculate odd parity of a byte using lookup table
 * @param x Byte value to calculate parity for
 * @return 1 if odd parity bit should be set, 0 otherwise
 */
static inline uint8_t oddparity8(const uint8_t x) {
    return OddByteParity[x];
}

/**
 * @brief Calculate even parity of a byte using lookup table
 * @param x Byte value to calculate parity for
 * @return 1 if even parity bit should be set, 0 otherwise
 */
static inline uint8_t evenparity8(const uint8_t x) {
    return EvenByteParity[x];
}

/**
 * @brief Calculate even parity of a 32-bit word
 * @param x 32-bit word to calculate parity for
 * @return 1 if even parity bit should be set, 0 otherwise
 */
static inline uint8_t evenparity32(uint32_t x) {
#if !defined __GNUC__
    x ^= x >> 16;
    x ^= x >> 8;
    return evenparity8(x & 0xFF);
#else
    return (__builtin_parity(x) & 0xFF);
#endif
}

/**
 * @brief Calculate odd parity of a 32-bit word
 * @param x 32-bit word to calculate parity for
 * @return 1 if odd parity bit should be set, 0 otherwise
 */
static inline uint8_t oddparity32(uint32_t x) {
#if !defined __GNUC__
    x ^= x >> 16;
    x ^= x >> 8;
    return oddparity8(x & 0xFF);
#else
    return !__builtin_parity(x);
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* __PARITY_H */
