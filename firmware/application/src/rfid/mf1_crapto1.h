/**
 * @file mf1_crapto1.h
 * @brief Crypto1 cipher implementation for MIFARE Classic
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * Copyright (C) 2008-2014 bla <blapost@gmail.com>
 * Optimized for Chameleon Ultra 2023-2025
 */

#ifndef CRAPTO1_INCLUDED
#define CRAPTO1_INCLUDED

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** LFSR polynomial for odd bits */
#define LF_POLY_ODD  (0x29CE5C)
/** LFSR polynomial for even bits */
#define LF_POLY_EVEN (0x870804)
/** Extract bit n from x */
#define BIT(x, n)    (((x) >> (n)) & 1)
/** Extract bit n from x with Big Endian conversion */
#define BEBIT(x, n)  BIT(x, (n) ^ 24)

/**
 * @brief Crypto1 cipher state containing odd and even bit registers
 */
struct Crypto1State {
    uint32_t odd;  /**< Odd bits of the LFSR state */
    uint32_t even; /**< Even bits of the LFSR state */
};

/**
 * @brief Initialize Crypto1 state with the provided key
 * @param state Crypto1 state structure
 * @param key 48-bit key value
 */
void crypto1_init(struct Crypto1State *state, uint64_t key);

/**
 * @brief Reset Crypto1 state
 * @param state Crypto1 state structure
 */
void crypto1_deinit(struct Crypto1State *state);

#if defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks malloc()/free()
/**
 * @brief Create and initialize a new Crypto1 state
 * @param key 48-bit key value
 * @return Pointer to initialized Crypto1 state or NULL if allocation failed
 */
struct Crypto1State *crypto1_create(uint64_t key);

/**
 * @brief Free a Crypto1 state
 * @param state Crypto1 state to free
 */
void crypto1_destroy(struct Crypto1State *state);
#endif

/**
 * @brief Extract LFSR state as a 48-bit value
 * @param state Crypto1 state structure
 * @param lfsr Pointer to store the 48-bit LFSR value
 */
void crypto1_get_lfsr(struct Crypto1State *state, uint64_t *lfsr);

/**
 * @brief Process a single bit through the Crypto1 LFSR
 * @param state Crypto1 state structure
 * @param in Input bit (0 or 1)
 * @param is_encrypted Flag indicating if input is encrypted
 * @return Output bit
 */
uint8_t crypto1_bit(struct Crypto1State *state, uint8_t in, int is_encrypted);

/**
 * @brief Process a byte through the Crypto1 LFSR
 * @param state Crypto1 state structure
 * @param in Input byte
 * @param is_encrypted Flag indicating if input is encrypted
 * @return Output byte
 */
uint8_t crypto1_byte(struct Crypto1State *state, uint8_t in, int is_encrypted);

/**
 * @brief Process a 32-bit word through the Crypto1 LFSR
 * @param state Crypto1 state structure
 * @param in Input word
 * @param is_encrypted Flag indicating if input is encrypted
 * @return Output word
 */
uint32_t crypto1_word(struct Crypto1State *state, uint32_t in, int is_encrypted);

/**
 * @brief Generate next PRNG state
 * @param x Current PRNG state
 * @param n Number of iterations
 * @return New PRNG state
 */
uint32_t prng_successor(uint32_t x, uint32_t n);

/**
 * @brief Roll back LFSR state by one bit
 * @param state Crypto1 state structure
 * @param in Input bit
 * @param fb Feedback bit
 * @return Output bit
 */
uint8_t lfsr_rollback_bit(struct Crypto1State *state, uint32_t in, int fb);

/**
 * @brief Roll back LFSR state by one byte
 * @param state Crypto1 state structure
 * @param in Input byte
 * @param fb Feedback bit
 * @return Output byte
 */
uint8_t lfsr_rollback_byte(struct Crypto1State *state, uint32_t in, int fb);

/**
 * @brief Roll back LFSR state by one 32-bit word
 * @param state Crypto1 state structure
 * @param in Input word
 * @param fb Feedback bit
 * @return Output word
 */
uint32_t lfsr_rollback_word(struct Crypto1State *state, uint32_t in, int fb);

/**
 * @brief Macro to iterate through valid nonces
 * 
 * This macro allows iterating through all valid nonces for a given filter
 * and filter size.
 * 
 * @param N Nonce variable
 * @param FILTER Filter value
 * @param FSIZE Filter size
 */
#define FOREACH_VALID_NONCE(N, FILTER, FSIZE)\
    uint32_t __n = 0,__M = 0, N = 0;\
    int __i;\
    for(; __n < 1 << 16; N = prng_successor(__M = ++__n, 16))\
        for(__i = FSIZE - 1; __i >= 0; __i--)\
            if(BIT(FILTER, __i) ^ evenparity32(__M & 0xFF01))\
                break;\
            else if(__i)\
                __M = prng_successor(__M, (__i == 7) ? 48 : 8);\
            else

#ifdef __OPTIMIZE_SIZE__
/**
 * @brief Filter function for Crypto1 - optimized for size
 * @param x Input value
 * @return Filter output
 */
int filter(uint32_t const x);
#else
/**
 * @brief Filter function for Crypto1 - optimized for speed
 * @param x Input value
 * @return Filter output
 */
static inline int filter(uint32_t const x) {
    uint32_t f;

    f  = 0xf22c0 >> (x       & 0xf) & 16;
    f |= 0x6c9c0 >> (x >>  4 & 0xf) &  8;
    f |= 0x3c8b0 >> (x >>  8 & 0xf) &  4;
    f |= 0x1e458 >> (x >> 12 & 0xf) &  2;
    f |= 0x0d938 >> (x >> 16 & 0xf) &  1;
    return BIT(0xEC57E80A, f);
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* CRAPTO1_INCLUDED */
