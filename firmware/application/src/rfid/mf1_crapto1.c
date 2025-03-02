/*  crypto1.c
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.
    
    Copyright (C) 2008-2008 bla <blapost@gmail.com>
    Optimized for Chameleon Ultra 2023-2025
*/
#include <stdlib.h>
#include "mf1_crapto1.h"
#include "parity.h"

#ifdef __OPTIMIZE_SIZE__
uint32_t filter(uint32_t const x) {
    uint32_t f;

    f  = 0xf22c0 >> (x       & 0xf) & 16;
    f |= 0x6c9c0 >> (x >>  4 & 0xf) &  8;
    f |= 0x3c8b0 >> (x >>  8 & 0xf) &  4;
    f |= 0x1e458 >> (x >> 12 & 0xf) &  2;
    f |= 0x0d938 >> (x >> 16 & 0xf) &  1;
    return BIT(0xEC57E80A, f);
}
#endif

/**
 * @brief Initialize Crypto1 state with the provided key
 * @param state Crypto1 state structure
 * @param key 48-bit key value
 */
void crypto1_init(struct Crypto1State *state, uint64_t key) {
    if (state == NULL)
        return;
    
    state->odd = 0;
    state->even = 0;
    
    // Load the key bits into odd/even registers
    for (int i = 47; i > 0; i -= 2) {
        state->odd  = state->odd  << 1 | BIT(key, (i - 1) ^ 7);
        state->even = state->even << 1 | BIT(key, i ^ 7);
    }
}

/**
 * @brief Reset Crypto1 state
 * @param state Crypto1 state structure
 */
__attribute__((always_inline)) inline void crypto1_deinit(struct Crypto1State *state) {
    state->odd = 0;
    state->even = 0;
}

#if defined(__arm__) || defined(__linux__) || defined(_WIN32) || defined(__APPLE__) // bare metal ARM Proxmark lacks calloc()/free()
/**
 * @brief Create and initialize a new Crypto1 state
 * @param key 48-bit key value
 * @return Pointer to initialized Crypto1 state or NULL if allocation failed
 */
struct Crypto1State *crypto1_create(uint64_t key) {
    struct Crypto1State *state = calloc(1, sizeof(*state));
    if (!state) return NULL;
    crypto1_init(state, key);
    return state;
}

/**
 * @brief Free a Crypto1 state
 * @param state Crypto1 state to free
 */
void crypto1_destroy(struct Crypto1State *state) {
    free(state);
}
#endif

/**
 * @brief Extract LFSR state as a 48-bit value
 * @param state Crypto1 state structure
 * @param lfsr Pointer to store the 48-bit LFSR value
 */
void crypto1_get_lfsr(struct Crypto1State *state, uint64_t *lfsr) {
    *lfsr = 0;
    for (int i = 23; i >= 0; --i) {
        *lfsr = (*lfsr << 1) | BIT(state->odd, i ^ 3);
        *lfsr = (*lfsr << 1) | BIT(state->even, i ^ 3);
    }
}

/**
 * @brief Process a single bit through the Crypto1 LFSR
 * @param s Crypto1 state structure
 * @param in Input bit (0 or 1)
 * @param is_encrypted Flag indicating if input is encrypted
 * @return Output bit
 */
uint8_t crypto1_bit(struct Crypto1State *s, uint8_t in, int is_encrypted) {
    uint32_t feedin;
    uint8_t ret = filter(s->odd);

    // Calculate feedback with current input
    feedin  = ret & (!!is_encrypted);
    feedin ^= !!in;
    feedin ^= LF_POLY_ODD & s->odd;
    feedin ^= LF_POLY_EVEN & s->even;
    
    // Shift in feedback bit
    uint32_t t = s->odd;
    s->odd = s->even;
    s->even = t << 1 | evenparity32(feedin);

    return ret;
}

/**
 * @brief Process a byte through the Crypto1 LFSR
 * @param s Crypto1 state structure
 * @param in Input byte
 * @param is_encrypted Flag indicating if input is encrypted
 * @return Output byte
 */
uint8_t crypto1_byte(struct Crypto1State *s, uint8_t in, int is_encrypted) {
    uint8_t ret = 0;

    // For best performance on ARM, use a separate shift register
    // instead of combining bit operations directly
    for (int i = 0; i < 8; i++) {
        ret |= crypto1_bit(s, BIT(in, i), is_encrypted) << i;
    }
    
    return ret;
}

/**
 * @brief Process a 32-bit word through the Crypto1 LFSR
 * @param s Crypto1 state structure
 * @param in Input word
 * @param is_encrypted Flag indicating if input is encrypted
 * @return Output word
 */
uint32_t crypto1_word(struct Crypto1State *s, uint32_t in, int is_encrypted) {
    uint32_t ret = 0;
    
    // Process 32 bits using array-based indexing to help compiler optimize
    for (int i = 0; i < 32; i++) {
        ret |= (uint32_t)crypto1_bit(s, BEBIT(in, i), is_encrypted) << ((24 ^ i) & 0x1F);
    }
    
    return ret;
}

/**
 * @brief Generate next PRNG state
 * @param x Current PRNG state
 * @param n Number of iterations
 * @return New PRNG state
 */
uint32_t prng_successor(uint32_t x, uint32_t n) {
    // Convert to big-endian for PRNG calculations
    x = __REV(x);

    // Fast path for common cases
    if (n == 1) {
        // Single iteration optimized
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    } else if (n == 16) {
        // 16 iterations (common in MIFARE auth)
        for (int i = 0; i < 16; i++) {
            x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
        }
    } else {
        // General case
        while (n--) {
            x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
        }
    }

    // Convert back from big-endian
    return __REV(x);
}
