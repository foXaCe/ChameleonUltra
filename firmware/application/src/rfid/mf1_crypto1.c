/**
 * @file mf1_crypto1.c
 * @brief Optimized MIFARE Classic Crypto1 implementation for Chameleon Ultra
 * 
 * This file contains an optimized implementation of the Crypto1 cipher
 * used in MIFARE Classic cards.
 */

#include "mf1_crypto1.h"
#include "parity.h"

// Define inline for better cross-platform support
#define __inline__ inline

// Use odd parity calculation from parity.h
#define ODD_PARITY oddparity8

// Always use platform-independent code for Chameleon Ultra (ARM-based)
#define NO_INLINE_ASM 1

// PRNG and LFSR constants
#define PRNG_MASK        0x002D0000UL  /* x^16 + x^14 + x^13 + x^11 + 1 */
#define PRNG_SIZE        4             /* Bytes */
#define NONCE_SIZE       4             /* Bytes */
#define LFSR_MASK_EVEN   0x2010E1UL
#define LFSR_MASK_ODD    0x3A7394UL
#define LFSR_SIZE        6             /* Bytes */

// Filter network function definitions from Timo Kasper's thesis
#define FA(x3, x2, x1, x0) ((((x0 | x1) ^ (x0 & x3)) ^ (x2 & ((x0 ^ x1) | x3))))
#define FB(x3, x2, x1, x0) ((((x0 & x1) | x2) ^ ((x0 ^ x1) & (x2 | x3))))
#define FC(x4, x3, x2, x1, x0) (((x0 | ((x1 | x4) & (x3 ^ x4))) ^ ((x0 ^ (x1 & x3)) & ((x2 ^ x3) | (x1 & x4)))))

// Platform-independent bit manipulation macros
#define SPLIT_BYTE(__even, __odd, __byte) \
    __even = (__even >> 1) | ((__byte & 0x01) << 7); __byte >>= 1; \
    __odd  = (__odd  >> 1) | ((__byte & 0x01) << 7); __byte >>= 1; \
    __even = (__even >> 1) | ((__byte & 0x01) << 7); __byte >>= 1; \
    __odd  = (__odd  >> 1) | ((__byte & 0x01) << 7); __byte >>= 1; \
    __even = (__even >> 1) | ((__byte & 0x01) << 7); __byte >>= 1; \
    __odd  = (__odd  >> 1) | ((__byte & 0x01) << 7); __byte >>= 1; \
    __even = (__even >> 1) | ((__byte & 0x01) << 7); __byte >>= 1; \
    __odd  = (__odd  >> 1) | ((__byte & 0x01) << 7)

#define SHIFT24(__b0, __b1, __b2, __in) \
    __b0 = (__b0 >> 1) | (__b1 << 7); \
    __b1 = (__b1 >> 1) | (__b2 << 7); \
    __b2 = (__b2 >> 1) | (((__in) & 0x01) << 7)

#define SHIFT24_COND_DECRYPT(__b0, __b1, __b2, __in, __stream, __decrypt) \
    __b0 = (__b0 >> 1) | (__b1 << 7); \
    __b1 = (__b1 >> 1) | (__b2 << 7); \
    __b2 = (__b2 >> 1) | (((__in) ^ (((__stream) & 0x01) & (__decrypt))) << 7)

#define SHIFT8(__byte, __in) \
    __byte = (__byte >> 1) | (((__in) & 0x01) << 7)

// Precalculated filter tables (stored in flash memory for better performance)
static const uint8_t __attribute__((aligned(4))) abFilterTable[3][256] = {
    /* for Odd[0] */
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    },
    /* for Odd[1] */
    {
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x04, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x04, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x04, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x00, 0x02, 0x02, 0x02, 0x02, 0x00, 0x00, 0x02,
        0x04, 0x04, 0x04, 0x06, 0x06, 0x04, 0x04, 0x06,
        0x04, 0x06, 0x06, 0x06, 0x06, 0x04, 0x04, 0x06
    },
    /* for Odd[2] */
    {
        0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x00, 0x08,
        0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x00, 0x08,
        0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x00, 0x08,
        0x10, 0x18, 0x18, 0x18, 0x10, 0x10, 0x10, 0x18,
        0x10, 0x10, 0x18, 0x10, 0x18, 0x18, 0x10, 0x18,
        0x10, 0x18, 0x18, 0x18, 0x10, 0x10, 0x10, 0x18,
        0x10, 0x10, 0x18, 0x10, 0x18, 0x18, 0x10, 0x18,
        0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x00, 0x08,
        0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x00, 0x08,
        0x10, 0x18, 0x18, 0x18, 0x10, 0x10, 0x10, 0x18,
        0x10, 0x10, 0x18, 0x10, 0x18, 0x18, 0x10, 0x18,
        0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x00, 0x08,
        0x10, 0x18, 0x18, 0x18, 0x10, 0x10, 0x10, 0x18,
        0x10, 0x10, 0x18, 0x10, 0x18, 0x18, 0x10, 0x18,
        0x10, 0x18, 0x18, 0x18, 0x10, 0x10, 0x10, 0x18,
        0x10, 0x10, 0x18, 0x10, 0x18, 0x18, 0x10, 0x18,
        0x10, 0x18, 0x18, 0x18, 0x10, 0x10, 0x10, 0x18,
        0x10, 0x10, 0x18, 0x10, 0x18, 0x18, 0x10, 0x18,
        0x10, 0x18, 0x18, 0x18, 0x10, 0x10, 0x10, 0x18,
        0x10, 0x10, 0x18, 0x10, 0x18, 0x18, 0x10, 0x18,
        0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x00, 0x08,
        0x00, 0x08, 0x08, 0x08, 0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x08, 0x00, 0x08, 0x08, 0x00, 0x08,
        0x10, 0x18, 0x18, 0x18, 0x10, 0x10, 0x10, 0x18,
        0x10, 0x10, 0x18, 0x10, 0x18, 0x18, 0x10, 0x18
    }
};

// Output tables for filter network
static const uint8_t __attribute__((aligned(4))) TableC0[32] = {
    /* fc with Input {4,3,2,1,0} = (0,0,0,0,0) to (1,1,1,1,1) - bit 0 */
    FC(0, 0, 0, 0, 0), FC(0, 0, 0, 0, 1), FC(0, 0, 0, 1, 0), FC(0, 0, 0, 1, 1),
    FC(0, 0, 1, 0, 0), FC(0, 0, 1, 0, 1), FC(0, 0, 1, 1, 0), FC(0, 0, 1, 1, 1),
    FC(0, 1, 0, 0, 0), FC(0, 1, 0, 0, 1), FC(0, 1, 0, 1, 0), FC(0, 1, 0, 1, 1),
    FC(0, 1, 1, 0, 0), FC(0, 1, 1, 0, 1), FC(0, 1, 1, 1, 0), FC(0, 1, 1, 1, 1),
    FC(1, 0, 0, 0, 0), FC(1, 0, 0, 0, 1), FC(1, 0, 0, 1, 0), FC(1, 0, 0, 1, 1),
    FC(1, 0, 1, 0, 0), FC(1, 0, 1, 0, 1), FC(1, 0, 1, 1, 0), FC(1, 0, 1, 1, 1),
    FC(1, 1, 0, 0, 0), FC(1, 1, 0, 0, 1), FC(1, 1, 0, 1, 0), FC(1, 1, 0, 1, 1),
    FC(1, 1, 1, 0, 0), FC(1, 1, 1, 0, 1), FC(1, 1, 1, 1, 0), FC(1, 1, 1, 1, 1)
};

static const uint8_t __attribute__((aligned(4))) TableC7[32] = {
    /* fc with Input {4,3,2,1,0} = (0,0,0,0,0) to (1,1,1,1,1) - bit 7 */
    FC(0, 0, 0, 0, 0) << 7, FC(0, 0, 0, 0, 1) << 7, FC(0, 0, 0, 1, 0) << 7, FC(0, 0, 0, 1, 1) << 7,
    FC(0, 0, 1, 0, 0) << 7, FC(0, 0, 1, 0, 1) << 7, FC(0, 0, 1, 1, 0) << 7, FC(0, 0, 1, 1, 1) << 7,
    FC(0, 1, 0, 0, 0) << 7, FC(0, 1, 0, 0, 1) << 7, FC(0, 1, 0, 1, 0) << 7, FC(0, 1, 0, 1, 1) << 7,
    FC(0, 1, 1, 0, 0) << 7, FC(0, 1, 1, 0, 1) << 7, FC(0, 1, 1, 1, 0) << 7, FC(0, 1, 1, 1, 1) << 7,
    FC(1, 0, 0, 0, 0) << 7, FC(1, 0, 0, 0, 1) << 7, FC(1, 0, 0, 1, 0) << 7, FC(1, 0, 0, 1, 1) << 7,
    FC(1, 0, 1, 0, 0) << 7, FC(1, 0, 1, 0, 1) << 7, FC(1, 0, 1, 1, 0) << 7, FC(1, 0, 1, 1, 1) << 7,
    FC(1, 1, 0, 0, 0) << 7, FC(1, 1, 0, 0, 1) << 7, FC(1, 1, 0, 1, 0) << 7, FC(1, 1, 0, 1, 1) << 7,
    FC(1, 1, 1, 0, 0) << 7, FC(1, 1, 1, 0, 1) << 7, FC(1, 1, 1, 1, 0) << 7, FC(1, 1, 1, 1, 1) << 7
};

static const uint8_t __attribute__((aligned(4))) TableC3[32] = {
    /* fc with Input {4,3,2,1,0} = (0,0,0,0,0) to (1,1,1,1,1) - bit 3 */
    FC(0, 0, 0, 0, 0) << 3, FC(0, 0, 0, 0, 1) << 3, FC(0, 0, 0, 1, 0) << 3, FC(0, 0, 0, 1, 1) << 3,
    FC(0, 0, 1, 0, 0) << 3, FC(0, 0, 1, 0, 1) << 3, FC(0, 0, 1, 1, 0) << 3, FC(0, 0, 1, 1, 1) << 3,
    FC(0, 1, 0, 0, 0) << 3, FC(0, 1, 0, 0, 1) << 3, FC(0, 1, 0, 1, 0) << 3, FC(0, 1, 0, 1, 1) << 3,
    FC(0, 1, 1, 0, 0) << 3, FC(0, 1, 1, 0, 1) << 3, FC(0, 1, 1, 1, 0) << 3, FC(0, 1, 1, 1, 1) << 3,
    FC(1, 0, 0, 0, 0) << 3, FC(1, 0, 0, 0, 1) << 3, FC(1, 0, 0, 1, 0) << 3, FC(1, 0, 0, 1, 1) << 3,
    FC(1, 0, 1, 0, 0) << 3, FC(1, 0, 1, 0, 1) << 3, FC(1, 0, 1, 1, 0) << 3, FC(1, 0, 1, 1, 1) << 3,
    FC(1, 1, 0, 0, 0) << 3, FC(1, 1, 0, 0, 1) << 3, FC(1, 1, 0, 1, 0) << 3, FC(1, 1, 0, 1, 1) << 3,
    FC(1, 1, 1, 0, 0) << 3, FC(1, 1, 1, 0, 1) << 3, FC(1, 1, 1, 1, 0) << 3, FC(1, 1, 1, 1, 1) << 3
};

// Filter output macros - optimized for Chameleon Ultra's ARM architecture
#define CRYPTO1_FILTER_OUTPUT_B7_24(__O0, __O1, __O2) \
    TableC7[abFilterTable[0][__O0] | abFilterTable[1][__O1] | abFilterTable[2][__O2]]

#define CRYPTO1_FILTER_OUTPUT_B3_24(__O0, __O1, __O2) \
    TableC3[abFilterTable[0][__O0] | abFilterTable[1][__O1] | abFilterTable[2][__O2]]

#define CRYPTO1_FILTER_OUTPUT_B0_24(__O0, __O1, __O2) \
    TableC0[abFilterTable[0][__O0] | abFilterTable[1][__O1] | abFilterTable[2][__O2]]

// LFSR state structure - split into even and odd for performance
typedef struct {
    uint8_t Even[LFSR_SIZE / 2];  // Even bits of the state
    uint8_t Odd[LFSR_SIZE / 2];   // Odd bits of the state
} Crypto1LfsrState_t;

// Global state
static Crypto1LfsrState_t State = { { 0 }, { 0 } };

/**
 * @brief Get the current Crypto1 state for debugging
 * @param pEven Buffer to store even bits (3 bytes)
 * @param pOdd Buffer to store odd bits (3 bytes)
 */
void Crypto1GetState(uint8_t *pEven, uint8_t *pOdd) {
    if (pEven) {
        pEven[0] = State.Even[0];
        pEven[1] = State.Even[1];
        pEven[2] = State.Even[2];
    }
    if (pOdd) {
        pOdd[0] = State.Odd[0];
        pOdd[1] = State.Odd[1];
        pOdd[2] = State.Odd[2];
    }
}

/**
 * @brief Calculate LFSR feedback for Crypto1
 * 
 * This function calculates a single bit of feedback from the LFSR state,
 * combining both even and odd taps as defined by the LFSR polynomials.
 * 
 * @param E0 First byte of even state
 * @param E1 Second byte of even state
 * @param E2 Third byte of even state
 * @param O0 First byte of odd state
 * @param O1 Second byte of odd state
 * @param O2 Third byte of odd state
 * @return Feedback bit (0 or 1)
 */
static __inline__ uint8_t Crypto1LFSRbyteFeedback(
    uint8_t E0, uint8_t E1, uint8_t E2,
    uint8_t O0, uint8_t O1, uint8_t O2) __attribute__((always_inline));

static uint8_t Crypto1LFSRbyteFeedback(
    uint8_t E0, uint8_t E1, uint8_t E2,
    uint8_t O0, uint8_t O1, uint8_t O2) {
    
    uint8_t Feedback;

    // Calculate feedback according to LFSR taps by XORing all tapped bits
    Feedback  = E0 & (uint8_t)(LFSR_MASK_EVEN);
    Feedback ^= E1 & (uint8_t)(LFSR_MASK_EVEN >> 8);
    Feedback ^= E2 & (uint8_t)(LFSR_MASK_EVEN >> 16);

    Feedback ^= O0 & (uint8_t)(LFSR_MASK_ODD);
    Feedback ^= O1 & (uint8_t)(LFSR_MASK_ODD >> 8);
    Feedback ^= O2 & (uint8_t)(LFSR_MASK_ODD >> 16);

    // Fold 8 bits into 1 bit
    Feedback ^= ((Feedback >> 4) | (Feedback << 4)); // Efficiently use byte swap
    Feedback ^= Feedback >> 2;
    Feedback ^= Feedback >> 1;

    return (Feedback & 1);
}

/**
 * @brief Advance Crypto1 LFSR by one bit
 * @param In Input bit to be XORed with feedback
 */
static __inline__ void Crypto1LFSR(uint8_t In) __attribute__((always_inline));

static void Crypto1LFSR(uint8_t In) {
    uint8_t Feedback;
    register uint8_t Temp0, Temp1, Temp2;

    // Load even state into local registers for better performance
    Temp0 = State.Even[0];
    Temp1 = State.Even[1];
    Temp2 = State.Even[2];

    // Calculate feedback by XORing all tapped bits
    Feedback  = Temp0 & (uint8_t)(LFSR_MASK_EVEN >> 0);
    Feedback ^= Temp1 & (uint8_t)(LFSR_MASK_EVEN >> 8);
    Feedback ^= Temp2 & (uint8_t)(LFSR_MASK_EVEN >> 16);

    Feedback ^= State.Odd[0] & (uint8_t)(LFSR_MASK_ODD >> 0);
    Feedback ^= State.Odd[1] & (uint8_t)(LFSR_MASK_ODD >> 8);
    Feedback ^= State.Odd[2] & (uint8_t)(LFSR_MASK_ODD >> 16);

    // Fold 8 bits into 1 bit
    Feedback ^= ((Feedback >> 4) | (Feedback << 4));
    Feedback ^= Feedback >> 2;
    Feedback ^= Feedback >> 1;
    Feedback &= 1; // Ensure we have only 1 bit

    // Shift the state with feedback and input
    SHIFT24(Temp0, Temp1, Temp2, Feedback ^ In);

    // Swap odd and even states as per Crypto1 algorithm
    State.Even[0] = State.Odd[0];
    State.Even[1] = State.Odd[1];
    State.Even[2] = State.Odd[2];

    State.Odd[0] = Temp0;
    State.Odd[1] = Temp1;
    State.Odd[2] = Temp2;
}

/**
 * @brief Get the current filter output without advancing the LFSR
 * @return Filter output bit (0 or 1)
 */
uint8_t Crypto1FilterOutput(void) {
    return (CRYPTO1_FILTER_OUTPUT_B0_24(State.Odd[0], State.Odd[1], State.Odd[2]));
}

/**
 * @brief Initialize Crypto1 cipher for standard authentication
 * 
 * This function sets up the Crypto1 state with the key and processes initial
 * card nonce XORed with UID bytes.
 * 
 * @param Key 6-byte key array
 * @param Uid 4-byte UID array 
 * @param CardNonce 4-byte nonce (encrypted in place)
 */
void Crypto1Setup(uint8_t Key[6], uint8_t Uid[4], uint8_t CardNonce[4]) {
    // Register variables for better performance on ARM
    register uint8_t Even0 = 0, Even1 = 0, Even2 = 0;
    register uint8_t Odd0 = 0, Odd1 = 0, Odd2 = 0;
    uint8_t KeyStream = 0, Feedback, Out, In, ByteCount;

    // Load key into LFSR state
    KeyStream = *Key++;
    SPLIT_BYTE(Even0, Odd0, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even0, Odd0, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even1, Odd1, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even1, Odd1, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even2, Odd2, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even2, Odd2, KeyStream);

    // Process each nonce byte
    for (ByteCount = 0; ByteCount < NONCE_SIZE; ByteCount++) {
        In = *CardNonce ^ *Uid++;
        KeyStream = 0; // Reset keystream for each byte

        // Process 8 bits of the current byte
        for (uint8_t bit = 0; bit < 8; bit++) {
            // Filter output for current bit
            Out = (bit & 1) ? 
                CRYPTO1_FILTER_OUTPUT_B0_24(Even0, Even1, Even2) :
                CRYPTO1_FILTER_OUTPUT_B0_24(Odd0, Odd1, Odd2);
            
            // Shift output bit into keystream
            SHIFT8(KeyStream, Out);
            
            // Calculate feedback with current input bit
            Feedback = (bit & 1) ?
                Crypto1LFSRbyteFeedback(Odd0, Odd1, Odd2, Even0, Even1, Even2) :
                Crypto1LFSRbyteFeedback(Even0, Even1, Even2, Odd0, Odd1, Odd2);
                
            Feedback ^= (In & 1);
            In >>= 1;
            
            // Shift state according to bit parity
            if (bit & 1) {
                SHIFT24(Odd0, Odd1, Odd2, Feedback);
            } else {
                SHIFT24(Even0, Even1, Even2, Feedback);
            }
        }

        // Encrypt the current nonce byte
        *CardNonce++ ^= KeyStream;
    }
    
    // Save state
    State.Even[0] = Even0;
    State.Even[1] = Even1;
    State.Even[2] = Even2;
    State.Odd[0]  = Odd0;
    State.Odd[1]  = Odd1;
    State.Odd[2]  = Odd2;
}

/**
 * @brief Initialize Crypto1 for nested authentication
 * 
 * This function is similar to Crypto1Setup but also handles parity bits
 * for nested authentication scenarios.
 * 
 * @param Key 6-byte key array
 * @param Uid 4-byte UID array
 * @param CardNonce 4-byte nonce (encrypted in place)
 * @param NonceParity 4-byte buffer for encrypted parity bits
 * @param Decrypt Flag indicating whether to decrypt (reader) or encrypt (tag)
 */
void Crypto1SetupNested(uint8_t Key[6], uint8_t Uid[4], uint8_t CardNonce[4], uint8_t NonceParity[4], bool Decrypt) {
    // Register variables for better performance on ARM
    register uint8_t Even0 = 0, Even1 = 0, Even2 = 0;
    register uint8_t Odd0 = 0, Odd1 = 0, Odd2 = 0;
    uint8_t KeyStream = 0, Feedback, Out, In, ByteCount;

    // Load key into LFSR state
    KeyStream = *Key++;
    SPLIT_BYTE(Even0, Odd0, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even0, Odd0, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even1, Odd1, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even1, Odd1, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even2, Odd2, KeyStream);
    KeyStream = *Key++;
    SPLIT_BYTE(Even2, Odd2, KeyStream);

    // Get first filter output
    Out = CRYPTO1_FILTER_OUTPUT_B0_24(Odd0, Odd1, Odd2);

    for (ByteCount = 0; ByteCount < NONCE_SIZE; ByteCount++) {
        In = *CardNonce ^ *Uid++;
        KeyStream = 0; // Reset keystream for each byte

        // Process 8 bits of the current byte
        for (uint8_t bit = 0; bit < 8; bit++) {
            // For first bit, reuse filter output from parity bit
            if (bit == 0) {
                SHIFT8(KeyStream, Out);
            } else {
                // Filter output for current bit
                Out = (bit & 1) ? 
                    CRYPTO1_FILTER_OUTPUT_B7_24(Even0, Even1, Even2) :
                    CRYPTO1_FILTER_OUTPUT_B7_24(Odd0, Odd1, Odd2);
                
                KeyStream = (KeyStream >> 1) | Out;
            }
            
            // Calculate feedback with current input bit
            Feedback = (bit & 1) ?
                Crypto1LFSRbyteFeedback(Odd0, Odd1, Odd2, Even0, Even1, Even2) :
                Crypto1LFSRbyteFeedback(Even0, Even1, Even2, Odd0, Odd1, Odd2);
                
            Feedback ^= (In & 1);
            In >>= 1;
            
            // Shift state according to bit parity
            if (bit & 1) {
                SHIFT24_COND_DECRYPT(Odd0, Odd1, Odd2, Feedback, Out, Decrypt);
            } else {
                SHIFT24_COND_DECRYPT(Even0, Even1, Even2, Feedback, Out, Decrypt);
            }
        }

        // Generate encrypted parity bit
        Out = CRYPTO1_FILTER_OUTPUT_B0_24(Odd0, Odd1, Odd2);
        *NonceParity++ = ODD_PARITY(*CardNonce) ^ Out;

        // Encrypt the current nonce byte
        *CardNonce++ ^= KeyStream;
    }
    
    // Save state
    State.Even[0] = Even0;
    State.Even[1] = Even1;
    State.Even[2] = Even2;
    State.Odd[0]  = Odd0;
    State.Odd[1]  = Odd1;
    State.Odd[2]  = Odd2;
}

/**
 * @brief Process and authenticate reader nonce
 * 
 * This function decrypts the reader nonce and updates the LFSR state
 * with the decrypted bits.
 * 
 * @param EncryptedReaderNonce 4-byte encrypted reader nonce
 */
void Crypto1Auth(uint8_t EncryptedReaderNonce[NONCE_SIZE]) {
    register uint8_t Even0, Even1, Even2;
    register uint8_t Odd0, Odd1, Odd2;
    uint8_t In, Feedback;

    // Load state into local registers
    Even0 = State.Even[0];
    Even1 = State.Even[1];
    Even2 = State.Even[2];
    Odd0 = State.Odd[0];
    Odd1 = State.Odd[1];
    Odd2 = State.Odd[2];

    // Process 4 bytes of reader nonce
    for (uint8_t i = 0; i < NONCE_SIZE; i++) {
        In = EncryptedReaderNonce[i];

        // Process all 8 bits of each byte
        for (uint8_t bit = 0; bit < 8; bit++) {
            // Calculate filter output for current bit position
            Feedback = (bit & 1) ? 
                CRYPTO1_FILTER_OUTPUT_B0_24(Even0, Even1, Even2) :
                CRYPTO1_FILTER_OUTPUT_B0_24(Odd0, Odd1, Odd2);
            
            // Calculate LFSR feedback and decrypt input
            Feedback = (bit & 1) ?
                Crypto1LFSRbyteFeedback(Odd0, Odd1, Odd2, Even0, Even1, Even2) :
                Crypto1LFSRbyteFeedback(Even0, Even1, Even2, Odd0, Odd1, Odd2);
                
            Feedback ^= Feedback ^ (In & 1);
            In >>= 1;
            
            // Shift state with feedback
            if (bit & 1) {
                SHIFT24(Odd0, Odd1, Odd2, Feedback);
            } else {
                SHIFT24(Even0, Even1, Even2, Feedback);
            }
        }
    }
    
    // Save state
    State.Even[0] = Even0;
    State.Even[1] = Even1;
    State.Even[2] = Even2;
    State.Odd[0]  = Odd0;
    State.Odd[1]  = Odd1;
    State.Odd[2]  = Odd2;
}

/**
 * @brief Generate 4 bits of keystream (nibble)
 * @return 4-bit keystream value in bits 3-0
 */
uint8_t Crypto1Nibble(void) {
    register uint8_t Even0, Even1, Even2;
    register uint8_t Odd0, Odd1, Odd2;
    uint8_t KeyStream, Feedback, Out;

    // Load state into local registers
    Even0 = State.Even[0];
    Even1 = State.Even[1];
    Even2 = State.Even[2];
    Odd0 = State.Odd[0];
    Odd1 = State.Odd[1];
    Odd2 = State.Odd[2];

    // Generate 4 bits of keystream
    KeyStream = CRYPTO1_FILTER_OUTPUT_B3_24(Odd0, Odd1, Odd2);
    
    // Process 4 bits
    for (uint8_t i = 0; i < 4; i++) {
        Feedback = (i & 1) ?
            Crypto1LFSRbyteFeedback(Odd0, Odd1, Odd2, Even0, Even1, Even2) :
            Crypto1LFSRbyteFeedback(Even0, Even1, Even2, Odd0, Odd1, Odd2);
            
        if (i & 1) {
            SHIFT24(Odd0, Odd1, Odd2, Feedback);
            Out = CRYPTO1_FILTER_OUTPUT_B3_24(Even0, Even1, Even2);
        } else {
            SHIFT24(Even0, Even1, Even2, Feedback);
            Out = CRYPTO1_FILTER_OUTPUT_B3_24(Odd0, Odd1, Odd2);
        }
        
        if (i < 3) { // Don't shift on last bit
            KeyStream = (KeyStream >> 1) | Out;
        }
    }

    // Save state
    State.Even[0] = Even0;
    State.Even[1] = Even1;
    State.Even[2] = Even2;
    State.Odd[0]  = Odd0;
    State.Odd[1]  = Odd1;
    State.Odd[2]  = Odd2;

    return KeyStream;
}

/**
 * @brief Generate 8 bits of keystream (byte)
 * @return 8-bit keystream value
 */
uint8_t Crypto1Byte(void) {
    register uint8_t Even0, Even1, Even2;
    register uint8_t Odd0, Odd1, Odd2;
    uint8_t KeyStream = 0, Feedback;

    // Load state into local registers
    Even0 = State.Even[0];
    Even1 = State.Even[1];
    Even2 = State.Even[2];
    Odd0 = State.Odd[0];
    Odd1 = State.Odd[1];
    Odd2 = State.Odd[2];

    // Initialize keystream with first bit
    KeyStream = CRYPTO1_FILTER_OUTPUT_B7_24(Odd0, Odd1, Odd2);
    
    // Generate 8 bits of keystream
    for (uint8_t i = 0; i < 8; i++) {
        Feedback = (i & 1) ?
            Crypto1LFSRbyteFeedback(Odd0, Odd1, Odd2, Even0, Even1, Even2) :
            Crypto1LFSRbyteFeedback(Even0, Even1, Even2, Odd0, Odd1, Odd2);
            
        if (i & 1) {
            SHIFT24(Odd0, Odd1, Odd2, Feedback);
            uint8_t out = CRYPTO1_FILTER_OUTPUT_B7_24(Even0, Even1, Even2);
            KeyStream = (KeyStream >> 1) | out;
        } else {
            SHIFT24(Even0, Even1, Even2, Feedback);
            if (i > 0) { // Skip for first bit (already initialized)
                uint8_t out = CRYPTO1_FILTER_OUTPUT_B7_24(Odd0, Odd1, Odd2);
                KeyStream = (KeyStream >> 1) | out;
            }
        }
    }

    // Save state
    State.Even[0] = Even0;
    State.Even[1] = Even1;
    State.Even[2] = Even2;
    State.Odd[0]  = Odd0;
    State.Odd[1]  = Odd1;
    State.Odd[2]  = Odd2;

    return KeyStream;
}

/**
 * @brief Process an array of bytes with Crypto1
 * 
 * This function encrypts/decrypts multiple bytes efficiently by
 * avoiding state load/store for each byte.
 * 
 * @param Buffer Array of bytes to encrypt/decrypt (in-place)
 * @param Count Number of bytes to process
 */
void Crypto1ByteArray(uint8_t *Buffer, uint8_t Count) {
    // Use a single optimized implementation that generates keystream
    // and applies it to each byte
    while (Count--) {
        *Buffer++ ^= Crypto1Byte();
    }
}

/**
 * @brief Process array of bytes with parity bit generation
 * 
 * This function encrypts bytes and generates encrypted parity bits
 * 
 * @param Buffer Array of bytes to encrypt (in-place)
 * @param Parity Buffer to store encrypted parity bits
 * @param Count Number of bytes to process
 */
void Crypto1ByteArrayWithParity(uint8_t *Buffer, uint8_t *Parity, uint8_t Count) {
    register uint8_t Even0, Even1, Even2;
    register uint8_t Odd0, Odd1, Odd2;
    uint8_t KeyStream = 0, Feedback, Out;

    // Load state into local registers
    Even0 = State.Even[0];
    Even1 = State.Even[1];
    Even2 = State.Even[2];
    Odd0 = State.Odd[0];
    Odd1 = State.Odd[1];
    Odd2 = State.Odd[2];

    // Get first filter output for bit 0 of first byte
    Out = CRYPTO1_FILTER_OUTPUT_B0_24(Odd0, Odd1, Odd2);

    while (Count--) {
        // Initialize keystream for current byte
        SHIFT8(KeyStream, Out);
        
        // Process 8 bits for each byte
        for (uint8_t bit = 0; bit < 8; bit++) {
            // Calculate feedback
            Feedback = (bit & 1) ?
                Crypto1LFSRbyteFeedback(Odd0, Odd1, Odd2, Even0, Even1, Even2) :
                Crypto1LFSRbyteFeedback(Even0, Even1, Even2, Odd0, Odd1, Odd2);
                
            // Shift state according to bit parity
            if (bit & 1) {
                SHIFT24(Odd0, Odd1, Odd2, Feedback);
                if (bit < 7) { // Don't get output for last bit
                    Out = CRYPTO1_FILTER_OUTPUT_B7_24(Even0, Even1, Even2);
                    KeyStream = (KeyStream >> 1) | Out;
                }
            } else {
                SHIFT24(Even0, Even1, Even2, Feedback);
                if (bit > 0) { // Skip first bit (already done)
                    Out = CRYPTO1_FILTER_OUTPUT_B7_24(Odd0, Odd1, Odd2);
                    KeyStream = (KeyStream >> 1) | Out;
                }
            }
        }

        // Generate parity bit for next byte
        Out = CRYPTO1_FILTER_OUTPUT_B0_24(Odd0, Odd1, Odd2);
        *Parity++ = ODD_PARITY(*Buffer) ^ Out;

        // Encrypt current byte
        *Buffer++ ^= KeyStream;
    }
    
    // Save state
    State.Even[0] = Even0;
    State.Even[1] = Even1;
    State.Even[2] = Even2;
    State.Odd[0]  = Odd0;
    State.Odd[1]  = Odd1;
    State.Odd[2]  = Odd2;
}

/**
 * @brief Process array of bytes with input-feeding and parity generation
 * 
 * This function is similar to Crypto1ByteArrayWithParity but also
 * feeds buffer contents into the LFSR.
 * 
 * @param Buffer Array of bytes to process (in-place)
 * @param Parity Buffer to store encrypted parity bits
 * @param Count Number of bytes to process
 */
void Crypto1ByteArrayWithParityHasIn(uint8_t *Buffer, uint8_t *Parity, uint8_t Count) {
    register uint8_t Even0, Even1, Even2;
    register uint8_t Odd0, Odd1, Odd2;
    uint8_t KeyStream = 0, Feedback, Out;

    // Load state into local registers
    Even0 = State.Even[0];
    Even1 = State.Even[1];
    Even2 = State.Even[2];
    Odd0 = State.Odd[0];
    Odd1 = State.Odd[1];
    Odd2 = State.Odd[2];

    // Get first filter output for bit 0 of first byte
    Out = CRYPTO1_FILTER_OUTPUT_B0_24(Odd0, Odd1, Odd2);

    while (Count--) {
        uint8_t In = *Buffer;
        
        // Initialize keystream for current byte
        SHIFT8(KeyStream, Out);
        
        // Process 8 bits for each byte
        for (uint8_t bit = 0; bit < 8; bit++) {
            // Calculate feedback with input
            Feedback = (bit & 1) ?
                Crypto1LFSRbyteFeedback(Odd0, Odd1, Odd2, Even0, Even1, Even2) :
                Crypto1LFSRbyteFeedback(Even0, Even1, Even2, Odd0, Odd1, Odd2);
                
            Feedback ^= (In & 1);
            In >>= 1;
            
            // Shift state according to bit parity
            if (bit & 1) {
                SHIFT24(Odd0, Odd1, Odd2, Feedback);
                if (bit < 7) { // Don't get output for last bit
                    Out = CRYPTO1_FILTER_OUTPUT_B7_24(Even0, Even1, Even2);
                    KeyStream = (KeyStream >> 1) | Out;
                }
            } else {
                SHIFT24(Even0, Even1, Even2, Feedback);
                if (bit > 0) { // Skip first bit (already done)
                    Out = CRYPTO1_FILTER_OUTPUT_B7_24(Odd0, Odd1, Odd2);
                    KeyStream = (KeyStream >> 1) | Out;
                }
            }
        }

        // Generate parity bit for this byte
        Out = CRYPTO1_FILTER_OUTPUT_B0_24(Odd0, Odd1, Odd2);
        *Parity++ = ODD_PARITY(*Buffer) ^ Out;

        // Encrypt current byte
        *Buffer++ ^= KeyStream;
    }
    
    // Save state
    State.Even[0] = Even0;
    State.Even[1] = Even1;
    State.Even[2] = Even2;
    State.Odd[0]  = Odd0;
    State.Odd[1]  = Odd1;
    State.Odd[2]  = Odd2;
}

/**
 * @brief Optimized PRNG function for Crypto1
 * 
 * This function efficiently advances the PRNG state by exploiting
 * the structure of the feedback polynomial.
 * 
 * @param State 4-byte PRNG state
 * @param ClockCount Number of iterations (must be multiple of 32)
 */
void Crypto1PRNG(uint8_t State[4], uint8_t ClockCount) {
    // Process state as 32-bit value for efficiency
    uint32_t Temp = ((uint32_t)State[0]) | 
                    ((uint32_t)State[1] << 8) | 
                    ((uint32_t)State[2] << 16) | 
                    ((uint32_t)State[3] << 24);
    
    // Process in chunks of 32 bits
    while (ClockCount >= 32) {
        // Optimize feedback calculation by processing in chunks
        
        // Process first 11 bits
        uint16_t Feedback = (uint16_t)(Temp >> 16);
        Feedback ^= Feedback >> 3;   // Fold 101 101 pattern to 101
        Feedback ^= Feedback >> 2;   // Fold 101 to 1
        Temp = (Temp >> 11) | (((uint32_t)Feedback) << (32 - 11));

        // Process next 11 bits
        Feedback = (uint16_t)(Temp >> 16);
        Feedback ^= Feedback >> 3;
        Feedback ^= Feedback >> 2;
        Temp = (Temp >> 11) | (((uint32_t)Feedback) << (32 - 11));

        // Process final 10 bits
        Feedback = (uint16_t)(Temp >> 16);
        Feedback ^= Feedback >> 3;
        Feedback ^= Feedback >> 2;
        Temp = (Temp >> 10) | (((uint32_t)Feedback) << (32 - 10));

        ClockCount -= 32;
    }

    // Store back state
    State[0] = (uint8_t)(Temp);
    State[1] = (uint8_t)(Temp >> 8);
    State[2] = (uint8_t)(Temp >> 16);
    State[3] = (uint8_t)(Temp >> 24);
}

/**
 * @brief Optimized PRNG successor function
 * 
 * This function is a portable implementation of prng_successor
 * using ARM-specific optimizations when available.
 * 
 * @param x Initial PRNG state
 * @param n Number of iterations
 * @return New PRNG state after n iterations
 */
uint32_t Crypto1FreePRNG(uint32_t x, uint32_t n) {
    // Use ARM-specific byte swap for better performance
    x = __builtin_bswap32(x);

    // Optimize common cases for better performance
    if (n == 1) {
        // Single iteration
        x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
    } else if (n == 16) {
        // 16 iterations (common in MIFARE authentication)
        for (uint8_t i = 0; i < 16; i++) {
            x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
        }
    } else {
        // General case
        while (n--) {
            x = x >> 1 | (x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31;
        }
    }

    // Return result with proper byte order
    return __builtin_bswap32(x);
}

/**
 * @brief Encrypt buffer with consideration for parity bits
 * 
 * This function encrypts a buffer including parity bits (every 9th bit).
 * 
 * @param Buffer Buffer to encrypt (in-place)
 * @param BitCount Total number of bits to process
 */
void Crypto1EncryptWithParity(uint8_t *Buffer, uint8_t BitCount) {
    for (uint8_t i = 0; i < BitCount; i++) {
        // XOR current bit with filter output
        Buffer[i / 8] ^= 
            CRYPTO1_FILTER_OUTPUT_B0_24(State.Odd[0], State.Odd[1], State.Odd[2])
            << (i % 8);
            
        // Only advance LFSR if not a parity bit
        if ((i + 1) % 9 != 0) {
            Crypto1LFSR(0);
        }
    }
}

/**
 * @brief Process reader auth with parity bits
 * 
 * This function handles reader authentication with proper parity bit processing.
 * 
 * @param PlainReaderAnswerWithParityBits 9-byte buffer with reader answer including parity
 */
void Crypto1ReaderAuthWithParity(uint8_t PlainReaderAnswerWithParityBits[9]) {
    uint8_t i = 0, feedback;
    
    // Process 72 bits (8 bytes + 8 parity bits)
    while (i < 72) {
        feedback = PlainReaderAnswerWithParityBits[i / 8] >> (i % 8);
        
        // XOR current bit with filter output
        PlainReaderAnswerWithParityBits[i / 8] ^=
            CRYPTO1_FILTER_OUTPUT_B0_24(State.Odd[0], State.Odd[1], State.Odd[2])
            << (i % 8);
            
        // Only advance LFSR if not a parity bit
        if ((i + 1) % 9 != 0) {
            // First 36 bits: feed back reader answer
            // Last 36 bits: no feedback
            if (i < 36) {
                Crypto1LFSR(feedback & 1);
            } else {
                Crypto1LFSR(0);
            }
        }
        
        i++;
    }
}
