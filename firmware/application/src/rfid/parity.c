/**
 * @file parity.c
 * @brief Parity calculation lookup tables
 * 
 * This file provides optimized lookup tables for calculating odd and even
 * parity of 8-bit values. Using lookup tables significantly improves performance
 * compared to bit-by-bit calculation, especially for RFID operations.
 * 
 * This code is licensed under the terms of the GNU GPL, version 2 or later.
 */

#include "parity.h"

/**
 * Lookup table for odd parity calculation
 * Returns 1 if the number of 1-bits in the index is even (need to add 1 for odd parity)
 * Returns 0 if the number of 1-bits in the index is odd (already has odd parity)
 */
const uint8_t __attribute__((aligned(4))) OddByteParity[256] = {
    /* 0x00-0x0F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x10-0x1F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x20-0x2F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x30-0x3F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x40-0x4F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x50-0x5F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x60-0x6F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x70-0x7F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x80-0x8F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x90-0x9F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0xA0-0xAF */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0xB0-0xBF */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0xC0-0xCF */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0xD0-0xDF */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0xE0-0xEF */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0xF0-0xFF */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1
};

/**
 * Lookup table for even parity calculation
 * Returns 0 if the number of 1-bits in the index is even (already has even parity)
 * Returns 1 if the number of 1-bits in the index is odd (need to add 1 for even parity)
 */
const uint8_t __attribute__((aligned(4))) EvenByteParity[256] = {
    /* 0x00-0x0F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x10-0x1F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x20-0x2F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x30-0x3F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x40-0x4F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x50-0x5F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x60-0x6F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0x70-0x7F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x80-0x8F */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0x90-0x9F */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0xA0-0xAF */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0xB0-0xBF */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0xC0-0xCF */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0,
    /* 0xD0-0xDF */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0xE0-0xEF */
    1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
    /* 0xF0-0xFF */
    0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0
};
