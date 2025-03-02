/**
 * @file mf1_crypto1.h
 * @brief Crypto1 cipher implementation for MIFARE Classic
 * 
 * This header provides functions for using the Crypto1 stream cipher
 * employed in MIFARE Classic RFID cards.
 * 
 * Optimized for Chameleon Ultra hardware.
 */

#ifndef CRYPTO1_H
#define CRYPTO1_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the current Crypto1 state for debugging
 * 
 * @param pEven Buffer to store even bits (3 bytes) or NULL
 * @param pOdd Buffer to store odd bits (3 bytes) or NULL
 */
void Crypto1GetState(uint8_t *pEven, uint8_t *pOdd);

/**
 * @brief Get the current filter output without advancing the LFSR
 * 
 * @return Filter output bit (0 or 1)
 */
uint8_t Crypto1FilterOutput(void);

/**
 * @brief Initialize Crypto1 cipher for standard authentication
 * 
 * Sets up the Crypto1 state with the key and processes initial
 * card nonce XORed with UID bytes.
 * 
 * @param Key 6-byte key array
 * @param Uid 4-byte UID array 
 * @param CardNonce 4-byte nonce (encrypted in place)
 */
void Crypto1Setup(uint8_t Key[6], uint8_t Uid[4], uint8_t CardNonce[4]);

/**
 * @brief Initialize Crypto1 for nested authentication
 * 
 * Similar to Crypto1Setup but also handles parity bits
 * for nested authentication scenarios.
 * 
 * @param Key 6-byte key array
 * @param Uid 4-byte UID array
 * @param CardNonce 4-byte nonce (encrypted in place)
 * @param NonceParity 4-byte buffer for encrypted parity bits
 * @param Decrypt Flag indicating whether to decrypt (reader) or encrypt (tag)
 */
void Crypto1SetupNested(uint8_t Key[6], uint8_t Uid[4], uint8_t CardNonce[4], uint8_t NonceParity[4], bool Decrypt);

/**
 * @brief Process and authenticate reader nonce
 * 
 * Decrypts the reader nonce and updates the LFSR state
 * with the decrypted bits.
 * 
 * @param EncryptedReaderNonce 4-byte encrypted reader nonce
 */
void Crypto1Auth(uint8_t EncryptedReaderNonce[4]);

/**
 * @brief Process an array of bytes with Crypto1
 * 
 * Encrypts/decrypts multiple bytes efficiently by
 * avoiding state load/store for each byte.
 * 
 * @param Buffer Array of bytes to encrypt/decrypt (in-place)
 * @param Count Number of bytes to process
 */
void Crypto1ByteArray(uint8_t *Buffer, uint8_t Count);

/**
 * @brief Process array of bytes with parity bit generation
 * 
 * Encrypts bytes and generates encrypted parity bits.
 * 
 * @param Buffer Array of bytes to encrypt (in-place)
 * @param Parity Buffer to store encrypted parity bits
 * @param Count Number of bytes to process
 */
void Crypto1ByteArrayWithParity(uint8_t *Buffer, uint8_t *Parity, uint8_t Count);

/**
 * @brief Process array of bytes with input-feeding and parity generation
 * 
 * Similar to Crypto1ByteArrayWithParity but also
 * feeds buffer contents into the LFSR.
 * 
 * @param Buffer Array of bytes to process (in-place)
 * @param Parity Buffer to store encrypted parity bits
 * @param Count Number of bytes to process
 */
void Crypto1ByteArrayWithParityHasIn(uint8_t *Buffer, uint8_t *Parity, uint8_t Count);

/**
 * @brief Generate 4 bits of keystream (nibble)
 * 
 * @return 4-bit keystream value in bits 3-0
 */
uint8_t Crypto1Nibble(void);

/**
 * @brief Generate 8 bits of keystream (byte)
 * 
 * @return 8-bit keystream value
 */
uint8_t Crypto1Byte(void);

/**
 * @brief Optimized PRNG function for Crypto1
 * 
 * Efficiently advances the PRNG state by exploiting
 * the structure of the feedback polynomial.
 * 
 * @param State 4-byte PRNG state
 * @param ClockCount Number of iterations (must be multiple of 32)
 */
void Crypto1PRNG(uint8_t State[4], uint8_t ClockCount);

/**
 * @brief Optimized PRNG successor function
 * 
 * Portable implementation of prng_successor
 * using ARM-specific optimizations when available.
 * 
 * @param x Initial PRNG state
 * @param n Number of iterations
 * @return New PRNG state after n iterations
 */
uint32_t Crypto1FreePRNG(uint32_t x, uint32_t n);

/**
 * @brief Encrypt buffer with consideration for parity bits
 * 
 * Encrypts a buffer including parity bits (every 9th bit).
 * 
 * @param Buffer Buffer to encrypt (in-place)
 * @param BitCount Total number of bits to process
 */
void Crypto1EncryptWithParity(uint8_t *Buffer, uint8_t BitCount);

/**
 * @brief Process reader auth with parity bits
 * 
 * Handles reader authentication with proper parity bit processing.
 * 
 * @param PlainReaderAnswerWithParityBits 9-byte buffer with reader answer including parity
 */
void Crypto1ReaderAuthWithParity(uint8_t PlainReaderAnswerWithParityBits[9]);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO1_H */
