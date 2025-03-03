/**
 * @file tag_base_type.h
 * @brief RFID tag type definitions for Chameleon Ultra
 * 
 * This header defines the various tag types supported by the Chameleon Ultra,
 * including both Low Frequency (125kHz) and High Frequency (13.56MHz) tags.
 * It provides enumerations for tag sensing and specific tag types, as well as
 * structures for maintaining tag information in device slots.
 */

#ifndef TAG_BASE_TYPE_H
#define TAG_BASE_TYPE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Field sensor type enumeration
 * 
 * Represents the type of electromagnetic field being sensed
 */
typedef enum {
    TAG_SENSE_NO = 0,   /**< No field induction detected */
    TAG_SENSE_LF,       /**< Low Frequency (125kHz) field induction */
    TAG_SENSE_HF        /**< High Frequency (13.56MHz) field induction */
} tag_sense_type_t;

/**
 * @brief Specific tag type enumeration
 * 
 * Comprehensive list of all supported tag types, organized by technology.
 * Values are grouped by categories with numeric ranges:
 * - 1-99: Legacy types (for backward compatibility)
 * - 100-999: LF tag types
 * - 1000+: HF tag types
 */
typedef enum {
    TAG_TYPE_UNDEFINED = 0,  /**< Undefined or unknown tag type */

    /* Legacy types (for backward compatibility) */
    OLD_TAG_TYPE_EM410X = 1,
    OLD_TAG_TYPE_MIFARE_Mini,
    OLD_TAG_TYPE_MIFARE_1024,
    OLD_TAG_TYPE_MIFARE_2048,
    OLD_TAG_TYPE_MIFARE_4096,
    OLD_TAG_TYPE_NTAG_213,
    OLD_TAG_TYPE_NTAG_215,
    OLD_TAG_TYPE_NTAG_216,

    /**** Low Frequency (LF) Tag Types ****/
    
    /* ASK Tag-Talk-First (100-199) */
    TAG_TYPE_EM410X = 100,   /**< EM4100/EM4102 transponder */
    /* Additional LF ASK tag types can be added here:
     * - FDX-B
     * - Securakey
     * - Gallagher
     * - PAC/Stanley
     * - Presco
     * - Visa2000
     * - Viking
     * - Noralsy
     * - Jablotron
     */

    /* FSK Tag-Talk-First (200-299) */
    /* Types to be added:
     * - HID Prox
     * - ioProx
     * - AWID
     * - Paradox
     */

    /* PSK Tag-Talk-First (300-399) */
    /* Types to be added:
     * - Indala
     * - Keri
     * - NexWatch
     */

    /* Reader-Talk-First (400-499) */
    /* Types to be added:
     * - T5577
     * - EM4x05/4x69
     * - EM4x50/4x70
     * - Hitag series
     */

    /**** High Frequency (HF) Tag Types ****/
    
    /* MIFARE Classic series (1000-1099) */
    TAG_TYPE_MIFARE_Mini = 1000,  /**< MIFARE Classic Mini (320 bytes) */
    TAG_TYPE_MIFARE_1024,         /**< MIFARE Classic 1K */
    TAG_TYPE_MIFARE_2048,         /**< MIFARE Classic 2K */
    TAG_TYPE_MIFARE_4096,         /**< MIFARE Classic 4K */
    
    /* MIFARE Ultralight/NTAG series (1100-1199) */
    TAG_TYPE_NTAG_213 = 1100,     /**< NTAG 213 (144 bytes) */
    TAG_TYPE_NTAG_215,            /**< NTAG 215 (504 bytes) */
    TAG_TYPE_NTAG_216,            /**< NTAG 216 (888 bytes) */
    TAG_TYPE_MF0ICU1,             /**< MIFARE Ultralight (64 bytes) */
    TAG_TYPE_MF0ICU2,             /**< MIFARE Ultralight C (192 bytes) */
    TAG_TYPE_MF0UL11,             /**< MIFARE Ultralight EV1 (48 bytes) */
    TAG_TYPE_MF0UL21,             /**< MIFARE Ultralight EV1 (128 bytes) */
    TAG_TYPE_NTAG_210,            /**< NTAG 210 (48 bytes) */
    TAG_TYPE_NTAG_212,            /**< NTAG 212 (128 bytes) */
    
    /* MIFARE Plus series (1200-1299) */
    /* To be implemented */
    
    /* DESFire series (1300-1399) */
    /* To be implemented */
    
    /* ST25TA series (2000-2099) */
    /* To be implemented */
    
    /* ISO14443A-4 series (3000-3099) */
    /* To be implemented */

} tag_specific_type_t;

/**
 * @brief Macro for mapping old LF tag types to new ones
 * 
 * Used for backward compatibility with existing configurations
 */
#define TAG_SPECIFIC_TYPE_OLD2NEW_LF_VALUES \
    {OLD_TAG_TYPE_EM410X, TAG_TYPE_EM410X}

/**
 * @brief Macro for mapping old HF tag types to new ones
 * 
 * Used for backward compatibility with existing configurations
 */
#define TAG_SPECIFIC_TYPE_OLD2NEW_HF_VALUES \
    {OLD_TAG_TYPE_MIFARE_Mini, TAG_TYPE_MIFARE_Mini},\
    {OLD_TAG_TYPE_MIFARE_1024, TAG_TYPE_MIFARE_1024},\
    {OLD_TAG_TYPE_MIFARE_2048, TAG_TYPE_MIFARE_2048},\
    {OLD_TAG_TYPE_MIFARE_4096, TAG_TYPE_MIFARE_4096},\
    {OLD_TAG_TYPE_NTAG_213, TAG_TYPE_NTAG_213},\
    {OLD_TAG_TYPE_NTAG_215, TAG_TYPE_NTAG_215},\
    {OLD_TAG_TYPE_NTAG_216, TAG_TYPE_NTAG_216}

/**
 * @brief Macro listing all supported LF tag types
 */
#define TAG_SPECIFIC_TYPE_LF_VALUES \
    TAG_TYPE_EM410X

/**
 * @brief Macro listing all supported HF tag types
 */
#define TAG_SPECIFIC_TYPE_HF_VALUES \
    TAG_TYPE_MIFARE_Mini,\
    TAG_TYPE_MIFARE_1024,\
    TAG_TYPE_MIFARE_2048,\
    TAG_TYPE_MIFARE_4096,\
    TAG_TYPE_NTAG_213,\
    TAG_TYPE_NTAG_215,\
    TAG_TYPE_NTAG_216,\
    TAG_TYPE_MF0ICU1,\
    TAG_TYPE_MF0ICU2,\
    TAG_TYPE_MF0UL11,\
    TAG_TYPE_MF0UL21,\
    TAG_TYPE_NTAG_210,\
    TAG_TYPE_NTAG_212

/**
 * @brief Structure to hold both HF and LF tag types for a slot
 */
typedef struct {
    tag_specific_type_t tag_hf;  /**< High frequency tag type */
    tag_specific_type_t tag_lf;  /**< Low frequency tag type */
} tag_slot_specific_type_t;

#ifdef __cplusplus
}
#endif

#endif /* TAG_BASE_TYPE_H */
