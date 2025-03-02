#include "hex_utils.h"

/**
 * @brief Convert uint64_t value to byte array in big-endian format
 * @param n Value to convert
 * @param len Number of bytes to write (1-8)
 * @param dest Destination buffer (must be at least len bytes)
 */
void num_to_bytes(uint64_t n, uint8_t len, uint8_t *dest) {
    // Most efficient implementation for all cases
    // This is actually faster than switch/case on ARM architecture
    while (len--) {
        dest[len] = (uint8_t)n;
        n >>= 8;
    }
}

/**
 * @brief Convert byte array in big-endian format to uint64_t value
 * @param src Source buffer to read from
 * @param len Number of bytes to read (1-8)
 * @return Converted uint64_t value
 */
uint64_t bytes_to_num(uint8_t *src, uint8_t len) {
    // Fast path for common sizes
    switch (len) {
        case 4:
            return ((uint32_t)src[0] << 24) |
                   ((uint32_t)src[1] << 16) |
                   ((uint32_t)src[2] << 8)  |
                   (uint32_t)src[3];
                
        case 2:
            return ((uint16_t)src[0] << 8) |
                   (uint16_t)src[1];
                
        case 1:
            return (uint64_t)src[0];
            
        case 0:
            return 0;
            
        default:
            break;
    }
    
    // Generic implementation with better performance
    uint64_t num = 0;
    for (uint8_t i = 0; i < len; i++) {
        num = (num << 8) | src[i];
    }
    
    return num;
}
