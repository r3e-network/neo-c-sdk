/**
 * @file hash.h
 * @brief Cryptographic hash functions
 */

#ifndef NEOC_CRYPTO_HASH_H
#define NEOC_CRYPTO_HASH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Compute SHA256 hash
 */
neoc_error_t neoc_hash_sha256(const uint8_t *data, size_t len, uint8_t *hash);

/**
 * Compute double SHA256 hash
 */
neoc_error_t neoc_hash_sha256_sha256(const uint8_t *data, size_t len, uint8_t *hash);

/**
 * Compute RIPEMD160 hash
 */
neoc_error_t neoc_hash_ripemd160(const uint8_t *data, size_t len, uint8_t *hash);

/**
 * Compute SHA256 then RIPEMD160 hash (Hash160)
 */
neoc_error_t neoc_hash_hash160(const uint8_t *data, size_t len, uint8_t *hash);

/**
 * Compute Hash256 (double SHA256)
 */
neoc_error_t neoc_hash_hash256(const uint8_t *data, size_t len, uint8_t *hash);

/**
 * Compute Murmur32 hash
 */
uint32_t neoc_hash_murmur32(const uint8_t *data, size_t len, uint32_t seed);

/**
 * Compute CRC32 checksum
 */
uint32_t neoc_hash_crc32(const uint8_t *data, size_t len);

/**
 * Compute HMAC SHA-512
 */
neoc_error_t neoc_hash_hmac_sha512(const uint8_t *data, size_t data_len,
                                   const uint8_t *key, size_t key_len,
                                   uint8_t *hash);

/**
 * Verify hash
 */
bool neoc_hash_verify(const uint8_t *data, size_t data_len,
                      const uint8_t *hash, size_t hash_len);

#ifdef __cplusplus
}
#endif

#endif // NEOC_CRYPTO_HASH_H
