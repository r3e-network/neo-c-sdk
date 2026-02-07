/**
 * @file neoc_hash.h
 * @brief Cryptographic hash functions for NeoC SDK
 * 
 * Provides SHA-256, RIPEMD-160, and combined hash functions
 * using OpenSSL for maximum security and performance.
 */

#ifndef NEOC_CRYPTO_NEOC_HASH_H
#define NEOC_CRYPTO_NEOC_HASH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "neoc/neoc_error.h"

/**
 * @brief SHA-256 hash size in bytes
 */
#define NEOC_SHA256_DIGEST_LENGTH 32

/**
 * @brief RIPEMD-160 hash size in bytes
 */
#define NEOC_RIPEMD160_DIGEST_LENGTH 20

/**
 * @brief Compute SHA-256 hash of input data
 * 
 * @param data Input data to hash
 * @param data_length Length of input data
 * @param digest Output buffer for 32-byte digest
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_sha256(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_SHA256_DIGEST_LENGTH]);

/**
 * @brief Compute double SHA-256 hash (SHA-256 of SHA-256)
 * 
 * This is commonly used in Bitcoin and Neo protocols.
 * 
 * @param data Input data to hash
 * @param data_length Length of input data
 * @param digest Output buffer for 32-byte digest
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_sha256_double(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_SHA256_DIGEST_LENGTH]);

/**
 * @brief Compute RIPEMD-160 hash of input data
 * 
 * @param data Input data to hash
 * @param data_length Length of input data
 * @param digest Output buffer for 20-byte digest
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_ripemd160(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_RIPEMD160_DIGEST_LENGTH]);

/**
 * @brief Compute SHA-256 then RIPEMD-160 hash (Hash160)
 * 
 * This is the standard hash function used for Neo addresses and script hashes.
 * 
 * @param data Input data to hash
 * @param data_length Length of input data
 * @param digest Output buffer for 20-byte digest
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_hash160(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_RIPEMD160_DIGEST_LENGTH]);

/**
 * @brief Compute SHA-256 hash (Hash256)
 * 
 * Convenience function for Hash256 computation.
 * 
 * @param data Input data to hash
 * @param data_length Length of input data
 * @param digest Output buffer for 32-byte digest
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_hash256(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_SHA256_DIGEST_LENGTH]);

/**
 * @brief Compute HMAC-SHA256
 * 
 * @param key HMAC key
 * @param key_length Length of HMAC key
 * @param data Input data
 * @param data_length Length of input data
 * @param digest Output buffer for 32-byte digest
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_hmac_sha256(const uint8_t* key, size_t key_length,
                             const uint8_t* data, size_t data_length,
                             uint8_t digest[NEOC_SHA256_DIGEST_LENGTH]);

/**
 * @brief Initialize crypto library
 * 
 * This function initializes OpenSSL. It should be called once
 * before using any crypto functions.
 * 
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_crypto_init(void);

/**
 * @brief Cleanup crypto library
 * 
 * This function cleans up OpenSSL resources. It should be called
 * once when done using crypto functions.
 */
void neoc_crypto_cleanup(void);

/**
 * @brief Check if crypto library is initialized
 * 
 * @return true if initialized, false otherwise
 */
bool neoc_crypto_is_initialized(void);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_CRYPTO_NEOC_HASH_H */
