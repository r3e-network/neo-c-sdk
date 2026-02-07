/**
 * @file crypto_lib.h
 * @brief NEO CryptoLib native contract wrapper
 */

#ifndef NEOC_CRYPTO_LIB_H_GUARD
#define NEOC_CRYPTO_LIB_H_GUARD

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/types/neoc_hash160.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief CryptoLib contract opaque type
 */
typedef struct neoc_crypto_lib neoc_crypto_lib_t;

/**
 * @brief Create CryptoLib contract instance
 *
 * @param lib Output CryptoLib contract (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_crypto_lib_create(neoc_crypto_lib_t **lib);

/**
 * @brief Build invocation script for sha256
 *
 * @param lib CryptoLib contract instance
 * @param data Input data to hash
 * @param data_len Length of input data
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_crypto_lib_sha256(neoc_crypto_lib_t *lib,
                                    const uint8_t *data,
                                    size_t data_len,
                                    uint8_t **script,
                                    size_t *script_len);

/**
 * @brief Build invocation script for ripemd160
 *
 * @param lib CryptoLib contract instance
 * @param data Input data to hash
 * @param data_len Length of input data
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_crypto_lib_ripemd160(neoc_crypto_lib_t *lib,
                                       const uint8_t *data,
                                       size_t data_len,
                                       uint8_t **script,
                                       size_t *script_len);

/**
 * @brief Build invocation script for murmur32
 *
 * @param lib CryptoLib contract instance
 * @param data Input data to hash
 * @param data_len Length of input data
 * @param seed Murmur32 seed value
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_crypto_lib_murmur32(neoc_crypto_lib_t *lib,
                                      const uint8_t *data,
                                      size_t data_len,
                                      uint32_t seed,
                                      uint8_t **script,
                                      size_t *script_len);

/**
 * @brief Build invocation script for verifyWithECDsa
 *
 * @param lib CryptoLib contract instance
 * @param message Message that was signed
 * @param msg_len Length of message
 * @param pubkey Public key bytes
 * @param pubkey_len Length of public key
 * @param signature Signature bytes
 * @param sig_len Length of signature
 * @param curve Named curve identifier
 * @param script Output script bytes (caller must free)
 * @param script_len Output script length
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_crypto_lib_verify_with_ecdsa(neoc_crypto_lib_t *lib,
                                               const uint8_t *message,
                                               size_t msg_len,
                                               const uint8_t *pubkey,
                                               size_t pubkey_len,
                                               const uint8_t *signature,
                                               size_t sig_len,
                                               uint8_t curve,
                                               uint8_t **script,
                                               size_t *script_len);

/**
 * @brief Free CryptoLib contract instance
 *
 * @param lib CryptoLib contract to free
 */
void neoc_crypto_lib_free(neoc_crypto_lib_t *lib);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_CRYPTO_LIB_H_GUARD */
