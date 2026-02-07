/**
 * @file neoc_hash.c
 * @brief Implementation of cryptographic hash functions using OpenSSL
 */

#include "neoc/crypto/neoc_hash.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdatomic.h>

/* Thread-safe one-time OpenSSL initialization. */
static atomic_int crypto_init_state = ATOMIC_VAR_INIT(0); /* 0=uninit, 1=initializing, 2=initialized */

neoc_error_t neoc_crypto_init(void) {
    int state = atomic_load(&crypto_init_state);
    if (state == 2) {
        return NEOC_SUCCESS;
    }

    int expected = 0;
    if (atomic_compare_exchange_strong(&crypto_init_state, &expected, 1)) {
        /* Initialize OpenSSL (safe no-op on OpenSSL >= 1.1). */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
#else
        OPENSSL_init_crypto(0, NULL);
#endif
        atomic_store(&crypto_init_state, 2);
        return NEOC_SUCCESS;
    }

    /* Another thread is initializing; wait until complete. */
    while (atomic_load(&crypto_init_state) == 1) {
        /* spin */
    }

    return NEOC_SUCCESS;
}

void neoc_crypto_cleanup(void) {
    /*
     * OpenSSL 1.1+ manages global cleanup automatically at process exit and
     * repeated init/cleanup cycles can cause subtle issues and leaks.
     * Keep this as a no-op to make neoc_cleanup() safe and idempotent.
     */
}

bool neoc_crypto_is_initialized(void) {
    return atomic_load(&crypto_init_state) == 2;
}

neoc_error_t neoc_sha256(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_SHA256_DIGEST_LENGTH]) {
    if (!data || !digest) {
        return NEOC_ERROR_NULL_POINTER;
    }
    
    if (!neoc_crypto_is_initialized()) {
        return NEOC_ERROR_CRYPTO_INIT;
    }
    
    SHA256_CTX ctx;
    if (!SHA256_Init(&ctx)) {
        return NEOC_ERROR_CRYPTO_HASH;
    }
    
    if (!SHA256_Update(&ctx, data, data_length)) {
        return NEOC_ERROR_CRYPTO_HASH;
    }
    
    if (!SHA256_Final(digest, &ctx)) {
        return NEOC_ERROR_CRYPTO_HASH;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_sha256_double(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_SHA256_DIGEST_LENGTH]) {
    if (!data || !digest) {
        return NEOC_ERROR_NULL_POINTER;
    }
    
    uint8_t first_hash[NEOC_SHA256_DIGEST_LENGTH];
    
    /* First SHA-256 */
    neoc_error_t result = neoc_sha256(data, data_length, first_hash);
    if (result != NEOC_SUCCESS) {
        return result;
    }
    
    /* Second SHA-256 */
    result = neoc_sha256(first_hash, NEOC_SHA256_DIGEST_LENGTH, digest);
    
    /* Clear intermediate result */
    memset(first_hash, 0, sizeof(first_hash));
    
    return result;
}

neoc_error_t neoc_ripemd160(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_RIPEMD160_DIGEST_LENGTH]) {
    if ((!data && data_length > 0) || !digest) {
        return NEOC_ERROR_NULL_POINTER;
    }
    
    if (!neoc_crypto_is_initialized()) {
        return NEOC_ERROR_CRYPTO_INIT;
    }
    
    RIPEMD160_CTX ctx;
    if (!RIPEMD160_Init(&ctx)) {
        return NEOC_ERROR_CRYPTO_HASH;
    }
    
    if (!RIPEMD160_Update(&ctx, data, data_length)) {
        return NEOC_ERROR_CRYPTO_HASH;
    }
    
    if (!RIPEMD160_Final(digest, &ctx)) {
        return NEOC_ERROR_CRYPTO_HASH;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_hash160(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_RIPEMD160_DIGEST_LENGTH]) {
    if (!data || !digest) {
        return NEOC_ERROR_NULL_POINTER;
    }
    
    uint8_t sha256_hash[NEOC_SHA256_DIGEST_LENGTH];
    
    /* First apply SHA-256 */
    neoc_error_t result = neoc_sha256(data, data_length, sha256_hash);
    if (result != NEOC_SUCCESS) {
        return result;
    }
    
    /* Then apply RIPEMD-160 */
    result = neoc_ripemd160(sha256_hash, NEOC_SHA256_DIGEST_LENGTH, digest);
    
    /* Clear intermediate result */
    memset(sha256_hash, 0, sizeof(sha256_hash));
    
    return result;
}

neoc_error_t neoc_hash256(const uint8_t* data, size_t data_length, uint8_t digest[NEOC_SHA256_DIGEST_LENGTH]) {
    /* Neo N3 Hash256 is double SHA-256: SHA256(SHA256(data)) */
    return neoc_sha256_double(data, data_length, digest);
}

neoc_error_t neoc_hmac_sha256(const uint8_t* key, size_t key_length,
                             const uint8_t* data, size_t data_length,
                             uint8_t digest[NEOC_SHA256_DIGEST_LENGTH]) {
    if (!key || !data || !digest) {
        return NEOC_ERROR_NULL_POINTER;
    }
    
    if (!neoc_crypto_is_initialized()) {
        return NEOC_ERROR_CRYPTO_INIT;
    }
    
    unsigned int digest_len = NEOC_SHA256_DIGEST_LENGTH;
    
    if (!HMAC(EVP_sha256(), key, (int)key_length, data, data_length, digest, &digest_len)) {
        return NEOC_ERROR_CRYPTO_HASH;
    }
    
    if (digest_len != NEOC_SHA256_DIGEST_LENGTH) {
        return NEOC_ERROR_CRYPTO_HASH;
    }
    
    return NEOC_SUCCESS;
}
