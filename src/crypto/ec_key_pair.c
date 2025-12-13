#include "neoc/crypto/ec_key_pair.h"
#include "neoc/crypto/ecdsa_signature.h"
#include "neoc/crypto/wif.h"
#include "neoc/crypto/neoc_hash.h"
#include "neoc/utils/neoc_base58.h"
#include "neoc/script/script_builder.h"
#include "neoc/neoc_memory.h"
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <string.h>
#include <stdlib.h>

// NEO uses secp256r1 (NIST P-256)
#define SECP256R1_NID NID_X9_62_prime256v1

// Create EC_GROUP for secp256r1
static EC_GROUP* create_secp256r1_group(void) {
    return EC_GROUP_new_by_curve_name(SECP256R1_NID);
}

// Alias for compatibility (old name)
neoc_error_t neoc_ec_key_pair_from_private_key(const uint8_t *private_key_bytes,
                                                size_t key_size,
                                                neoc_ec_key_pair_t **key_pair) {
    if (key_size != 32) {
        return neoc_error_set(NEOC_ERROR_INVALID_LENGTH, "Private key must be 32 bytes");
    }
    return neoc_ec_key_pair_create_from_private_key(private_key_bytes, key_pair);
}

neoc_error_t neoc_ec_key_pair_create_from_private_key(const uint8_t *private_key_bytes,
                                                       neoc_ec_key_pair_t **key_pair) {
    if (!private_key_bytes) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "private_key_bytes is NULL");
    }
    if (!key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "key_pair is NULL");
    }
    
    neoc_error_t err = neoc_crypto_init();
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    *key_pair = calloc(1, sizeof(neoc_ec_key_pair_t));
    if (!*key_pair) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate key pair");
    }
    
    // Create private key structure
    (*key_pair)->private_key = calloc(1, sizeof(neoc_ec_private_key_t));
    if (!(*key_pair)->private_key) {
        free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate private key");
    }
    
    // Copy private key bytes
    memcpy((*key_pair)->private_key->bytes, private_key_bytes, 32);
    
    // Create EC_KEY
    EC_KEY *ec_key = EC_KEY_new();
    if (!ec_key) {
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to create EC_KEY");
    }
    
    EC_GROUP *group = create_secp256r1_group();
    if (!group || EC_KEY_set_group(ec_key, group) != 1) {
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to set EC group");
    }
    
    // Set private key
    BIGNUM *priv_bn = BN_bin2bn(private_key_bytes, 32, NULL);
    if (!priv_bn || EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
        BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to set private key");
    }
    
    // Calculate public key from private key
    EC_POINT *pub_point = EC_POINT_new(group);
    if (!pub_point ||
        EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL) != 1) {
        EC_POINT_free(pub_point);
        BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to calculate public key");
    }

    if (EC_KEY_set_public_key(ec_key, pub_point) != 1) {
        EC_POINT_free(pub_point);
        BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to set public key");
    }
    
    // Create EVP_PKEY for higher-level operations
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_set1_EC_KEY(pkey, ec_key) != 1) {
        EVP_PKEY_free(pkey);
        EC_POINT_free(pub_point);
        BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to create EVP_PKEY");
    }
    (*key_pair)->private_key->pkey = pkey;
    (*key_pair)->private_key->ec_key = ec_key;
    
    // Create public key structure
    (*key_pair)->public_key = calloc(1, sizeof(neoc_ec_public_key_t));
    if (!(*key_pair)->public_key) {
        EC_POINT_free(pub_point);
        BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
        EC_GROUP_free(group);
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate public key");
    }
    
    (*key_pair)->public_key->point = pub_point;
    (*key_pair)->public_key->group = group;
    (*key_pair)->public_key->is_compressed = true;
    
    // Get compressed public key
    size_t compressed_len = EC_POINT_point2oct(group, pub_point,
                                                POINT_CONVERSION_COMPRESSED,
                                                (*key_pair)->public_key->compressed,
                                                33, NULL);
    if (compressed_len != 33) {
        BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to get compressed public key");
    }

    // Get uncompressed public key
    size_t uncompressed_len = EC_POINT_point2oct(group, pub_point,
                                                  POINT_CONVERSION_UNCOMPRESSED,
                                                  (*key_pair)->public_key->uncompressed,
                                                  65, NULL);
    if (uncompressed_len != 65) {
        BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
        neoc_ec_key_pair_free(*key_pair);
        *key_pair = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to get uncompressed public key");
    }

    BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_key_pair_create_random(neoc_ec_key_pair_t **key_pair) {
    if (!key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "key_pair is NULL in create_random");
    }

    neoc_error_t err = neoc_crypto_init();
    if (err != NEOC_SUCCESS) {
        return err;
    }

    // Generate random 32-byte private key
    uint8_t private_key[32];
    int rand_result = RAND_bytes(private_key, 32);
    if (rand_result != 1) {
        // Clear buffer even on failure to prevent partial random data leakage
        OPENSSL_cleanse(private_key, sizeof(private_key));
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to generate random bytes from OpenSSL");
    }

    // Create key pair from private key
    err = neoc_ec_key_pair_create_from_private_key(private_key, key_pair);

    // Clear private key from memory
    OPENSSL_cleanse(private_key, sizeof(private_key));

    return err;
}

neoc_error_t neoc_ec_key_pair_get_address(const neoc_ec_key_pair_t *key_pair, char **address) {
    if (!key_pair || !address) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Get script hash first
    neoc_hash160_t script_hash;
    neoc_error_t err = neoc_ec_key_pair_get_script_hash(key_pair, &script_hash);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Convert script hash to address (allocate memory for address)
    char temp_address[58];  // Max NEO address length
    err = neoc_hash160_to_address(&script_hash, temp_address, sizeof(temp_address));
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    size_t addr_len = strlen(temp_address) + 1;
    *address = neoc_malloc(addr_len);
    if (!*address) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    memcpy(*address, temp_address, addr_len);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_key_pair_get_script_hash(const neoc_ec_key_pair_t *key_pair,
                                               neoc_hash160_t *script_hash) {
    if (!key_pair || !script_hash || !key_pair->public_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Build verification script from public key
    uint8_t *script = NULL;
    size_t script_len = 0;
    neoc_error_t err = neoc_script_builder_build_verification_script(
        key_pair->public_key->compressed, 33, &script, &script_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Hash the script to get script hash (Hash160 = RIPEMD160(SHA256(data)))
    uint8_t hash160[20];
    err = neoc_hash160(script, script_len, hash160);
    free(script);
    
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Copy the hash to the script_hash structure
    memcpy(script_hash->data, hash160, 20);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_key_pair_sign(const neoc_ec_key_pair_t *key_pair,
                                    const uint8_t *message_hash,
                                    neoc_ecdsa_signature_t **signature) {
    if (!key_pair || !message_hash || !signature || !key_pair->private_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *signature = calloc(1, sizeof(neoc_ecdsa_signature_t));
    if (!*signature) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate signature");
    }
    
    // Create signature using ECDSA
    ECDSA_SIG *sig = ECDSA_do_sign(message_hash, 32, key_pair->private_key->ec_key);
    if (!sig) {
        free(*signature);
        *signature = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to create signature");
    }
    
    // Get r and s components
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    
    // Convert to bytes (padded to 32 bytes)
    if (BN_bn2binpad(r, (*signature)->r, 32) != 32 ||
        BN_bn2binpad(s, (*signature)->s, 32) != 32) {
        ECDSA_SIG_free(sig);
        free(*signature);
        *signature = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to convert signature components");
    }
    
    ECDSA_SIG_free(sig);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_key_pair_export_as_wif(const neoc_ec_key_pair_t *key_pair, char **wif) {
    if (!key_pair || !wif || !key_pair->private_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    return neoc_private_key_to_wif(key_pair->private_key->bytes, wif);
}

neoc_error_t neoc_ec_key_pair_import_from_wif(const char *wif, neoc_ec_key_pair_t **key_pair) {
    if (!wif || !key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Convert WIF to private key
    uint8_t *private_key = NULL;
    neoc_error_t err = neoc_wif_to_private_key(wif, &private_key);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Create key pair from private key
    err = neoc_ec_key_pair_create_from_private_key(private_key, key_pair);
    
    // Clear and free private key
    OPENSSL_cleanse(private_key, 32);
    free(private_key);
    
    return err;
}

void neoc_ec_key_pair_free(neoc_ec_key_pair_t *key_pair) {
    if (!key_pair) return;

    if (key_pair->private_key) {
        // EVP_PKEY_set1_EC_KEY increments EC_KEY refcount, so we must free both.
        // Order matters: free EVP_PKEY first (decrements EC_KEY refcount),
        // then free EC_KEY (decrements again, reaching 0).
        if (key_pair->private_key->pkey) {
            EVP_PKEY_free(key_pair->private_key->pkey);
        }
        if (key_pair->private_key->ec_key) {
            EC_KEY_free(key_pair->private_key->ec_key);
        }
        OPENSSL_cleanse(key_pair->private_key->bytes, 32);
        free(key_pair->private_key);
    }
    
    if (key_pair->public_key) {
        neoc_ec_public_key_free(key_pair->public_key);
    }
    
    free(key_pair);
}

neoc_error_t neoc_ec_public_key_from_private(const uint8_t *private_key_bytes,
                                              neoc_ec_public_key_t **public_key) {
    if (!private_key_bytes || !public_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Create key pair to derive public key from private key
    neoc_ec_key_pair_t *key_pair = NULL;
    neoc_error_t err = neoc_ec_key_pair_create_from_private_key(private_key_bytes, &key_pair);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Copy public key
    *public_key = calloc(1, sizeof(neoc_ec_public_key_t));
    if (!*public_key) {
        neoc_ec_key_pair_free(key_pair);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate public key");
    }
    
    // Deep copy the public key
    (*public_key)->group = create_secp256r1_group();
    if (!(*public_key)->group) {
        free(*public_key);
        *public_key = NULL;
        neoc_ec_key_pair_free(key_pair);
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to create EC group");
    }

    (*public_key)->point = EC_POINT_dup(key_pair->public_key->point,
                                         key_pair->public_key->group);
    if (!(*public_key)->point) {
        EC_GROUP_free((*public_key)->group);
        free(*public_key);
        *public_key = NULL;
        neoc_ec_key_pair_free(key_pair);
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to duplicate EC point");
    }
    (*public_key)->is_compressed = key_pair->public_key->is_compressed;
    memcpy((*public_key)->compressed, key_pair->public_key->compressed, 33);
    memcpy((*public_key)->uncompressed, key_pair->public_key->uncompressed, 65);
    
    // Clean up the key pair while preserving the copied public key
    key_pair->public_key = NULL;  // Prevent double-free
    neoc_ec_key_pair_free(key_pair);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_public_key_from_bytes(const uint8_t *encoded, size_t encoded_len,
                                            neoc_ec_public_key_t **public_key) {
    if (!encoded || !public_key || (encoded_len != 33 && encoded_len != 65)) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid public key length");
    }
    
    neoc_error_t err = neoc_crypto_init();
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    *public_key = calloc(1, sizeof(neoc_ec_public_key_t));
    if (!*public_key) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate public key");
    }
    
    (*public_key)->group = create_secp256r1_group();
    (*public_key)->point = EC_POINT_new((*public_key)->group);
    
    if (!(*public_key)->point ||
        EC_POINT_oct2point((*public_key)->group, (*public_key)->point, 
                           encoded, encoded_len, NULL) != 1) {
        neoc_ec_public_key_free(*public_key);
        *public_key = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to decode public key");
    }
    
    // Store both compressed and uncompressed forms
    EC_POINT_point2oct((*public_key)->group, (*public_key)->point,
                       POINT_CONVERSION_COMPRESSED,
                       (*public_key)->compressed, 33, NULL);
    
    EC_POINT_point2oct((*public_key)->group, (*public_key)->point,
                       POINT_CONVERSION_UNCOMPRESSED,
                       (*public_key)->uncompressed, 65, NULL);
    
    (*public_key)->is_compressed = (encoded_len == 33);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_public_key_get_encoded(const neoc_ec_public_key_t *public_key,
                                             bool compressed,
                                             uint8_t **encoded,
                                             size_t *encoded_len) {
    if (!public_key || !encoded || !encoded_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (compressed) {
        *encoded_len = 33;
        *encoded = malloc(33);
        if (!*encoded) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate memory");
        }
        memcpy(*encoded, public_key->compressed, 33);
    } else {
        *encoded_len = 65;
        *encoded = malloc(65);
        if (!*encoded) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate memory");
        }
        memcpy(*encoded, public_key->uncompressed, 65);
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_public_key_to_bytes(const neoc_ec_public_key_t *public_key,
                                          uint8_t *bytes,
                                          size_t *len) {
    if (!public_key || !bytes || !len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    if (*len < 33) {
        return neoc_error_set(NEOC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for public key");
    }

    memcpy(bytes, public_key->compressed, 33);
    *len = 33;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_public_key_clone(const neoc_ec_public_key_t *public_key,
                                      neoc_ec_public_key_t **clone) {
    if (!public_key || !clone) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    return neoc_ec_public_key_from_bytes(public_key->compressed, 33, clone);
}

void neoc_ec_public_key_free(neoc_ec_public_key_t *public_key) {
    if (!public_key) return;
    
    if (public_key->point) {
        EC_POINT_free(public_key->point);
    }
    if (public_key->group) {
        EC_GROUP_free(public_key->group);
    }
    
    free(public_key);
}

void neoc_ec_private_key_free(neoc_ec_private_key_t *private_key) {
    if (!private_key) return;
    
    if (private_key->pkey) {
        EVP_PKEY_free(private_key->pkey);
    }
    if (private_key->ec_key) {
        EC_KEY_free(private_key->ec_key);
    }
    OPENSSL_cleanse(private_key->bytes, 32);
    
    free(private_key);
}

neoc_error_t neoc_ec_key_pair_get_private_key(const neoc_ec_key_pair_t *key_pair,
                                               uint8_t *private_key,
                                               size_t *key_len) {
    if (!key_pair || !private_key || !key_len) {
        return NEOC_ERROR_NULL_POINTER;
    }
    
    if (!key_pair->private_key) {
        return NEOC_ERROR_INVALID_STATE;
    }
    
    if (*key_len < 32) {
        *key_len = 32;
        return NEOC_ERROR_BUFFER_TOO_SMALL;
    }
    
    memcpy(private_key, key_pair->private_key->bytes, 32);
    *key_len = 32;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_key_pair_get_public_key(const neoc_ec_key_pair_t *key_pair,
                                              uint8_t *public_key,
                                              size_t *key_len) {
    if (!key_pair || !public_key || !key_len) {
        return NEOC_ERROR_NULL_POINTER;
    }
    
    if (!key_pair->public_key) {
        return NEOC_ERROR_INVALID_STATE;
    }
    
    if (*key_len < 33) {
        *key_len = 33;
        return NEOC_ERROR_BUFFER_TOO_SMALL;
    }
    
    memcpy(public_key, key_pair->public_key->compressed, 33);
    *key_len = 33;

    return NEOC_SUCCESS;
}

neoc_error_t neoc_ec_key_pair_get_public_key_object(const neoc_ec_key_pair_t *key_pair,
                                                    neoc_ec_public_key_t **public_key) {
    if (!key_pair || !public_key) {
        return NEOC_ERROR_NULL_POINTER;
    }

    uint8_t encoded[65];
    size_t encoded_len = sizeof(encoded);
    neoc_error_t err = neoc_ec_key_pair_get_public_key(key_pair, encoded, &encoded_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    return neoc_ec_public_key_from_bytes(encoded, encoded_len, public_key);
}
