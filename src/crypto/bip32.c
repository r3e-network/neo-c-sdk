/**
 * @file bip32.c
 * @brief BIP-32 HD wallet implementation
 */

#include "neoc/crypto/bip32.h"
#include "neoc/crypto/sha256.h"
#include "neoc/crypto/neoc_hash.h"
#include "neoc/utils/neoc_base58.h"
#include "neoc/neoc_memory.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

// Version bytes for extended keys
static const uint8_t MAINNET_PRIVATE[4] = {0x04, 0x88, 0xAD, 0xE4}; // xprv
static const uint8_t MAINNET_PUBLIC[4] = {0x04, 0x88, 0xB2, 0x1E};  // xpub
static const uint8_t TESTNET_PRIVATE[4] = {0x04, 0x35, 0x83, 0x94}; // tprv
static const uint8_t TESTNET_PUBLIC[4] = {0x04, 0x35, 0x87, 0xCF};  // tpub

// Helper function to compute HMAC-SHA512
static int hmac_sha512(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t output[64]) {
    unsigned int out_len = 64;
    HMAC(EVP_sha512(), key, key_len, data, data_len, output, &out_len);
    return (out_len == 64) ? 0 : -1;
}

neoc_error_t neoc_bip32_from_seed_raw(const uint8_t *seed,
                                      size_t seed_len,
                                      neoc_bip32_key_t *master_key) {
    if (!seed || !master_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (seed_len < 16 || seed_len > 64) {
        return neoc_error_set(NEOC_ERROR_INVALID_LENGTH, "Seed must be 16-64 bytes");
    }
    
    // Compute HMAC-SHA512(key="Neo seed", data=seed)
    uint8_t hmac_result[64];
    if (hmac_sha512((const uint8_t*)BIP32_SEED_KEY, strlen(BIP32_SEED_KEY),
                    seed, seed_len, hmac_result) != 0) {
        return neoc_error_set(NEOC_ERROR_CRYPTO, "HMAC-SHA512 failed");
    }
    
    // Initialize master key
    memset(master_key, 0, sizeof(neoc_bip32_key_t));
    memcpy(master_key->version, MAINNET_PRIVATE, 4);
    master_key->depth = 0;
    master_key->child_number = 0;
    master_key->is_private = true;
    
    // Left 32 bytes = private key, right 32 bytes = chain code
    master_key->key[0] = 0x00; // Private key prefix
    memcpy(&master_key->key[1], hmac_result, 32);
    memcpy(master_key->chain_code, &hmac_result[32], 32);
    
    // Clear sensitive data
    neoc_secure_memzero(hmac_result, sizeof(hmac_result));
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_from_seed_alloc(const uint8_t *seed,
                                        size_t seed_len,
                                        neoc_bip32_key_t **master_key) {
    if (!master_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid master key pointer");
    }
    *master_key = neoc_calloc(1, sizeof(neoc_bip32_key_t));
    if (!*master_key) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate master key");
    }
    neoc_error_t err = neoc_bip32_from_seed_raw(seed, seed_len, *master_key);
    if (err != NEOC_SUCCESS) {
        neoc_free(*master_key);
        *master_key = NULL;
    }
    return err;
}

neoc_error_t neoc_bip32_derive_child(const neoc_bip32_key_t *parent,
                                      uint32_t index,
                                      neoc_bip32_key_t *child) {
    if (!parent || !child) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint8_t data[37];
    uint8_t hmac_result[64];
    
    // Check if hardened derivation
    bool hardened = (index & BIP32_HARDENED_KEY_START) != 0;
    
    if (hardened && !parent->is_private) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, 
                            "Cannot derive hardened child from public key");
    }
    
    // Prepare data for HMAC
    if (hardened) {
        // Hardened: 0x00 || private_key || index
        memcpy(data, parent->key, 33);
    } else {
        // Non-hardened: public_key || index
        if (parent->is_private) {
            // Derive public key from private key
            EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            if (!ec_key) {
                return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to create EC key");
            }

            BIGNUM *priv_bn = BN_bin2bn(&parent->key[1], 32, NULL);
            if (!priv_bn || !EC_KEY_set_private_key(ec_key, priv_bn)) {
                BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
                EC_KEY_free(ec_key);
                return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to set private key");
            }

            const EC_GROUP *group = EC_KEY_get0_group(ec_key);
            EC_POINT *pub_point = EC_POINT_new(group);
            if (!pub_point || !EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
                EC_POINT_free(pub_point);
                BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
                EC_KEY_free(ec_key);
                return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to compute public key");
            }

            size_t pub_len = EC_POINT_point2oct(group, pub_point,
                                               POINT_CONVERSION_COMPRESSED,
                                               data, 33, NULL);

            EC_POINT_free(pub_point);
            BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
            EC_KEY_free(ec_key);

            if (pub_len != 33) {
                return neoc_error_set(NEOC_ERROR_CRYPTO, "Invalid public key length");
            }
        } else {
            memcpy(data, parent->key, 33);
        }
    }
    
    // Append index (big-endian)
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;
    
    // Compute HMAC-SHA512
    if (hmac_sha512(parent->chain_code, 32, data, 37, hmac_result) != 0) {
        return neoc_error_set(NEOC_ERROR_CRYPTO, "HMAC-SHA512 failed");
    }
    
    // Initialize child key
    memcpy(child, parent, sizeof(neoc_bip32_key_t));
    child->depth = parent->depth + 1;
    child->child_number = index;
    
    // Get parent fingerprint
    if (parent->depth > 0) {
        neoc_bip32_get_fingerprint(parent, child->parent_fingerprint);
    }
    
    // Derive child private key
    if (parent->is_private) {
        // Add parent private key to IL (mod n)
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        BIGNUM *order = BN_new();
        BIGNUM *parent_key = BN_bin2bn(&parent->key[1], 32, NULL);
        BIGNUM *il = BN_bin2bn(hmac_result, 32, NULL);
        BIGNUM *child_key = BN_new();
        BN_CTX *ctx = BN_CTX_new();

        EC_GROUP_get_order(group, order, ctx);
        BN_mod_add(child_key, parent_key, il, order, ctx);

        // Check if result is valid
        if (BN_is_zero(child_key) || BN_cmp(child_key, order) >= 0) {
            BN_CTX_free(ctx);
            BN_clear_free(child_key);   // Use clear_free for sensitive key material
            BN_clear_free(il);          // Intermediate key is sensitive
            BN_clear_free(parent_key);  // Parent key is sensitive
            BN_free(order);
            EC_GROUP_free(group);
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Invalid child key");
        }

        // Store child private key
        child->key[0] = 0x00;
        BN_bn2binpad(child_key, &child->key[1], 32);
        child->is_private = true;

        BN_CTX_free(ctx);
        BN_clear_free(child_key);   // Use clear_free for sensitive key material
        BN_clear_free(il);          // Intermediate key is sensitive
        BN_clear_free(parent_key);  // Parent key is sensitive
        BN_free(order);
        EC_GROUP_free(group);
    } else {
        // Derive child public key (point addition)
        EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        if (!group) {
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to create EC group");
        }
        BIGNUM *il = BN_bin2bn(hmac_result, 32, NULL);
        EC_POINT *parent_point = EC_POINT_new(group);
        EC_POINT *child_point = EC_POINT_new(group);
        EC_POINT *generator_point = EC_POINT_new(group);
        BN_CTX *ctx = BN_CTX_new();

        // Get parent public key point
        if (EC_POINT_oct2point(group, parent_point, &parent->key[0], 33, ctx) != 1) {
            EC_POINT_free(parent_point);
            EC_POINT_free(child_point);
            EC_POINT_free(generator_point);
            BN_CTX_free(ctx);
            BN_clear_free(il);  // Use clear_free for intermediate key material
            EC_GROUP_free(group);
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Invalid parent public key");
        }

        // Get generator point and multiply by il
        const EC_POINT *generator = EC_GROUP_get0_generator(group);
        if (!generator) {
            EC_POINT_free(parent_point);
            EC_POINT_free(child_point);
            EC_POINT_free(generator_point);
            BN_CTX_free(ctx);
            BN_clear_free(il);  // Use clear_free for intermediate key material
            EC_GROUP_free(group);
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Cannot get generator point");
        }

        EC_POINT_copy(generator_point, generator);
        if (EC_POINT_mul(group, generator_point, il, NULL, NULL, ctx) != 1) {
            EC_POINT_free(parent_point);
            EC_POINT_free(child_point);
            EC_POINT_free(generator_point);
            BN_CTX_free(ctx);
            BN_clear_free(il);  // Use clear_free for intermediate key material
            EC_GROUP_free(group);
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Point multiplication failed");
        }

        // Add parent point to generator*il to get child point
        if (EC_POINT_add(group, child_point, parent_point, generator_point, ctx) != 1) {
            EC_POINT_free(parent_point);
            EC_POINT_free(child_point);
            EC_POINT_free(generator_point);
            BN_CTX_free(ctx);
            BN_clear_free(il);  // Use clear_free for intermediate key material
            EC_GROUP_free(group);
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Point addition failed");
        }

        // Convert child point back to compressed public key
        if (EC_POINT_point2oct(group, child_point, POINT_CONVERSION_COMPRESSED,
                              child->key, 33, ctx) != 33) {
            EC_POINT_free(parent_point);
            EC_POINT_free(child_point);
            EC_POINT_free(generator_point);
            BN_CTX_free(ctx);
            BN_clear_free(il);  // Use clear_free for intermediate key material
            EC_GROUP_free(group);
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Point to octets conversion failed");
        }

        child->is_private = false;

        EC_POINT_free(parent_point);
        EC_POINT_free(child_point);
        EC_POINT_free(generator_point);
        BN_CTX_free(ctx);
        BN_clear_free(il);  // Use clear_free for intermediate key material
        EC_GROUP_free(group);
    }
    
    // Set child chain code
    memcpy(child->chain_code, &hmac_result[32], 32);
    
    // Clear sensitive data
    neoc_secure_memzero(hmac_result, sizeof(hmac_result));
    neoc_secure_memzero(data, sizeof(data));
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_derive_path_raw(const neoc_bip32_key_t *master,
                                        const char *path,
                                        neoc_bip32_key_t *derived) {
    if (!master || !path || !derived) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint32_t indices[32];
    size_t indices_count;
    
    neoc_error_t err = neoc_bip32_parse_path(path, indices, 32, &indices_count);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    return neoc_bip32_derive_path_indices(master, indices, indices_count, derived);
}

neoc_error_t neoc_bip32_derive_path_indices(const neoc_bip32_key_t *master,
                                             const uint32_t *indices,
                                             size_t indices_count,
                                             neoc_bip32_key_t *derived) {
    if (!master || !indices || !derived) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    neoc_bip32_key_t current;
    memcpy(&current, master, sizeof(neoc_bip32_key_t));
    
    for (size_t i = 0; i < indices_count; i++) {
        neoc_bip32_key_t next;
        neoc_error_t err = neoc_bip32_derive_child(&current, indices[i], &next);
        if (err != NEOC_SUCCESS) {
            return err;
        }
        memcpy(&current, &next, sizeof(neoc_bip32_key_t));
    }
    
    memcpy(derived, &current, sizeof(neoc_bip32_key_t));
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_derive_path_indices_alloc(const neoc_bip32_key_t *master,
                                                  const uint32_t *indices,
                                                  size_t indices_count,
                                                  neoc_bip32_key_t **derived) {
    if (!derived) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid derived pointer");
    }
    *derived = neoc_calloc(1, sizeof(neoc_bip32_key_t));
    if (!*derived) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate derived key");
    }
    neoc_error_t err = neoc_bip32_derive_path_indices(master, indices, indices_count, *derived);
    if (err != NEOC_SUCCESS) {
        neoc_free(*derived);
        *derived = NULL;
    }
    return err;
}

neoc_error_t neoc_bip32_get_public_key(const neoc_bip32_key_t *key,
                                        neoc_bip32_key_t *public_key) {
    if (!key || !public_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    memcpy(public_key, key, sizeof(neoc_bip32_key_t));
    
    if (key->is_private) {
        // Convert private to public
        EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec_key) {
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to create EC key");
        }

        BIGNUM *priv_bn = BN_bin2bn(&key->key[1], 32, NULL);
        if (!priv_bn || !EC_KEY_set_private_key(ec_key, priv_bn)) {
            BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
            EC_KEY_free(ec_key);
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to set private key");
        }

        const EC_GROUP *group = EC_KEY_get0_group(ec_key);
        EC_POINT *pub_point = EC_POINT_new(group);
        if (!pub_point || !EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
            EC_POINT_free(pub_point);
            BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
            EC_KEY_free(ec_key);
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Failed to compute public key");
        }

        size_t pub_len = EC_POINT_point2oct(group, pub_point,
                                           POINT_CONVERSION_COMPRESSED,
                                           public_key->key, 33, NULL);

        EC_POINT_free(pub_point);
        BN_clear_free(priv_bn);  // Use clear_free for sensitive key material
        EC_KEY_free(ec_key);

        if (pub_len != 33) {
            return neoc_error_set(NEOC_ERROR_CRYPTO, "Invalid public key length");
        }

        // Update version to public
        memcpy(public_key->version, MAINNET_PUBLIC, 4);
        public_key->is_private = false;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_to_ec_key_pair_raw(const neoc_bip32_key_t *bip32_key,
                                           neoc_ec_key_pair_t *ec_key) {
    if (!bip32_key || !ec_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (!bip32_key->is_private) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, 
                            "Cannot create EC key pair from public key only");
    }
    
    neoc_ec_key_pair_t *tmp = NULL;
    neoc_error_t err = neoc_ec_key_pair_from_private_key(&bip32_key->key[1], 32, &tmp);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    *ec_key = *tmp;
    neoc_free(tmp);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_to_ec_key_pair_alloc(const neoc_bip32_key_t *bip32_key,
                                             neoc_ec_key_pair_t **ec_key) {
    if (!ec_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid EC key pointer");
    }
    *ec_key = NULL;
    neoc_error_t err = neoc_ec_key_pair_from_private_key(&bip32_key->key[1], 32, ec_key);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_get_fingerprint(const neoc_bip32_key_t *key,
                                         uint8_t fingerprint[BIP32_FINGERPRINT_SIZE]) {
    if (!key || !fingerprint) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint8_t public_key[33];
    
    if (key->is_private) {
        // Get public key from private
        neoc_bip32_key_t pub_key;
        neoc_error_t err = neoc_bip32_get_public_key(key, &pub_key);
        if (err != NEOC_SUCCESS) {
            return err;
        }
        memcpy(public_key, pub_key.key, 33);
    } else {
        memcpy(public_key, key->key, 33);
    }
    
    // Fingerprint = first 4 bytes of HASH160(public_key)
    neoc_hash160_t hash;
    neoc_error_t err = neoc_hash160_from_data(&hash, public_key, 33);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    memcpy(fingerprint, hash.data, BIP32_FINGERPRINT_SIZE);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_parse_path(const char *path,
                                    uint32_t *indices,
                                    size_t max_indices,
                                    size_t *indices_count) {
    if (!path || !indices || !indices_count) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *indices_count = 0;
    
    // Skip 'm' or 'M' at the beginning
    if (*path == 'm' || *path == 'M') {
        path++;
        if (*path == '/') {
            path++;
        }
    }
    
    char buffer[32];
    size_t buf_pos = 0;
    
    while (*path && *indices_count < max_indices) {
        if (*path == '/') {
            if (buf_pos > 0) {
                buffer[buf_pos] = '\0';
                
                // Check for hardened marker
                bool hardened = false;
                if (buffer[buf_pos - 1] == '\'' || buffer[buf_pos - 1] == 'h') {
                    hardened = true;
                    buffer[buf_pos - 1] = '\0';
                }
                
                // Parse index
                char *endptr;
                unsigned long index = strtoul(buffer, &endptr, 10);
                if (*endptr != '\0' || index > 0x7FFFFFFF) {
                    return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, 
                                        "Invalid path component");
                }
                
                if (hardened) {
                    index |= BIP32_HARDENED_KEY_START;
                }
                
                indices[(*indices_count)++] = (uint32_t)index;
                buf_pos = 0;
            }
            path++;
        } else {
            if (buf_pos >= sizeof(buffer) - 1) {
                return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Path component too long");
            }
            buffer[buf_pos++] = *path++;
        }
    }
    
    // Handle last component
    if (buf_pos > 0) {
        buffer[buf_pos] = '\0';
        
        bool hardened = false;
        if (buffer[buf_pos - 1] == '\'' || buffer[buf_pos - 1] == 'h') {
            hardened = true;
            buffer[buf_pos - 1] = '\0';
        }
        
        char *endptr;
        unsigned long index = strtoul(buffer, &endptr, 10);
        if (*endptr != '\0' || index > 0x7FFFFFFF) {
            return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid path component");
        }
        
        if (hardened) {
            index |= BIP32_HARDENED_KEY_START;
        }
        
        indices[(*indices_count)++] = (uint32_t)index;
    }
    
    return NEOC_SUCCESS;
}

void neoc_bip32_key_free(neoc_bip32_key_t *key) {
    if (!key) {
        return;
    }
    neoc_secure_memzero(key, sizeof(neoc_bip32_key_t));
    neoc_free(key);
}

neoc_error_t neoc_bip32_get_neo_path(uint32_t account,
                                      uint32_t change,
                                      uint32_t address_index,
                                      uint32_t indices[5]) {
    if (!indices) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid indices array");
    }
    
    // m/44'/888'/account'/change/address_index
    indices[0] = BIP32_NEO_PURPOSE | BIP32_HARDENED_KEY_START;
    indices[1] = BIP32_NEO_COIN_TYPE | BIP32_HARDENED_KEY_START;
    indices[2] = account | BIP32_HARDENED_KEY_START;
    indices[3] = change;
    indices[4] = address_index;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_serialize(const neoc_bip32_key_t *key,
                                   char *xkey,
                                   size_t xkey_size) {
    if (!key || !xkey) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (xkey_size < 112) {
        return neoc_error_set(NEOC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for xkey");
    }
    
    uint8_t data[BIP32_SERIALIZED_SIZE];
    size_t pos = 0;
    
    // Version
    memcpy(&data[pos], key->version, 4);
    pos += 4;
    
    // Depth
    data[pos++] = key->depth;
    
    // Parent fingerprint
    memcpy(&data[pos], key->parent_fingerprint, 4);
    pos += 4;
    
    // Child number (big-endian)
    data[pos++] = (key->child_number >> 24) & 0xFF;
    data[pos++] = (key->child_number >> 16) & 0xFF;
    data[pos++] = (key->child_number >> 8) & 0xFF;
    data[pos++] = key->child_number & 0xFF;
    
    // Chain code
    memcpy(&data[pos], key->chain_code, 32);
    pos += 32;
    
    // Key data
    memcpy(&data[pos], key->key, 33);
    pos += 33;
    
    // Base58Check encode
    char *encoded = neoc_base58_check_encode_alloc(data, BIP32_SERIALIZED_SIZE);
    if (!encoded) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to encode xkey");
    }
    
    size_t encoded_len = strlen(encoded);
    if (encoded_len >= xkey_size) {
        neoc_free(encoded);
        return neoc_error_set(NEOC_ERROR_BUFFER_TOO_SMALL, "Buffer too small");
    }
    
    strcpy(xkey, encoded);
    neoc_free(encoded);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_bip32_deserialize(const char *xkey,
                                     neoc_bip32_key_t *key) {
    if (!xkey || !key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    size_t decoded_len;
    uint8_t *decoded = neoc_base58_check_decode_alloc(xkey, &decoded_len);
    if (!decoded) {
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid xkey format");
    }
    
    if (decoded_len != BIP32_SERIALIZED_SIZE) {
        neoc_free(decoded);
        return neoc_error_set(NEOC_ERROR_INVALID_LENGTH, "Invalid xkey length");
    }
    
    size_t pos = 0;
    
    // Version
    memcpy(key->version, &decoded[pos], 4);
    pos += 4;
    
    // Check if private or public
    if (memcmp(key->version, MAINNET_PRIVATE, 4) == 0 ||
        memcmp(key->version, TESTNET_PRIVATE, 4) == 0) {
        key->is_private = true;
    } else if (memcmp(key->version, MAINNET_PUBLIC, 4) == 0 ||
               memcmp(key->version, TESTNET_PUBLIC, 4) == 0) {
        key->is_private = false;
    } else {
        neoc_free(decoded);
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Unknown xkey version");
    }
    
    // Depth
    key->depth = decoded[pos++];
    
    // Parent fingerprint
    memcpy(key->parent_fingerprint, &decoded[pos], 4);
    pos += 4;
    
    // Child number (big-endian)
    key->child_number = ((uint32_t)decoded[pos] << 24) |
                        ((uint32_t)decoded[pos + 1] << 16) |
                        ((uint32_t)decoded[pos + 2] << 8) |
                        decoded[pos + 3];
    pos += 4;
    
    // Chain code
    memcpy(key->chain_code, &decoded[pos], 32);
    pos += 32;
    
    // Key data
    memcpy(key->key, &decoded[pos], 33);
    
    neoc_free(decoded);
    return NEOC_SUCCESS;
}
