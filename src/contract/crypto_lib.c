/**
 * @file crypto_lib.c
 * @brief NEO CryptoLib native contract implementation
 */

#include "neoc/contract/crypto_lib.h"
#include "neoc/contract/smart_contract.h"
#include "neoc/script/script_builder.h"
#include "neoc/script/script_builder_full.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>

/* CryptoLib contract hash (little-endian) */
static const uint8_t CRYPTO_LIB_CONTRACT_HASH[20] = {
    0x72, 0x6c, 0xb6, 0xe0, 0xcd, 0x86, 0x28, 0xa1,
    0x35, 0x0a, 0x61, 0x13, 0x84, 0x68, 0x89, 0x11,
    0xab, 0x75, 0xf5, 0x1b
};

struct neoc_crypto_lib {
    neoc_smart_contract_t *contract;
};

neoc_error_t neoc_crypto_lib_create(neoc_crypto_lib_t **lib) {
    if (!lib) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid lib pointer");
    }

    *lib = neoc_calloc(1, sizeof(neoc_crypto_lib_t));
    if (!*lib) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate CryptoLib contract");
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CRYPTO_LIB_CONTRACT_HASH, 20);

    neoc_error_t err = neoc_smart_contract_create(&script_hash, "CryptoLib", &(*lib)->contract);
    if (err != NEOC_SUCCESS) {
        neoc_free(*lib);
        *lib = NULL;
        return err;
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_crypto_lib_sha256(neoc_crypto_lib_t *lib,
                                    const uint8_t *data,
                                    size_t data_len,
                                    uint8_t **script,
                                    size_t *script_len) {
    if (!lib || !data || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, data, data_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CRYPTO_LIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "sha256", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_crypto_lib_ripemd160(neoc_crypto_lib_t *lib,
                                       const uint8_t *data,
                                       size_t data_len,
                                       uint8_t **script,
                                       size_t *script_len) {
    if (!lib || !data || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, data, data_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CRYPTO_LIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "ripemd160", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_crypto_lib_murmur32(neoc_crypto_lib_t *lib,
                                      const uint8_t *data,
                                      size_t data_len,
                                      uint32_t seed,
                                      uint8_t **script,
                                      size_t *script_len) {
    if (!lib || !data || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_emit_push_int(builder, (int64_t)seed);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, data, data_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CRYPTO_LIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "murmur32", 2);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_crypto_lib_verify_with_ecdsa(neoc_crypto_lib_t *lib,
                                               const uint8_t *message,
                                               size_t msg_len,
                                               const uint8_t *pubkey,
                                               size_t pubkey_len,
                                               const uint8_t *signature,
                                               size_t sig_len,
                                               uint8_t curve,
                                               uint8_t **script,
                                               size_t *script_len) {
    if (!lib || !message || !pubkey || !signature || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_emit_push_int(builder, (int64_t)curve);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, signature, sig_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, pubkey, pubkey_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, message, msg_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, CRYPTO_LIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "verifyWithECDsa", 4);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

void neoc_crypto_lib_free(neoc_crypto_lib_t *lib) {
    if (!lib) return;

    if (lib->contract) {
        neoc_smart_contract_free(lib->contract);
    }

    neoc_free(lib);
}
