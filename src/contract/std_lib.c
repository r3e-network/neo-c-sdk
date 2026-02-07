/**
 * @file std_lib.c
 * @brief NEO StdLib native contract implementation
 */

#include "neoc/contract/std_lib.h"
#include "neoc/contract/smart_contract.h"
#include "neoc/script/script_builder.h"
#include "neoc/script/script_builder_full.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>

/* StdLib contract hash (little-endian) */
static const uint8_t STDLIB_CONTRACT_HASH[20] = {
    0xac, 0xce, 0x6f, 0xd8, 0x0d, 0x44, 0xe1, 0x79,
    0x6a, 0xa0, 0xc2, 0xc6, 0x25, 0xe9, 0xe4, 0xe0,
    0xce, 0x39, 0xef, 0xc0
};

struct neoc_std_lib {
    neoc_smart_contract_t *contract;
};

neoc_error_t neoc_std_lib_create(neoc_std_lib_t **lib) {
    if (!lib) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid lib pointer");
    }

    *lib = neoc_calloc(1, sizeof(neoc_std_lib_t));
    if (!*lib) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate StdLib contract");
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    neoc_error_t err = neoc_smart_contract_create(&script_hash, "StdLib", &(*lib)->contract);
    if (err != NEOC_SUCCESS) {
        neoc_free(*lib);
        *lib = NULL;
        return err;
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_std_lib_serialize(neoc_std_lib_t *lib,
                                    const uint8_t *data, size_t data_len,
                                    uint8_t **script, size_t *script_len) {
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
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "serialize", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_deserialize(neoc_std_lib_t *lib,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t **script, size_t *script_len) {
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
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "deserialize", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_json_serialize(neoc_std_lib_t *lib,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t **script, size_t *script_len) {
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
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "jsonSerialize", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_json_deserialize(neoc_std_lib_t *lib,
                                            const char *json_str,
                                            uint8_t **script, size_t *script_len) {
    if (!lib || !json_str || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, (const uint8_t *)json_str, strlen(json_str));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "jsonDeserialize", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_base64_encode(neoc_std_lib_t *lib,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t **script, size_t *script_len) {
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
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "base64Encode", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_base64_decode(neoc_std_lib_t *lib,
                                         const char *encoded,
                                         uint8_t **script, size_t *script_len) {
    if (!lib || !encoded || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, (const uint8_t *)encoded, strlen(encoded));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "base64Decode", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_base58_encode(neoc_std_lib_t *lib,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t **script, size_t *script_len) {
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
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "base58Encode", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_base58_decode(neoc_std_lib_t *lib,
                                         const char *encoded,
                                         uint8_t **script, size_t *script_len) {
    if (!lib || !encoded || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, (const uint8_t *)encoded, strlen(encoded));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "base58Decode", 1);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_itoa(neoc_std_lib_t *lib,
                                int64_t value, uint32_t base,
                                uint8_t **script, size_t *script_len) {
    if (!lib || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_emit_push_int(builder, (int64_t)base);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_emit_push_int(builder, value);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "itoa", 2);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_atoi(neoc_std_lib_t *lib,
                                const char *str, uint32_t base,
                                uint8_t **script, size_t *script_len) {
    if (!lib || !str || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_emit_push_int(builder, (int64_t)base);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, (const uint8_t *)str, strlen(str));
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "atoi", 2);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_memory_compare(neoc_std_lib_t *lib,
                                          const uint8_t *a, size_t a_len,
                                          const uint8_t *b, size_t b_len,
                                          uint8_t **script, size_t *script_len) {
    if (!lib || !a || !b || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, b, b_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, a, a_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "memoryCompare", 2);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

neoc_error_t neoc_std_lib_memory_search(neoc_std_lib_t *lib,
                                         const uint8_t *mem, size_t mem_len,
                                         const uint8_t *value, size_t value_len,
                                         uint8_t **script, size_t *script_len) {
    if (!lib || !mem || !value || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_script_builder_t *builder;
    neoc_error_t err = neoc_script_builder_create(&builder);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_script_builder_push_data(builder, value, value_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_push_data(builder, mem, mem_len);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    neoc_hash160_t script_hash;
    memcpy(script_hash.data, STDLIB_CONTRACT_HASH, 20);

    err = neoc_script_builder_emit_app_call(builder, &script_hash, "memorySearch", 2);
    if (err != NEOC_SUCCESS) {
        neoc_script_builder_free(builder);
        return err;
    }

    err = neoc_script_builder_to_array(builder, script, script_len);
    neoc_script_builder_free(builder);
    return err;
}

void neoc_std_lib_free(neoc_std_lib_t *lib) {
    if (!lib) return;

    if (lib->contract) {
        neoc_smart_contract_free(lib->contract);
    }

    neoc_free(lib);
}
