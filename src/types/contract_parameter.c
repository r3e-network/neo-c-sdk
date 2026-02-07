/**
 * @file contract_parameter.c
 * @brief Backwards compatible contract parameter helpers
 */

#include "neoc/types/contract_parameter.h"

#include "neoc/neoc_error.h"
#include "neoc/neoc_memory.h"
#include "neoc/utils/neoc_base64.h"
#include "neoc/utils/neoc_hex.h"

#include <stdlib.h>
#include <string.h>

static int ascii_tolower(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A' + 'a';
    }
    return c;
}

static bool equals_ignore_case(const char *a, const char *b) {
    if (!a || !b) {
        return false;
    }
    while (*a && *b) {
        if (ascii_tolower((unsigned char)*a) != ascii_tolower((unsigned char)*b)) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static neoc_error_t decode_fixed_bytes(const void *value,
                                       size_t value_size,
                                       uint8_t *out,
                                       size_t out_size) {
    if (!out || out_size == 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "decode_fixed_bytes: invalid output");
    }
    if (!value || value_size == 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "decode_fixed_bytes: missing value");
    }

    if (value_size == out_size) {
        memcpy(out, value, out_size);
        return NEOC_SUCCESS;
    }

    const char *value_str = (const char *)value;
    char *tmp = neoc_strndup(value_str, value_size);
    if (!tmp) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "decode_fixed_bytes: allocation failed");
    }

    size_t decoded_len = 0;
    neoc_error_t err = neoc_hex_decode(tmp, out, out_size, &decoded_len);
    if (err == NEOC_SUCCESS && decoded_len == out_size) {
        neoc_free(tmp);
        return NEOC_SUCCESS;
    }

    decoded_len = 0;
    err = neoc_base64_decode(tmp, out, out_size, &decoded_len);
    if (err == NEOC_SUCCESS && decoded_len == out_size) {
        neoc_free(tmp);
        return NEOC_SUCCESS;
    }

    neoc_free(tmp);
    return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Value is not valid hex/base64 or wrong length");
}

static neoc_error_t create_param_without_name(neoc_contract_parameter_type_t type,
                                              const void *value,
                                              size_t value_size,
                                              neoc_contract_parameter_t **param) {
    switch (type) {
        case NEOC_CONTRACT_PARAM_ANY:
            return neoc_contract_param_create_any((void *)value, param);

        case NEOC_CONTRACT_PARAM_BOOLEAN: {
            if (!value || value_size == 0) {
                return neoc_contract_param_create_boolean(false, param);
            }
            if (value_size == sizeof(bool)) {
                return neoc_contract_param_create_boolean(*(const bool *)value, param);
            }
            if (value_size == sizeof(uint8_t)) {
                return neoc_contract_param_create_boolean(*(const uint8_t *)value != 0, param);
            }

            char *tmp = neoc_strndup((const char *)value, value_size);
            if (!tmp) {
                return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate boolean string");
            }
            bool parsed = false;
            if (equals_ignore_case(tmp, "true") || strcmp(tmp, "1") == 0) {
                parsed = true;
            } else if (equals_ignore_case(tmp, "false") || strcmp(tmp, "0") == 0) {
                parsed = false;
            } else {
                neoc_free(tmp);
                return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid boolean value");
            }
            neoc_free(tmp);
            return neoc_contract_param_create_boolean(parsed, param);
        }

        case NEOC_CONTRACT_PARAM_INTEGER: {
            if (!value || value_size == 0) {
                return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Missing integer value");
            }
            if (value_size == sizeof(int64_t)) {
                return neoc_contract_param_create_integer(*(const int64_t *)value, param);
            }

            char *tmp = neoc_strndup((const char *)value, value_size);
            if (!tmp) {
                return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate integer string");
            }
            char *end = NULL;
            long long parsed = strtoll(tmp, &end, 10);
            if (!end || end == tmp || *end != '\0') {
                neoc_free(tmp);
                return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid integer value");
            }
            neoc_free(tmp);
            return neoc_contract_param_create_integer((int64_t)parsed, param);
        }

        case NEOC_CONTRACT_PARAM_BYTE_ARRAY:
            return neoc_contract_param_create_byte_array((const uint8_t *)value, value ? value_size : 0, param);

        case NEOC_CONTRACT_PARAM_STRING: {
            const char *str = "";
            char *tmp = NULL;
            if (value && value_size > 0) {
                tmp = neoc_strndup((const char *)value, value_size);
                if (!tmp) {
                    return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate string value");
                }
                str = tmp;
            }
            neoc_error_t err = neoc_contract_param_create_string(str, param);
            if (tmp) {
                neoc_free(tmp);
            }
            return err;
        }

        case NEOC_CONTRACT_PARAM_HASH160: {
            uint8_t buf[20];
            neoc_error_t err = decode_fixed_bytes(value, value_size, buf, sizeof(buf));
            if (err != NEOC_SUCCESS) {
                return err;
            }
            neoc_hash160_t hash;
            memcpy(hash.data, buf, sizeof(buf));
            return neoc_contract_param_create_hash160(&hash, param);
        }

        case NEOC_CONTRACT_PARAM_HASH256: {
            uint8_t buf[32];
            neoc_error_t err = decode_fixed_bytes(value, value_size, buf, sizeof(buf));
            if (err != NEOC_SUCCESS) {
                return err;
            }
            neoc_hash256_t hash;
            memcpy(hash.data, buf, sizeof(buf));
            return neoc_contract_param_create_hash256(&hash, param);
        }

        case NEOC_CONTRACT_PARAM_PUBLIC_KEY: {
            uint8_t buf[33];
            neoc_error_t err = decode_fixed_bytes(value, value_size, buf, sizeof(buf));
            if (err != NEOC_SUCCESS) {
                return err;
            }
            return neoc_contract_param_create_public_key(buf, param);
        }

        case NEOC_CONTRACT_PARAM_SIGNATURE: {
            uint8_t buf[64];
            neoc_error_t err = decode_fixed_bytes(value, value_size, buf, sizeof(buf));
            if (err != NEOC_SUCCESS) {
                return err;
            }
            return neoc_contract_param_create_signature(buf, param);
        }

        case NEOC_CONTRACT_PARAM_VOID: {
            if (!param) {
                return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid parameter pointer");
            }
            neoc_contract_parameter_t *out = neoc_calloc(1, sizeof(neoc_contract_parameter_t));
            if (!out) {
                return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate void parameter");
            }
            out->type = NEOC_CONTRACT_PARAM_VOID;
            *param = out;
            return NEOC_SUCCESS;
        }

        default:
            return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "Unsupported legacy contract parameter type");
    }
}

neoc_error_t neoc_contract_parameter_create(neoc_contract_parameter_type_t type,
                                           const char *name,
                                           const void *value,
                                           size_t value_size,
                                           neoc_contract_parameter_t **param) {
    if (!param) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid parameter pointer");
    }

    *param = NULL;
    neoc_error_t err = create_param_without_name(type, value, value_size, param);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    if (name && name[0] != '\0') {
        err = neoc_contract_param_set_name(*param, name);
        if (err != NEOC_SUCCESS) {
            neoc_contract_param_free(*param);
            *param = NULL;
            return err;
        }
    }

    return NEOC_SUCCESS;
}

void neoc_contract_parameter_free(neoc_contract_parameter_t *param) {
    neoc_contract_param_free(param);
}

neoc_error_t neoc_contract_parameter_create_bool(bool value, neoc_contract_parameter_t **param) {
    return neoc_contract_parameter_create(NEOC_CONTRACT_PARAM_BOOLEAN,
                                          NULL,
                                          &value,
                                          sizeof(value),
                                          param);
}

neoc_error_t neoc_contract_parameter_create_int(int64_t value, neoc_contract_parameter_t **param) {
    return neoc_contract_parameter_create(NEOC_CONTRACT_PARAM_INTEGER,
                                          NULL,
                                          &value,
                                          sizeof(value),
                                          param);
}

neoc_error_t neoc_contract_parameter_create_string(const char *value, neoc_contract_parameter_t **param) {
    if (!value || !param) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid string value");
    }
    return neoc_contract_parameter_create(NEOC_CONTRACT_PARAM_STRING,
                                          NULL,
                                          value,
                                          strlen(value),
                                          param);
}

neoc_error_t neoc_contract_parameter_create_bytes(const uint8_t *value,
                                                  size_t len,
                                                  neoc_contract_parameter_t **param) {
    if ((!value && len > 0) || !param) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid byte array");
    }
    return neoc_contract_parameter_create(NEOC_CONTRACT_PARAM_BYTE_ARRAY,
                                          NULL,
                                          value,
                                          len,
                                          param);
}

