#include "neoc/types/contract_parameter_type.h"
#include "neoc/neoc_error.h"
#include <ctype.h>

static int to_lower_char(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

static bool equals_ignore_case(const char *a, const char *b) {
    if (!a || !b) {
        return false;
    }
    while (*a && *b) {
        if (to_lower_char((unsigned char)*a) != to_lower_char((unsigned char)*b)) {
            return false;
        }
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

const char* neoc_contract_parameter_type_to_string(neoc_contract_parameter_type_t type) {
    switch (type) {
        case NEOC_CONTRACT_PARAM_ANY: return "Any";
        case NEOC_CONTRACT_PARAM_BOOLEAN: return "Boolean";
        case NEOC_CONTRACT_PARAM_INTEGER: return "Integer";
        case NEOC_CONTRACT_PARAM_BYTE_ARRAY: return "ByteArray";
        case NEOC_CONTRACT_PARAM_STRING: return "String";
        case NEOC_CONTRACT_PARAM_HASH160: return "Hash160";
        case NEOC_CONTRACT_PARAM_HASH256: return "Hash256";
        case NEOC_CONTRACT_PARAM_PUBLIC_KEY: return "PublicKey";
        case NEOC_CONTRACT_PARAM_SIGNATURE: return "Signature";
        case NEOC_CONTRACT_PARAM_ARRAY: return "Array";
        case NEOC_CONTRACT_PARAM_MAP: return "Map";
        case NEOC_CONTRACT_PARAM_INTEROP_INTERFACE: return "InteropInterface";
        case NEOC_CONTRACT_PARAM_VOID: return "Void";
        default: return NULL;
    }
}

neoc_error_t neoc_contract_parameter_type_from_string(const char *str,
                                                       neoc_contract_parameter_type_t *type) {
    if (!str || !type) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid contract parameter type string");
    }

    const struct {
        const char *name;
        neoc_contract_parameter_type_t value;
    } mapping[] = {
        { "Any", NEOC_CONTRACT_PARAM_ANY },
        { "Boolean", NEOC_CONTRACT_PARAM_BOOLEAN },
        { "Integer", NEOC_CONTRACT_PARAM_INTEGER },
        { "ByteArray", NEOC_CONTRACT_PARAM_BYTE_ARRAY },
        { "String", NEOC_CONTRACT_PARAM_STRING },
        { "Hash160", NEOC_CONTRACT_PARAM_HASH160 },
        { "Hash256", NEOC_CONTRACT_PARAM_HASH256 },
        { "PublicKey", NEOC_CONTRACT_PARAM_PUBLIC_KEY },
        { "Signature", NEOC_CONTRACT_PARAM_SIGNATURE },
        { "Array", NEOC_CONTRACT_PARAM_ARRAY },
        { "Map", NEOC_CONTRACT_PARAM_MAP },
        { "InteropInterface", NEOC_CONTRACT_PARAM_INTEROP_INTERFACE },
        { "Void", NEOC_CONTRACT_PARAM_VOID }
    };

    for (size_t i = 0; i < sizeof(mapping) / sizeof(mapping[0]); ++i) {
        if (equals_ignore_case(str, mapping[i].name)) {
            *type = mapping[i].value;
            return NEOC_SUCCESS;
        }
    }

    return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Unknown contract parameter type");
}

bool neoc_contract_parameter_type_is_valid(neoc_contract_parameter_type_t type) {
    switch (type) {
        case NEOC_CONTRACT_PARAM_ANY:
        case NEOC_CONTRACT_PARAM_BOOLEAN:
        case NEOC_CONTRACT_PARAM_INTEGER:
        case NEOC_CONTRACT_PARAM_BYTE_ARRAY:
        case NEOC_CONTRACT_PARAM_STRING:
        case NEOC_CONTRACT_PARAM_HASH160:
        case NEOC_CONTRACT_PARAM_HASH256:
        case NEOC_CONTRACT_PARAM_PUBLIC_KEY:
        case NEOC_CONTRACT_PARAM_SIGNATURE:
        case NEOC_CONTRACT_PARAM_ARRAY:
        case NEOC_CONTRACT_PARAM_MAP:
        case NEOC_CONTRACT_PARAM_INTEROP_INTERFACE:
        case NEOC_CONTRACT_PARAM_VOID:
            return true;
        default:
            return false;
    }
}

uint8_t neoc_contract_parameter_type_to_byte(neoc_contract_parameter_type_t type) {
    return (uint8_t)type;
}

neoc_error_t neoc_contract_parameter_type_from_byte(uint8_t byte,
                                                     neoc_contract_parameter_type_t *type) {
    if (!type) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid contract parameter type pointer");
    }

    neoc_contract_parameter_type_t candidate = (neoc_contract_parameter_type_t)byte;
    if (!neoc_contract_parameter_type_is_valid(candidate)) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid contract parameter type byte");
    }

    *type = candidate;
    return NEOC_SUCCESS;
}
