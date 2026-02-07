#include "neoc/transaction/witness.h"
#include "neoc/utils/neoc_hex.h"
#include "neoc/neoc_memory.h"
#include "neoc/serialization/binary_writer.h"
#include "neoc/serialization/binary_reader.h"
#include "neoc/script/script_helper.h"
#include <string.h>

static size_t neoc_var_int_size(uint64_t value) {
    if (value < 0xFD) {
        return 1;
    } else if (value <= 0xFFFF) {
        return 3;
    } else if (value <= 0xFFFFFFFF) {
        return 5;
    }
    return 9;
}

neoc_error_t neoc_witness_create(const uint8_t *invocation_script,
                                  size_t invocation_len,
                                  const uint8_t *verification_script,
                                  size_t verification_len,
                                  neoc_witness_t **witness) {
    if (!witness) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid witness pointer");
    }
    
    *witness = neoc_calloc(1, sizeof(neoc_witness_t));
    if (!*witness) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate witness");
    }
    
    // Copy invocation script
    if (invocation_script && invocation_len > 0) {
        (*witness)->invocation_script = neoc_malloc(invocation_len);
        if (!(*witness)->invocation_script) {
            neoc_free(*witness);
            *witness = NULL;
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate invocation script");
        }
        memcpy((*witness)->invocation_script, invocation_script, invocation_len);
        (*witness)->invocation_script_len = invocation_len;
    }
    
    // Copy verification script
    if (verification_script && verification_len > 0) {
        (*witness)->verification_script = neoc_malloc(verification_len);
        if (!(*witness)->verification_script) {
            if ((*witness)->invocation_script) {
                neoc_free((*witness)->invocation_script);
            }
            neoc_free(*witness);
            *witness = NULL;
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate verification script");
        }
        memcpy((*witness)->verification_script, verification_script, verification_len);
        (*witness)->verification_script_len = verification_len;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_witness_create_from_signature(const uint8_t *signature,
                                                 size_t signature_len,
                                                 const uint8_t *public_key,
                                                 size_t public_key_len,
                                                 neoc_witness_t **witness) {
    if (!signature || !public_key || !witness) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    // Create Neo N3 invocation script using helper (syscall-based format)
    uint8_t *invocation_script = NULL;
    size_t invocation_len = 0;
    neoc_error_t err = neoc_script_create_single_sig_invocation(signature, signature_len,
                                                                 &invocation_script, &invocation_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    // Create Neo N3 verification script using helper (syscall-based format)
    uint8_t *verification_script = NULL;
    size_t verification_len = 0;
    err = neoc_script_create_single_sig_verification(public_key, public_key_len,
                                                      &verification_script, &verification_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(invocation_script);
        return err;
    }

    // Create witness
    err = neoc_witness_create(invocation_script, invocation_len,
                               verification_script, verification_len,
                               witness);

    neoc_free(invocation_script);
    neoc_free(verification_script);

    return err;
}

size_t neoc_witness_get_size(const neoc_witness_t *witness) {
    if (!witness) return 0;
    
    size_t size = 0;
    size += neoc_var_int_size(witness->invocation_script_len) + witness->invocation_script_len;
    size += neoc_var_int_size(witness->verification_script_len) + witness->verification_script_len;
    return size;
}

neoc_error_t neoc_witness_serialize(const neoc_witness_t *witness,
                                     uint8_t **bytes,
                                     size_t *bytes_len) {
    if (!witness || !bytes || !bytes_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(64, true, &writer);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_binary_writer_write_var_bytes(writer,
                                             witness->invocation_script,
                                             witness->invocation_script_len);
    if (err == NEOC_SUCCESS) {
        err = neoc_binary_writer_write_var_bytes(writer,
                                                 witness->verification_script,
                                                 witness->verification_script_len);
    }

    if (err == NEOC_SUCCESS) {
        err = neoc_binary_writer_to_array(writer, bytes, bytes_len);
    }

    neoc_binary_writer_free(writer);
    return err;
}

neoc_error_t neoc_witness_deserialize(const uint8_t *bytes,
                                       size_t bytes_len,
                                       neoc_witness_t **witness) {
    if (!bytes || !witness) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(bytes, bytes_len, &reader);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    uint8_t *invocation = NULL;
    size_t invocation_len = 0;
    err = neoc_binary_reader_read_var_bytes(reader, &invocation, &invocation_len);
    if (err != NEOC_SUCCESS) {
        neoc_binary_reader_free(reader);
        return err;
    }

    uint8_t *verification = NULL;
    size_t verification_len = 0;
    err = neoc_binary_reader_read_var_bytes(reader, &verification, &verification_len);
    if (err != NEOC_SUCCESS) {
        if (invocation) neoc_free(invocation);
        neoc_binary_reader_free(reader);
        return err;
    }

    err = neoc_witness_create(invocation, invocation_len,
                              verification, verification_len,
                              witness);

    if (invocation) neoc_free(invocation);
    if (verification) neoc_free(verification);
    neoc_binary_reader_free(reader);
    return err;
}

void neoc_witness_free(neoc_witness_t *witness) {
    if (!witness) return;
    
    if (witness->invocation_script) {
        neoc_free(witness->invocation_script);
    }
    
    if (witness->verification_script) {
        neoc_free(witness->verification_script);
    }
    
    neoc_free(witness);
}

char* neoc_witness_to_json(const neoc_witness_t *witness) {
    if (!witness) {
        return NULL;
    }
    
    // Convert scripts to hex strings
    char* invocation_hex = "";
    char* verification_hex = "";
    
    if (witness->invocation_script && witness->invocation_script_len > 0) {
        invocation_hex = neoc_hex_encode_alloc(witness->invocation_script, witness->invocation_script_len, false, false);
        if (!invocation_hex) invocation_hex = "";
    }
    
    if (witness->verification_script && witness->verification_script_len > 0) {
        verification_hex = neoc_hex_encode_alloc(witness->verification_script, witness->verification_script_len, false, false);
        if (!verification_hex) verification_hex = "";
    }
    
    // Create JSON string
    size_t json_size = 256 + strlen(invocation_hex) + strlen(verification_hex);
    char* json = neoc_malloc(json_size);
    if (!json) {
        if (invocation_hex && strlen(invocation_hex) > 0) neoc_free(invocation_hex);
        if (verification_hex && strlen(verification_hex) > 0) neoc_free(verification_hex);
        return NULL;
    }
    
    snprintf(json, json_size,
             "{\"invocation\":\"%s\",\"verification\":\"%s\"}",
             invocation_hex, verification_hex);
    
    // Free hex strings if they were allocated
    if (invocation_hex && strlen(invocation_hex) > 0) neoc_free(invocation_hex);
    if (verification_hex && strlen(verification_hex) > 0) neoc_free(verification_hex);
    
    return json;
}

neoc_error_t neoc_witness_clone(const neoc_witness_t *source, neoc_witness_t **dest) {
    if (!source || !dest) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    return neoc_witness_create(source->invocation_script,
                              source->invocation_script_len,
                              source->verification_script,
                              source->verification_script_len,
                              dest);
}
