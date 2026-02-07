/**
 * @file ecdsasignature.c
 * @brief ECDSA signature utilities (R/S) and recoverable signature helpers.
 *
 * Ported from NeoSwift's ECDSASignature and Sign.SignatureData.
 */

#include "neoc/crypto/ecdsa_signature.h"
#include "neoc/neoc_error.h"
#include "neoc/neoc_memory.h"

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <string.h>

#define NEOC_SIGNATURE_COMPONENT_SIZE 32u
#define NEOC_SIGNATURE_BYTE_LENGTH 64u

/* Half curve order constant used for canonical S checks. */
static const uint8_t SECP256R1_HALF_CURVE_ORDER[NEOC_SIGNATURE_COMPONENT_SIZE] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static neoc_error_t neoc_copy_component(uint8_t *dest,
                                        size_t dest_len,
                                        const uint8_t *src,
                                        size_t src_len,
                                        const char *component_name) {
    if (!dest || !src) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Null pointer");
    }
    if (dest_len < NEOC_SIGNATURE_COMPONENT_SIZE ||
        src_len != NEOC_SIGNATURE_COMPONENT_SIZE) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              component_name ? component_name
                                             : "Invalid component length");
    }
    memcpy(dest, src, NEOC_SIGNATURE_COMPONENT_SIZE);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ecdsa_signature_create(const uint8_t *r,
                                         const uint8_t *s,
                                         neoc_ecdsa_signature_t **signature) {
    if (!r || !s || !signature) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_ecdsa_signature_t *sig =
        neoc_malloc(sizeof(neoc_ecdsa_signature_t));
    if (!sig) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate signature");
    }

    memcpy(sig->r, r, NEOC_SIGNATURE_COMPONENT_SIZE);
    memcpy(sig->s, s, NEOC_SIGNATURE_COMPONENT_SIZE);

    *signature = sig;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ecdsa_signature_from_bytes(const uint8_t *bytes,
                                             size_t length,
                                             neoc_ecdsa_signature_t **signature) {
    if (!bytes || !signature) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (length != NEOC_SIGNATURE_BYTE_LENGTH) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "ECDSA signature must be 64 bytes");
    }

    return neoc_ecdsa_signature_create(bytes,
                                       bytes + NEOC_SIGNATURE_COMPONENT_SIZE,
                                       signature);
}

neoc_error_t neoc_ecdsa_signature_to_bytes(const neoc_ecdsa_signature_t *signature,
                                           uint8_t **bytes,
                                           size_t *length) {
    if (!signature || !bytes) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    uint8_t *buffer = neoc_malloc(NEOC_SIGNATURE_BYTE_LENGTH);
    if (!buffer) {
        return neoc_error_set(NEOC_ERROR_MEMORY,
                              "Failed to allocate signature buffer");
    }

    memcpy(buffer, signature->r, NEOC_SIGNATURE_COMPONENT_SIZE);
    memcpy(buffer + NEOC_SIGNATURE_COMPONENT_SIZE,
           signature->s,
           NEOC_SIGNATURE_COMPONENT_SIZE);

    *bytes = buffer;
    if (length) {
        *length = NEOC_SIGNATURE_BYTE_LENGTH;
    }
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ecdsa_signature_from_der(const uint8_t *der_bytes,
                                           size_t der_len,
                                           neoc_ecdsa_signature_t **signature) {
    if (!der_bytes || !signature) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (der_len == 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "DER length must be greater than zero");
    }

    const unsigned char *cursor = der_bytes;
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &cursor, (long)der_len);
    if (!sig) {
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid DER encoding");
    }

    const BIGNUM *r_bn = NULL;
    const BIGNUM *s_bn = NULL;
    ECDSA_SIG_get0(sig, &r_bn, &s_bn);

    neoc_ecdsa_signature_t *result =
        neoc_malloc(sizeof(neoc_ecdsa_signature_t));
    if (!result) {
        ECDSA_SIG_free(sig);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate signature");
    }

    memset(result->r, 0, NEOC_SIGNATURE_COMPONENT_SIZE);
    memset(result->s, 0, NEOC_SIGNATURE_COMPONENT_SIZE);

    int r_len = BN_num_bytes(r_bn);
    int s_len = BN_num_bytes(s_bn);
    if (r_len > (int)NEOC_SIGNATURE_COMPONENT_SIZE ||
        s_len > (int)NEOC_SIGNATURE_COMPONENT_SIZE) {
        neoc_free(result);
        ECDSA_SIG_free(sig);
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT,
                              "Signature component too large");
    }

    BN_bn2bin(r_bn,
              result->r + (NEOC_SIGNATURE_COMPONENT_SIZE - (size_t)r_len));
    BN_bn2bin(s_bn,
              result->s + (NEOC_SIGNATURE_COMPONENT_SIZE - (size_t)s_len));

    *signature = result;
    ECDSA_SIG_free(sig);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ecdsa_signature_get_r(const neoc_ecdsa_signature_t *signature,
                                        uint8_t *r_out,
                                        size_t r_capacity) {
    return neoc_copy_component(r_out,
                               r_capacity,
                               signature ? signature->r : NULL,
                               NEOC_SIGNATURE_COMPONENT_SIZE,
                               "Invalid R length");
}

neoc_error_t neoc_ecdsa_signature_get_s(const neoc_ecdsa_signature_t *signature,
                                        uint8_t *s_out,
                                        size_t s_capacity) {
    return neoc_copy_component(s_out,
                               s_capacity,
                               signature ? signature->s : NULL,
                               NEOC_SIGNATURE_COMPONENT_SIZE,
                               "Invalid S length");
}

neoc_error_t neoc_ecdsa_signature_is_canonical(const neoc_ecdsa_signature_t *signature,
                                               bool *is_canonical) {
    if (!signature || !is_canonical) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    *is_canonical =
        memcmp(signature->s,
               SECP256R1_HALF_CURVE_ORDER,
               NEOC_SIGNATURE_COMPONENT_SIZE) <= 0;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_ecdsa_signature_to_der(const neoc_ecdsa_signature_t *signature,
                                         uint8_t **der_bytes,
                                         size_t *der_len) {
    if (!signature || !der_bytes) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (!sig) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate ECDSA_SIG");
    }

    BIGNUM *r_bn = BN_bin2bn(signature->r, NEOC_SIGNATURE_COMPONENT_SIZE, NULL);
    BIGNUM *s_bn = BN_bin2bn(signature->s, NEOC_SIGNATURE_COMPONENT_SIZE, NULL);
    if (!r_bn || !s_bn) {
        BN_free(r_bn);
        BN_free(s_bn);
        ECDSA_SIG_free(sig);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to create BIGNUM");
    }

    ECDSA_SIG_set0(sig, r_bn, s_bn);
    int required = i2d_ECDSA_SIG(sig, NULL);
    if (required <= 0) {
        ECDSA_SIG_free(sig);
        return neoc_error_set(NEOC_ERROR_INTERNAL, "DER sizing failure");
    }

    uint8_t *buffer = neoc_malloc((size_t)required);
    if (!buffer) {
        ECDSA_SIG_free(sig);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate DER buffer");
    }

    uint8_t *cursor = buffer;
    int written = i2d_ECDSA_SIG(sig, &cursor);
    ECDSA_SIG_free(sig);

    if (written != required) {
        neoc_free(buffer);
        return neoc_error_set(NEOC_ERROR_INTERNAL, "DER encoding mismatch");
    }

    *der_bytes = buffer;
    if (der_len) {
        *der_len = (size_t)written;
    }
    return NEOC_SUCCESS;
}

void neoc_ecdsa_signature_free(neoc_ecdsa_signature_t *signature) {
    if (!signature) {
        return;
    }
    memset(signature, 0, sizeof(neoc_ecdsa_signature_t));
    neoc_free(signature);
}

neoc_error_t neoc_signature_data_create(uint8_t v,
                                        const uint8_t *r,
                                        const uint8_t *s,
                                        neoc_signature_data_t **sig_data) {
    if (!r || !s || !sig_data) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    neoc_signature_data_t *data =
        neoc_malloc(sizeof(neoc_signature_data_t));
    if (!data) {
        return neoc_error_set(NEOC_ERROR_MEMORY,
                              "Failed to allocate signature data");
    }

    data->v = v;
    memcpy(data->r, r, NEOC_SIGNATURE_COMPONENT_SIZE);
    memcpy(data->s, s, NEOC_SIGNATURE_COMPONENT_SIZE);

    *sig_data = data;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_signature_data_create_checked(uint8_t v,
                                                const uint8_t *r,
                                                size_t r_len,
                                                const uint8_t *s,
                                                size_t s_len,
                                                neoc_signature_data_t **sig_data) {
    if (!r || !s || !sig_data) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (r_len != NEOC_SIGNATURE_COMPONENT_SIZE || s_len != NEOC_SIGNATURE_COMPONENT_SIZE) {
        return neoc_error_set(NEOC_ERROR_INVALID_LENGTH, "Signature components must be 32 bytes");
    }
    return neoc_signature_data_create(v, r, s, sig_data);
}

neoc_error_t neoc_signature_data_from_bytes(const uint8_t *signature,
                                            size_t signature_length,
                                            neoc_signature_data_t **sig_data) {
    return neoc_signature_data_from_bytes_with_v(0,
                                                 signature,
                                                 signature_length,
                                                 sig_data);
}

neoc_error_t neoc_signature_data_from_bytes_with_v(uint8_t v,
                                                   const uint8_t *signature,
                                                   size_t signature_length,
                                                   neoc_signature_data_t **sig_data) {
    if (!signature || !sig_data) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (signature_length != NEOC_SIGNATURE_BYTE_LENGTH) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Signature must be 64 bytes");
    }

    return neoc_signature_data_create(v,
                                      signature,
                                      signature + NEOC_SIGNATURE_COMPONENT_SIZE,
                                      sig_data);
}

neoc_error_t neoc_signature_data_to_bytes(const neoc_signature_data_t *sig_data,
                                          uint8_t **bytes) {
    if (!sig_data || !bytes) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    uint8_t *buffer = neoc_malloc(NEOC_SIGNATURE_BYTE_LENGTH);
    if (!buffer) {
        return neoc_error_set(NEOC_ERROR_MEMORY,
                              "Failed to allocate signature buffer");
    }

    memcpy(buffer, sig_data->r, NEOC_SIGNATURE_COMPONENT_SIZE);
    memcpy(buffer + NEOC_SIGNATURE_COMPONENT_SIZE,
           sig_data->s,
           NEOC_SIGNATURE_COMPONENT_SIZE);

    *bytes = buffer;
    return NEOC_SUCCESS;
}

uint8_t neoc_signature_data_get_v(const neoc_signature_data_t *sig_data) {
    return sig_data ? sig_data->v : 0;
}

const uint8_t *neoc_signature_data_get_r(const neoc_signature_data_t *sig_data,
                                         size_t *length) {
    if (length) {
        *length = sig_data ? NEOC_SIGNATURE_COMPONENT_SIZE : 0;
    }
    return sig_data ? sig_data->r : NULL;
}

const uint8_t *neoc_signature_data_get_s(const neoc_signature_data_t *sig_data,
                                         size_t *length) {
    if (length) {
        *length = sig_data ? NEOC_SIGNATURE_COMPONENT_SIZE : 0;
    }
    return sig_data ? sig_data->s : NULL;
}

void neoc_signature_data_free(neoc_signature_data_t *sig_data) {
    if (!sig_data) {
        return;
    }
    memset(sig_data, 0, sizeof(neoc_signature_data_t));
    neoc_free(sig_data);
}
