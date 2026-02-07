/**
 * @file ecdsa_signature.h
 * @brief ECDSA signature and signature data helpers.
 *
 * Closely follows NeoSwift's ECDSASignature and Sign.SignatureData types.
 */

#ifndef NEOC_CRYPTO_ECDSA_SIGNATURE_H
#define NEOC_CRYPTO_ECDSA_SIGNATURE_H

#include "neoc/neoc_error.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Canonical ECDSA signature container (R, S components).
 */
typedef struct {
    uint8_t r[32];
    uint8_t s[32];
} neoc_ecdsa_signature_t;

neoc_error_t neoc_ecdsa_signature_create(const uint8_t *r,
                                         const uint8_t *s,
                                         neoc_ecdsa_signature_t **signature);

neoc_error_t neoc_ecdsa_signature_from_bytes(const uint8_t *bytes,
                                             size_t length,
                                             neoc_ecdsa_signature_t **signature);

neoc_error_t neoc_ecdsa_signature_to_bytes(const neoc_ecdsa_signature_t *signature,
                                           uint8_t **bytes,
                                           size_t *length);

neoc_error_t neoc_ecdsa_signature_from_der(const uint8_t *der_bytes,
                                           size_t der_len,
                                           neoc_ecdsa_signature_t **signature);

neoc_error_t neoc_ecdsa_signature_get_r(const neoc_ecdsa_signature_t *signature,
                                        uint8_t *r_out,
                                        size_t r_capacity);

neoc_error_t neoc_ecdsa_signature_get_s(const neoc_ecdsa_signature_t *signature,
                                        uint8_t *s_out,
                                        size_t s_capacity);

neoc_error_t neoc_ecdsa_signature_is_canonical(const neoc_ecdsa_signature_t *signature,
                                               bool *is_canonical);

neoc_error_t neoc_ecdsa_signature_to_der(const neoc_ecdsa_signature_t *signature,
                                         uint8_t **der_bytes,
                                         size_t *der_len);

void neoc_ecdsa_signature_free(neoc_ecdsa_signature_t *signature);

/**
 * @brief Signature data (v, r, s) used by recoverable signatures.
 */
typedef struct {
    uint8_t v;
    uint8_t r[32];
    uint8_t s[32];
} neoc_signature_data_t;

neoc_error_t neoc_signature_data_create(uint8_t v,
                                        const uint8_t *r,
                                        const uint8_t *s,
                                        neoc_signature_data_t **sig_data);

/**
 * @brief Create signature data while validating component sizes.
 *
 * This helper avoids undefined behaviour when callers may not have fixed-size
 * 32-byte buffers for @p r and @p s.
 */
neoc_error_t neoc_signature_data_create_checked(uint8_t v,
                                                const uint8_t *r,
                                                size_t r_len,
                                                const uint8_t *s,
                                                size_t s_len,
                                                neoc_signature_data_t **sig_data);

neoc_error_t neoc_signature_data_from_bytes(const uint8_t *signature,
                                            size_t signature_length,
                                            neoc_signature_data_t **sig_data);

neoc_error_t neoc_signature_data_from_bytes_with_v(uint8_t v,
                                                   const uint8_t *signature,
                                                   size_t signature_length,
                                                   neoc_signature_data_t **sig_data);

neoc_error_t neoc_signature_data_to_bytes(const neoc_signature_data_t *sig_data,
                                          uint8_t **bytes);

uint8_t neoc_signature_data_get_v(const neoc_signature_data_t *sig_data);

const uint8_t *neoc_signature_data_get_r(const neoc_signature_data_t *sig_data,
                                         size_t *length);

const uint8_t *neoc_signature_data_get_s(const neoc_signature_data_t *sig_data,
                                         size_t *length);

void neoc_signature_data_free(neoc_signature_data_t *sig_data);

#ifdef __cplusplus
}
#endif

#endif /* NEOC_CRYPTO_ECDSA_SIGNATURE_H */
