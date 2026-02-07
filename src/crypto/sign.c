#include "neoc/crypto/sign.h"

#include "neoc/crypto/ecdsa_signature.h"
#include "neoc/crypto/ec_key_pair.h"
#include "neoc/crypto/neoc_hash.h"
#include "neoc/neoc_error.h"
#include "neoc/neoc_memory.h"
#include "neoc/neo_constants.h"
#include "neoc/types/neoc_hash160.h"
#include "neoc/utils/neoc_hex.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <string.h>

#define NEOC_RECOVERY_V_OFFSET 27u
#define NEOC_SIGNATURE_COMPONENT_SIZE 32u

static neoc_error_t neoc_signature_make_canonical(neoc_ecdsa_signature_t *signature,
                                                  const EC_GROUP *group) {
    if (!signature || !group) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid signature or curve group");
    }

    const uint8_t *half_order = neoc_get_secp256r1_half_curve_order();
    if (memcmp(signature->s, half_order, NEOC_SIGNATURE_COMPONENT_SIZE) <= 0) {
        return NEOC_SUCCESS;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return neoc_error_set(NEOC_ERROR_MEMORY,
                              "Failed to allocate BN context");
    }

    neoc_error_t err = NEOC_SUCCESS;
    BIGNUM *order = BN_new();
    BIGNUM *s_bn = BN_bin2bn(signature->s, NEOC_SIGNATURE_COMPONENT_SIZE, NULL);
    if (!order || !s_bn) {
        err = neoc_error_set(NEOC_ERROR_MEMORY,
                             "Failed to allocate signature components");
        goto cleanup;
    }

    if (EC_GROUP_get_order(group, order, ctx) != 1) {
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to obtain curve order");
        goto cleanup;
    }

    if (BN_sub(s_bn, order, s_bn) != 1) {
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to canonicalize signature");
        goto cleanup;
    }

    if (BN_bn2binpad(s_bn, signature->s, NEOC_SIGNATURE_COMPONENT_SIZE) !=
        (int)NEOC_SIGNATURE_COMPONENT_SIZE) {
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to normalize canonical signature");
        goto cleanup;
    }

cleanup:
    BN_free(order);
    BN_free(s_bn);
    BN_CTX_free(ctx);
    return err;
}

static EC_KEY *neoc_ec_key_from_public(const neoc_ec_public_key_t *public_key) {
    if (!public_key) {
        return NULL;
    }

    EC_KEY *ec_key = EC_KEY_new();
    if (!ec_key) {
        return NULL;
    }

    EC_GROUP *group = EC_GROUP_dup(public_key->group);
    if (!group) {
        EC_KEY_free(ec_key);
        return NULL;
    }

    if (EC_KEY_set_group(ec_key, group) != 1) {
        EC_GROUP_free(group);
        EC_KEY_free(ec_key);
        return NULL;
    }
    /* EC_KEY_set_group duplicates the group; caller retains ownership. */
    EC_GROUP_free(group);
    group = NULL;

    const EC_GROUP *key_group = EC_KEY_get0_group(ec_key);
    EC_POINT *point = EC_POINT_dup(public_key->point, key_group);
    if (!point) {
        EC_KEY_free(ec_key);
        return NULL;
    }

    if (EC_KEY_set_public_key(ec_key, point) != 1) {
        EC_POINT_free(point);
        EC_KEY_free(ec_key);
        return NULL;
    }

    EC_POINT_free(point);
    return ec_key;
}

static neoc_error_t neoc_compute_message_hash(const uint8_t *message,
                                              size_t message_len,
                                              uint8_t out_hash[NEOC_SHA256_DIGEST_LENGTH]) {
    if (!message && message_len > 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Message pointer is NULL");
    }

    return neoc_sha256(message ? message : (const uint8_t *)"", message_len,
                       out_hash);
}

static neoc_error_t neoc_signature_data_from_ecdsa(int rec_id,
                                                   const neoc_ecdsa_signature_t *ecdsa_sig,
                                                   neoc_signature_data_t **sig_data) {
    if (!ecdsa_sig || !sig_data) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid signature data arguments");
    }

    if (rec_id < 0 || rec_id > 3) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid recovery identifier");
    }

    return neoc_signature_data_create((uint8_t)(rec_id + NEOC_RECOVERY_V_OFFSET),
                                      ecdsa_sig->r,
                                      ecdsa_sig->s,
                                      sig_data);
}

static neoc_error_t neoc_find_recovery_id(const uint8_t *message_hash,
                                          const neoc_ecdsa_signature_t *ecdsa_sig,
                                          const neoc_ec_key_pair_t *key_pair,
                                          int *out_rec_id) {
    if (!message_hash || !ecdsa_sig || !key_pair || !out_rec_id ||
        !key_pair->public_key || !key_pair->private_key ||
        !key_pair->private_key->ec_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid inputs for recovery id detection");
    }

    const uint8_t *expected_compressed = key_pair->public_key->compressed;
    neoc_error_t err = NEOC_ERROR_NOT_FOUND;

    for (int rec_id = 0; rec_id < 4; ++rec_id) {
        neoc_ec_public_key_t *candidate = NULL;
        neoc_error_t rec_err =
            neoc_recover_from_signature(rec_id, ecdsa_sig, message_hash,
                                        &candidate);
        if (rec_err != NEOC_SUCCESS) {
            if (rec_err == NEOC_ERROR_NOT_FOUND) {
                continue;
            }
            err = rec_err;
            break;
        }

        if (candidate &&
            memcmp(candidate->compressed, expected_compressed,
                   NEOC_PUBLIC_KEY_SIZE_COMPRESSED) == 0) {
            *out_rec_id = rec_id;
            neoc_ec_public_key_free(candidate);
            return NEOC_SUCCESS;
        }

        neoc_ec_public_key_free(candidate);
    }

    return err == NEOC_ERROR_NOT_FOUND
               ? neoc_error_set(NEOC_ERROR_CRYPTO,
                                "Could not determine recovery identifier")
               : err;
}

neoc_error_t neoc_sign_message(const uint8_t *message,
                               size_t message_len,
                               const neoc_ec_key_pair_t *key_pair,
                               neoc_signature_data_t **sig_data) {
    if (!key_pair || !sig_data || !key_pair->private_key ||
        !key_pair->private_key->ec_key || !key_pair->public_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid inputs for signing");
    }

    *sig_data = NULL;

    uint8_t message_hash[NEOC_SHA256_DIGEST_LENGTH] = {0};
    neoc_error_t err =
        neoc_compute_message_hash(message, message_len, message_hash);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    neoc_ecdsa_signature_t *ecdsa_sig = NULL;
    err = neoc_ec_key_pair_sign(key_pair, message_hash, &ecdsa_sig);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    const EC_GROUP *group =
        EC_KEY_get0_group(key_pair->private_key->ec_key);
    if (!group) {
        neoc_ecdsa_signature_free(ecdsa_sig);
        return neoc_error_set(NEOC_ERROR_CRYPTO,
                              "Failed to retrieve EC group");
    }

    err = neoc_signature_make_canonical(ecdsa_sig, group);
    if (err != NEOC_SUCCESS) {
        neoc_ecdsa_signature_free(ecdsa_sig);
        return err;
    }

    int rec_id = -1;
    err = neoc_find_recovery_id(message_hash, ecdsa_sig, key_pair, &rec_id);
    if (err != NEOC_SUCCESS) {
        neoc_ecdsa_signature_free(ecdsa_sig);
        return err;
    }

    err = neoc_signature_data_from_ecdsa(rec_id, ecdsa_sig, sig_data);
    neoc_ecdsa_signature_free(ecdsa_sig);
    return err;
}

neoc_error_t neoc_sign_hex_message(const char *hex_message,
                                   const neoc_ec_key_pair_t *key_pair,
                                   neoc_signature_data_t **sig_data) {
    if (!hex_message || !key_pair || !sig_data) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid inputs for hex signing");
    }

    size_t decoded_len = 0;
    uint8_t *decoded = neoc_hex_decode_alloc(hex_message, &decoded_len);
    if (!decoded && decoded_len > 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_HEX,
                              "Failed to decode hex message");
    }

    neoc_error_t err = neoc_sign_message(decoded, decoded_len, key_pair,
                                         sig_data);
    if (decoded) {
        neoc_free(decoded);
    }
    return err;
}

neoc_error_t neoc_recover_from_signature(int rec_id,
                                         const neoc_ecdsa_signature_t *signature,
                                         const uint8_t *message_hash,
                                         neoc_ec_public_key_t **public_key) {
    if (!signature || !message_hash || !public_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid inputs for signature recovery");
    }

    *public_key = NULL;

    if (rec_id < 0 || rec_id > 3) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Recovery identifier must be between 0 and 3");
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate BN_CTX");
    }

    neoc_error_t err = NEOC_SUCCESS;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        BN_CTX_free(ctx);
        return neoc_error_set(NEOC_ERROR_CRYPTO,
                              "Failed to create EC group");
    }

    BN_CTX_start(ctx);
    BIGNUM *order = BN_CTX_get(ctx);
    BIGNUM *prime = BN_CTX_get(ctx);
    BIGNUM *x = BN_CTX_get(ctx);
    BIGNUM *i_bn = BN_CTX_get(ctx);
    BIGNUM *e = BN_CTX_get(ctx);
    BIGNUM *e_inv = BN_CTX_get(ctx);
    BIGNUM *sr_inv = BN_CTX_get(ctx);
    BIGNUM *e_invr_inv = BN_CTX_get(ctx);
    if (!e_invr_inv) {
        err = neoc_error_set(NEOC_ERROR_MEMORY,
                             "Failed to allocate BIGNUMs");
        goto cleanup;
    }

    if (EC_GROUP_get_order(group, order, ctx) != 1 ||
        EC_GROUP_get_curve_GFp(group, prime, NULL, NULL, ctx) != 1) {
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to obtain curve parameters");
        goto cleanup;
    }

    BIGNUM *r = BN_bin2bn(signature->r, NEOC_SIGNATURE_COMPONENT_SIZE, NULL);
    BIGNUM *s = BN_bin2bn(signature->s, NEOC_SIGNATURE_COMPONENT_SIZE, NULL);
    if (!r || !s) {
        err = neoc_error_set(NEOC_ERROR_MEMORY,
                             "Failed to allocate signature components");
        goto cleanup_bn;
    }

    if (BN_set_word(i_bn, (unsigned long)(rec_id / 2)) != 1 ||
        BN_mul(x, order, i_bn, ctx) != 1 ||
        BN_add(x, x, r) != 1) {
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to compute candidate x coordinate");
        goto cleanup_sig_bn;
    }

    if (BN_cmp(x, prime) >= 0) {
        err = neoc_error_set(NEOC_ERROR_NOT_FOUND,
                             "Candidate x is outside field range");
        goto cleanup_sig_bn;
    }

    EC_POINT *point_R = EC_POINT_new(group);
    if (!point_R ||
        EC_POINT_set_compressed_coordinates_GFp(group, point_R, x,
                                                rec_id & 1, ctx) != 1) {
        err = neoc_error_set(NEOC_ERROR_NOT_FOUND,
                             "Failed to decompress candidate point");
        EC_POINT_free(point_R);
        goto cleanup_sig_bn;
    }

    EC_POINT *check = EC_POINT_new(group);
    if (!check ||
        EC_POINT_mul(group, check, NULL, point_R, order, ctx) != 1) {
        EC_POINT_free(point_R);
        EC_POINT_free(check);
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to validate candidate point");
        goto cleanup_sig_bn;
    }

    if (!EC_POINT_is_at_infinity(group, check)) {
        EC_POINT_free(point_R);
        EC_POINT_free(check);
        err = neoc_error_set(NEOC_ERROR_NOT_FOUND,
                             "Candidate point is not valid on curve");
        goto cleanup_sig_bn;
    }
    EC_POINT_free(check);

    if (BN_bin2bn(message_hash, NEOC_SHA256_DIGEST_LENGTH, e) == NULL ||
        BN_mod(e, e, order, ctx) != 1) {
        EC_POINT_free(point_R);
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to prepare message hash");
        goto cleanup_sig_bn;
    }

    BN_zero(e_inv);
    if (BN_mod_sub(e_inv, e_inv, e, order, ctx) != 1) {
        EC_POINT_free(point_R);
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to compute -e mod n");
        goto cleanup_sig_bn;
    }

    BIGNUM *r_inv = BN_mod_inverse(NULL, r, order, ctx);
    if (!r_inv) {
        EC_POINT_free(point_R);
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to compute inverse of r");
        goto cleanup_sig_bn;
    }

    if (BN_mod_mul(sr_inv, s, r_inv, order, ctx) != 1 ||
        BN_mod_mul(e_invr_inv, e_inv, r_inv, order, ctx) != 1) {
        BN_free(r_inv);
        EC_POINT_free(point_R);
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to compute signature multipliers");
        goto cleanup_sig_bn;
    }

    EC_POINT *sr_point = EC_POINT_new(group);
    EC_POINT *e_point = EC_POINT_new(group);
    EC_POINT *public_point = EC_POINT_new(group);

    if (!sr_point || !e_point || !public_point ||
        EC_POINT_mul(group, sr_point, NULL, point_R, sr_inv, ctx) != 1 ||
        EC_POINT_mul(group, e_point, NULL, EC_GROUP_get0_generator(group),
                     e_invr_inv, ctx) != 1 ||
        EC_POINT_add(group, public_point, sr_point, e_point, ctx) != 1) {
        BN_free(r_inv);
        EC_POINT_free(point_R);
        EC_POINT_free(sr_point);
        EC_POINT_free(e_point);
        EC_POINT_free(public_point);
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to derive public key point");
        goto cleanup_sig_bn;
    }

    uint8_t compressed[NEOC_PUBLIC_KEY_SIZE_COMPRESSED] = {0};
    size_t written =
        EC_POINT_point2oct(group,
                           public_point,
                           POINT_CONVERSION_COMPRESSED,
                           compressed,
                           sizeof(compressed),
                           ctx);

    BN_free(r_inv);
    EC_POINT_free(point_R);
    EC_POINT_free(sr_point);
    EC_POINT_free(e_point);
    EC_POINT_free(public_point);

    if (written != NEOC_PUBLIC_KEY_SIZE_COMPRESSED) {
        err = neoc_error_set(NEOC_ERROR_CRYPTO,
                             "Failed to encode recovered public key");
        goto cleanup_sig_bn;
    }

    err = neoc_ec_public_key_from_bytes(compressed,
                                        NEOC_PUBLIC_KEY_SIZE_COMPRESSED,
                                        public_key);

cleanup_sig_bn:
    BN_free(r);
    BN_free(s);

cleanup_bn:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return err;

cleanup:
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    return err;
}

neoc_error_t neoc_signed_message_to_key(const uint8_t *message,
                                        size_t message_len,
                                        const neoc_signature_data_t *sig_data,
                                        neoc_ec_public_key_t **public_key) {
    if (!sig_data || !public_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid inputs for public key recovery");
    }

    *public_key = NULL;

    uint8_t v = neoc_signature_data_get_v(sig_data);
    int rec_id = -1;
    if (v >= NEOC_RECOVERY_V_OFFSET &&
        v < NEOC_RECOVERY_V_OFFSET + 8) {
        rec_id = (int)v - NEOC_RECOVERY_V_OFFSET;
    } else if (v < 4) {
        rec_id = v;
    } else {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Unsupported recovery identifier");
    }

    size_t r_len = 0, s_len = 0;
    const uint8_t *r = neoc_signature_data_get_r(sig_data, &r_len);
    const uint8_t *s = neoc_signature_data_get_s(sig_data, &s_len);
    if (!r || !s || r_len != NEOC_SIGNATURE_COMPONENT_SIZE ||
        s_len != NEOC_SIGNATURE_COMPONENT_SIZE) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid signature data components");
    }

    neoc_ecdsa_signature_t *ecdsa_sig = NULL;
    neoc_error_t err =
        neoc_ecdsa_signature_create(r, s, &ecdsa_sig);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    uint8_t message_hash[NEOC_SHA256_DIGEST_LENGTH] = {0};
    err = neoc_compute_message_hash(message, message_len, message_hash);
    if (err == NEOC_SUCCESS) {
        err = neoc_recover_from_signature(rec_id, ecdsa_sig, message_hash,
                                          public_key);
    }

    neoc_ecdsa_signature_free(ecdsa_sig);
    return err;
}

neoc_error_t neoc_recover_signing_script_hash(
    const uint8_t *message,
    size_t message_len,
    const neoc_signature_data_t *sig_data,
    neoc_hash160_t *script_hash) {
    if (!script_hash) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Script hash output is NULL");
    }

    neoc_ec_public_key_t *public_key = NULL;
    neoc_error_t err = neoc_signed_message_to_key(message, message_len,
                                                  sig_data, &public_key);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    uint8_t *encoded = NULL;
    size_t encoded_len = 0;
    err = neoc_ec_public_key_get_encoded(public_key, true, &encoded,
                                         &encoded_len);
    if (err == NEOC_SUCCESS) {
        if (encoded_len != NEOC_PUBLIC_KEY_SIZE_COMPRESSED) {
            err = neoc_error_set(NEOC_ERROR_INVALID_LENGTH,
                                 "Unexpected public key length");
        } else {
            err = neoc_hash160_from_public_key(script_hash, encoded);
        }
    }

    if (encoded) {
        free(encoded);
    }
    neoc_ec_public_key_free(public_key);
    return err;
}

bool neoc_verify_signature(const uint8_t *message,
                           size_t message_len,
                           const neoc_signature_data_t *sig_data,
                           const neoc_ec_public_key_t *public_key) {
    if (!sig_data || !public_key) {
        return false;
    }

    uint8_t message_hash[NEOC_SHA256_DIGEST_LENGTH] = {0};
    if (neoc_compute_message_hash(message, message_len, message_hash) !=
        NEOC_SUCCESS) {
        return false;
    }

    size_t r_len = 0, s_len = 0;
    const uint8_t *r = neoc_signature_data_get_r(sig_data, &r_len);
    const uint8_t *s = neoc_signature_data_get_s(sig_data, &s_len);
    if (!r || !s || r_len != NEOC_SIGNATURE_COMPONENT_SIZE ||
        s_len != NEOC_SIGNATURE_COMPONENT_SIZE) {
        return false;
    }

    BIGNUM *r_bn = BN_bin2bn(r, NEOC_SIGNATURE_COMPONENT_SIZE, NULL);
    BIGNUM *s_bn = BN_bin2bn(s, NEOC_SIGNATURE_COMPONENT_SIZE, NULL);
    if (!r_bn || !s_bn) {
        BN_free(r_bn);
        BN_free(s_bn);
        return false;
    }

    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig || ECDSA_SIG_set0(ecdsa_sig, r_bn, s_bn) != 1) {
        BN_free(r_bn);
        BN_free(s_bn);
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }

    EC_KEY *ec_key = neoc_ec_key_from_public(public_key);
    if (!ec_key) {
        ECDSA_SIG_free(ecdsa_sig);
        return false;
    }

    int verify_status =
        ECDSA_do_verify(message_hash, NEOC_SHA256_DIGEST_LENGTH,
                        ecdsa_sig, ec_key);

    ECDSA_SIG_free(ecdsa_sig);
    EC_KEY_free(ec_key);
    return verify_status == 1;
}

neoc_error_t neoc_public_key_from_private_key(
    const neoc_ec_private_key_t *private_key,
    neoc_ec_public_key_t **public_key) {
    if (!private_key || !public_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid private key arguments");
    }

    *public_key = NULL;
    return neoc_ec_public_key_from_private(private_key->bytes, public_key);
}

neoc_error_t neoc_verify_message(const uint8_t *message,
                                 size_t message_len,
                                 const neoc_signature_data_t *signature,
                                 const neoc_ec_key_pair_t *key_pair,
                                 bool *verified) {
    if (!signature || !key_pair || !key_pair->public_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT,
                              "Invalid inputs for signature verification");
    }

    bool is_valid = neoc_verify_signature(message, message_len, signature,
                                          key_pair->public_key);
    if (verified) {
        *verified = is_valid;
    }

    return NEOC_SUCCESS;
}
