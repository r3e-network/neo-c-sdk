#define NEOC_ACCOUNT_DISABLE_OVERLOADS

/**
 * @file account.c
 * @brief NEO account implementation
 */

#include "neoc/wallet/account.h"
#include "neoc/wallet/multi_sig.h"
#include "neoc/wallet/nep6.h"
#include "neoc/neoc_memory.h"
#include "neoc/crypto/ec_key_pair.h"
#include "neoc/crypto/ecdsa_signature.h"
#include "neoc/crypto/neoc_hash.h"
#include "neoc/crypto/nep2.h"
#include "neoc/types/neoc_hash256.h"
#include "neoc/crypto/sign.h"
#include "neoc/script/script_helper.h"
#include "neoc/script/verification_script.h"
#include "neoc/script/interop_service.h"
#include "neoc/utils/neoc_base64.h"
#include "neoc/types/contract_parameter_type.h"
#include "neoc/transaction/witness.h"
#include <string.h>
#include <stdlib.h>

typedef struct {
    int threshold;
    int nr_participants;
    bool is_address_only;
} neoc_account_multisig_info_t;

// Helper function for internal use
static bool is_multisig_internal(const neoc_account_t *account) {
    if (!account || !account->extra) {
        return false;
    }

    switch (account->extra_type) {
        case NEOC_ACCOUNT_EXTRA_MULTISIG: {
            neoc_multi_sig_account_t *multisig = (neoc_multi_sig_account_t *)account->extra;
            if (!multisig) {
                return false;
            }
            return multisig->threshold > 0 &&
                   multisig->threshold <= multisig->public_key_count &&
                   multisig->public_key_count >= 1;
        }
        case NEOC_ACCOUNT_EXTRA_MULTISIG_INFO: {
            neoc_account_multisig_info_t *info = (neoc_account_multisig_info_t *)account->extra;
            if (!info) {
                return false;
            }
            return info->threshold > 0 &&
                   info->threshold <= info->nr_participants &&
                   info->nr_participants >= 1;
        }
        default:
            return false;
    }
}

static void neoc_account_clear_encrypted_key(neoc_account_t *account) {
    if (!account || !account->encrypted_key) {
        return;
    }
    neoc_secure_memzero(account->encrypted_key, account->encrypted_key_len);
    neoc_free(account->encrypted_key);
    account->encrypted_key = NULL;
    account->encrypted_key_len = 0;
}

static neoc_error_t neoc_account_store_encrypted_key(neoc_account_t *account, const char *encrypted_key) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "account_store_encrypted_key: invalid account");
    }
    neoc_account_clear_encrypted_key(account);

    if (account->verification_script) {
        neoc_secure_memzero(account->verification_script, account->verification_script_len);
        neoc_free(account->verification_script);
        account->verification_script = NULL;
        account->verification_script_len = 0;
    }
    if (!encrypted_key) {
        return NEOC_SUCCESS;
    }
    size_t len = strlen(encrypted_key);
    char *copy = neoc_malloc(len + 1);
    if (!copy) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "account_store_encrypted_key: allocation failed");
    }
    memcpy(copy, encrypted_key, len + 1);
    account->encrypted_key = (uint8_t *)copy;
    account->encrypted_key_len = len;
    return NEOC_SUCCESS;
}

// Account implementation uses the public struct from account.h

neoc_error_t neoc_account_create_with_label(const char *label, neoc_account_t **account) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid account pointer");
    }
    
    *account = neoc_calloc(1, sizeof(neoc_account_t));
    if (!*account) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account");
    }
    
    // Generate new key pair
    neoc_error_t err = neoc_ec_key_pair_create_random(&(*account)->key_pair);
    if (err != NEOC_SUCCESS) {
        neoc_free(*account);
        return err;
    }
    
    // Generate verification script from public key
    uint8_t public_key[65];  // Buffer for public key
    size_t public_key_len = sizeof(public_key);
    err = neoc_ec_key_pair_get_public_key((*account)->key_pair, public_key, &public_key_len);
    if (err != NEOC_SUCCESS) {
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return err;
    }
    
    uint8_t *verification_script = NULL;
    size_t verification_script_len = 0;
    err = neoc_script_create_single_sig_verification(public_key, public_key_len,
                                                     &verification_script,
                                                     &verification_script_len);
    if (err != NEOC_SUCCESS) {
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return err;
    }
    
    // Calculate script hash from verification script (value type, not pointer)
    err = neoc_hash160_from_script(&(*account)->script_hash,
                                   verification_script,
                                   verification_script_len);
    if (err != NEOC_SUCCESS) {
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(verification_script);
        neoc_free(*account);
        return err;
    }

    (*account)->verification_script = verification_script;
    (*account)->verification_script_len = verification_script_len;
    
    // Generate address from script hash
    (*account)->address = neoc_malloc(NEOC_ADDRESS_LENGTH);
    if (!(*account)->address) {
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    err = neoc_hash160_to_address(&(*account)->script_hash, (*account)->address, NEOC_ADDRESS_LENGTH);
    if (err != NEOC_SUCCESS) {
        neoc_free((*account)->address);
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return err;
    }
    
    const char *label_source = label ? label : (*account)->address;
    (*account)->label = neoc_strdup(label_source);
    if (!(*account)->label) {
        neoc_free((*account)->address);
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free((*account));
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account label");
    }

    (*account)->is_default = false;
    (*account)->is_locked = false;
    (*account)->extra_type = NEOC_ACCOUNT_EXTRA_NONE;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_create_random(neoc_account_t **account) {
    return neoc_account_create_with_label(NULL, account);
}

neoc_error_t neoc_account_create_from_key_pair_with_label(const char *label,
                                                          const neoc_ec_key_pair_t *key_pair,
                                                          neoc_account_t **account) {
    if (!key_pair || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *account = neoc_calloc(1, sizeof(neoc_account_t));
    if (!*account) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account");
    }
    
    // Get private key from source key pair
    uint8_t private_key[32];
    size_t private_key_len = sizeof(private_key);
    neoc_error_t err = neoc_ec_key_pair_get_private_key(key_pair, private_key, &private_key_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(*account);
        return err;
    }
    
    // Create new key pair from private key
    err = neoc_ec_key_pair_create_from_private_key(private_key, &(*account)->key_pair);
    if (err != NEOC_SUCCESS) {
        neoc_free(*account);
        return err;
    }
    
    // Generate verification script from public key
    uint8_t public_key[65];  // Buffer for public key
    size_t public_key_len = sizeof(public_key);
    err = neoc_ec_key_pair_get_public_key((*account)->key_pair, public_key, &public_key_len);
    if (err != NEOC_SUCCESS) {
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return err;
    }
    
    uint8_t *verification_script = NULL;
    size_t verification_script_len = 0;
    err = neoc_script_create_single_sig_verification(public_key, public_key_len,
                                                     &verification_script,
                                                     &verification_script_len);
    if (err != NEOC_SUCCESS) {
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return err;
    }
    
    // Calculate script hash (value type, not pointer)
    err = neoc_hash160_from_script(&(*account)->script_hash,
                                   verification_script,
                                   verification_script_len);
    if (err != NEOC_SUCCESS) {
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(verification_script);
        neoc_free(*account);
        return err;
    }

    (*account)->verification_script = verification_script;
    (*account)->verification_script_len = verification_script_len;
    
    // Generate address
    (*account)->address = neoc_malloc(NEOC_ADDRESS_LENGTH);
    if (!(*account)->address) {
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    err = neoc_hash160_to_address(&(*account)->script_hash, (*account)->address, NEOC_ADDRESS_LENGTH);
    if (err != NEOC_SUCCESS) {
        neoc_free((*account)->address);
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return err;
    }
    
    const char *label_source = label ? label : (*account)->address;
    (*account)->label = neoc_strdup(label_source);
    if (!(*account)->label) {
        neoc_free((*account)->address);
        neoc_ec_key_pair_free((*account)->key_pair);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account label");
    }

    (*account)->is_default = false;
    (*account)->is_locked = false;
    (*account)->extra_type = NEOC_ACCOUNT_EXTRA_NONE;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_create_from_wif_with_label(const char *label,
                                                     const char *wif,
                                                     neoc_account_t **account) {
    if (!wif || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Import key pair from WIF
    neoc_ec_key_pair_t *key_pair = NULL;
    neoc_error_t err = neoc_ec_key_pair_import_from_wif(wif, &key_pair);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Create account from key pair
    err = neoc_account_create_from_key_pair_with_label(label, key_pair, account);
    neoc_ec_key_pair_free(key_pair);
    
    return err;
}

neoc_error_t neoc_account_create_from_nep2_with_label(const char *label,
                                                      const char *encrypted_key,
                                                      const char *passphrase,
                                                      neoc_account_t **account) {
    (void)label;  // Suppress unused parameter warning
    if (!encrypted_key || !passphrase || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Decrypt NEP-2 encrypted private key
    uint8_t private_key[32];
    neoc_error_t err = neoc_nep2_decrypt(encrypted_key, passphrase, NULL, private_key, sizeof(private_key));
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Create EC key pair from private key
    neoc_ec_key_pair_t *key_pair = NULL;
    err = neoc_ec_key_pair_from_private_key(private_key, 32, &key_pair);
    
    // Clear private key from memory
    memset(private_key, 0, sizeof(private_key));
    
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Create account from key pair
    err = neoc_account_create_from_key_pair_with_label(label, key_pair, account);
    neoc_ec_key_pair_free(key_pair);
    return err;
}



neoc_ec_public_key_t* neoc_account_get_public_key(const neoc_account_t *account) {
    if (!account || !account->key_pair) {
        return NULL;
    }
    return account->key_pair->public_key;
}

neoc_ec_key_pair_t* neoc_account_get_key_pair_ptr(const neoc_account_t *account) {
    return account ? account->key_pair : NULL;
}

neoc_error_t neoc_account_get_key_pair_copy(const neoc_account_t *account,
                                            neoc_ec_key_pair_t **key_pair) {
    if (!account || !key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    *key_pair = NULL;
    if (!account->key_pair) {
        return NEOC_SUCCESS;
    }

    uint8_t private_key[32];
    size_t private_key_len = sizeof(private_key);
    neoc_error_t err = neoc_ec_key_pair_get_private_key(account->key_pair, private_key, &private_key_len);
    if (err != NEOC_SUCCESS) {
        neoc_secure_memzero(private_key, sizeof(private_key));
        return err;
    }

    err = neoc_ec_key_pair_create_from_private_key(private_key, key_pair);
    neoc_secure_memzero(private_key, sizeof(private_key));
    return err;
}

neoc_error_t neoc_account_export_wif(const neoc_account_t *account, char **wif) {
    if (!account || !wif) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (account->is_locked) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account is locked");
    }
    
    if (!account->key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account has no key pair");
    }
    
    return neoc_ec_key_pair_export_as_wif(account->key_pair, wif);
}

neoc_error_t neoc_account_export_nep2(const neoc_account_t *account,
                                      const char *password,
                                      char **nep2_key) {
    if (!account || !password || !nep2_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (!account->key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account has no key pair to encrypt");
    }
    
    // Get private key from account
    uint8_t private_key[32];
    size_t private_key_len = sizeof(private_key);
    neoc_error_t err = neoc_ec_key_pair_get_private_key(account->key_pair, private_key, &private_key_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    char *encrypted = neoc_calloc(1, 64);
    if (!encrypted) {
        memset(private_key, 0, sizeof(private_key));
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate NEP-2 buffer");
    }
    
    err = neoc_nep2_encrypt(private_key, password, NULL, encrypted, 64);
    memset(private_key, 0, sizeof(private_key));
    
    if (err != NEOC_SUCCESS) {
        neoc_free(encrypted);
        return err;
    }
    
    *nep2_key = encrypted;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_sign(const neoc_account_t *account,
                                const uint8_t *data,
                                size_t data_len,
                                uint8_t **signature,
                                size_t *signature_len) {
    if (!account || !data || !signature || !signature_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (!account->key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account has no key pair for signing");
    }
    
    if (data_len != 32) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Account sign expects 32-byte hash");
    }
    
    neoc_ecdsa_signature_t *ecdsa_sig = NULL;
    neoc_error_t err = neoc_ec_key_pair_sign(account->key_pair, data, &ecdsa_sig);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    err = neoc_ecdsa_signature_to_bytes(ecdsa_sig, signature, signature_len);
    neoc_ecdsa_signature_free(ecdsa_sig);
    
    return err;
}

neoc_error_t neoc_account_sign_hash(const neoc_account_t *account,
                                    const neoc_hash256_t *hash,
                                    neoc_witness_t **witness) {
    if (!account || !hash || !witness) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (!account->key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account has no key pair for signing");
    }
    
    // Sign hash
    neoc_ecdsa_signature_t *ecdsa_sig = NULL;
    neoc_error_t err = neoc_ec_key_pair_sign(account->key_pair, hash->data, &ecdsa_sig);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    uint8_t *signature_bytes = NULL;
    size_t signature_len = 0;
    err = neoc_ecdsa_signature_to_bytes(ecdsa_sig, &signature_bytes, &signature_len);
    neoc_ecdsa_signature_free(ecdsa_sig);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Create invocation script from signature
    uint8_t *invocation_script = NULL;
    size_t invocation_len = 0;
    err = neoc_script_create_single_sig_invocation(signature_bytes, signature_len, &invocation_script, &invocation_len);
    neoc_free(signature_bytes);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Get verification script
    uint8_t *verification_script = NULL;
    size_t verification_len = 0;
    err = neoc_account_get_verification_script(account, &verification_script, &verification_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(invocation_script);
        return err;
    }
    
    // Create witness
    err = neoc_witness_create(invocation_script, invocation_len, verification_script, verification_len, witness);
    
    neoc_free(invocation_script);
    neoc_free(verification_script);
    
    return err;
}



bool neoc_account_is_default_value(const neoc_account_t *account) {
    return account ? account->is_default : false;
}

neoc_error_t neoc_account_set_default(neoc_account_t *account, bool is_default) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid account");
    }
    account->is_default = is_default;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_is_default_out(const neoc_account_t *account, bool *is_default) {
    if (!account || !is_default) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    *is_default = account->is_default;
    return NEOC_SUCCESS;
}



neoc_error_t neoc_account_set_label(neoc_account_t *account, const char *label) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid account");
    }
    
    if (account->label) {
        neoc_free(account->label);
    }
    if (label) {
        account->label = neoc_strdup(label);
        if (!account->label) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account label");
        }
    } else {
        account->label = NULL;
    }
    return NEOC_SUCCESS;
}

// Multi-signature account functions

neoc_error_t neoc_account_create_multisig_from_public_keys(neoc_ec_public_key_t **public_keys,
                                                           size_t key_count,
                                                           int threshold,
                                                           neoc_account_t **account) {
    if (!public_keys || !account || key_count == 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (threshold <= 0 || threshold > (int)key_count) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid threshold");
    }
    
    if (key_count > 1024) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Too many public keys");
    }
    
    // Create multi-sig account using the multi_sig module
    neoc_multi_sig_account_t *multisig = NULL;
    neoc_error_t err = neoc_multi_sig_create((uint8_t)threshold, public_keys, (uint8_t)key_count, &multisig);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Create account structure
    *account = neoc_calloc(1, sizeof(neoc_account_t));
    if (!*account) {
        neoc_multi_sig_free(multisig);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account");
    }
    
    // Get address from script hash
    (*account)->address = neoc_malloc(NEOC_ADDRESS_LENGTH);
    if (!(*account)->address) {
        neoc_multi_sig_free(multisig);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    err = neoc_hash160_to_address(&multisig->script_hash, (*account)->address, NEOC_ADDRESS_LENGTH);
    if (err != NEOC_SUCCESS) {
        neoc_free((*account)->address);
        neoc_multi_sig_free(multisig);
        neoc_free(*account);
        return err;
    }
    
    // Copy script hash
    memcpy(&(*account)->script_hash, &multisig->script_hash, sizeof(neoc_hash160_t));
    
    // Set up multi-sig specific fields
    (*account)->label = neoc_strdup((*account)->address);
    if (!(*account)->label) {
        neoc_free((*account)->address);
        neoc_multi_sig_free(multisig);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account label");
    }

    (*account)->key_pair = NULL; // Multi-sig accounts don't have a single key pair
    (*account)->is_default = false;
    (*account)->is_locked = false;
    (*account)->encrypted_key = NULL;
    (*account)->encrypted_key_len = 0;
    (*account)->extra = multisig; // Store the multi-sig data in extra field
    (*account)->extra_type = NEOC_ACCOUNT_EXTRA_MULTISIG;

    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_create_multisig(int threshold,
                                          neoc_ec_public_key_t **public_keys,
                                          size_t key_count,
                                          neoc_account_t **account) {
    return neoc_account_create_multisig_from_public_keys(public_keys,
                                                         key_count,
                                                         threshold,
                                                         account);
}

neoc_error_t neoc_account_create_multi_sig(neoc_ec_public_key_t **public_keys,
                                           size_t key_count,
                                           int threshold,
                                           neoc_account_t **account) {
    return neoc_account_create_multisig_from_public_keys(public_keys,
                                                         key_count,
                                                         threshold,
                                                         account);
}

neoc_error_t neoc_account_create_multisig_with_address(const char *address,
                                                      int threshold,
                                                      int nr_participants,
                                                      neoc_account_t **account) {
    if (!address || !account || threshold <= 0 || nr_participants <= 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (threshold > nr_participants) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Threshold cannot exceed number of participants");
    }
    
    // Create account structure
    *account = neoc_calloc(1, sizeof(neoc_account_t));
    if (!*account) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account");
    }
    
    // Set address
    (*account)->address = neoc_strdup(address);
    if (!(*account)->address) {
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    // Calculate script hash from address
    neoc_error_t err = neoc_hash160_from_address(&(*account)->script_hash, address);
    if (err != NEOC_SUCCESS) {
        neoc_free((*account)->address);
        neoc_free(*account);
        return err;
    }

    // Create a simple multi-sig info structure to store threshold and participants
    neoc_account_multisig_info_t *info = neoc_malloc(sizeof(neoc_account_multisig_info_t));
    if (!info) {
        neoc_free((*account)->address);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate multi-sig info");
    }

    info->threshold = threshold;
    info->nr_participants = nr_participants;
    info->is_address_only = true;

    // Set up account fields
    (*account)->label = neoc_strdup(address);
    if (!(*account)->label) {
        neoc_free(info);
        neoc_free((*account)->address);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account label");
    }
    (*account)->key_pair = NULL;
    (*account)->is_default = false;
    (*account)->is_locked = false;
    (*account)->encrypted_key = NULL;
    (*account)->encrypted_key_len = 0;
    (*account)->extra = info;
    (*account)->extra_type = NEOC_ACCOUNT_EXTRA_MULTISIG_INFO;

    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_create_from_verification_script(const uint8_t *script,
                                                          size_t script_len,
                                                          neoc_account_t **account) {
    if (!script || script_len == 0 || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Create account structure
    *account = neoc_calloc(1, sizeof(neoc_account_t));
    if (!*account) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account");
    }
    
    // Calculate script hash from verification script
    neoc_error_t err = neoc_hash160_from_script(&(*account)->script_hash, script, script_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(*account);
        return err;
    }

    uint8_t *script_copy = neoc_malloc(script_len);
    if (!script_copy) {
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to cache verification script");
    }
    memcpy(script_copy, script, script_len);
    (*account)->verification_script = script_copy;
    (*account)->verification_script_len = script_len;
    
    // Generate address from script hash
    (*account)->address = neoc_malloc(NEOC_ADDRESS_LENGTH);
    if (!(*account)->address) {
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    err = neoc_hash160_to_address(&(*account)->script_hash, (*account)->address, NEOC_ADDRESS_LENGTH);
    if (err != NEOC_SUCCESS) {
        neoc_free((*account)->address);
        neoc_free(*account);
        return err;
    }
    
    // Analyze script to determine if it's multi-sig and extract threshold/participants
    if (script_len >= 4) {
        size_t pos = 0;
        
        // Check for multi-sig pattern: PUSH<m> ... PUSH<n> SYSCALL
        // First byte should be PUSH opcode for threshold (m)
        uint8_t threshold = 0;
        if (script[pos] >= 0x11 && script[pos] <= 0x20) { // PUSH1 to PUSH16
            threshold = script[pos] - 0x10;
            pos++;
        } else if (script[pos] == 0x00) { // PUSHINT8
            pos++;
            if (pos < script_len) {
                threshold = script[pos++];
            }
        }
        
        // Count public keys (33-byte compressed or 65-byte uncompressed)
        int pubkey_count = 0;
        while (pos < script_len - 2) {
            if (script[pos] == 0x21) { // 33-byte push (compressed pubkey)
                pos += 34; // Skip opcode + 33 bytes
                pubkey_count++;
            } else if (script[pos] == 0x41) { // 65-byte push (uncompressed pubkey)  
                pos += 66; // Skip opcode + 65 bytes
                pubkey_count++;
            } else if (script[pos] == 0x0C && pos + 1 < script_len) { // PUSHDATA1
                uint8_t len = script[pos + 1];
                if (len == 33 || len == 65) {
                    pos += 2 + len;
                    pubkey_count++;
                } else {
                    break;
                }
            } else {
                break; // Not a public key push
            }
        }
        
        // Check for participant count push
        uint8_t participants = 0;
        if (pos < script_len && script[pos] >= 0x11 && script[pos] <= 0x20) { // PUSH1 to PUSH16
            participants = script[pos] - 0x10;
            pos++;
        } else if (pos < script_len && script[pos] == 0x00) { // PUSHINT8
            pos++;
            if (pos < script_len) {
                participants = script[pos++];
            }
        }
        
        // Check for CHECKMULTISIG syscall (0x41 followed by 4-byte hash)
        bool is_multisig = false;
        if (pos + 4 < script_len && script[pos] == 0x41) { // SYSCALL
            uint32_t expected_hash = neoc_interop_get_hash(NEOC_INTEROP_SYSTEM_CRYPTO_CHECKMULTISIG);
            uint32_t script_hash = (uint32_t)script[pos + 1]
                                  | ((uint32_t)script[pos + 2] << 8)
                                  | ((uint32_t)script[pos + 3] << 16)
                                  | ((uint32_t)script[pos + 4] << 24);
            if (script_hash == expected_hash) {
                is_multisig = true;
            }
        }
        
        // If it's a multi-sig script, store the info
        if (is_multisig && threshold > 0 && participants > 0 && 
            participants == pubkey_count && threshold <= participants) {
            // Allocate multisig info structure
            neoc_account_multisig_info_t *info = neoc_malloc(sizeof(neoc_account_multisig_info_t));
            if (info) {
                info->threshold = threshold;
                info->nr_participants = participants;
                info->is_address_only = true; // We don't have the public keys stored
                (*account)->extra = info;
                (*account)->extra_type = NEOC_ACCOUNT_EXTRA_MULTISIG_INFO;
            }
        }
    }

    // Set basic fields
    (*account)->label = neoc_strdup((*account)->address);
    if (!(*account)->label) {
        if ((*account)->extra && (*account)->extra_type == NEOC_ACCOUNT_EXTRA_MULTISIG_INFO) {
            neoc_free((*account)->extra);
            (*account)->extra = NULL;
            (*account)->extra_type = NEOC_ACCOUNT_EXTRA_NONE;
        }
        neoc_free((*account)->verification_script);
        neoc_free((*account)->address);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account label");
    }
    (*account)->key_pair = NULL;
    (*account)->is_default = false;
    (*account)->is_locked = false;
    (*account)->encrypted_key = NULL;
    (*account)->encrypted_key_len = 0;
    if (!(*account)->extra) {
        (*account)->extra_type = NEOC_ACCOUNT_EXTRA_NONE;
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_create_from_public_key(neoc_ec_public_key_t *public_key,
                                                  neoc_account_t **account) {
    if (!public_key || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Create account structure
    *account = neoc_calloc(1, sizeof(neoc_account_t));
    if (!*account) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account");
    }
    
    // Get encoded public key
    uint8_t *pubkey_bytes = NULL;
    size_t pubkey_size = 0;
    neoc_error_t err = neoc_ec_public_key_get_encoded(public_key, true, &pubkey_bytes, &pubkey_size);
    if (err != NEOC_SUCCESS) {
        neoc_free(*account);
        return err;
    }
    
    // Generate verification script from public key
    uint8_t *verification_script = NULL;
    size_t verification_script_len = 0;
    err = neoc_script_create_single_sig_verification(pubkey_bytes, pubkey_size,
                                                     &verification_script,
                                                     &verification_script_len);
    neoc_free(pubkey_bytes);
    if (err != NEOC_SUCCESS) {
        neoc_free(*account);
        return err;
    }
    
    // Calculate script hash from verification script
    err = neoc_hash160_from_script(&(*account)->script_hash, verification_script, verification_script_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(verification_script);
        neoc_free(*account);
        return err;
    }

    (*account)->verification_script = verification_script;
    (*account)->verification_script_len = verification_script_len;
    
    // Generate address from script hash
    (*account)->address = neoc_malloc(NEOC_ADDRESS_LENGTH);
    if (!(*account)->address) {
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    err = neoc_hash160_to_address(&(*account)->script_hash, (*account)->address, NEOC_ADDRESS_LENGTH);
    if (err != NEOC_SUCCESS) {
        neoc_free((*account)->address);
        neoc_free(*account);
        return err;
    }
    
    // Set up account fields
    (*account)->label = neoc_strdup((*account)->address);
    if (!(*account)->label) {
        neoc_free((*account)->verification_script);
        neoc_free((*account)->address);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account label");
    }

    (*account)->key_pair = NULL; // We don't have the private key, only public key
    (*account)->is_default = false;
    (*account)->is_locked = false;
    (*account)->encrypted_key = NULL;
    (*account)->encrypted_key_len = 0;
    (*account)->extra = NULL;
    (*account)->extra_type = NEOC_ACCOUNT_EXTRA_NONE;

    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_create_from_address(const char *address, neoc_account_t **account) {
    if (!address || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Create account structure
    *account = neoc_calloc(1, sizeof(neoc_account_t));
    if (!*account) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account");
    }
    
    // Set address
    (*account)->address = neoc_strdup(address);
    if (!(*account)->address) {
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    // Calculate script hash from address
    neoc_error_t err = neoc_hash160_from_address(&(*account)->script_hash, address);
    if (err != NEOC_SUCCESS) {
        neoc_free((*account)->address);
        neoc_free(*account);
        return err;
    }

    // Set up account fields
    (*account)->label = neoc_strdup(address);
    if (!(*account)->label) {
        neoc_free((*account)->address);
        neoc_free(*account);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account label");
    }
    (*account)->key_pair = NULL;
    (*account)->is_default = false;
    (*account)->is_locked = false;
    (*account)->encrypted_key = NULL;
    (*account)->encrypted_key_len = 0;
    (*account)->extra = NULL;
    (*account)->extra_type = NEOC_ACCOUNT_EXTRA_NONE;

    return NEOC_SUCCESS;
}

const char* neoc_account_get_address_ptr(const neoc_account_t *account) {
    return account ? account->address : NULL;
}

neoc_error_t neoc_account_get_address_copy(const neoc_account_t *account, char **address) {
    if (!account || !address) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (!account->address) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account has no address");
    }
    
    *address = neoc_strdup(account->address);
    if (!*address) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    return NEOC_SUCCESS;
}

const neoc_hash160_t* neoc_account_get_script_hash_ptr(const neoc_account_t *account) {
    return account ? &account->script_hash : NULL;
}

neoc_error_t neoc_account_get_script_hash_copy(const neoc_account_t *account, neoc_hash160_t *hash) {
    if (!account || !hash) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    memcpy(hash, &account->script_hash, sizeof(neoc_hash160_t));
    return NEOC_SUCCESS;
}

const char* neoc_account_get_label_ptr(const neoc_account_t *account) {
    return account ? account->label : NULL;
}

neoc_error_t neoc_account_get_label_copy(const neoc_account_t *account, char **label) {
    if (!account || !label) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    if (!account->label) {
        *label = NULL;
        return NEOC_SUCCESS;
    }
    *label = neoc_strdup(account->label);
    if (!*label) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate label");
    }
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_get_verification_script(const neoc_account_t *account,
                                                   uint8_t **script,
                                                   size_t *script_len) {
    if (!account || !script || !script_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Return cached verification script if available
    if (account->verification_script && account->verification_script_len > 0) {
        *script = neoc_malloc(account->verification_script_len);
        if (!*script) {
            return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate cached verification script");
        }
        memcpy(*script, account->verification_script, account->verification_script_len);
        *script_len = account->verification_script_len;
        return NEOC_SUCCESS;
    }

    // Check if this is a multi-sig account with verification script
    if (account->extra_type == NEOC_ACCOUNT_EXTRA_MULTISIG) {
        neoc_multi_sig_account_t *multisig = (neoc_multi_sig_account_t *)account->extra;
        if (multisig && multisig->verification_script) {
            *script = neoc_malloc(multisig->script_size);
            if (!*script) {
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate script");
            }
            memcpy(*script, multisig->verification_script, multisig->script_size);
            *script_len = multisig->script_size;
            return NEOC_SUCCESS;
        }
    } else if (account->extra_type == NEOC_ACCOUNT_EXTRA_MULTISIG_INFO) {
        *script = NULL;
        *script_len = 0;
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Verification script not available for address-only multi-sig account");
    }
    
    // For single-sig accounts, generate verification script from public key
    if (account->key_pair) {
        uint8_t public_key[65];
        size_t public_key_len = sizeof(public_key);
        neoc_error_t err = neoc_ec_key_pair_get_public_key(account->key_pair, public_key, &public_key_len);
        if (err != NEOC_SUCCESS) {
            return err;
        }
        
        return neoc_script_create_single_sig_verification(public_key, public_key_len, script, script_len);
    }
    
    // No verification script available
    *script = NULL;
    *script_len = 0;
    return neoc_error_set(NEOC_ERROR_INVALID_STATE, "No verification script available");
}

neoc_verification_script_t* neoc_account_get_verification_script_ptr(const neoc_account_t *account) {
    if (!account) {
        return NULL;
    }
    uint8_t *script = NULL;
    size_t script_len = 0;
    neoc_error_t err = neoc_account_get_verification_script(account, &script, &script_len);
    if (err != NEOC_SUCCESS) {
        return NULL;
    }

    neoc_verification_script_t *verification_script = NULL;
    err = neoc_verification_script_create(script, script_len, &verification_script);
    neoc_free(script);
    if (err != NEOC_SUCCESS) {
        return NULL;
    }
    return verification_script;
}

neoc_error_t neoc_account_get_verification_script_object(const neoc_account_t *account,
                                                          neoc_verification_script_t **script) {
    if (!script) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid script pointer");
    }
    *script = NULL;
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid account");
    }

    uint8_t *script_bytes = NULL;
    size_t script_len = 0;
    neoc_error_t err = neoc_account_get_verification_script(account, &script_bytes, &script_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_verification_script_create(script_bytes, script_len, script);
    neoc_free(script_bytes);
    return err;
}

neoc_error_t neoc_account_is_multisig(const neoc_account_t *account, bool *is_multisig) {
    if (!account || !is_multisig) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *is_multisig = is_multisig_internal(account);
    return NEOC_SUCCESS;
}

bool neoc_account_is_multi_sig(const neoc_account_t *account) {
    return is_multisig_internal(account);
}

neoc_error_t neoc_account_to_nep6(const neoc_account_t *account,
                                  neoc_nep6_account_t **nep6_account) {
    if (!account || !nep6_account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "account_to_nep6: invalid arguments");
    }
    if (!account->address) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "account_to_nep6: account missing address");
    }

    const char *label = account->label && account->label[0] != '\0' ? account->label : NULL;
    const char *encrypted_key = (const char *)account->encrypted_key;

    neoc_error_t err = neoc_nep6_account_create(account->address,
                                                label,
                                                account->is_default,
                                                account->is_locked,
                                                encrypted_key,
                                                nep6_account);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    uint8_t *verification_script = NULL;
    size_t verification_script_len = 0;
    err = neoc_account_get_verification_script(account, &verification_script, &verification_script_len);
    if (err == NEOC_SUCCESS && verification_script && verification_script_len > 0) {
        char *script_base64 = neoc_base64_encode_alloc(verification_script, verification_script_len);
        neoc_free(verification_script);
        if (!script_base64) {
            neoc_nep6_account_free(*nep6_account);
            *nep6_account = NULL;
            return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "account_to_nep6: contract script allocation failed");
        }

        neoc_nep6_contract_t *contract = NULL;
        neoc_nep6_parameter_t parameter_template = {
            .name = "signature",
            .type = NEOC_PARAM_TYPE_SIGNATURE
        };
        neoc_error_t contract_err = neoc_nep6_contract_create(script_base64,
                                                              &parameter_template,
                                                              1,
                                                              false,
                                                              &contract);
        neoc_free(script_base64);
        if (contract_err == NEOC_SUCCESS) {
            (void)neoc_nep6_account_set_contract(*nep6_account, contract);
        } else {
            neoc_nep6_account_free(*nep6_account);
            *nep6_account = NULL;
            return contract_err;
        }
    } else {
        neoc_free(verification_script);
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_from_nep6(const neoc_nep6_account_t *nep6_account,
                                    neoc_account_t **account) {
    if (!nep6_account || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "account_from_nep6: invalid arguments");
    }

    const char *address = neoc_nep6_account_get_address(nep6_account);
    if (!address) {
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "account_from_nep6: missing address");
    }

    neoc_error_t err = neoc_account_create_from_address(address, account);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    const char *label = neoc_nep6_account_get_label(nep6_account);
    if (label) {
        (void)neoc_account_set_label(*account, label);
    }

    bool is_default = neoc_nep6_account_is_default(nep6_account);
    (void)neoc_account_set_default(*account, is_default);

    const char *encrypted_key = neoc_nep6_account_get_key(nep6_account);
    err = neoc_account_store_encrypted_key(*account, encrypted_key);
    if (err != NEOC_SUCCESS) {
        neoc_account_free(*account);
        *account = NULL;
        return err;
    }

    bool is_locked = neoc_nep6_account_is_locked(nep6_account);
    (*account)->is_locked = is_locked || (encrypted_key != NULL);

    neoc_nep6_contract_t *contract = neoc_nep6_account_get_contract(nep6_account);
    if (contract) {
        const char *script_base64 = neoc_nep6_contract_get_script(contract);
        if (script_base64) {
            size_t decoded_len = 0;
            uint8_t *decoded = neoc_base64_decode_alloc(script_base64, &decoded_len);
            if (decoded) {
                if ((*account)->verification_script) {
                    neoc_free((*account)->verification_script);
                }
                (*account)->verification_script = decoded;
                (*account)->verification_script_len = decoded_len;
            }
        }
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_create_from_nep6(const neoc_nep6_account_t *nep6_account,
                                           neoc_account_t **account) {
    return neoc_account_from_nep6(nep6_account, account);
}

neoc_error_t neoc_account_get_signing_threshold(const neoc_account_t *account, int *threshold) {
    if (!account || !threshold) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (!is_multisig_internal(account)) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account is not multi-signature");
    }
    
    switch (account->extra_type) {
        case NEOC_ACCOUNT_EXTRA_MULTISIG: {
            neoc_multi_sig_account_t *multisig = (neoc_multi_sig_account_t *)account->extra;
            if (multisig && multisig->threshold > 0 && multisig->threshold <= multisig->public_key_count) {
                *threshold = multisig->threshold;
                return NEOC_SUCCESS;
            }
            break;
        }
        case NEOC_ACCOUNT_EXTRA_MULTISIG_INFO: {
            neoc_account_multisig_info_t *info = (neoc_account_multisig_info_t *)account->extra;
            if (info && info->threshold > 0) {
                *threshold = info->threshold;
                return NEOC_SUCCESS;
            }
            break;
        }
        default:
            break;
    }

    return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Cannot determine signing threshold");
}

neoc_error_t neoc_account_get_nr_participants(const neoc_account_t *account, int *nr_participants) {
    if (!account || !nr_participants) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (!is_multisig_internal(account)) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account is not multi-signature");
    }
    
    switch (account->extra_type) {
        case NEOC_ACCOUNT_EXTRA_MULTISIG: {
            neoc_multi_sig_account_t *multisig = (neoc_multi_sig_account_t *)account->extra;
            if (multisig && multisig->public_key_count > 0) {
                *nr_participants = multisig->public_key_count;
                return NEOC_SUCCESS;
            }
            break;
        }
        case NEOC_ACCOUNT_EXTRA_MULTISIG_INFO: {
            neoc_account_multisig_info_t *info = (neoc_account_multisig_info_t *)account->extra;
            if (info && info->nr_participants > 0) {
                *nr_participants = info->nr_participants;
                return NEOC_SUCCESS;
            }
            break;
        }
        default:
            break;
    }

    return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Cannot determine number of participants");
}

neoc_error_t neoc_account_lock_internal(neoc_account_t *account) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    account->is_locked = true;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_unlock_internal(neoc_account_t *account) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    account->is_locked = false;
    return NEOC_SUCCESS;
}

bool neoc_account_has_encrypted_private_key_value(const neoc_account_t *account) {
    return account ? (account->encrypted_key != NULL && account->encrypted_key_len > 0) : false;
}

neoc_error_t neoc_account_has_encrypted_private_key_out(const neoc_account_t *account,
                                                        bool *has_encrypted_key) {
    if (!account || !has_encrypted_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    *has_encrypted_key = account->encrypted_key != NULL && account->encrypted_key_len > 0;
    return NEOC_SUCCESS;
}

const char* neoc_account_get_encrypted_private_key_ptr(const neoc_account_t *account) {
    if (!account || !account->encrypted_key) {
        return NULL;
    }
    return (const char *)account->encrypted_key;
}

neoc_error_t neoc_account_get_encrypted_private_key_copy(const neoc_account_t *account,
                                                         char **encrypted_key) {
    if (!encrypted_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid encrypted key output");
    }
    *encrypted_key = NULL;
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid account");
    }
    if (!account->encrypted_key) {
        return NEOC_SUCCESS;
    }
    char *copy = neoc_strdup((const char *)account->encrypted_key);
    if (!copy) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to copy encrypted key");
    }
    *encrypted_key = copy;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_get_encrypted_private_key(const neoc_account_t *account,
                                                    uint8_t **encrypted_key,
                                                    size_t *encrypted_key_len) {
    if (!account || !encrypted_key || !encrypted_key_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    *encrypted_key = NULL;
    *encrypted_key_len = 0;
    if (!account->encrypted_key) {
        return NEOC_SUCCESS;
    }
    size_t len = account->encrypted_key_len;
    uint8_t *copy = neoc_malloc(len + 1);
    if (!copy) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate encrypted key copy");
    }
    memcpy(copy, account->encrypted_key, len);
    copy[len] = '\0';
    *encrypted_key = copy;
    *encrypted_key_len = len;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_set_encrypted_private_key(neoc_account_t *account,
                                                    const uint8_t *encrypted_key,
                                                    size_t encrypted_key_len) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid account");
    }
    if (!encrypted_key || encrypted_key_len == 0) {
        neoc_account_clear_encrypted_key(account);
        return NEOC_SUCCESS;
    }
    char *buffer = neoc_malloc(encrypted_key_len + 1);
    if (!buffer) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate encrypted key");
    }
    memcpy(buffer, encrypted_key, encrypted_key_len);
    buffer[encrypted_key_len] = '\0';
    neoc_account_clear_encrypted_key(account);
    account->encrypted_key = (uint8_t *)buffer;
    account->encrypted_key_len = encrypted_key_len;
    return NEOC_SUCCESS;
}

static void neoc_scrypt_to_nep2(const neoc_scrypt_params_t *scrypt,
                                neoc_nep2_params_t *out_params,
                                const neoc_nep2_params_t **result) {
    if (!scrypt) {
        *result = NULL;
        return;
    }
    out_params->n = scrypt->n;
    out_params->r = scrypt->r;
    out_params->p = scrypt->p;
    *result = out_params;
}

neoc_error_t neoc_account_encrypt_private_key_with_params(neoc_account_t *account,
                                                          const char *password,
                                                          const neoc_scrypt_params_t *params) {
    if (!account || !password) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "encrypt_private_key: invalid arguments");
    }
    if (!account->key_pair) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "encrypt_private_key: account has no key pair");
    }

    uint8_t private_key[32];
    size_t private_key_len = sizeof(private_key);
    neoc_error_t err = neoc_ec_key_pair_get_private_key(account->key_pair, private_key, &private_key_len);
    if (err != NEOC_SUCCESS) {
        neoc_secure_memzero(private_key, sizeof(private_key));
        return err;
    }

    neoc_nep2_params_t nep2_local;
    const neoc_nep2_params_t *nep2_params = NULL;
    neoc_scrypt_to_nep2(params, &nep2_local, &nep2_params);

    char encrypted_key[128];
    err = neoc_nep2_encrypt(private_key, password, nep2_params, encrypted_key, sizeof(encrypted_key));
    neoc_secure_memzero(private_key, sizeof(private_key));
    if (err != NEOC_SUCCESS) {
        return err;
    }

    err = neoc_account_store_encrypted_key(account, encrypted_key);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    account->is_locked = true;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_decrypt_private_key_with_params(neoc_account_t *account,
                                                          const char *password,
                                                          const neoc_scrypt_params_t *params) {
    if (!account || !password) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "decrypt_private_key: invalid arguments");
    }
    const char *encrypted_key = (const char *)account->encrypted_key;
    if (!encrypted_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "decrypt_private_key: no encrypted key available");
    }

    uint8_t private_key[32];
    neoc_nep2_params_t nep2_local;
    const neoc_nep2_params_t *nep2_params = NULL;
    neoc_scrypt_to_nep2(params, &nep2_local, &nep2_params);

    neoc_error_t err = neoc_nep2_decrypt(encrypted_key, password, nep2_params, private_key, sizeof(private_key));
    if (err != NEOC_SUCCESS) {
        neoc_secure_memzero(private_key, sizeof(private_key));
        return err;
    }

    neoc_ec_key_pair_t *key_pair = NULL;
    err = neoc_ec_key_pair_create_from_private_key(private_key, &key_pair);
    neoc_secure_memzero(private_key, sizeof(private_key));
    if (err != NEOC_SUCCESS) {
        return err;
    }

    if (account->key_pair) {
        neoc_ec_key_pair_free(account->key_pair);
    }
    account->key_pair = key_pair;
    account->is_locked = false;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_account_encrypt(neoc_account_t *account, const char *password) {
    return neoc_account_encrypt_private_key_with_params(account, password, NULL);
}

neoc_error_t neoc_account_decrypt(neoc_account_t *account, const char *password) {
    return neoc_account_decrypt_private_key_with_params(account, password, NULL);
}

bool neoc_account_is_locked_value(const neoc_account_t *account) {
    return account ? account->is_locked : false;
}

neoc_error_t neoc_account_is_locked_out(const neoc_account_t *account, bool *is_locked) {
    if (!account || !is_locked) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    *is_locked = account->is_locked;
    return NEOC_SUCCESS;
}


void neoc_account_free(neoc_account_t *account) {
    if (!account) return;
    
    if (account->key_pair) {
        neoc_ec_key_pair_free(account->key_pair);
    }
    
    if (account->address) {
        neoc_free(account->address);
    }
    
    if (account->label) {
        neoc_free(account->label);
    }
    
    neoc_account_clear_encrypted_key(account);

    // Free verification script
    if (account->verification_script) {
        neoc_free(account->verification_script);
    }

    // Free multi-sig data if present
    if (account->extra) {
        switch (account->extra_type) {
            case NEOC_ACCOUNT_EXTRA_MULTISIG:
                neoc_multi_sig_free((neoc_multi_sig_account_t *)account->extra);
                break;
            case NEOC_ACCOUNT_EXTRA_MULTISIG_INFO:
            default:
                neoc_free(account->extra);
                break;
        }
    }
    
    neoc_free(account);
}
