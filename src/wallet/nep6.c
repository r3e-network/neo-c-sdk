#define NEOC_NEP6_DISABLE_OVERLOADS

#ifdef HAVE_CJSON
#include <cjson/cJSON.h>
#endif

/**
 * @file nep6.c
 * @brief NEP-6 wallet file format implementation
 */

#include "neoc/wallet/nep6.h"
#include "neoc/crypto/nep2.h"
#include "neoc/crypto/ec_key_pair.h"
#include "neoc/utils/neoc_base58.h"
#include "neoc/neoc_memory.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// NEP-6 wallet structure
struct neoc_nep6_wallet_t {
    char *name;
    char *version;
    neoc_nep6_scrypt_params_t scrypt;
    neoc_nep6_account_t **accounts;
    size_t account_count;
    size_t account_capacity;
    void *extra;  // Extra data
};

neoc_error_t neoc_nep6_wallet_create(const char *name,
                                      const char *version,
                                      neoc_nep6_wallet_t **wallet) {
    if (!wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid wallet pointer");
    }
    
    *wallet = neoc_calloc(1, sizeof(neoc_nep6_wallet_t));
    if (!*wallet) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate wallet");
    }
    
    (*wallet)->name = neoc_strdup(name ? name : "NeoC Wallet");
    (*wallet)->version = neoc_strdup(version ? version : "1.0");
    
    // Set default scrypt parameters
    (*wallet)->scrypt.n = 16384;
    (*wallet)->scrypt.r = 8;
    (*wallet)->scrypt.p = 8;
    
    // Initialize account array
    (*wallet)->account_capacity = 10;
    (*wallet)->accounts = neoc_calloc((*wallet)->account_capacity, sizeof(neoc_nep6_account_t*));
    if (!(*wallet)->accounts) {
        neoc_free((*wallet)->name);
        neoc_free((*wallet)->version);
        neoc_free(*wallet);
        *wallet = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate accounts");
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nep6_wallet_add_account(neoc_nep6_wallet_t *wallet,
                                           const uint8_t *private_key,
                                           const char *password,
                                           const char *label,
                                           bool is_default) {
    if (!wallet || !private_key || !password) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Create EC key pair
    neoc_ec_key_pair_t *key_pair = NULL;
    neoc_error_t err = neoc_ec_key_pair_from_private_key(private_key, 32, &key_pair);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Get address
    char *address_ptr = NULL;
    err = neoc_ec_key_pair_get_address(key_pair, &address_ptr);
    if (err != NEOC_SUCCESS || !address_ptr) {
        neoc_ec_key_pair_free(key_pair);
        return err;
    }
    
    char address[64];
    strncpy(address, address_ptr, sizeof(address) - 1);
    address[sizeof(address) - 1] = '\0';
    neoc_free(address_ptr);
    
    // Encrypt private key using NEP-2
    char encrypted_key[64];
    neoc_nep2_params_t nep2_params = {
        .n = wallet->scrypt.n,
        .r = wallet->scrypt.r,
        .p = wallet->scrypt.p
    };
    err = neoc_nep2_encrypt(private_key, password, &nep2_params, encrypted_key, sizeof(encrypted_key));
    if (err != NEOC_SUCCESS) {
        neoc_ec_key_pair_free(key_pair);
        return err;
    }
    
    neoc_nep6_account_t *account = NULL;
    neoc_error_t create_err = neoc_nep6_account_create(address,
                                                       label,
                                                       is_default,
                                                       false,
                                                       encrypted_key,
                                                       NULL,
                                                       &account);
    if (create_err != NEOC_SUCCESS) {
        neoc_ec_key_pair_free(key_pair);
        return create_err;
    }
    
    // Create default contract (single signature)
    // Get public key
    uint8_t public_key[65];
    size_t public_key_len = sizeof(public_key);
    neoc_ec_key_pair_get_public_key(key_pair, public_key, &public_key_len);
    
    // Create verification script (simplified)
    uint8_t script[35];
    script[0] = 0x21; // PUSH21
    memcpy(script + 1, public_key, 33);
    script[34] = 0xAC; // CHECKSIG
    
    // Convert to hex
    char hex_script[71];
    for (int i = 0; i < 35; i++) {
        sprintf(hex_script + i * 2, "%02x", script[i]);
    }

    neoc_nep6_contract_t *contract = NULL;
    neoc_nep6_parameter_t contract_param = {
        .name = "signature",
        .type = NEOC_PARAM_TYPE_SIGNATURE
    };
    neoc_error_t contract_err = neoc_nep6_contract_create(hex_script,
                                                          &contract_param,
                                                          1,
                                                          false,
                                                          &contract);
    if (contract_err == NEOC_SUCCESS) {
        (void)neoc_nep6_account_set_contract(account, contract);
    } else {
        neoc_nep6_account_free(account);
        neoc_ec_key_pair_free(key_pair);
        return contract_err;
    }
    
    neoc_ec_key_pair_free(key_pair);
    
    neoc_error_t add_err = neoc_nep6_wallet_add_account_existing(wallet, account);
    if (add_err != NEOC_SUCCESS) {
        neoc_nep6_account_free(account);
        return add_err;
    }
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nep6_wallet_add_account_existing(neoc_nep6_wallet_t *wallet,
                                                   neoc_nep6_account_t *account) {
    if (!wallet || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_add_account: invalid arguments");
    }

    const char *address = neoc_nep6_account_get_address(account);
    if (!address) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_add_account: account missing address");
    }

    for (size_t i = 0; i < wallet->account_count; ++i) {
        const char *existing_address = neoc_nep6_account_get_address(wallet->accounts[i]);
        if (existing_address && strcmp(existing_address, address) == 0) {
            return neoc_error_set(NEOC_ERROR_INVALID_STATE, "wallet_add_account: account already present");
        }
    }

    if (wallet->account_count >= wallet->account_capacity) {
        size_t new_capacity = wallet->account_capacity ? wallet->account_capacity * 2 : 4;
        neoc_nep6_account_t **new_accounts = neoc_realloc(wallet->accounts,
                                                           new_capacity * sizeof(neoc_nep6_account_t *));
        if (!new_accounts) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "wallet_add_account: resize failed");
        }
        wallet->accounts = new_accounts;
        wallet->account_capacity = new_capacity;
    }

    if (neoc_nep6_account_is_default(account)) {
        for (size_t i = 0; i < wallet->account_count; ++i) {
            (void)neoc_nep6_account_set_default(wallet->accounts[i], false);
        }
    }

    wallet->accounts[wallet->account_count++] = account;
    return NEOC_SUCCESS;
}

const char* neoc_nep6_wallet_get_name_ptr(const neoc_nep6_wallet_t *wallet) {
    return wallet ? wallet->name : NULL;
}

neoc_error_t neoc_nep6_wallet_get_name_copy(const neoc_nep6_wallet_t *wallet, char **name_out) {
    if (!name_out) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_get_name: invalid output");
    }
    if (!wallet || !wallet->name) {
        *name_out = NULL;
        return wallet ? NEOC_SUCCESS : neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_get_name: invalid wallet");
    }
    *name_out = neoc_strdup(wallet->name);
    if (!*name_out) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "wallet_get_name: allocation failed");
    }
    return NEOC_SUCCESS;
}

const char* neoc_nep6_wallet_get_version_ptr(const neoc_nep6_wallet_t *wallet) {
    return wallet ? wallet->version : NULL;
}

neoc_error_t neoc_nep6_wallet_get_version_copy(const neoc_nep6_wallet_t *wallet, char **version_out) {
    if (!version_out) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_get_version: invalid output");
    }
    if (!wallet || !wallet->version) {
        *version_out = NULL;
        return wallet ? NEOC_SUCCESS : neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_get_version: invalid wallet");
    }
    *version_out = neoc_strdup(wallet->version);
    if (!*version_out) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "wallet_get_version: allocation failed");
    }
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nep6_wallet_set_version(neoc_nep6_wallet_t *wallet,
                                           const char *version) {
    if (!wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_set_version: invalid wallet");
    }
    if (wallet->version) {
        neoc_free(wallet->version);
        wallet->version = NULL;
    }
    if (version) {
        wallet->version = neoc_strdup(version);
        if (!wallet->version) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "wallet_set_version: allocation failed");
        }
    }
    return NEOC_SUCCESS;
}

const neoc_nep6_scrypt_params_t* neoc_nep6_wallet_get_scrypt_raw(const neoc_nep6_wallet_t *wallet) {
    return wallet ? &wallet->scrypt : NULL;
}

neoc_scrypt_params_t* neoc_nep6_wallet_get_scrypt_copy(const neoc_nep6_wallet_t *wallet) {
    if (!wallet) {
        return NULL;
    }
    neoc_scrypt_params_t *params = neoc_calloc(1, sizeof(neoc_scrypt_params_t));
    if (!params) {
        return NULL;
    }
    params->n = wallet->scrypt.n;
    params->r = wallet->scrypt.r;
    params->p = wallet->scrypt.p;
    params->dk_len = 64;
    return params;
}

neoc_error_t neoc_nep6_wallet_get_scrypt_out(const neoc_nep6_wallet_t *wallet,
                                             neoc_scrypt_params_t *params_out) {
    if (!wallet || !params_out) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_get_scrypt: invalid arguments");
    }
    params_out->n = wallet->scrypt.n;
    params_out->r = wallet->scrypt.r;
    params_out->p = wallet->scrypt.p;
    if (params_out->dk_len == 0) {
        params_out->dk_len = 64;
    }
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nep6_wallet_set_scrypt(neoc_nep6_wallet_t *wallet,
                                          const neoc_scrypt_params_t *params) {
    if (!wallet || !params) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_set_scrypt: invalid arguments");
    }
    wallet->scrypt.n = params->n;
    wallet->scrypt.r = params->r;
    wallet->scrypt.p = params->p;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nep6_wallet_remove_account(neoc_nep6_wallet_t *wallet,
                                              const char *address) {
    if (!wallet || !address) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    for (size_t i = 0; i < wallet->account_count; i++) {
        if (strcmp(wallet->accounts[i]->address, address) == 0) {
            // Free account
            neoc_nep6_account_free(wallet->accounts[i]);
            
            // Shift remaining accounts
            for (size_t j = i; j < wallet->account_count - 1; j++) {
                wallet->accounts[j] = wallet->accounts[j + 1];
            }
            
            wallet->account_count--;
            return NEOC_SUCCESS;
        }
    }
    
    return neoc_error_set(NEOC_ERROR_NOT_FOUND, "Account not found");
}

neoc_nep6_account_t* neoc_nep6_wallet_get_account_by_address(const neoc_nep6_wallet_t *wallet,
                                                              const char *address) {
    if (!wallet || !address) {
        return NULL;
    }

    for (size_t i = 0; i < wallet->account_count; i++) {
        const char *current_address = neoc_nep6_account_get_address(wallet->accounts[i]);
        if (current_address && strcmp(current_address, address) == 0) {
            return wallet->accounts[i];
        }
    }

    return NULL;
}

neoc_nep6_account_t* neoc_nep6_wallet_find_account_by_address(const neoc_nep6_wallet_t *wallet,
                                                               const char *address) {
    return neoc_nep6_wallet_get_account_by_address(wallet, address);
}

neoc_nep6_account_t* neoc_nep6_wallet_get_default_account_ptr(const neoc_nep6_wallet_t *wallet) {
    if (!wallet) {
        return NULL;
    }

    for (size_t i = 0; i < wallet->account_count; i++) {
        if (neoc_nep6_account_is_default(wallet->accounts[i])) {
            return wallet->accounts[i];
        }
    }

    return wallet->account_count > 0 ? wallet->accounts[0] : NULL;
}

neoc_error_t neoc_nep6_wallet_get_default_account_out(const neoc_nep6_wallet_t *wallet,
                                                       neoc_nep6_account_t **account) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid account pointer");
    }
    neoc_nep6_account_t *result = neoc_nep6_wallet_get_default_account_ptr(wallet);
    if (!result) {
        return neoc_error_set(NEOC_ERROR_NOT_FOUND, "No accounts in wallet");
    }
    *account = result;
    return NEOC_SUCCESS;
}

size_t neoc_nep6_wallet_get_account_count_value(const neoc_nep6_wallet_t *wallet) {
    return wallet ? wallet->account_count : 0;
}

neoc_error_t neoc_nep6_wallet_get_account_count_out(const neoc_nep6_wallet_t *wallet,
                                                     size_t *count_out) {
    if (!count_out) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid count pointer");
    }
    *count_out = neoc_nep6_wallet_get_account_count_value(wallet);
    return NEOC_SUCCESS;
}

neoc_nep6_account_t* neoc_nep6_wallet_get_account_by_index(const neoc_nep6_wallet_t *wallet,
                                                            size_t index) {
    if (!wallet || index >= wallet->account_count) {
        return NULL;
    }
    return wallet->accounts[index];
}

neoc_error_t neoc_nep6_account_decrypt_private_key(const neoc_nep6_account_t *account,
                                                    const char *password,
                                                    uint8_t *private_key,
                                                    size_t private_key_len) {
    if (!account || !password || !private_key) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (private_key_len < 32) {
        return neoc_error_set(NEOC_ERROR_BUFFER_TOO_SMALL, "Buffer too small");
    }
    
    if (!account->key) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "No encrypted key");
    }
    
    // Decrypt using NEP-2
    return neoc_nep2_decrypt(account->key, password, NULL, private_key, private_key_len);
}

void neoc_nep6_wallet_free(neoc_nep6_wallet_t *wallet) {
    if (!wallet) return;
    
    neoc_free(wallet->name);
    neoc_free(wallet->version);
    
    for (size_t i = 0; i < wallet->account_count; i++) {
        neoc_nep6_account_free(wallet->accounts[i]);
    }
    neoc_free(wallet->accounts);
    
    neoc_free(wallet->extra);
    neoc_free(wallet);
}

// Simplified JSON serialization (without external JSON library)
neoc_error_t neoc_nep6_wallet_to_json(const neoc_nep6_wallet_t *wallet,
                                       char **json,
                                       size_t *json_len) {
    if (!wallet || !json || !json_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Estimate size
    size_t estimated_size = 4096 + wallet->account_count * 512;
    char *buffer = neoc_malloc(estimated_size);
    if (!buffer) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate buffer");
    }
    
    // Build JSON manually (simplified)
    int offset = snprintf(buffer, estimated_size,
        "{\n"
        "  \"name\": \"%s\",\n"
        "  \"version\": \"%s\",\n"
        "  \"scrypt\": {\n"
        "    \"n\": %u,\n"
        "    \"r\": %u,\n"
        "    \"p\": %u\n"
        "  },\n"
        "  \"accounts\": [\n",
        wallet->name ? wallet->name : "",
        wallet->version ? wallet->version : "",
        wallet->scrypt.n,
        wallet->scrypt.r,
        wallet->scrypt.p
    );
    
    for (size_t i = 0; i < wallet->account_count; i++) {
        neoc_nep6_account_t *acc = wallet->accounts[i];
        offset += snprintf(buffer + offset, estimated_size - offset,
            "    {\n"
            "      \"address\": \"%s\",\n"
            "      \"label\": %s,\n"
            "      \"isDefault\": %s,\n"
            "      \"lock\": %s,\n"
            "      \"key\": \"%s\",\n"
            "      \"contract\": {\n"
            "        \"script\": \"",
            acc->address ? acc->address : "",
            acc->label ? (char[256]){0} : "null",  // Simplified
            acc->is_default ? "true" : "false",
            acc->lock ? "true" : "false",
            acc->key ? acc->key : ""
        );
        
        if (acc->label) {
            snprintf(buffer + offset - strlen("null,\n"), 256, "\"%s\",\n", acc->label);
        }
        
        offset = strlen(buffer);
        
        // Add the script (empty for now) and parameters
        offset += snprintf(buffer + offset, estimated_size - offset, 
            "\",\n"
            "        \"parameters\": []");
        
        if (acc->contract && acc->contract->is_deployed) {
            offset += snprintf(buffer + offset, estimated_size - offset,
                ",\n"
                "        \"deployed\": true\n"
                "      }\n"
                "    }%s\n",
                i < wallet->account_count - 1 ? "," : ""
            );
        } else {
            offset += snprintf(buffer + offset, estimated_size - offset,
                "],\n"
                "        \"deployed\": false\n"
                "      }\n"
                "    }%s\n",
                i < wallet->account_count - 1 ? "," : ""
            );
        }
    }
    
    offset += snprintf(buffer + offset, estimated_size - offset,
        "  ]\n"
        "}\n"
    );
    
    *json = buffer;
    *json_len = offset;
    
    return NEOC_SUCCESS;
}

// Simplified file I/O
neoc_error_t neoc_nep6_wallet_to_file(const neoc_nep6_wallet_t *wallet,
                                       const char *filename) {
    if (!wallet || !filename) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    char *json = NULL;
    size_t json_len = 0;
    neoc_error_t err = neoc_nep6_wallet_to_json(wallet, &json, &json_len);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    FILE *file = fopen(filename, "w");
    if (!file) {
        neoc_free(json);
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Failed to open file");
    }
    
    size_t written = fwrite(json, 1, json_len, file);
    fclose(file);
    neoc_free(json);
    
    if (written != json_len) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Failed to write file");
    }
    
    return NEOC_SUCCESS;
}

// JSON loading functions (returns NOT_IMPLEMENTED if JSON parser not available)
neoc_error_t neoc_nep6_wallet_from_json(const char *json_str,
                                         neoc_nep6_wallet_t **wallet) {
    if (!json_str || !wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // This would require a JSON parser - simplified stub
    #ifdef HAVE_CJSON
    cJSON *json_obj = cJSON_Parse(json_str);
    if (!json_obj) {
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid JSON");
    }
    
    *wallet = neoc_calloc(1, sizeof(neoc_nep6_wallet_t));
    if (!*wallet) {
        cJSON_Delete(json_obj);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate wallet");
    }
    
    // Parse name
    cJSON *name = cJSON_GetObjectItem(json_obj, "name");
    if (name && cJSON_IsString(name)) {
        (*wallet)->name = neoc_strdup(name->valuestring);
        if (!(*wallet)->name) {
            cJSON_Delete(json_obj);
            neoc_nep6_wallet_free(*wallet);
            *wallet = NULL;
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate wallet name");
        }
    }
    
    // Parse version
    cJSON *version = cJSON_GetObjectItem(json_obj, "version");
    if (version && cJSON_IsString(version)) {
        (*wallet)->version = neoc_strdup(version->valuestring);
        if (!(*wallet)->version) {
            cJSON_Delete(json_obj);
            neoc_nep6_wallet_free(*wallet);
            *wallet = NULL;
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate wallet version");
        }
    }
    
    // Parse scrypt parameters
    cJSON *scrypt = cJSON_GetObjectItem(json_obj, "scrypt");
    if (scrypt) {
        cJSON *n = cJSON_GetObjectItem(scrypt, "n");
        cJSON *r = cJSON_GetObjectItem(scrypt, "r");
        cJSON *p = cJSON_GetObjectItem(scrypt, "p");
        
        if (n) (*wallet)->scrypt.n = n->valueint;
        if (r) (*wallet)->scrypt.r = r->valueint;
        if (p) (*wallet)->scrypt.p = p->valueint;
    }
    
    // Parse accounts
    cJSON *accounts = cJSON_GetObjectItem(json_obj, "accounts");
    if (accounts && cJSON_IsArray(accounts)) {
        (*wallet)->account_count = cJSON_GetArraySize(accounts);
        (*wallet)->accounts = neoc_calloc((*wallet)->account_count, sizeof(neoc_nep6_account_t*));
        if (!(*wallet)->accounts && (*wallet)->account_count > 0) {
            cJSON_Delete(json_obj);
            neoc_nep6_wallet_free(*wallet);
            *wallet = NULL;
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate accounts array");
        }
        
        for (size_t i = 0; i < (*wallet)->account_count; i++) {
            cJSON *account = cJSON_GetArrayItem(accounts, (int)i);
            // Parse each account...
            neoc_nep6_account_t *acc = neoc_calloc(1, sizeof(neoc_nep6_account_t));
            if (!acc) {
                cJSON_Delete(json_obj);
                neoc_nep6_wallet_free(*wallet);
                *wallet = NULL;
                return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account");
            }
            
            cJSON *address = cJSON_GetObjectItem(account, "address");
            if (address && cJSON_IsString(address)) {
                acc->address = neoc_strdup(address->valuestring);
                if (!acc->address) {
                    neoc_nep6_account_free(acc);
                    cJSON_Delete(json_obj);
                    neoc_nep6_wallet_free(*wallet);
                    *wallet = NULL;
                    return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
                }
            }
            
            cJSON *label = cJSON_GetObjectItem(account, "label");
            if (label && cJSON_IsString(label)) {
                acc->label = neoc_strdup(label->valuestring);
                if (!acc->label) {
                    neoc_nep6_account_free(acc);
                    cJSON_Delete(json_obj);
                    neoc_nep6_wallet_free(*wallet);
                    *wallet = NULL;
                    return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate label");
                }
            }
            
            cJSON *isDefault = cJSON_GetObjectItem(account, "isDefault");
            if (isDefault && cJSON_IsBool(isDefault)) {
                acc->is_default = cJSON_IsTrue(isDefault);
            }
            
            cJSON *lock = cJSON_GetObjectItem(account, "lock");
            if (lock && cJSON_IsBool(lock)) {
                acc->lock = cJSON_IsTrue(lock);
            }
            
            cJSON *key = cJSON_GetObjectItem(account, "key");
            if (key && cJSON_IsString(key)) {
                acc->key = neoc_strdup(key->valuestring);
                if (!acc->key) {
                    neoc_nep6_account_free(acc);
                    cJSON_Delete(json_obj);
                    neoc_nep6_wallet_free(*wallet);
                    *wallet = NULL;
                    return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate key");
                }
            }
            
            (*wallet)->accounts[i] = acc;
        }
    }
    
    cJSON_Delete(json_obj);
    return NEOC_SUCCESS;
#else
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif
}

neoc_error_t neoc_nep6_wallet_from_file(const char *filename,
                                         neoc_nep6_wallet_t **wallet) {
    if (!filename || !wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Read file contents
    FILE *file = fopen(filename, "r");
    if (!file) {
        return neoc_error_set(NEOC_ERROR_FILE, "Failed to open wallet file");
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 10485760) { // Max 10MB for wallet file
        fclose(file);
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid wallet file size");
    }
    
    // Read file contents
    char *content = neoc_malloc(file_size + 1);
    if (!content) {
        fclose(file);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate buffer");
    }
    
    size_t read_size = fread(content, 1, file_size, file);
    fclose(file);
    
    if (read_size != (size_t)file_size) {
        neoc_free(content);
        return neoc_error_set(NEOC_ERROR_FILE, "Failed to read wallet file");
    }
    
    content[file_size] = '\0';
    
    // Parse JSON into wallet
    neoc_error_t err = neoc_nep6_wallet_from_json(content, wallet);
    neoc_free(content);
    
    return err;
}
