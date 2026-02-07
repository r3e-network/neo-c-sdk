#include "neoc/wallet/wallet.h"
#include "neoc/wallet/nep6.h"
#include "neoc/types/neoc_hash160.h"
#include "neoc/neoc_memory.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define INITIAL_ACCOUNT_CAPACITY 10

neoc_error_t neoc_wallet_create(const char *name, neoc_wallet_t **wallet) {
    if (!wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid wallet pointer");
    }
    
    *wallet = neoc_calloc(1, sizeof(neoc_wallet_t));
    if (!*wallet) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate wallet");
    }
    
    // Set wallet name
    if (name) {
        (*wallet)->name = neoc_strdup(name);
        if (!(*wallet)->name) {
            neoc_free(*wallet);
            *wallet = NULL;
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate wallet name");
        }
    } else {
        (*wallet)->name = neoc_strdup("NeoC Wallet");
        if (!(*wallet)->name) {
            neoc_free(*wallet);
            *wallet = NULL;
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate wallet name");
        }
    }
    
    // Set version
    (*wallet)->version = neoc_strdup("1.0");
    if (!(*wallet)->version) {
        neoc_free((*wallet)->name);
        neoc_free(*wallet);
        *wallet = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate version");
    }
    
    // Allocate initial account array
    (*wallet)->accounts = neoc_calloc(INITIAL_ACCOUNT_CAPACITY, sizeof(neoc_account_t*));
    if (!(*wallet)->accounts) {
        neoc_free((*wallet)->version);
        neoc_free((*wallet)->name);
        neoc_free(*wallet);
        *wallet = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate account array");
    }
    
    (*wallet)->account_capacity = INITIAL_ACCOUNT_CAPACITY;
    (*wallet)->account_count = 0;
    (*wallet)->default_account = NULL;
    
    return NEOC_SUCCESS;
}

const char* neoc_wallet_get_name_ptr(const neoc_wallet_t *wallet) {
    return wallet ? wallet->name : NULL;
}

neoc_error_t neoc_wallet_get_name_copy(const neoc_wallet_t *wallet, char **name_out) {
    if (!name_out) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_get_name: invalid output pointer");
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

neoc_error_t neoc_wallet_add_account(neoc_wallet_t *wallet, neoc_account_t *account) {
    if (!wallet || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Check if account already exists
    for (size_t i = 0; i < wallet->account_count; i++) {
        if (strcmp(wallet->accounts[i]->address, account->address) == 0) {
            return neoc_error_set(NEOC_ERROR_INVALID_STATE, "Account already exists in wallet");
        }
    }
    
    // Resize array if needed
    if (wallet->account_count >= wallet->account_capacity) {
        size_t new_capacity = wallet->account_capacity * 2;
        neoc_account_t **new_accounts = neoc_realloc(wallet->accounts,
                                                 new_capacity * sizeof(neoc_account_t*));
        if (!new_accounts) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to resize account array");
        }
        wallet->accounts = new_accounts;
        wallet->account_capacity = new_capacity;
    }
    
    // Add account
    wallet->accounts[wallet->account_count++] = account;
    
    // Set as default if it's the first account
    if (wallet->account_count == 1) {
        wallet->default_account = account;
        account->is_default = true;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_wallet_remove_account(neoc_wallet_t *wallet, const char *address) {
    if (!wallet || !address) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Find account
    size_t index = (size_t)-1;
    for (size_t i = 0; i < wallet->account_count; i++) {
        if (strcmp(wallet->accounts[i]->address, address) == 0) {
            index = i;
            break;
        }
    }
    
    if (index == (size_t)-1) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Account not found");
    }
    
    neoc_account_t *account = wallet->accounts[index];
    
    // Update default account if needed
    if (account == wallet->default_account) {
        wallet->default_account = NULL;
        if (wallet->account_count > 1) {
            // Set another account as default
            wallet->default_account = (index > 0) ? wallet->accounts[0] : wallet->accounts[1];
            wallet->default_account->is_default = true;
        }
    }
    
    // Remove account from array
    for (size_t i = index; i < wallet->account_count - 1; i++) {
        wallet->accounts[i] = wallet->accounts[i + 1];
    }
    wallet->account_count--;
    
    // Free the account
    neoc_account_free(account);
    
    return NEOC_SUCCESS;
}

neoc_account_t* neoc_wallet_get_account_by_address(const neoc_wallet_t *wallet, const char *address) {
    if (!wallet || !address) {
        return NULL;
    }
    
    for (size_t i = 0; i < wallet->account_count; i++) {
        if (strcmp(wallet->accounts[i]->address, address) == 0) {
            return wallet->accounts[i];
        }
    }
    
    return NULL;
}

neoc_account_t* neoc_wallet_get_account_by_index(const neoc_wallet_t *wallet, size_t index) {
    if (!wallet || index >= wallet->account_count) {
        return NULL;
    }
    return wallet->accounts[index];
}

neoc_account_t* neoc_wallet_get_account_by_script_hash(const neoc_wallet_t *wallet,
                                                        const neoc_hash160_t *script_hash) {
    if (!wallet || !script_hash) {
        return NULL;
    }
    
    for (size_t i = 0; i < wallet->account_count; i++) {
        if (memcmp(&wallet->accounts[i]->script_hash, script_hash, sizeof(neoc_hash160_t)) == 0) {
            return wallet->accounts[i];
        }
    }
    
    return NULL;
}

neoc_account_t** neoc_wallet_get_accounts(const neoc_wallet_t *wallet, size_t *count) {
    if (!wallet || !count) {
        if (count) *count = 0;
        return NULL;
    }
    
    *count = wallet->account_count;
    return wallet->accounts;
}

neoc_account_t* neoc_wallet_get_default_account_ptr(const neoc_wallet_t *wallet) {
    return wallet ? wallet->default_account : NULL;
}

neoc_error_t neoc_wallet_get_default_account_out(const neoc_wallet_t *wallet,
                                                  neoc_account_t **account) {
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_get_default_account: invalid output pointer");
    }
    neoc_account_t *result = neoc_wallet_get_default_account_ptr(wallet);
    if (!result) {
        return neoc_error_set(NEOC_ERROR_NOT_FOUND, "No default account");
    }
    *account = result;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_wallet_set_default_account_str(neoc_wallet_t *wallet, const char *address) {
    if (!wallet || !address) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    neoc_account_t *account = neoc_wallet_get_account_by_address(wallet, address);
    if (!account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Account not found");
    }
    
    // Update old default
    if (wallet->default_account) {
        wallet->default_account->is_default = false;
    }
    
    // Set new default
    wallet->default_account = account;
    account->is_default = true;

    return NEOC_SUCCESS;
}

neoc_error_t neoc_wallet_set_default_account_hash(neoc_wallet_t *wallet,
                                                  const neoc_hash160_t *script_hash) {
    if (!wallet || !script_hash) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char address[NEOC_ADDRESS_LENGTH];
    neoc_error_t err = neoc_hash160_to_address(script_hash, address, sizeof(address));
    if (err != NEOC_SUCCESS) {
        return err;
    }
    return neoc_wallet_set_default_account_str(wallet, address);
}

neoc_error_t neoc_wallet_set_default_account_account(neoc_wallet_t *wallet,
                                                     const neoc_account_t *account) {
    if (!wallet || !account) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    const char *address = neoc_account_get_address_ptr(account);
    if (!address) {
        // Attempt to derive address from script hash if available
        char address_buffer[NEOC_ADDRESS_LENGTH];
        neoc_error_t err = neoc_hash160_to_address(neoc_account_get_script_hash_ptr(account),
                                                   address_buffer,
                                                   sizeof(address_buffer));
        if (err != NEOC_SUCCESS) {
            return err;
        }
        return neoc_wallet_set_default_account_str(wallet, address_buffer);
    }

    return neoc_wallet_set_default_account_str(wallet, address);
}

neoc_account_t* neoc_wallet_create_account(neoc_wallet_t *wallet, const char *label) {
    if (!wallet) {
        return NULL;
    }
    
    neoc_account_t *account = NULL;
    neoc_error_t err = neoc_account_create(label, &account);
    if (err != NEOC_SUCCESS) {
        return NULL;
    }
    
    err = neoc_wallet_add_account(wallet, account);
    if (err != NEOC_SUCCESS) {
        neoc_account_free(account);
        return NULL;
    }
    
    return account;
}

neoc_account_t* neoc_wallet_import_from_wif(neoc_wallet_t *wallet,
                                             const char *wif,
                                             const char *label) {
    if (!wallet || !wif) {
        return NULL;
    }
    
    neoc_account_t *account = NULL;
    neoc_error_t err = neoc_account_create_from_wif(label, wif, &account);
    if (err != NEOC_SUCCESS) {
        return NULL;
    }
    
    err = neoc_wallet_add_account(wallet, account);
    if (err != NEOC_SUCCESS) {
        neoc_account_free(account);
        return NULL;
    }
    
    return account;
}

neoc_account_t* neoc_wallet_import_from_nep2(neoc_wallet_t *wallet,
                                              const char *nep2,
                                              const char *passphrase,
                                              const char *label) {
    if (!wallet || !nep2 || !passphrase) {
        return NULL;
    }
    
    neoc_account_t *account = NULL;
    neoc_error_t err = neoc_account_create_from_nep2(label, nep2, passphrase, &account);
    if (err != NEOC_SUCCESS) {
        return NULL;
    }
    
    err = neoc_wallet_add_account(wallet, account);
    if (err != NEOC_SUCCESS) {
        neoc_account_free(account);
        return NULL;
    }
    
    return account;
}

bool neoc_wallet_contains(const neoc_wallet_t *wallet, const char *address) {
    return neoc_wallet_get_account_by_address(wallet, address) != NULL;
}

size_t neoc_wallet_get_account_count_value(const neoc_wallet_t *wallet) {
    return wallet ? wallet->account_count : 0;
}

neoc_error_t neoc_wallet_get_account_count_out(const neoc_wallet_t *wallet, size_t *count_out) {
    if (!count_out) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_get_account_count: invalid output pointer");
    }
    *count_out = neoc_wallet_get_account_count_value(wallet);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_wallet_lock_all(neoc_wallet_t *wallet, const char *passphrase) {
    (void)passphrase; // Note: passphrase not used in current lock implementation
    if (!wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    for (size_t i = 0; i < wallet->account_count; i++) {
        neoc_error_t err = neoc_account_lock(wallet->accounts[i]);
        if (err != NEOC_SUCCESS) {
            return err;
        }
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_wallet_unlock_all(neoc_wallet_t *wallet, const char *passphrase) {
    (void)passphrase; // Note: passphrase not used in current unlock implementation
    if (!wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    for (size_t i = 0; i < wallet->account_count; i++) {
        neoc_error_t err = neoc_account_unlock(wallet->accounts[i]);
        if (err != NEOC_SUCCESS) {
            return err;
        }
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_wallet_to_nep6(const neoc_wallet_t *wallet, neoc_nep6_wallet_t **nep6_wallet) {
    if (!wallet || !nep6_wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_to_nep6: invalid arguments");
    }

    const char *name = wallet->name ? wallet->name : "NeoC Wallet";
    const char *version = wallet->version ? wallet->version : "1.0";

    neoc_error_t err = neoc_nep6_wallet_create(name, version, nep6_wallet);
    if (err != NEOC_SUCCESS) {
        *nep6_wallet = NULL;
        return err;
    }

    if (wallet->version) {
        (void)neoc_nep6_wallet_set_version(*nep6_wallet, wallet->version);
    }

    for (size_t i = 0; i < wallet->account_count; i++) {
        neoc_account_t *account = wallet->accounts[i];
        if (!account) {
            continue;
        }

        neoc_nep6_account_t *nep6_account = NULL;
        err = neoc_account_to_nep6(account, &nep6_account);
        if (err != NEOC_SUCCESS) {
            neoc_nep6_wallet_free(*nep6_wallet);
            *nep6_wallet = NULL;
            return err;
        }

        err = neoc_nep6_wallet_add_account(*nep6_wallet, nep6_account);
        if (err != NEOC_SUCCESS) {
            neoc_nep6_account_free(nep6_account);
            neoc_nep6_wallet_free(*nep6_wallet);
            *nep6_wallet = NULL;
            return err;
        }
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_wallet_from_nep6(const neoc_nep6_wallet_t *nep6_wallet, neoc_wallet_t **wallet) {
    if (!nep6_wallet || !wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "wallet_from_nep6: invalid arguments");
    }

    const char *name = neoc_nep6_wallet_get_name(nep6_wallet);
    neoc_error_t err = neoc_wallet_create(name, wallet);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    char *version_copy = NULL;
    err = neoc_nep6_wallet_get_version(nep6_wallet, &version_copy);
    if (err == NEOC_SUCCESS && version_copy) {
        neoc_free((*wallet)->version);
        (*wallet)->version = version_copy;
    }

    size_t account_count = neoc_nep6_wallet_get_account_count(nep6_wallet);
    for (size_t i = 0; i < account_count; i++) {
        const neoc_nep6_account_t *nep6_account = neoc_nep6_wallet_get_account(nep6_wallet, i);
        if (!nep6_account) {
            continue;
        }

        neoc_account_t *account = NULL;
        err = neoc_account_from_nep6(nep6_account, &account);
        if (err != NEOC_SUCCESS) {
            neoc_wallet_free(*wallet);
            *wallet = NULL;
            return err;
        }

        err = neoc_wallet_add_account(*wallet, account);
        if (err != NEOC_SUCCESS) {
            neoc_account_free(account);
            neoc_wallet_free(*wallet);
            *wallet = NULL;
            return err;
        }

        if (account->is_default) {
            (void)neoc_wallet_set_default_account_account(*wallet, account);
        }
    }

    return NEOC_SUCCESS;
}

neoc_error_t neoc_wallet_load(const char *path, neoc_wallet_t **wallet) {
    if (!path || !wallet) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Read file contents
    FILE *file = fopen(path, "r");
    if (!file) {
        return neoc_error_set(NEOC_ERROR_IO, "Cannot open wallet file");
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (size <= 0) {
        fclose(file);
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Empty wallet file");
    }
    
    // Allocate buffer and read file
    char *buffer = neoc_malloc(size + 1);
    if (!buffer) {
        fclose(file);
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Cannot allocate file buffer");
    }
    
    size_t read_bytes = fread(buffer, 1, size, file);
    fclose(file);
    buffer[read_bytes] = '\0';
    
    // Try to load as NEP-6 wallet
    neoc_nep6_wallet_t *nep6_wallet;
    neoc_error_t err = neoc_nep6_wallet_from_json(buffer, &nep6_wallet);
    
    neoc_free(buffer);
    
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Convert NEP-6 wallet to generic wallet
    err = neoc_wallet_from_nep6(nep6_wallet, wallet);
    neoc_nep6_wallet_free(nep6_wallet);
    return err;
}

neoc_error_t neoc_wallet_save(const neoc_wallet_t *wallet, const char *path) {
    if (!wallet || !path) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Create NEP-6 wallet from generic wallet
    neoc_nep6_wallet_t *nep6_wallet = NULL;
    neoc_error_t err = neoc_wallet_to_nep6(wallet, &nep6_wallet);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Convert to JSON
    char *json_str;
    size_t json_len = 0;
    err = neoc_nep6_wallet_to_json(nep6_wallet, &json_str, &json_len);
    neoc_nep6_wallet_free(nep6_wallet);
    
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Write to file
    FILE *file = fopen(path, "w");
    if (!file) {
        neoc_free(json_str);
        return neoc_error_set(NEOC_ERROR_IO, "Cannot create wallet file");
    }
    
    json_len = strlen(json_str);
    size_t written = fwrite(json_str, 1, json_len, file);
    fclose(file);
    neoc_free(json_str);
    
    if (written != json_len) {
        return neoc_error_set(NEOC_ERROR_IO, "Failed to write complete wallet file");
    }
    
    return NEOC_SUCCESS;
}

void neoc_wallet_free(neoc_wallet_t *wallet) {
    if (!wallet) return;
    
    // Free all accounts
    for (size_t i = 0; i < wallet->account_count; i++) {
        neoc_account_free(wallet->accounts[i]);
    }
    neoc_free(wallet->accounts);
    
    // Free wallet fields
    if (wallet->name) {
        neoc_free(wallet->name);
    }
    
    if (wallet->version) {
        neoc_free(wallet->version);
    }
    
    if (wallet->extra) {
        neoc_free(wallet->extra);
    }
    
    neoc_free(wallet);
}
