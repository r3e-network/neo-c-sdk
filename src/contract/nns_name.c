/**
 * @file nns_name.c
 * @brief NNS Name record implementation
 */

#include "neoc/contract/nns_name.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>
#include <time.h>

struct neoc_nns_name {
    char *name;
    neoc_hash160_t owner;
    uint64_t expiration;
    bool is_root;
};

neoc_error_t neoc_nns_name_create(const char *name,
                                   const neoc_hash160_t *owner,
                                   uint64_t expiration,
                                   neoc_nns_name_t **nns_name) {
    if (!name || !owner || !nns_name) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *nns_name = neoc_calloc(1, sizeof(neoc_nns_name_t));
    if (!*nns_name) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate NNS name");
    }
    
    (*nns_name)->name = neoc_strdup(name);
    if (!(*nns_name)->name) {
        neoc_free(*nns_name);
        *nns_name = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate name");
    }
    
    memcpy(&(*nns_name)->owner, owner, sizeof(neoc_hash160_t));
    (*nns_name)->expiration = expiration;
    
    // Check if root domain (no dots)
    (*nns_name)->is_root = (strchr(name, '.') == NULL);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_name_get_name(const neoc_nns_name_t *nns_name, char **name) {
    if (!nns_name || !name) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *name = neoc_strdup(nns_name->name);
    if (!*name) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to duplicate name");
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_name_get_owner(const neoc_nns_name_t *nns_name,
                                      neoc_hash160_t *owner) {
    if (!nns_name || !owner) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    memcpy(owner, &nns_name->owner, sizeof(neoc_hash160_t));
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_name_get_expiration(const neoc_nns_name_t *nns_name,
                                           uint64_t *expiration) {
    if (!nns_name || !expiration) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *expiration = nns_name->expiration;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_name_is_expired(const neoc_nns_name_t *nns_name, bool *expired) {
    if (!nns_name || !expired) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint64_t current_time = (uint64_t)time(NULL) * 1000;  // Convert to milliseconds
    *expired = (current_time > nns_name->expiration);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_name_is_root(const neoc_nns_name_t *nns_name, bool *is_root) {
    if (!nns_name || !is_root) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *is_root = nns_name->is_root;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_nns_name_get_parent(const neoc_nns_name_t *nns_name, char **parent) {
    if (!nns_name || !parent) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (nns_name->is_root) {
        *parent = NULL;
        return NEOC_SUCCESS;
    }
    
    // Find last dot
    const char *last_dot = strrchr(nns_name->name, '.');
    if (!last_dot || last_dot == nns_name->name) {
        *parent = NULL;
        return NEOC_SUCCESS;
    }
    
    // Extract parent domain
    size_t parent_len = last_dot - nns_name->name;
    *parent = neoc_calloc(parent_len + 1, 1);
    if (!*parent) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate parent");
    }
    
    memcpy(*parent, nns_name->name, parent_len);
    return NEOC_SUCCESS;
}

void neoc_nns_name_free(neoc_nns_name_t *nns_name) {
    if (!nns_name) return;
    
    neoc_free(nns_name->name);
    neoc_free(nns_name);
}
