/**
 * @file neoc_uri.c
 * @brief NEO URI scheme implementation
 */

#include "neoc/contract/neoc_uri.h"
#include "neoc/neoc_memory.h"
#include "neoc/neoc_error.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

struct neoc_neo_uri {
    char *address;
    char *asset;
    uint64_t amount;
    char *description;
};

neoc_error_t neoc_neo_uri_parse(const char *uri, neoc_neo_uri_t **parsed_uri) {
    if (!uri || !parsed_uri) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Check URI scheme
    if (strncmp(uri, "neo:", 4) != 0) {
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid NEO URI scheme");
    }
    
    *parsed_uri = neoc_calloc(1, sizeof(neoc_neo_uri_t));
    if (!*parsed_uri) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate URI");
    }
    
    const char *ptr = uri + 4;
    
    // Extract address (up to ? or end)
    const char *query = strchr(ptr, '?');
    size_t addr_len = query ? (size_t)(query - ptr) : strlen(ptr);
    
    (*parsed_uri)->address = neoc_calloc(addr_len + 1, 1);
    if (!(*parsed_uri)->address) {
        neoc_neo_uri_free(*parsed_uri);
        *parsed_uri = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate address");
    }
    
    memcpy((*parsed_uri)->address, ptr, addr_len);
    
    // Parse query parameters if present
    if (query) {
        ptr = query + 1;
        
        while (*ptr) {
            // Find parameter name
            const char *eq = strchr(ptr, '=');
            if (!eq) break;
            
            size_t name_len = eq - ptr;
            const char *value = eq + 1;
            const char *amp = strchr(value, '&');
            size_t value_len = amp ? (size_t)(amp - value) : strlen(value);
            
            // Process known parameters
            if (name_len == 5 && strncmp(ptr, "asset", 5) == 0) {
                (*parsed_uri)->asset = neoc_calloc(value_len + 1, 1);
                if ((*parsed_uri)->asset) {
                    memcpy((*parsed_uri)->asset, value, value_len);
                }
            } else if (name_len == 6 && strncmp(ptr, "amount", 6) == 0) {
                char *amount_str = neoc_calloc(value_len + 1, 1);
                if (amount_str) {
                    memcpy(amount_str, value, value_len);
                    (*parsed_uri)->amount = strtoull(amount_str, NULL, 10);
                    neoc_free(amount_str);
                }
            } else if (name_len == 11 && strncmp(ptr, "description", 11) == 0) {
                (*parsed_uri)->description = neoc_calloc(value_len + 1, 1);
                if ((*parsed_uri)->description) {
                    memcpy((*parsed_uri)->description, value, value_len);
                }
            }
            
            ptr = amp ? amp + 1 : value + value_len;
        }
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_neo_uri_build(const char *address,
                                 const char *asset,
                                 uint64_t amount,
                                 const char *description,
                                 char **uri) {
    if (!address || !uri) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Calculate required size
    size_t size = strlen("neo:") + strlen(address) + 1;
    
    if (asset || amount || description) {
        size += 1;  // '?'
        if (asset) {
            size += strlen("asset=") + strlen(asset) + 1;
        }
        if (amount > 0) {
            size += strlen("amount=") + 20 + 1;  // Max uint64 digits
        }
        if (description) {
            size += strlen("description=") + strlen(description) + 1;
        }
    }
    
    *uri = neoc_calloc(size, 1);
    if (!*uri) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate URI");
    }
    
    // Build URI
    strcpy(*uri, "neo:");
    strcat(*uri, address);
    
    bool first = true;
    if (asset || amount || description) {
        strcat(*uri, "?");
        
        if (asset) {
            if (!first) strcat(*uri, "&");
            strcat(*uri, "asset=");
            strcat(*uri, asset);
            first = false;
        }
        
        if (amount > 0) {
            if (!first) strcat(*uri, "&");
            char amount_str[32];
            snprintf(amount_str, sizeof(amount_str), "amount=%" PRIu64, (uint64_t)amount);
            strcat(*uri, amount_str);
            first = false;
        }
        
        if (description) {
            if (!first) strcat(*uri, "&");
            strcat(*uri, "description=");
            strcat(*uri, description);
        }
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_neo_uri_get_address(const neoc_neo_uri_t *uri, char **address) {
    if (!uri || !address) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (uri->address) {
        *address = neoc_strdup(uri->address);
        if (!*address) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to duplicate address");
        }
    } else {
        *address = NULL;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_neo_uri_get_asset(const neoc_neo_uri_t *uri, char **asset) {
    if (!uri || !asset) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (uri->asset) {
        *asset = neoc_strdup(uri->asset);
        if (!*asset) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to duplicate asset");
        }
    } else {
        *asset = NULL;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_neo_uri_get_amount(const neoc_neo_uri_t *uri, uint64_t *amount) {
    if (!uri || !amount) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *amount = uri->amount;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_neo_uri_get_description(const neoc_neo_uri_t *uri, char **description) {
    if (!uri || !description) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (uri->description) {
        *description = neoc_strdup(uri->description);
        if (!*description) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to duplicate description");
        }
    } else {
        *description = NULL;
    }
    
    return NEOC_SUCCESS;
}

void neoc_neo_uri_free(neoc_neo_uri_t *uri) {
    if (!uri) return;
    
    neoc_free(uri->address);
    neoc_free(uri->asset);
    neoc_free(uri->description);
    neoc_free(uri);
}
