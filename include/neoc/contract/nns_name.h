/**
 * @file nns_name.h
 * @brief NNS Name record interface
 */

#ifndef NEOC_NNS_NAME_H
#define NEOC_NNS_NAME_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/types/neoc_hash160.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * NNS Name structure (opaque)
 */
typedef struct neoc_nns_name neoc_nns_name_t;

/**
 * Create a new NNS name record
 */
neoc_error_t neoc_nns_name_create(const char *name,
                                   const neoc_hash160_t *owner,
                                   uint64_t expiration,
                                   neoc_nns_name_t **nns_name);

/**
 * Get name
 */
neoc_error_t neoc_nns_name_get_name(const neoc_nns_name_t *nns_name,
                                     char **name);

/**
 * Get owner
 */
neoc_error_t neoc_nns_name_get_owner(const neoc_nns_name_t *nns_name,
                                      neoc_hash160_t *owner);

/**
 * Get expiration
 */
neoc_error_t neoc_nns_name_get_expiration(const neoc_nns_name_t *nns_name,
                                           uint64_t *expiration);

/**
 * Check if expired
 */
neoc_error_t neoc_nns_name_is_expired(const neoc_nns_name_t *nns_name,
                                       bool *expired);

/**
 * Check if this name represents a root domain (no dots)
 */
neoc_error_t neoc_nns_name_is_root(const neoc_nns_name_t *nns_name,
                                    bool *is_root);

/**
 * Get the parent domain for a subdomain (NULL for roots)
 */
neoc_error_t neoc_nns_name_get_parent(const neoc_nns_name_t *nns_name,
                                       char **parent);

/**
 * Free NNS name
 */
void neoc_nns_name_free(neoc_nns_name_t *nns_name);

#ifdef __cplusplus
}
#endif

#endif // NEOC_NNS_NAME_H
