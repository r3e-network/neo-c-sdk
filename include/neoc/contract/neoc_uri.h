/**
 * @file neoc_uri.h
 * @brief NEO URI scheme interface
 */

#ifndef NEOC_NEO_URI_H
#define NEOC_NEO_URI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * NEO URI structure (opaque)
 */
typedef struct neoc_neo_uri neoc_neo_uri_t;

/**
 * Parse a NEO URI string
 */
neoc_error_t neoc_neo_uri_parse(const char *uri, neoc_neo_uri_t **parsed_uri);

/**
 * Build a NEO URI string
 */
neoc_error_t neoc_neo_uri_build(const char *address,
                                 const char *asset,
                                 uint64_t amount,
                                 const char *description,
                                 char **uri);

/**
 * Get address from URI
 */
neoc_error_t neoc_neo_uri_get_address(const neoc_neo_uri_t *uri, char **address);

/**
 * Get asset from URI
 */
neoc_error_t neoc_neo_uri_get_asset(const neoc_neo_uri_t *uri, char **asset);

/**
 * Get amount from URI
 */
neoc_error_t neoc_neo_uri_get_amount(const neoc_neo_uri_t *uri, uint64_t *amount);

/**
 * Get description from URI
 */
neoc_error_t neoc_neo_uri_get_description(const neoc_neo_uri_t *uri, char **description);

/**
 * Free NEO URI
 */
void neoc_neo_uri_free(neoc_neo_uri_t *uri);

#ifdef __cplusplus
}
#endif

#endif // NEOC_NEO_URI_H
