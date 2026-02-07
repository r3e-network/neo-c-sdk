/**
 * @file neoc.c
 * @brief Main implementation file for NeoC SDK
 */

#include "neoc/neoc.h"
#include "neoc/crypto/neoc_hash.h"
#include <string.h>
#include <stdatomic.h>

/* Version information */
#define NEOC_VERSION_MAJOR 1
#define NEOC_VERSION_MINOR 2
#define NEOC_VERSION_PATCH 0

/* Build information */
static const char* version_string = "1.2.0";
static const char* build_info = "NeoC SDK v1.2.0 - Neo N3 v3.9.1 compatible";

/* Global state tracking */
static atomic_bool neoc_is_initialized = ATOMIC_VAR_INIT(false);

neoc_error_t neoc_init(void) {
    /* Initialize crypto subsystem */
    neoc_error_t result = neoc_crypto_init();
    if (result != NEOC_SUCCESS) {
        return result;
    }
    
    atomic_store(&neoc_is_initialized, true);
    return NEOC_SUCCESS;
}

void neoc_cleanup(void) {
    if (!atomic_exchange(&neoc_is_initialized, false)) {
        return;
    }
    
    /* Cleanup crypto subsystem */
    neoc_crypto_cleanup();
}

const char* neoc_get_version(void) {
    return version_string;
}

const char* neoc_get_build_info(void) {
    return build_info;
}
