/**
 * @file neo_constants.c
 * @brief NEO blockchain constants implementation
 */

#include "neoc/neo_constants.h"
#include "neoc/types/neoc_hash160.h"

// Version information
const char* const NEO_VERSION = "3.9.1";
const char* const NEO_VERSION_STRING = "NEO v3.9.1";

// NEO N3 blockchain constants - these are runtime values, not macros

// Native token hashes are defined in contract modules (`neoc_token.c`, `gas_token.c`).

const uint8_t POLICY_CONTRACT_SCRIPT_HASH[20] = {
    0xcc, 0x5e, 0x40, 0x09, 0xd8, 0x22, 0xc3, 0x05,
    0x50, 0xe9, 0xf2, 0x02, 0x3e, 0x45, 0xcf, 0xb8,
    0x8d, 0xa5, 0x8c, 0x7c
};

const uint8_t ROLE_MANAGEMENT_SCRIPT_HASH[20] = {
    0x59, 0x7c, 0x32, 0x9e, 0x08, 0x71, 0x50, 0x48,
    0xe1, 0x6f, 0xa8, 0x7b, 0x36, 0x33, 0xf5, 0x31,
    0x27, 0x74, 0xd8, 0x49
};

const uint8_t ORACLE_CONTRACT_SCRIPT_HASH[20] = {
    0x88, 0xc8, 0x7c, 0xeb, 0xfa, 0x51, 0x81, 0xa5,
    0xeb, 0x78, 0x4f, 0xa5, 0x85, 0x09, 0xe9, 0xf1,
    0xbc, 0x1f, 0x71, 0x54
};

const uint8_t LEDGER_CONTRACT_SCRIPT_HASH[20] = {
    0xda, 0x65, 0xda, 0xc1, 0xaa, 0xce, 0x1a, 0xb6,
    0x9f, 0xac, 0x0f, 0x78, 0xab, 0x8e, 0x9e, 0xd9,
    0x9c, 0xbe, 0x6e, 0xfc
};

const uint8_t MANAGEMENT_CONTRACT_SCRIPT_HASH[20] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff
};

const uint8_t CRYPTO_LIB_SCRIPT_HASH[20] = {
    0x72, 0x60, 0x14, 0x14, 0x2b, 0xa1, 0x9e, 0x8e,
    0xd0, 0x11, 0x87, 0xb2, 0x26, 0xfd, 0xb0, 0x71,
    0x14, 0xdb, 0xc5, 0x51
};

const uint8_t STD_LIB_SCRIPT_HASH[20] = {
    0xac, 0xce, 0x6f, 0xd8, 0x0e, 0xfe, 0x6d, 0x2d,
    0xfa, 0xa2, 0x90, 0x1c, 0x1b, 0x9c, 0x4c, 0xd6,
    0x8e, 0xb9, 0xe3, 0x5f
};

// Economic model parameters
const uint64_t TOTAL_NEO_SUPPLY = 100000000;  // 100 million NEO
const uint64_t TOTAL_GAS_SUPPLY = 5219090400000000;  // Total GAS to be generated
const uint32_t GENERATION_AMOUNT[8] = {8, 7, 6, 5, 4, 3, 2, 1};
const uint32_t DECREASING_INTERVAL = 2000000;  // Blocks

// Default network fees
const uint64_t DEFAULT_SYSTEM_FEE = 0;
const uint64_t DEFAULT_NETWORK_FEE = 0;
const uint32_t FEE_PER_BYTE = 1000;  // 0.00001 GAS per byte
const uint32_t EXEC_FEE_FACTOR = 30;
const uint32_t STORAGE_PRICE = 100000;  // 0.001 GAS per byte

// Script verification limits
const uint32_t NEO_MAX_STACK_SIZE = 2048;
const uint32_t NEO_MAX_ITEM_SIZE = 1048576;  // 1 MB
const uint32_t NEO_MAX_INVOCATION_STACK_SIZE = 1024;
const uint32_t NEO_MAX_TRY_CATCH_DEPTH = 16;

// Address prefixes
const uint8_t NEO_ADDRESS_VERSION_MAINNET = 0x35;  // Mainnet 'N' prefix
const uint8_t NEO_ADDRESS_VERSION_TESTNET = 0x19;  // Testnet 'T' prefix

// Block time and limits
const uint32_t NEO_MILLISECONDS_PER_BLOCK = 15000;  // 15 seconds
const uint32_t NEO_MAX_TRANSACTIONS_PER_BLOCK = 512;
const uint32_t NEO_MAX_BLOCK_SIZE = 2097152;  // 2 MB
const uint64_t NEO_MAX_BLOCK_SYSTEM_FEE = 900000000000ULL;  // 9000 GAS

// Contract deployment costs
const uint64_t CONTRACT_DEPLOY_MIN_FEE = 1000000000;  // 10 GAS minimum
const uint32_t CONTRACT_DEPLOY_FEE_PER_BYTE = 100000;  // 0.001 GAS per byte

// Oracle service
const uint64_t ORACLE_REQUEST_FEE = 50000000;  // 0.5 GAS per request
const uint32_t ORACLE_RESPONSE_MAX_SIZE = 65536;  // 64 KB
const uint32_t ORACLE_FILTER_MAX_SIZE = 128;
const uint32_t ORACLE_MAX_URL_LENGTH = 256;

// NEP standards versions
const char* const NEP11_VERSION = "1.0";
const char* const NEP17_VERSION = "1.0";
const char* const NEP24_VERSION = "1.0";

// Network magic numbers
const uint32_t MAINNET_MAGIC = 0x334F454E;  // N3 mainnet: 860833102
const uint32_t TESTNET_MAGIC = 0x334F4554;  // N3 testnet: 894710606

// Cryptographic curve management (matches Swift SECP256R1_DOMAIN)
static int current_curve_type = NEOC_DEFAULT_CURVE_TYPE;
static int curve_initialized = 0;

// SECP256R1 half curve order (matches Swift SECP256R1_HALF_CURVE_ORDER)
static const uint8_t SECP256R1_HALF_CURVE_ORDER[32] = {
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};

void neoc_init_secp256r1_domain(void) {
    if (!curve_initialized) {
        // Initialize OpenSSL and curve parameters
        curve_initialized = 1;
        current_curve_type = NEOC_DEFAULT_CURVE_TYPE;
    }
}

void neoc_cleanup_secp256r1_domain(void) {
    curve_initialized = 0;
}

void neoc_set_curve_for_tests(int curve_type) {
    // Function matches Swift startUsingCurveForTests
    current_curve_type = curve_type;
}

void neoc_reset_curve_from_tests(void) {
    // Function matches Swift stopUsingOtherCurveForTests
    current_curve_type = NEOC_DEFAULT_CURVE_TYPE;
}

const uint8_t* neoc_get_secp256r1_half_curve_order(void) {
    return SECP256R1_HALF_CURVE_ORDER;
}

size_t neoc_get_secp256r1_half_curve_order_size(void) {
    return sizeof(SECP256R1_HALF_CURVE_ORDER);
}
