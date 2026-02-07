/**
 * @file neo_constants.h
 * @brief NEO blockchain constants
 */

#ifndef NEOC_NEO_CONSTANTS_H
#define NEOC_NEO_CONSTANTS_H

#include <stdint.h>
#include <stddef.h>  // For size_t

#ifdef __cplusplus
extern "C" {
#endif

// Network magic numbers
#define NEOC_MAINNET_MAGIC 0x334F454E
#define NEOC_TESTNET_MAGIC 0x334F4554

// Sizes and limits from Swift NeoConstants
#define NEOC_PRIVATE_KEY_SIZE 32
#define NEOC_PUBLIC_KEY_SIZE_COMPRESSED 33
#define NEOC_PUBLIC_KEY_SIZE_UNCOMPRESSED 65
#define NEOC_SIGNATURE_SIZE 64
#define NEOC_HASH160_SIZE 20
#define NEOC_HASH256_SIZE 32
#define NEOC_VERIFICATION_SCRIPT_SIZE 40
#define NEOC_MAX_SCRIPT_SIZE 102400

// Multi-signature limits
#define NEOC_MAX_PUBLIC_KEYS_PER_MULTISIG_ACCOUNT 1024

// Transaction limits
#define NEOC_CURRENT_TX_VERSION 0
#define NEOC_MAX_TRANSACTION_SIZE 102400
#define NEOC_MAX_TRANSACTION_ATTRIBUTES 16
#define NEOC_MAX_WITNESSES 16
#define NEOC_MAX_SIGNERS 16
#define NEOC_MAX_SIGNER_SUBITEMS 16

// Contract and manifest limits
#define NEOC_MAX_MANIFEST_SIZE 0xFFFF
#define NEOC_MAX_ITERATOR_ITEMS_DEFAULT 100

// Block limits
#define NEOC_MAX_BLOCK_SIZE 2097152
#define NEOC_MAX_BLOCK_SYSTEM_FEE 900000000000
#define NEOC_SECONDS_PER_BLOCK 15

// Hash constants
#define NEOC_HASH160_STRING_LENGTH (NEOC_HASH160_SIZE * 2 + 1)  // hex string + null terminator
#define NEOC_HASH256_STRING_LENGTH (NEOC_HASH256_SIZE * 2 + 1)
#define NEOC_MAX_HEX_STRING_LENGTH 1024

// Address constants
#define NEOC_ADDRESS_VERSION 0x35
#define NEOC_ADDRESS_MAX_LENGTH 64
#define NEOC_WIF_MAX_LENGTH 64

// VM limits
#define NEOC_MAX_STACK_SIZE 2048
#define NEOC_MAX_ITEM_SIZE 1048576
#define NEOC_MAX_INVOCATION_STACK_SIZE 1024

// Native contract hashes (as strings) - defined in respective contract files
// extern const char* NEOC_NEO_TOKEN_HASH;
// extern const char* NEOC_GAS_TOKEN_HASH;
#define NEOC_NEO_TOKEN_HASH_HEX "ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5"
#define NEOC_GAS_TOKEN_HASH_HEX "d2a4cff31913016155e38e474a2c06d08be276cf"
extern const char* NEOC_POLICY_CONTRACT_HASH;
extern const char* NEOC_ROLE_MANAGEMENT_HASH;
extern const char* NEOC_ORACLE_CONTRACT_HASH;
extern const char* NEOC_DESIGNATION_CONTRACT_HASH;
extern const char* NEOC_LEDGER_CONTRACT_HASH;
extern const char* NEOC_MANAGEMENT_CONTRACT_HASH;
extern const char* NEOC_CRYPTO_CONTRACT_HASH;
extern const char* NEOC_STD_CONTRACT_HASH;

// Default values
#define NEOC_DEFAULT_ACCOUNT_LABEL "Default"
#define NEOC_DEFAULT_SCRYPT_N 16384
#define NEOC_DEFAULT_SCRYPT_R 8
#define NEOC_DEFAULT_SCRYPT_P 8

// Cryptographic curve constants
#define NEOC_SECP256R1_CURVE_NAME "secp256r1"
#define NEOC_DEFAULT_CURVE_TYPE 1 // EC256r1

// Curve domain management (matches Swift SECP256R1_DOMAIN functionality)
extern void neoc_init_secp256r1_domain(void);
extern void neoc_cleanup_secp256r1_domain(void);
extern void neoc_set_curve_for_tests(int curve_type);
extern void neoc_reset_curve_from_tests(void);
extern const uint8_t* neoc_get_secp256r1_half_curve_order(void);
extern size_t neoc_get_secp256r1_half_curve_order_size(void);

// Version
#define NEOC_PROTOCOL_VERSION 0

// Neo N3 protocol version compatibility markers
#define NEOC_PROTOCOL_VERSION_391 0x00030901  /* Neo N3 v3.9.1 */
#define NEOC_SDK_VERSION_MAJOR 1
#define NEOC_SDK_VERSION_MINOR 2
#define NEOC_SDK_VERSION_PATCH 0

#ifdef __cplusplus
}
#endif

#endif // NEOC_NEO_CONSTANTS_H
