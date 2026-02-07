/**
 * @file rpc_client.h
 * @brief Neo JSON-RPC client implementation
 */

#ifndef NEOC_RPC_CLIENT_H
#define NEOC_RPC_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "neoc/neoc_error.h"
#include "neoc/types/neoc_hash160.h"
#include "neoc/types/neoc_hash256.h"

#ifdef __cplusplus
extern "C" {
#endif

// Forward declarations
#ifndef NEOC_RPC_CLIENT_FORWARD_DECLARED
#define NEOC_RPC_CLIENT_FORWARD_DECLARED
typedef struct neoc_rpc_client_t neoc_rpc_client_t;
#endif
typedef struct neoc_rpc_request_t neoc_rpc_request_t;
typedef struct neoc_rpc_response_t neoc_rpc_response_t;

// RPC Methods
#define RPC_GET_BEST_BLOCK_HASH "getbestblockhash"
#define RPC_GET_BLOCK "getblock"
#define RPC_GET_BLOCK_COUNT "getblockcount"
#define RPC_GET_BLOCK_HASH "getblockhash"
#define RPC_GET_BLOCK_HEADER "getblockheader"
#define RPC_GET_BLOCK_HEADER_COUNT "getblockheadercount"
#define RPC_GET_CONTRACT_STATE "getcontractstate"
#define RPC_GET_NATIVE_CONTRACTS "getnativecontracts"
#define RPC_GET_MEMPOOL "getrawmempool"
#define RPC_GET_TRANSACTION "getrawtransaction"
#define RPC_GET_STORAGE "getstorage"
#define RPC_GET_TRANSACTION_HEIGHT "gettransactionheight"
#define RPC_GET_NEXT_VALIDATORS "getnextblockvalidators"
#define RPC_GET_COMMITTEE "getcommittee"
#define RPC_INVOKE_CONTRACT_VERIFY "invokecontractverify"
#define RPC_INVOKE_FUNCTION "invokefunction"
#define RPC_INVOKE_SCRIPT "invokescript"
#define RPC_GET_UNCLAIMED_GAS "getunclaimedgas"
#define RPC_LIST_PLUGINS "listplugins"
#define RPC_SEND_RAW_TRANSACTION "sendrawtransaction"
#define RPC_SUBMIT_BLOCK "submitblock"
#define RPC_GET_CONNECTION_COUNT "getconnectioncount"
#define RPC_GET_PEERS "getpeers"
#define RPC_GET_VERSION "getversion"
#define RPC_GET_STATE_ROOT "getstateroot"
#define RPC_GET_STATE_HEIGHT "getstateheight"
#define RPC_GET_STATE "getstate"
#define RPC_FIND_STATES "findstates"
#define RPC_GET_PROOF "getproof"
#define RPC_VERIFY_PROOF "verifyproof"
#define RPC_GET_APPLICATION_LOG "getapplicationlog"
#define RPC_GET_NEP17_BALANCES "getnep17balances"
#define RPC_GET_NEP17_TRANSFERS "getnep17transfers"
#define RPC_GET_NEP11_BALANCES "getnep11balances"
#define RPC_GET_NEP11_TRANSFERS "getnep11transfers"
#define RPC_GET_NEP11_PROPERTIES "getnep11properties"
#define RPC_VALIDATE_ADDRESS "validateaddress"
#define RPC_GET_CANDIDATES "getcandidates"
#define RPC_CALCULATE_NETWORK_FEE "calculatenetworkfee"
#define RPC_TRAVERSE_ITERATOR "traverseiterator"
#define RPC_TERMINATE_SESSION "terminatesession"

/**
 * @brief Block information
 */
typedef struct neoc_rpc_block {
    neoc_hash256_t hash;
    uint32_t index;
    uint32_t version;
    neoc_hash256_t previous_hash;
    neoc_hash256_t merkle_root;
    uint64_t timestamp;
    uint64_t nonce;
    neoc_hash160_t next_consensus;
    uint32_t primary_index;
    size_t tx_count;
    neoc_hash256_t *tx_hashes;
} neoc_rpc_block_t;

typedef struct neoc_rpc_block neoc_block_t;

/**
 * @brief Transaction information
 */
typedef struct neoc_rpc_transaction {
    neoc_hash256_t hash;
    uint32_t size;
    uint32_t version;
    uint64_t nonce;
    neoc_hash160_t sender;
    uint64_t system_fee;
    uint64_t network_fee;
    uint32_t valid_until_block;
    uint8_t *script;
    size_t script_size;
} neoc_rpc_transaction_t;

/**
 * @brief NEP-17 balance entry
 */
typedef struct {
    neoc_hash160_t asset_hash;
    char *amount;
    uint64_t last_updated_block;
} neoc_nep17_balance_t;

/**
 * @brief Contract state
 */
#include "neoc/protocol/contract_response_types.h"

/**
 * @brief Create a new RPC client
 * 
 * @param url RPC endpoint URL
 * @param client Output client handle
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_client_create(const char *url, neoc_rpc_client_t **client);

/**
 * @brief Set RPC client timeout
 * 
 * @param client RPC client handle
 * @param timeout_ms Timeout in milliseconds
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_client_set_timeout(neoc_rpc_client_t *client, uint32_t timeout_ms);

/**
 * @brief Get best block hash
 * 
 * @param client RPC client handle
 * @param hash Output hash
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_best_block_hash(neoc_rpc_client_t *client, neoc_hash256_t *hash);

/**
 * @brief Get block hash by index
 * 
 * @param client RPC client handle
 * @param block_index Block index
 * @param hash Output hash
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_block_hash(neoc_rpc_client_t *client,
                                     uint32_t block_index,
                                     neoc_hash256_t *hash);

/**
 * @brief Execute a raw JSON-RPC call
 *
 * @param client RPC client handle
 * @param method Method name
 * @param params JSON string representing parameters (pass NULL for empty array)
 * @param result Output JSON string (caller must free with free())
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_call_raw(neoc_rpc_client_t *client,
                               const char *method,
                               const char *params,
                               char **result);

/**
 * @brief Get block by hash
 * 
 * @param client RPC client handle
 * @param hash Block hash
 * @param verbose Include transaction details
 * @param block Output block information
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_block(neoc_rpc_client_t *client,
                                 const neoc_hash256_t *hash,
                                 bool verbose,
                                 neoc_block_t **block);

/**
 * @brief Get block count
 * 
 * @param client RPC client handle
 * @param count Output block count
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_block_count(neoc_rpc_client_t *client, uint32_t *count);

/**
 * @brief Get transaction by hash
 * 
 * @param client RPC client handle
 * @param hash Transaction hash
 * @param verbose Include details
 * @param transaction Output transaction
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_transaction(neoc_rpc_client_t *client,
                                       const neoc_hash256_t *hash,
                                       bool verbose,
                                       neoc_rpc_transaction_t **transaction);

/**
 * @brief Send raw transaction
 * 
 * @param client RPC client handle
 * @param tx_data Serialized transaction data
 * @param tx_size Transaction data size
 * @param tx_hash Output transaction hash
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_send_raw_transaction(neoc_rpc_client_t *client,
                                            const uint8_t *tx_data,
                                            size_t tx_size,
                                            neoc_hash256_t *tx_hash);

/**
 * @brief Get contract state
 * 
 * @param client RPC client handle
 * @param script_hash Contract script hash
 * @param state Output contract state
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_contract_state(neoc_rpc_client_t *client,
                                          const neoc_hash160_t *script_hash,
                                          neoc_contract_state_t **state);

/**
 * @brief Invoke contract function
 * 
 * @param client RPC client handle
 * @param script_hash Contract script hash
 * @param method Method name
 * @param params Parameters (JSON array string)
 * @param signers Signers (JSON array string)
 * @param result Output result (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_invoke_function(neoc_rpc_client_t *client,
                                       const neoc_hash160_t *script_hash,
                                       const char *method,
                                       const char *params,
                                       const char *signers,
                                       char **result);

/**
 * @brief Invoke script
 * 
 * @param client RPC client handle
 * @param script Script bytes
 * @param script_size Script size
 * @param signers Signers (JSON array string)
 * @param result Output result (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_invoke_script(neoc_rpc_client_t *client,
                                     const uint8_t *script,
                                     size_t script_size,
                                     const char *signers,
                                     char **result);

/**
 * @brief Get NEP-17 balances
 * 
 * @param client RPC client handle
 * @param address Address hash
 * @param balances Output balances array
 * @param count Output balance count
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_nep17_balances(neoc_rpc_client_t *client,
                                          const neoc_hash160_t *address,
                                          neoc_nep17_balance_t **balances,
                                          size_t *count);

/**
 * @brief Get storage value
 * 
 * @param client RPC client handle
 * @param script_hash Contract script hash
 * @param key Storage key
 * @param key_size Key size
 * @param value Output value (base64 encoded)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_storage(neoc_rpc_client_t *client,
                                   const neoc_hash160_t *script_hash,
                                   const uint8_t *key,
                                   size_t key_size,
                                   char **value);

/**
 * @brief Get application log
 * 
 * @param client RPC client handle
 * @param tx_hash Transaction hash
 * @param log Output log (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_application_log(neoc_rpc_client_t *client,
                                           const neoc_hash256_t *tx_hash,
                                           char **log);

/**
 * @brief Get version information
 * 
 * @param client RPC client handle
 * @param version Output version info (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_version(neoc_rpc_client_t *client, char **version);

/**
 * @brief Get committee members
 * 
 * @param client RPC client handle
 * @param committee Output committee list (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_committee(neoc_rpc_client_t *client, char **committee);

/**
 * @brief Get next block validators
 * 
 * @param client RPC client handle
 * @param validators Output validators list (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_next_validators(neoc_rpc_client_t *client, char **validators);

/**
 * @brief Get connection count
 * 
 * @param client RPC client handle
 * @param count Output connection count
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_connection_count(neoc_rpc_client_t *client, uint32_t *count);

/**
 * @brief Get connected peers
 * 
 * @param client RPC client handle
 * @param peers Output peers info (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_peers(neoc_rpc_client_t *client, char **peers);

/**
 * @brief Get raw mempool
 * 
 * @param client RPC client handle
 * @param mempool Output mempool transactions (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_raw_mempool(neoc_rpc_client_t *client, char **mempool);

/**
 * @brief Get transaction height
 * 
 * @param client RPC client handle
 * @param tx_hash Transaction hash
 * @param height Output block height
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_transaction_height(neoc_rpc_client_t *client,
                                              const neoc_hash256_t *tx_hash,
                                              uint32_t *height);

/**
 * @brief Get state height
 * 
 * @param client RPC client handle
 * @param height Output state height
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_state_height(neoc_rpc_client_t *client, uint32_t *height);

/**
 * @brief Get native contracts
 * 
 * @param client RPC client handle
 * @param contracts Output native contracts (JSON string)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_rpc_get_native_contracts(neoc_rpc_client_t *client, char **contracts);

/**
 * @brief Get block header by hash
 */
neoc_error_t neoc_rpc_get_block_header(neoc_rpc_client_t *client,
                                        const neoc_hash256_t *hash,
                                        bool verbose,
                                        char **header);

/**
 * @brief Get block header count
 */
neoc_error_t neoc_rpc_get_block_header_count(neoc_rpc_client_t *client, uint32_t *count);

/**
 * @brief Invoke contract verify
 */
neoc_error_t neoc_rpc_invoke_contract_verify(neoc_rpc_client_t *client,
                                              const neoc_hash160_t *script_hash,
                                              const char *params,
                                              const char *signers,
                                              char **result);

/**
 * @brief Get unclaimed GAS for an address
 */
neoc_error_t neoc_rpc_get_unclaimed_gas(neoc_rpc_client_t *client,
                                         const char *address,
                                         char **unclaimed);

/**
 * @brief Calculate network fee for a transaction
 */
neoc_error_t neoc_rpc_calculate_network_fee(neoc_rpc_client_t *client,
                                             const uint8_t *tx_data,
                                             size_t tx_size,
                                             char **fee);

/**
 * @brief Get NEP-17 transfer history
 */
neoc_error_t neoc_rpc_get_nep17_transfers(neoc_rpc_client_t *client,
                                           const char *address,
                                           char **transfers);

/**
 * @brief Get NEP-11 balances
 */
neoc_error_t neoc_rpc_get_nep11_balances(neoc_rpc_client_t *client,
                                          const char *address,
                                          char **balances);

/**
 * @brief Get NEP-11 transfer history
 */
neoc_error_t neoc_rpc_get_nep11_transfers(neoc_rpc_client_t *client,
                                           const char *address,
                                           char **transfers);

/**
 * @brief Get NEP-11 token properties
 */
neoc_error_t neoc_rpc_get_nep11_properties(neoc_rpc_client_t *client,
                                            const neoc_hash160_t *script_hash,
                                            const char *token_id,
                                            char **properties);

/**
 * @brief List plugins
 */
neoc_error_t neoc_rpc_list_plugins(neoc_rpc_client_t *client, char **plugins);

/**
 * @brief Submit a block
 */
neoc_error_t neoc_rpc_submit_block(neoc_rpc_client_t *client,
                                    const uint8_t *block_data,
                                    size_t block_size,
                                    bool *accepted);

/**
 * @brief Validate an address
 */
neoc_error_t neoc_rpc_validate_address(neoc_rpc_client_t *client,
                                        const char *address,
                                        bool *is_valid);

/**
 * @brief Get candidates
 */
neoc_error_t neoc_rpc_get_candidates(neoc_rpc_client_t *client, char **candidates);

/**
 * @brief Traverse an iterator (session-based)
 */
neoc_error_t neoc_rpc_traverse_iterator(neoc_rpc_client_t *client,
                                         const char *session_id,
                                         const char *iterator_id,
                                         uint32_t count,
                                         char **items);

/**
 * @brief Terminate a session
 */
neoc_error_t neoc_rpc_terminate_session(neoc_rpc_client_t *client,
                                         const char *session_id,
                                         bool *success);

/**
 * @brief Get state root by index
 */
neoc_error_t neoc_rpc_get_state_root(neoc_rpc_client_t *client,
                                      uint32_t index,
                                      char **state_root);

/**
 * @brief Get state value
 */
neoc_error_t neoc_rpc_get_state(neoc_rpc_client_t *client,
                                 const neoc_hash256_t *root_hash,
                                 const neoc_hash160_t *script_hash,
                                 const uint8_t *key,
                                 size_t key_size,
                                 char **value);

/**
 * @brief Find states matching a prefix
 */
neoc_error_t neoc_rpc_find_states(neoc_rpc_client_t *client,
                                   const neoc_hash256_t *root_hash,
                                   const neoc_hash160_t *script_hash,
                                   const uint8_t *prefix,
                                   size_t prefix_size,
                                   char **states);

/**
 * @brief Get proof for a storage key
 */
neoc_error_t neoc_rpc_get_proof(neoc_rpc_client_t *client,
                                 const neoc_hash256_t *root_hash,
                                 const neoc_hash160_t *script_hash,
                                 const uint8_t *key,
                                 size_t key_size,
                                 char **proof);

/**
 * @brief Verify a state proof
 */
neoc_error_t neoc_rpc_verify_proof(neoc_rpc_client_t *client,
                                    const neoc_hash256_t *root_hash,
                                    const char *proof,
                                    char **value);

/**
 * @brief Free RPC client
 * 
 * @param client RPC client handle
 */
void neoc_rpc_client_free(neoc_rpc_client_t *client);

/**
 * @brief Free block structure
 * 
 * @param block Block to free
 */
void neoc_rpc_block_free(neoc_block_t *block);

/**
 * @brief Free transaction structure
 * 
 * @param transaction Transaction to free
 */
void neoc_rpc_transaction_free(neoc_rpc_transaction_t *transaction);

/**
 * @brief Free contract state
 * 
 * @param state Contract state to free
 */
void neoc_rpc_contract_state_free(neoc_contract_state_t *state);

/**
 * @brief Free NEP-17 balances
 * 
 * @param balances Balances array
 * @param count Number of balances
 */
void neoc_rpc_nep17_balances_free(neoc_nep17_balance_t *balances, size_t count);

#ifdef __cplusplus
}
#endif

#endif // NEOC_RPC_CLIENT_H
