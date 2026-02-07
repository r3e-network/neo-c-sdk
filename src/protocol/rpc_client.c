/**
 * @file rpc_client.c
 * @brief Neo JSON-RPC client implementation
 */

#include "neoc/protocol/rpc_client.h"
#include "neoc/protocol/response/contract_nef.h"
#include "neoc/contract/contract_manifest.h"
#include "neoc/utils/neoc_hex.h"
#include "neoc/utils/neoc_base64.h"
#include "neoc/neo_constants.h"
#include "neoc/neoc_memory.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __APPLE__
#include <AvailabilityMacros.h>
#endif

// Check for libcurl
#ifdef HAVE_CURL
#include <curl/curl.h>
#endif

// Check for cJSON
#ifdef HAVE_CJSON
#include <cjson/cJSON.h>
#endif

// RPC client structure
struct neoc_rpc_client_t {
    char *url;
    uint32_t timeout_ms;
    uint32_t request_id;
#ifdef HAVE_CURL
    CURL *curl;
#endif
};

// Response buffer structure
typedef struct {
    char *data;
    size_t size;
    size_t capacity;
} response_buffer_t;

#ifdef HAVE_CURL
// CURL write callback
static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    response_buffer_t *buf = (response_buffer_t *)userp;
    
    // Resize buffer if needed
    if (buf->size + real_size + 1 > buf->capacity) {
        size_t new_capacity = (buf->size + real_size + 1) * 2;
        char *new_data = neoc_realloc(buf->data, new_capacity);
        if (!new_data) {
            return 0; // Error
        }
        buf->data = new_data;
        buf->capacity = new_capacity;
    }
    
    memcpy(&(buf->data[buf->size]), contents, real_size);
    buf->size += real_size;
    buf->data[buf->size] = '\0';
    
    return real_size;
}
#endif

neoc_error_t neoc_rpc_client_create(const char *url, neoc_rpc_client_t **client) {
    if (!url || !client) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *client = neoc_calloc(1, sizeof(neoc_rpc_client_t));
    if (!*client) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate RPC client");
    }
    
    (*client)->url = neoc_strdup(url);
    if (!(*client)->url) {
        neoc_free(*client);
        *client = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate URL");
    }
    
    (*client)->timeout_ms = 30000; // Default 30 seconds
    (*client)->request_id = 1;
    
#ifdef HAVE_CURL
    (*client)->curl = curl_easy_init();
    if (!(*client)->curl) {
        neoc_free((*client)->url);
        neoc_free(*client);
        *client = NULL;
        return neoc_error_set(NEOC_ERROR_CRYPTO_INIT, "Failed to initialize CURL");
    }
#endif
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_rpc_client_set_timeout(neoc_rpc_client_t *client, uint32_t timeout_ms) {
    if (!client) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid client");
    }
    
    client->timeout_ms = timeout_ms;
    return NEOC_SUCCESS;
}

// Helper function to make RPC call
static neoc_error_t make_rpc_call(neoc_rpc_client_t *client,
                                   const char *method,
                                   const char *params,
                                   char **result) {
    if (!client || !method || !result) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
#ifndef HAVE_CURL
    (void)params;
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "CURL support not compiled in");
#else
#ifndef HAVE_CJSON
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#else
    
    // Create JSON-RPC request
    cJSON *request = cJSON_CreateObject();
    if (!request) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to create JSON request");
    }
    
    cJSON_AddStringToObject(request, "jsonrpc", "2.0");
    cJSON_AddStringToObject(request, "method", method);
    cJSON_AddNumberToObject(request, "id", client->request_id++);
    
    if (params) {
        cJSON *params_json = cJSON_Parse(params);
        if (!params_json) {
            cJSON_Delete(request);
            return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid JSON parameters");
        }
        cJSON_AddItemToObject(request, "params", params_json);
    } else {
        cJSON *params_array = cJSON_CreateArray();
        cJSON_AddItemToObject(request, "params", params_array);
    }
    
    char *request_str = cJSON_PrintUnformatted(request);
    cJSON_Delete(request);
    
    if (!request_str) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to serialize request");
    }
    
    // Setup response buffer
    response_buffer_t response_buf = {0};
    response_buf.data = neoc_malloc(4096);
    response_buf.capacity = 4096;
    
    if (!response_buf.data) {
        free(request_str);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate response buffer");
    }
    
    // Setup CURL
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(client->curl, CURLOPT_URL, client->url);
    curl_easy_setopt(client->curl, CURLOPT_POSTFIELDS, request_str);
    curl_easy_setopt(client->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(client->curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(client->curl, CURLOPT_WRITEDATA, &response_buf);
    curl_easy_setopt(client->curl, CURLOPT_TIMEOUT_MS, client->timeout_ms);
    
    // Perform request
    CURLcode res = curl_easy_perform(client->curl);
    
    curl_slist_free_all(headers);
    free(request_str);
    
    if (res != CURLE_OK) {
        neoc_free(response_buf.data);
        return neoc_error_set(NEOC_ERROR_NETWORK, curl_easy_strerror(res));
    }
    
    // Parse response
    cJSON *response = cJSON_Parse(response_buf.data);
    if (!response) {
        neoc_free(response_buf.data);
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Failed to parse response");
    }
    
    // Check for error
    cJSON *error = cJSON_GetObjectItem(response, "error");
    if (error) {
        cJSON *error_msg = cJSON_GetObjectItem(error, "message");
        const char *msg = error_msg ? error_msg->valuestring : "RPC error";
        neoc_error_t err = neoc_error_set(NEOC_ERROR_RPC, msg);
        cJSON_Delete(response);
        neoc_free(response_buf.data);
        return err;
    }
    
    // Get result
    cJSON *result_json = cJSON_GetObjectItem(response, "result");
    if (result_json) {
        char *tmp = cJSON_PrintUnformatted(result_json);
        if (!tmp) {
            cJSON_Delete(response);
            neoc_free(response_buf.data);
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to serialize RPC result");
        }
        *result = neoc_strdup(tmp);
        free(tmp);
    } else {
        *result = neoc_strdup("null");
    }
    
    cJSON_Delete(response);
    neoc_free(response_buf.data);
    
    return NEOC_SUCCESS;
#endif // HAVE_CJSON
#endif // HAVE_CURL
}

neoc_error_t neoc_rpc_get_best_block_hash(neoc_rpc_client_t *client, neoc_hash256_t *hash) {
    if (!client || !hash) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    char *result = NULL;
    neoc_error_t err = make_rpc_call(client, RPC_GET_BEST_BLOCK_HASH, NULL, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
#ifdef HAVE_CJSON
    // Result should be a string hash
    cJSON *json = cJSON_Parse(result);
    if (json && cJSON_IsString(json)) {
        const char *hash_str = json->valuestring;
        if (hash_str && strlen(hash_str) == 66 && hash_str[0] == '0' && hash_str[1] == 'x') {
            err = neoc_hash256_from_string(hash_str + 2, hash);
        } else {
            err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid hash format");
        }
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
    neoc_free(result);
#else
    neoc_free(result);
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif
    
    return err;
}

neoc_error_t neoc_rpc_get_block_hash(neoc_rpc_client_t *client,
                                     uint32_t block_index,
                                     neoc_hash256_t *hash) {
    if (!client || !hash) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[32];
    snprintf(params, sizeof(params), "[%u]", block_index);

    char *result = NULL;
    neoc_error_t err = make_rpc_call(client, RPC_GET_BLOCK_HASH, params, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }

#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json && cJSON_IsString(json)) {
        const char *hash_str = json->valuestring;
        if (hash_str) {
            if (strncmp(hash_str, "0x", 2) == 0) {
                hash_str += 2;
            }
            err = neoc_hash256_from_string(hash_str, hash);
        } else {
            err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid hash response");
        }
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
    neoc_free(result);
#else
    neoc_free(result);
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif

    return err;
}

neoc_error_t neoc_rpc_call_raw(neoc_rpc_client_t *client,
                               const char *method,
                               const char *params,
                               char **result) {
    if (!client || !method || !result) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    return make_rpc_call(client, method, params, result);
}

neoc_error_t neoc_rpc_get_block_count(neoc_rpc_client_t *client, uint32_t *count) {
    if (!client || !count) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    char *result = NULL;
    neoc_error_t err = make_rpc_call(client, RPC_GET_BLOCK_COUNT, NULL, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json && cJSON_IsNumber(json)) {
        *count = (uint32_t)json->valueint;
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
    neoc_free(result);
#else
    neoc_free(result);
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif
    
    return err;
}

neoc_error_t neoc_rpc_send_raw_transaction(neoc_rpc_client_t *client,
                                            const uint8_t *tx_data,
                                            size_t tx_size,
                                            neoc_hash256_t *tx_hash) {
    if (!client || !tx_data || !tx_hash) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Convert transaction to base64
    size_t base64_len = neoc_base64_encode_buffer_size(tx_size);
    char *base64_tx = neoc_malloc(base64_len);
    if (!base64_tx) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate base64 buffer");
    }
    
    neoc_error_t err = neoc_base64_encode(tx_data, tx_size, base64_tx, base64_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(base64_tx);
        return err;
    }
    
    // Create params array
    char params[1024];
    snprintf(params, sizeof(params), "[\"%s\"]", base64_tx);
    neoc_free(base64_tx);
    
    char *result = NULL;
    err = make_rpc_call(client, RPC_SEND_RAW_TRANSACTION, params, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json) {
        cJSON *hash_json = cJSON_GetObjectItem(json, "hash");
        if (hash_json && cJSON_IsString(hash_json)) {
            const char *hash_str = hash_json->valuestring;
            if (hash_str && strlen(hash_str) == 66 && hash_str[0] == '0' && hash_str[1] == 'x') {
                err = neoc_hash256_from_string(hash_str + 2, tx_hash);
            } else {
                err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid hash format");
            }
        } else {
            err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "No hash in response");
        }
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
    neoc_free(result);
#else
    neoc_free(result);
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif
    
    return err;
}

neoc_error_t neoc_rpc_invoke_function(neoc_rpc_client_t *client,
                                       const neoc_hash160_t *script_hash,
                                       const char *method,
                                       const char *params,
                                       const char *signers,
                                       char **result) {
    if (!client || !script_hash || !method || !result) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Convert script hash to hex string with prefix
    char hash_hex[NEOC_HASH160_STRING_LENGTH];
    neoc_error_t err = neoc_hash160_to_hex(script_hash, hash_hex, sizeof(hash_hex), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    char hash_prefixed[NEOC_HASH160_STRING_LENGTH + 3];
    snprintf(hash_prefixed, sizeof(hash_prefixed), "0x%s", hash_hex);

    // Build params array
    char rpc_params[4096];
    snprintf(rpc_params, sizeof(rpc_params), "[\"%s\", \"%s\", %s, %s]",
             hash_prefixed, method,
             params ? params : "[]",
             signers ? signers : "[]");
    
    return make_rpc_call(client, RPC_INVOKE_FUNCTION, rpc_params, result);
}

neoc_error_t neoc_rpc_invoke_script(neoc_rpc_client_t *client,
                                     const uint8_t *script,
                                     size_t script_size,
                                     const char *signers,
                                     char **result) {
    if (!client || !script || !result) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Convert script to base64
    size_t base64_len = neoc_base64_encode_buffer_size(script_size);
    char *base64_script = neoc_malloc(base64_len);
    if (!base64_script) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate base64 buffer");
    }
    
    neoc_error_t err = neoc_base64_encode(script, script_size, base64_script, base64_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(base64_script);
        return err;
    }
    
    // Build params array
    char rpc_params[8192];
    snprintf(rpc_params, sizeof(rpc_params), "[\"%s\", %s]",
             base64_script,
             signers ? signers : "[]");
    neoc_free(base64_script);
    
    return make_rpc_call(client, RPC_INVOKE_SCRIPT, rpc_params, result);
}

neoc_error_t neoc_rpc_get_nep17_balances(neoc_rpc_client_t *client,
                                          const neoc_hash160_t *address,
                                          neoc_nep17_balance_t **balances,
                                          size_t *count) {
    if (!client || !address || !balances || !count) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Convert address to string
    char addr_str[42];
    neoc_error_t err = neoc_hash160_to_address(address, addr_str, sizeof(addr_str));
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Build params
    char params[128];
    snprintf(params, sizeof(params), "[\"%s\"]", addr_str);
    
    char *result = NULL;
    err = make_rpc_call(client, RPC_GET_NEP17_BALANCES, params, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json) {
        cJSON *balance_array = cJSON_GetObjectItem(json, "balance");
        if (balance_array && cJSON_IsArray(balance_array)) {
            *count = cJSON_GetArraySize(balance_array);
            if (*count > 0) {
                *balances = neoc_calloc(*count, sizeof(neoc_nep17_balance_t));
                if (*balances) {
                    for (size_t i = 0; i < *count; i++) {
                        cJSON *item = cJSON_GetArrayItem(balance_array, i);
                        if (item) {
                            cJSON *asset = cJSON_GetObjectItem(item, "assethash");
                            cJSON *amount = cJSON_GetObjectItem(item, "amount");
                            cJSON *updated = cJSON_GetObjectItem(item, "lastupdatedblock");
                            
                            if (asset && cJSON_IsString(asset)) {
                                neoc_hash160_from_string(asset->valuestring, &(*balances)[i].asset_hash);
                            }
                            if (amount && cJSON_IsString(amount)) {
                                (*balances)[i].amount = neoc_strdup(amount->valuestring);
                            }
                            if (updated && cJSON_IsNumber(updated)) {
                                (*balances)[i].last_updated_block = updated->valueint;
                            }
                        }
                    }
                } else {
                    err = neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate balances");
                }
            }
        } else {
            *count = 0;
            *balances = NULL;
        }
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
    neoc_free(result);
#else
    neoc_free(result);
    *count = 0;
    *balances = NULL;
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif
    
    return err;
}

neoc_error_t neoc_rpc_get_version(neoc_rpc_client_t *client, char **version) {
    if (!client || !version) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    return make_rpc_call(client, RPC_GET_VERSION, NULL, version);
}

neoc_error_t neoc_rpc_get_storage(neoc_rpc_client_t *client,
                                   const neoc_hash160_t *script_hash,
                                   const uint8_t *key,
                                   size_t key_size,
                                   char **value) {
    if (!client || !script_hash || !key || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Convert script hash to string
    char hash_str[NEOC_HASH160_STRING_LENGTH];
    neoc_error_t err = neoc_hash160_to_hex(script_hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Convert key to base64
    size_t base64_len = neoc_base64_encode_buffer_size(key_size);
    char *base64_key = neoc_malloc(base64_len);
    if (!base64_key) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate base64 buffer");
    }
    
    err = neoc_base64_encode(key, key_size, base64_key, base64_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(base64_key);
        return err;
    }
    
    // Build params
    char params[512];
    snprintf(params, sizeof(params), "[\"0x%s\", \"%s\"]", hash_str, base64_key);
    neoc_free(base64_key);
    
    return make_rpc_call(client, RPC_GET_STORAGE, params, value);
}

neoc_error_t neoc_rpc_get_application_log(neoc_rpc_client_t *client,
                                           const neoc_hash256_t *tx_hash,
                                           char **log) {
    if (!client || !tx_hash || !log) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Convert transaction hash to string
    char hash_str[NEOC_HASH256_STRING_LENGTH];
    neoc_error_t err = neoc_hash256_to_hex(tx_hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Build params
    char params[128];
    snprintf(params, sizeof(params), "[\"0x%s\"]", hash_str);
    
    return make_rpc_call(client, RPC_GET_APPLICATION_LOG, params, log);
}

void neoc_rpc_block_free(neoc_block_t *block) {
    if (!block) return;
    
    // Free transaction hashes array
    if (block->tx_hashes) {
        neoc_free(block->tx_hashes);
    }
    
    neoc_free(block);
}

void neoc_rpc_transaction_free(neoc_rpc_transaction_t *transaction) {
    if (!transaction) return;
    
    // Free script data
    if (transaction->script) {
        neoc_free(transaction->script);
    }
    
    neoc_free(transaction);
}

void neoc_rpc_contract_state_free(neoc_contract_state_t *state) {
    if (!state) return;
    
    neoc_contract_nef_dispose(&state->nef);
    neoc_contract_manifest_dispose(&state->manifest);
    neoc_free(state);
}

void neoc_rpc_nep17_balances_free(neoc_nep17_balance_t *balances, size_t count) {
    if (!balances) return;
    
    for (size_t i = 0; i < count; i++) {
        neoc_free(balances[i].amount);
    }
    neoc_free(balances);
}

void neoc_rpc_client_free(neoc_rpc_client_t *client) {
    if (!client) return;
    
#ifdef HAVE_CURL
    if (client->curl) {
        curl_easy_cleanup(client->curl);
    }
#endif
    
    neoc_free(client->url);
    neoc_free(client);
}

// Complete implementations of RPC methods
neoc_error_t neoc_rpc_get_block(neoc_rpc_client_t *client,
                                 const neoc_hash256_t *hash,
                                 bool verbose,
                                 neoc_block_t **block) {
    if (!client || !hash || !block) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
#ifndef HAVE_CURL
    (void)verbose;
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "libcurl support not compiled in");
#else
#ifndef HAVE_CJSON
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#else
    
    // Convert hash to hex string
    char hash_str[65];
    neoc_error_t err = neoc_hash256_to_hex(hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Build params array
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(hash_str));
    cJSON_AddItemToArray(params, cJSON_CreateBool(verbose));
    
    char *params_str = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    // Make RPC call
    char *result = NULL;
    err = make_rpc_call(client, RPC_GET_BLOCK, params_str, &result);
    free(params_str);
    
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Parse the result
    cJSON *json = cJSON_Parse(result);
    if (!json) {
        neoc_free(result);
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid JSON response");
    }
    
    // Allocate block structure
    *block = neoc_calloc(1, sizeof(neoc_block_t));
    if (!*block) {
        cJSON_Delete(json);
        neoc_free(result);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate block");
    }
    
    // Parse block fields
    cJSON *item;
    
    // Hash
    item = cJSON_GetObjectItem(json, "hash");
    if (item && cJSON_IsString(item)) {
        const char *hash_hex = item->valuestring;
        if (hash_hex && strlen(hash_hex) >= 2 && hash_hex[0] == '0' && hash_hex[1] == 'x') {
            neoc_hash256_from_string(hash_hex + 2, &(*block)->hash);
        }
    }
    
    // Index
    item = cJSON_GetObjectItem(json, "index");
    if (item && cJSON_IsNumber(item)) {
        (*block)->index = (uint32_t)item->valueint;
    }
    
    // Version
    item = cJSON_GetObjectItem(json, "version");
    if (item && cJSON_IsNumber(item)) {
        (*block)->version = (uint32_t)item->valueint;
    }
    
    // Previous hash
    item = cJSON_GetObjectItem(json, "previousblockhash");
    if (item && cJSON_IsString(item)) {
        const char *prev_hash = item->valuestring;
        if (prev_hash && strlen(prev_hash) >= 2 && prev_hash[0] == '0' && prev_hash[1] == 'x') {
            neoc_hash256_from_string(prev_hash + 2, &(*block)->previous_hash);
        }
    }
    
    // Merkle root
    item = cJSON_GetObjectItem(json, "merkleroot");
    if (item && cJSON_IsString(item)) {
        const char *merkle = item->valuestring;
        if (merkle && strlen(merkle) >= 2 && merkle[0] == '0' && merkle[1] == 'x') {
            neoc_hash256_from_string(merkle + 2, &(*block)->merkle_root);
        }
    }
    
    // Timestamp
    item = cJSON_GetObjectItem(json, "time");
    if (item && cJSON_IsNumber(item)) {
        (*block)->timestamp = (uint64_t)item->valuedouble;
    }
    
    // Nonce
    item = cJSON_GetObjectItem(json, "nonce");
    if (item && cJSON_IsString(item)) {
        (*block)->nonce = strtoull(item->valuestring, NULL, 16);
    }
    
    // Next consensus
    item = cJSON_GetObjectItem(json, "nextconsensus");
    if (item && cJSON_IsString(item)) {
        neoc_hash160_from_address(&(*block)->next_consensus, item->valuestring);
    }
    
    // Primary index
    item = cJSON_GetObjectItem(json, "primary");
    if (item && cJSON_IsNumber(item)) {
        (*block)->primary_index = (uint32_t)item->valueint;
    }
    
    // Transaction hashes
    cJSON *tx_array = cJSON_GetObjectItem(json, "tx");
    if (tx_array && cJSON_IsArray(tx_array)) {
        (*block)->tx_count = cJSON_GetArraySize(tx_array);
        if ((*block)->tx_count > 0) {
            (*block)->tx_hashes = neoc_calloc((*block)->tx_count, sizeof(neoc_hash256_t));
            if ((*block)->tx_hashes) {
                for (size_t i = 0; i < (*block)->tx_count; i++) {
                    cJSON *tx_item = cJSON_GetArrayItem(tx_array, i);
                    if (tx_item) {
                        if (cJSON_IsString(tx_item)) {
                            // Just a hash string
                            const char *tx_hash = tx_item->valuestring;
                            if (tx_hash && strlen(tx_hash) >= 2 && tx_hash[0] == '0' && tx_hash[1] == 'x') {
                                neoc_hash256_from_string(tx_hash + 2, &(*block)->tx_hashes[i]);
                            }
                        } else if (cJSON_IsObject(tx_item)) {
                            // Full transaction object - just extract hash
                            cJSON *tx_hash_item = cJSON_GetObjectItem(tx_item, "hash");
                            if (tx_hash_item && cJSON_IsString(tx_hash_item)) {
                                const char *tx_hash = tx_hash_item->valuestring;
                                if (tx_hash && strlen(tx_hash) >= 2 && tx_hash[0] == '0' && tx_hash[1] == 'x') {
                                    neoc_hash256_from_string(tx_hash + 2, &(*block)->tx_hashes[i]);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    cJSON_Delete(json);
    neoc_free(result);
    
    return NEOC_SUCCESS;
#endif // HAVE_CJSON
#endif // HAVE_CURL
}

neoc_error_t neoc_rpc_get_transaction(neoc_rpc_client_t *client,
                                       const neoc_hash256_t *hash,
                                       bool verbose,
                                       neoc_rpc_transaction_t **transaction) {
    if (!client || !hash || !transaction) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
#ifndef HAVE_CURL
    (void)verbose;
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "libcurl support not compiled in");
#else
#ifndef HAVE_CJSON
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#else
    
    // Convert hash to hex string
    char hash_str[65];
    neoc_error_t err = neoc_hash256_to_hex(hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Build params array
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(hash_str));
    cJSON_AddItemToArray(params, cJSON_CreateBool(verbose));
    
    char *params_str = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    // Make RPC call
    char *result = NULL;
    err = make_rpc_call(client, RPC_GET_TRANSACTION, params_str, &result);
    free(params_str);
    
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Parse the result
    cJSON *json = cJSON_Parse(result);
    if (!json) {
        neoc_free(result);
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid JSON response");
    }
    
    // Allocate transaction structure
    *transaction = neoc_calloc(1, sizeof(neoc_rpc_transaction_t));
    if (!*transaction) {
        cJSON_Delete(json);
        neoc_free(result);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate transaction");
    }
    
    // Parse transaction fields
    cJSON *item;
    
    // Hash
    item = cJSON_GetObjectItem(json, "hash");
    if (item && cJSON_IsString(item)) {
        const char *hash_hex = item->valuestring;
        if (hash_hex && strlen(hash_hex) >= 2 && hash_hex[0] == '0' && hash_hex[1] == 'x') {
            neoc_hash256_from_string(hash_hex + 2, &(*transaction)->hash);
        }
    }
    
    // Size
    item = cJSON_GetObjectItem(json, "size");
    if (item && cJSON_IsNumber(item)) {
        (*transaction)->size = (uint32_t)item->valueint;
    }
    
    // Version
    item = cJSON_GetObjectItem(json, "version");
    if (item && cJSON_IsNumber(item)) {
        (*transaction)->version = (uint32_t)item->valueint;
    }
    
    // Nonce
    item = cJSON_GetObjectItem(json, "nonce");
    if (item && cJSON_IsNumber(item)) {
        (*transaction)->nonce = (uint64_t)item->valuedouble;
    }
    
    // Sender
    item = cJSON_GetObjectItem(json, "sender");
    if (item && cJSON_IsString(item)) {
        neoc_hash160_from_address(&(*transaction)->sender, item->valuestring);
    }
    
    // System fee
    item = cJSON_GetObjectItem(json, "sysfee");
    if (item && cJSON_IsString(item)) {
        (*transaction)->system_fee = strtoull(item->valuestring, NULL, 10);
    }
    
    // Network fee
    item = cJSON_GetObjectItem(json, "netfee");
    if (item && cJSON_IsString(item)) {
        (*transaction)->network_fee = strtoull(item->valuestring, NULL, 10);
    }
    
    // Valid until block
    item = cJSON_GetObjectItem(json, "validuntilblock");
    if (item && cJSON_IsNumber(item)) {
        (*transaction)->valid_until_block = (uint32_t)item->valueint;
    }
    
    // Script
    item = cJSON_GetObjectItem(json, "script");
    if (item && cJSON_IsString(item)) {
        const char *script_hex = item->valuestring;
        size_t hex_len = strlen(script_hex);
        (*transaction)->script_size = hex_len / 2;
        (*transaction)->script = neoc_malloc((*transaction)->script_size);
        if ((*transaction)->script) {
            neoc_hex_decode(script_hex, (*transaction)->script, (*transaction)->script_size, NULL);
        }
    }
    
    cJSON_Delete(json);
    neoc_free(result);
    
    return NEOC_SUCCESS;
#endif // HAVE_CJSON
#endif // HAVE_CURL
}

neoc_error_t neoc_rpc_get_contract_state(neoc_rpc_client_t *client,
                                          const neoc_hash160_t *script_hash,
                                          neoc_contract_state_t **state) {
    if (!client || !script_hash || !state) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
#ifndef HAVE_CURL
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "libcurl support not compiled in");
#else
#ifndef HAVE_CJSON
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#else
    
    // Convert script hash to hex string
    char hash_str[41];
    neoc_error_t err = neoc_hash160_to_hex(script_hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Build params array
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(hash_str));
    
    char *params_str = cJSON_PrintUnformatted(params);
    cJSON_Delete(params);
    
    // Make RPC call
    char *result = NULL;
    err = make_rpc_call(client, RPC_GET_CONTRACT_STATE, params_str, &result);
    free(params_str);
    
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Parse the result
    cJSON *json = cJSON_Parse(result);
    if (!json) {
        neoc_free(result);
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid JSON response");
    }
    
    // Allocate contract state structure
    *state = neoc_calloc(1, sizeof(neoc_contract_state_t));
    if (!*state) {
        cJSON_Delete(json);
        neoc_free(result);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate contract state");
    }
    
    // Parse contract state fields
    cJSON *item;
    
    // ID
    item = cJSON_GetObjectItem(json, "id");
    if (item && cJSON_IsNumber(item)) {
        (*state)->id = (uint32_t)item->valueint;
    }
    
    // Update counter
    item = cJSON_GetObjectItem(json, "updatecounter");
    if (item && cJSON_IsNumber(item)) {
        (*state)->update_counter = (uint32_t)item->valueint;
    }
    
    // Hash
    item = cJSON_GetObjectItem(json, "hash");
    if (item && cJSON_IsString(item)) {
        const char *hash_hex = item->valuestring;
        if (hash_hex && strlen(hash_hex) >= 2 && hash_hex[0] == '0' && hash_hex[1] == 'x') {
            neoc_hash160_from_hex(&(*state)->hash, hash_hex + 2);
        }
    }
    
    // NEF (Neo Executable Format)
    item = cJSON_GetObjectItem(json, "nef");
    if (item) {
        // Parse NEF structure from JSON
        cJSON *magic_item = cJSON_GetObjectItem(item, "magic");
        if (magic_item && cJSON_IsNumber(magic_item)) {
            (*state)->nef.magic = (uint32_t)magic_item->valueint;
        } else {
            (*state)->nef.magic = 0x3346454E; // Default NEF3 magic
        }
        
        cJSON *compiler_item = cJSON_GetObjectItem(item, "compiler");
        if (compiler_item && cJSON_IsString(compiler_item)) {
            (*state)->nef.compiler = neoc_strdup(compiler_item->valuestring);
        }
        
        cJSON *source_item = cJSON_GetObjectItem(item, "source");
        if (source_item && cJSON_IsString(source_item)) {
            (*state)->nef.source = neoc_strdup(source_item->valuestring);
        }
        
        cJSON *script_item = cJSON_GetObjectItem(item, "script");
        if (script_item && cJSON_IsString(script_item)) {
            size_t script_len = 0;
            uint8_t *decoded = neoc_base64_decode_alloc(script_item->valuestring, &script_len);
            if (decoded) {
                (*state)->nef.script = decoded;
                (*state)->nef.script_length = script_len;
            }
        }
        
        cJSON *checksum_item = cJSON_GetObjectItem(item, "checksum");
        if (checksum_item && cJSON_IsNumber(checksum_item)) {
            (*state)->nef.checksum = (uint32_t)checksum_item->valueint;
        }
        
        (*state)->nef.token_count = 0;
        (*state)->nef.tokens = NULL;
    }
    
    // Manifest
    item = cJSON_GetObjectItem(json, "manifest");
    if (item) {
        // Parse manifest structure from JSON
        cJSON *name_item = cJSON_GetObjectItem(item, "name");
        if (name_item && cJSON_IsString(name_item)) {
            (*state)->manifest.name = neoc_strdup(name_item->valuestring);
        } else {
            (*state)->manifest.name = neoc_strdup("Contract");
        }
        
        // Parse groups array
        cJSON *groups_item = cJSON_GetObjectItem(item, "groups");
        if (groups_item && cJSON_IsArray(groups_item)) {
            (*state)->manifest.group_count = cJSON_GetArraySize(groups_item);
            if ((*state)->manifest.group_count > 0) {
                (*state)->manifest.groups = neoc_calloc((*state)->manifest.group_count, sizeof(neoc_contract_group_t));
                // Parse group details if needed
            }
        }
        
        // Parse supported standards
        cJSON *standards_item = cJSON_GetObjectItem(item, "supportedstandards");
        if (standards_item && cJSON_IsArray(standards_item)) {
            (*state)->manifest.supported_standards_count = cJSON_GetArraySize(standards_item);
            if ((*state)->manifest.supported_standards_count > 0) {
                (*state)->manifest.supported_standards = neoc_calloc((*state)->manifest.supported_standards_count, sizeof(char*));
                size_t i = 0;
                cJSON *std_item = NULL;
                cJSON_ArrayForEach(std_item, standards_item) {
                    if (i >= (*state)->manifest.supported_standards_count) break;
                    if (cJSON_IsString(std_item)) {
                        (*state)->manifest.supported_standards[i] = neoc_strdup(std_item->valuestring);
                    }
                    i++;
                }
            }
        }
        
        // Parse ABI
        cJSON *abi_item = cJSON_GetObjectItem(item, "abi");
        if (abi_item) {
            // Parse methods
            cJSON *methods_item = cJSON_GetObjectItem(abi_item, "methods");
            if (methods_item && cJSON_IsArray(methods_item)) {
                (*state)->manifest.abi.method_count = cJSON_GetArraySize(methods_item);
                if ((*state)->manifest.abi.method_count > 0) {
                    (*state)->manifest.abi.methods = neoc_calloc((*state)->manifest.abi.method_count, sizeof(neoc_contract_method_t));
                    // Parse method details if needed
                }
            }
            
            // Parse events
            cJSON *events_item = cJSON_GetObjectItem(abi_item, "events");
            if (events_item && cJSON_IsArray(events_item)) {
                (*state)->manifest.abi.event_count = cJSON_GetArraySize(events_item);
                if ((*state)->manifest.abi.event_count > 0) {
                    (*state)->manifest.abi.events = neoc_calloc((*state)->manifest.abi.event_count, sizeof(neoc_contract_event_t));
                    // Parse event details if needed
                }
            }
        }
        
        // Parse permissions
        cJSON *permissions_item = cJSON_GetObjectItem(item, "permissions");
        if (permissions_item && cJSON_IsArray(permissions_item)) {
            (*state)->manifest.permission_count = cJSON_GetArraySize(permissions_item);
            if ((*state)->manifest.permission_count > 0) {
                (*state)->manifest.permissions = neoc_calloc((*state)->manifest.permission_count, sizeof(neoc_contract_permission_t));
                // Parse permission details if needed
            }
        }
        
        // Parse trusts
        cJSON *trusts_item = cJSON_GetObjectItem(item, "trusts");
        if (trusts_item && cJSON_IsArray(trusts_item)) {
            (*state)->manifest.trust_count = cJSON_GetArraySize(trusts_item);
            if ((*state)->manifest.trust_count > 0) {
                (*state)->manifest.trusts = neoc_calloc((*state)->manifest.trust_count, sizeof(char*));
                // Parse trust details if needed
            }
        }
        
        // Parse extra field
        cJSON *extra_item = cJSON_GetObjectItem(item, "extra");
        if (extra_item) {
            char *extra_str = cJSON_PrintUnformatted(extra_item);
            if (extra_str) {
                (*state)->manifest.extra = neoc_strdup(extra_str);
                free(extra_str);
            }
        }
    }
    
    cJSON_Delete(json);
    neoc_free(result);
    
    return NEOC_SUCCESS;
#endif // HAVE_CJSON
#endif // HAVE_CURL
}

// Additional RPC methods

neoc_error_t neoc_rpc_get_committee(neoc_rpc_client_t *client, char **committee) {
    if (!client || !committee) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    return make_rpc_call(client, RPC_GET_COMMITTEE, "[]", committee);
}

neoc_error_t neoc_rpc_get_next_validators(neoc_rpc_client_t *client, char **validators) {
    if (!client || !validators) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    return make_rpc_call(client, RPC_GET_NEXT_VALIDATORS, "[]", validators);
}

neoc_error_t neoc_rpc_get_connection_count(neoc_rpc_client_t *client, uint32_t *count) {
    if (!client || !count) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    char *result = NULL;
    neoc_error_t err = make_rpc_call(client, RPC_GET_CONNECTION_COUNT, "[]", &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json && cJSON_IsNumber(json)) {
        *count = (uint32_t)json->valueint;
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
#else
    *count = (uint32_t)atoi(result);
#endif
    
    neoc_free(result);
    return err;
}

neoc_error_t neoc_rpc_get_peers(neoc_rpc_client_t *client, char **peers) {
    if (!client || !peers) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    return make_rpc_call(client, RPC_GET_PEERS, "[]", peers);
}

neoc_error_t neoc_rpc_get_raw_mempool(neoc_rpc_client_t *client, char **mempool) {
    if (!client || !mempool) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    return make_rpc_call(client, RPC_GET_MEMPOOL, "[]", mempool);
}

neoc_error_t neoc_rpc_get_transaction_height(neoc_rpc_client_t *client,
                                              const neoc_hash256_t *tx_hash,
                                              uint32_t *height) {
    if (!client || !tx_hash || !height) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    // Convert hash to hex string
    char hash_str[65];
    neoc_error_t err = neoc_hash256_to_hex(tx_hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
    // Build params
    char params[128];
    snprintf(params, sizeof(params), "[\"%s\"]", hash_str);
    
    char *result = NULL;
    err = make_rpc_call(client, RPC_GET_TRANSACTION_HEIGHT, params, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json && cJSON_IsNumber(json)) {
        *height = (uint32_t)json->valueint;
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
#else
    *height = (uint32_t)atoi(result);
#endif
    
    neoc_free(result);
    return err;
}

neoc_error_t neoc_rpc_get_state_height(neoc_rpc_client_t *client, uint32_t *height) {
    if (!client || !height) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    char *result = NULL;
    neoc_error_t err = make_rpc_call(client, RPC_GET_STATE_HEIGHT, "[]", &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    
#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json) {
        cJSON *local = cJSON_GetObjectItem(json, "localrootindex");
        if (local && cJSON_IsNumber(local)) {
            *height = (uint32_t)local->valueint;
        }
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
#else
    *height = 0;
#endif
    
    neoc_free(result);
    return err;
}

neoc_error_t neoc_rpc_get_native_contracts(neoc_rpc_client_t *client, char **contracts) {
    if (!client || !contracts) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    return make_rpc_call(client, RPC_GET_NATIVE_CONTRACTS, "[]", contracts);
}

/* ---- Phase 2: New RPC method implementations for Neo N3 v3.9.1 ---- */

neoc_error_t neoc_rpc_get_block_header(neoc_rpc_client_t *client,
                                        const neoc_hash256_t *hash,
                                        bool verbose,
                                        char **header) {
    if (!client || !hash || !header) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char hash_str[65];
    neoc_error_t err = neoc_hash256_to_hex(hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    char params[128];
    snprintf(params, sizeof(params), "[\"0x%s\", %d]", hash_str, verbose ? 1 : 0);

    return make_rpc_call(client, RPC_GET_BLOCK_HEADER, params, header);
}

neoc_error_t neoc_rpc_get_block_header_count(neoc_rpc_client_t *client, uint32_t *count) {
    if (!client || !count) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char *result = NULL;
    neoc_error_t err = make_rpc_call(client, RPC_GET_BLOCK_HEADER_COUNT, NULL, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }

#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json && cJSON_IsNumber(json)) {
        *count = (uint32_t)json->valueint;
        cJSON_Delete(json);
    } else {
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
    neoc_free(result);
#else
    neoc_free(result);
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif

    return err;
}

neoc_error_t neoc_rpc_invoke_contract_verify(neoc_rpc_client_t *client,
                                              const neoc_hash160_t *script_hash,
                                              const char *params,
                                              const char *signers,
                                              char **result) {
    if (!client || !script_hash || !result) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char hash_hex[NEOC_HASH160_STRING_LENGTH];
    neoc_error_t err = neoc_hash160_to_hex(script_hash, hash_hex, sizeof(hash_hex), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    char rpc_params[4096];
    snprintf(rpc_params, sizeof(rpc_params), "[\"0x%s\", %s, %s]",
             hash_hex,
             params ? params : "[]",
             signers ? signers : "[]");

    return make_rpc_call(client, RPC_INVOKE_CONTRACT_VERIFY, rpc_params, result);
}

neoc_error_t neoc_rpc_get_unclaimed_gas(neoc_rpc_client_t *client,
                                         const char *address,
                                         char **unclaimed) {
    if (!client || !address || !unclaimed) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[128];
    snprintf(params, sizeof(params), "[\"%s\"]", address);

    return make_rpc_call(client, RPC_GET_UNCLAIMED_GAS, params, unclaimed);
}

neoc_error_t neoc_rpc_calculate_network_fee(neoc_rpc_client_t *client,
                                             const uint8_t *tx_data,
                                             size_t tx_size,
                                             char **fee) {
    if (!client || !tx_data || !fee) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    size_t base64_len = neoc_base64_encode_buffer_size(tx_size);
    char *base64_tx = neoc_malloc(base64_len);
    if (!base64_tx) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate base64 buffer");
    }

    neoc_error_t err = neoc_base64_encode(tx_data, tx_size, base64_tx, base64_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(base64_tx);
        return err;
    }

    size_t params_len = base64_len + 8;
    char *params = neoc_malloc(params_len);
    if (!params) {
        neoc_free(base64_tx);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate params buffer");
    }
    snprintf(params, params_len, "[\"%s\"]", base64_tx);
    neoc_free(base64_tx);

    err = make_rpc_call(client, RPC_CALCULATE_NETWORK_FEE, params, fee);
    neoc_free(params);
    return err;
}

neoc_error_t neoc_rpc_get_nep17_transfers(neoc_rpc_client_t *client,
                                           const char *address,
                                           char **transfers) {
    if (!client || !address || !transfers) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[128];
    snprintf(params, sizeof(params), "[\"%s\"]", address);

    return make_rpc_call(client, RPC_GET_NEP17_TRANSFERS, params, transfers);
}

neoc_error_t neoc_rpc_get_nep11_balances(neoc_rpc_client_t *client,
                                          const char *address,
                                          char **balances) {
    if (!client || !address || !balances) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[128];
    snprintf(params, sizeof(params), "[\"%s\"]", address);

    return make_rpc_call(client, RPC_GET_NEP11_BALANCES, params, balances);
}

neoc_error_t neoc_rpc_get_nep11_transfers(neoc_rpc_client_t *client,
                                           const char *address,
                                           char **transfers) {
    if (!client || !address || !transfers) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[128];
    snprintf(params, sizeof(params), "[\"%s\"]", address);

    return make_rpc_call(client, RPC_GET_NEP11_TRANSFERS, params, transfers);
}

neoc_error_t neoc_rpc_get_nep11_properties(neoc_rpc_client_t *client,
                                            const neoc_hash160_t *script_hash,
                                            const char *token_id,
                                            char **properties) {
    if (!client || !script_hash || !token_id || !properties) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char hash_hex[NEOC_HASH160_STRING_LENGTH];
    neoc_error_t err = neoc_hash160_to_hex(script_hash, hash_hex, sizeof(hash_hex), false);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    char params[256];
    snprintf(params, sizeof(params), "[\"0x%s\", \"%s\"]", hash_hex, token_id);

    return make_rpc_call(client, RPC_GET_NEP11_PROPERTIES, params, properties);
}

neoc_error_t neoc_rpc_list_plugins(neoc_rpc_client_t *client, char **plugins) {
    if (!client || !plugins) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    return make_rpc_call(client, RPC_LIST_PLUGINS, NULL, plugins);
}

neoc_error_t neoc_rpc_submit_block(neoc_rpc_client_t *client,
                                    const uint8_t *block_data,
                                    size_t block_size,
                                    bool *accepted) {
    if (!client || !block_data || !accepted) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    size_t base64_len = neoc_base64_encode_buffer_size(block_size);
    char *base64_block = neoc_malloc(base64_len);
    if (!base64_block) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate base64 buffer");
    }

    neoc_error_t err = neoc_base64_encode(block_data, block_size, base64_block, base64_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(base64_block);
        return err;
    }

    size_t params_len = base64_len + 8;
    char *params = neoc_malloc(params_len);
    if (!params) {
        neoc_free(base64_block);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate params buffer");
    }
    snprintf(params, params_len, "[\"%s\"]", base64_block);
    neoc_free(base64_block);

    char *result = NULL;
    err = make_rpc_call(client, RPC_SUBMIT_BLOCK, params, &result);
    neoc_free(params);
    if (err != NEOC_SUCCESS) {
        return err;
    }

#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json && cJSON_IsBool(json)) {
        *accepted = cJSON_IsTrue(json);
        cJSON_Delete(json);
    } else {
        *accepted = false;
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
    neoc_free(result);
#else
    neoc_free(result);
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif

    return err;
}

neoc_error_t neoc_rpc_validate_address(neoc_rpc_client_t *client,
                                        const char *address,
                                        bool *is_valid) {
    if (!client || !address || !is_valid) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[128];
    snprintf(params, sizeof(params), "[\"%s\"]", address);

    char *result = NULL;
    neoc_error_t err = make_rpc_call(client, RPC_VALIDATE_ADDRESS, params, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }

#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json) {
        cJSON *valid = cJSON_GetObjectItem(json, "isvalid");
        *is_valid = (valid && cJSON_IsTrue(valid));
        cJSON_Delete(json);
    } else {
        *is_valid = false;
        err = neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Invalid response format");
    }
    neoc_free(result);
#else
    neoc_free(result);
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif

    return err;
}

neoc_error_t neoc_rpc_get_candidates(neoc_rpc_client_t *client, char **candidates) {
    if (!client || !candidates) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    return make_rpc_call(client, RPC_GET_CANDIDATES, NULL, candidates);
}

neoc_error_t neoc_rpc_traverse_iterator(neoc_rpc_client_t *client,
                                         const char *session_id,
                                         const char *iterator_id,
                                         uint32_t count,
                                         char **items) {
    if (!client || !session_id || !iterator_id || !items) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[256];
    snprintf(params, sizeof(params), "[\"%s\", \"%s\", %u]",
             session_id, iterator_id, count);

    return make_rpc_call(client, RPC_TRAVERSE_ITERATOR, params, items);
}

neoc_error_t neoc_rpc_terminate_session(neoc_rpc_client_t *client,
                                         const char *session_id,
                                         bool *success) {
    if (!client || !session_id || !success) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[128];
    snprintf(params, sizeof(params), "[\"%s\"]", session_id);

    char *result = NULL;
    neoc_error_t err = make_rpc_call(client, RPC_TERMINATE_SESSION, params, &result);
    if (err != NEOC_SUCCESS) {
        return err;
    }

#ifdef HAVE_CJSON
    cJSON *json = cJSON_Parse(result);
    if (json && cJSON_IsBool(json)) {
        *success = cJSON_IsTrue(json);
        cJSON_Delete(json);
    } else {
        *success = true; /* session termination returns true on success */
    }
    neoc_free(result);
#else
    neoc_free(result);
    err = neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "cJSON support not compiled in");
#endif

    return err;
}

neoc_error_t neoc_rpc_get_state_root(neoc_rpc_client_t *client,
                                      uint32_t index,
                                      char **state_root) {
    if (!client || !state_root) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char params[32];
    snprintf(params, sizeof(params), "[%u]", index);

    return make_rpc_call(client, RPC_GET_STATE_ROOT, params, state_root);
}

neoc_error_t neoc_rpc_get_state(neoc_rpc_client_t *client,
                                 const neoc_hash256_t *root_hash,
                                 const neoc_hash160_t *script_hash,
                                 const uint8_t *key,
                                 size_t key_size,
                                 char **value) {
    if (!client || !root_hash || !script_hash || !key || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char root_str[65];
    neoc_error_t err = neoc_hash256_to_hex(root_hash, root_str, sizeof(root_str), false);
    if (err != NEOC_SUCCESS) return err;

    char hash_str[41];
    err = neoc_hash160_to_hex(script_hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) return err;

    size_t b64_len = neoc_base64_encode_buffer_size(key_size);
    char *b64_key = neoc_malloc(b64_len);
    if (!b64_key) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate buffer");
    }
    err = neoc_base64_encode(key, key_size, b64_key, b64_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(b64_key);
        return err;
    }

    char params[512];
    snprintf(params, sizeof(params),
             "[\"0x%s\", \"0x%s\", \"%s\"]", root_str, hash_str, b64_key);
    neoc_free(b64_key);

    return make_rpc_call(client, RPC_GET_STATE, params, value);
}

neoc_error_t neoc_rpc_find_states(neoc_rpc_client_t *client,
                                   const neoc_hash256_t *root_hash,
                                   const neoc_hash160_t *script_hash,
                                   const uint8_t *prefix,
                                   size_t prefix_size,
                                   char **states) {
    if (!client || !root_hash || !script_hash || !prefix || !states) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char root_str[65];
    neoc_error_t err = neoc_hash256_to_hex(root_hash, root_str, sizeof(root_str), false);
    if (err != NEOC_SUCCESS) return err;

    char hash_str[41];
    err = neoc_hash160_to_hex(script_hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) return err;

    size_t b64_len = neoc_base64_encode_buffer_size(prefix_size);
    char *b64_prefix = neoc_malloc(b64_len);
    if (!b64_prefix) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate buffer");
    }
    err = neoc_base64_encode(prefix, prefix_size, b64_prefix, b64_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(b64_prefix);
        return err;
    }

    char params[512];
    snprintf(params, sizeof(params),
             "[\"0x%s\", \"0x%s\", \"%s\"]", root_str, hash_str, b64_prefix);
    neoc_free(b64_prefix);

    return make_rpc_call(client, RPC_FIND_STATES, params, states);
}

neoc_error_t neoc_rpc_get_proof(neoc_rpc_client_t *client,
                                 const neoc_hash256_t *root_hash,
                                 const neoc_hash160_t *script_hash,
                                 const uint8_t *key,
                                 size_t key_size,
                                 char **proof) {
    if (!client || !root_hash || !script_hash || !key || !proof) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char root_str[65];
    neoc_error_t err = neoc_hash256_to_hex(root_hash, root_str, sizeof(root_str), false);
    if (err != NEOC_SUCCESS) return err;

    char hash_str[41];
    err = neoc_hash160_to_hex(script_hash, hash_str, sizeof(hash_str), false);
    if (err != NEOC_SUCCESS) return err;

    size_t b64_len = neoc_base64_encode_buffer_size(key_size);
    char *b64_key = neoc_malloc(b64_len);
    if (!b64_key) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate buffer");
    }
    err = neoc_base64_encode(key, key_size, b64_key, b64_len);
    if (err != NEOC_SUCCESS) {
        neoc_free(b64_key);
        return err;
    }

    char params[512];
    snprintf(params, sizeof(params),
             "[\"0x%s\", \"0x%s\", \"%s\"]", root_str, hash_str, b64_key);
    neoc_free(b64_key);

    return make_rpc_call(client, RPC_GET_PROOF, params, proof);
}

neoc_error_t neoc_rpc_verify_proof(neoc_rpc_client_t *client,
                                    const neoc_hash256_t *root_hash,
                                    const char *proof,
                                    char **value) {
    if (!client || !root_hash || !proof || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    char root_str[65];
    neoc_error_t err = neoc_hash256_to_hex(root_hash, root_str, sizeof(root_str), false);
    if (err != NEOC_SUCCESS) return err;

    size_t params_len = strlen(proof) + 128;
    char *params = neoc_malloc(params_len);
    if (!params) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate params buffer");
    }
    snprintf(params, params_len, "[\"0x%s\", \"%s\"]", root_str, proof);

    err = make_rpc_call(client, RPC_VERIFY_PROOF, params, value);
    neoc_free(params);
    return err;
}
