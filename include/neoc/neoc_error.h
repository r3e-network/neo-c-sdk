/**
 * @file neoc_error.h
 * @brief Error handling system for NeoC SDK
 * 
 * Provides comprehensive error reporting with error codes, messages,
 * and stack traces for debugging. Thread-safe and memory-safe.
 */

#ifndef NEOC_ERROR_H
#define NEOC_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Error codes used throughout NeoC SDK
 */
typedef enum {
    NEOC_SUCCESS = 0,                    ///< Operation completed successfully
    
    /* General errors */
    NEOC_ERROR_NULL_POINTER = -1,       ///< Null pointer provided
    NEOC_ERROR_INVALID_ARGUMENT = -2,   ///< Invalid argument provided
    NEOC_ERROR_OUT_OF_MEMORY = -3,      ///< Memory allocation failed
    NEOC_ERROR_BUFFER_TOO_SMALL = -4,   ///< Buffer too small for operation
    NEOC_ERROR_INVALID_STATE = -5,      ///< Object in invalid state
    NEOC_ERROR_NOT_IMPLEMENTED = -6,    ///< Feature not implemented
    NEOC_ERROR_INVALID_LENGTH = -7,     ///< Invalid length provided
    NEOC_ERROR_END_OF_STREAM = -8,      ///< End of stream reached
    NEOC_ERROR_BUFFER_OVERFLOW = -9,    ///< Buffer overflow occurred
    
    /* Parsing/Format errors */
    NEOC_ERROR_INVALID_FORMAT = -10,    ///< Invalid format for data
    NEOC_ERROR_INVALID_HEX = -11,       ///< Invalid hexadecimal string
    NEOC_ERROR_INVALID_BASE58 = -12,    ///< Invalid Base58 string
    NEOC_ERROR_INVALID_BASE64 = -13,    ///< Invalid Base64 string
    NEOC_ERROR_DESERIALIZE = -14,       ///< Deserialization failed
    NEOC_ERROR_SERIALIZE = -15,         ///< Serialization failed
    NEOC_ERROR_OUT_OF_BOUNDS = -16,     ///< Index out of bounds
    NEOC_ERROR_NOT_FOUND = -17,         ///< Item not found
    NEOC_ERROR_INVALID_SIZE = -18,      ///< Invalid size
    NEOC_ERROR_INVALID_PASSWORD = -19,  ///< Invalid password
    NEOC_ERROR_NOT_SUPPORTED = -101,    ///< Operation not supported

    /* Deprecated aliases - use canonical names instead */
    /** @deprecated Use NEOC_ERROR_INVALID_ARGUMENT instead */
    NEOC_ERROR_INVALID_PARAM = NEOC_ERROR_INVALID_ARGUMENT,
    /** @deprecated Use NEOC_ERROR_INVALID_FORMAT instead */
    NEOC_ERROR_INVALID_DATA = NEOC_ERROR_INVALID_FORMAT,
    /** @deprecated Use NEOC_ERROR_INVALID_FORMAT instead */
    NEOC_ERROR_INVALID_TYPE = NEOC_ERROR_INVALID_FORMAT,
    /** @deprecated Use NEOC_ERROR_BUFFER_OVERFLOW instead */
    NEOC_ERROR_OVERFLOW = NEOC_ERROR_BUFFER_OVERFLOW,

    /* Cryptographic errors */
    NEOC_ERROR_CRYPTO = -20,            ///< Generic cryptographic error
    NEOC_ERROR_CRYPTO_INIT = -21,       ///< Cryptographic initialization failed
    NEOC_ERROR_CRYPTO_INVALID_KEY = -22, ///< Invalid cryptographic key
    NEOC_ERROR_CRYPTO_SIGN = -23,       ///< Signing operation failed
    NEOC_ERROR_CRYPTO_VERIFY = -24,     ///< Verification failed
    NEOC_ERROR_CRYPTO_HASH = -25,       ///< Hash operation failed
    NEOC_ERROR_CRYPTO_RANDOM = -26,     ///< Random generation failed
    
    /* Alias for compatibility */
    NEOC_ERROR_MEMORY = NEOC_ERROR_OUT_OF_MEMORY,
    
    /* Network/Protocol errors */
    NEOC_ERROR_NETWORK = -30,           ///< Network operation failed
    NEOC_ERROR_PROTOCOL = -31,          ///< Protocol error
    NEOC_ERROR_RPC = -32,               ///< RPC call failed
    NEOC_ERROR_HTTP = -33,              ///< HTTP request failed
    
    /* Transaction errors */
    NEOC_ERROR_TX_INVALID = -40,        ///< Invalid transaction
    NEOC_ERROR_TX_SIZE = -41,           ///< Transaction size exceeded
    NEOC_ERROR_TX_SCRIPT = -42,         ///< Transaction script error
    NEOC_ERROR_TX_WITNESS = -43,        ///< Transaction witness error
    
    /* Contract errors */
    NEOC_ERROR_CONTRACT_INVALID = -50,  ///< Invalid contract
    NEOC_ERROR_CONTRACT_INVOKE = -51,   ///< Contract invocation failed
    NEOC_ERROR_CONTRACT_MANIFEST = -52, ///< Contract manifest error
    
    /* Wallet errors */
    NEOC_ERROR_WALLET_INVALID = -60,    ///< Invalid wallet
    NEOC_ERROR_WALLET_LOCKED = -61,     ///< Wallet is locked
    NEOC_ERROR_WALLET_DECRYPT = -62,    ///< Wallet decryption failed
    NEOC_ERROR_WALLET_ACCOUNT = -63,    ///< Account error
    
    /* System errors */
    NEOC_ERROR_SYSTEM = -70,            ///< System error
    NEOC_ERROR_IO = -71,                ///< I/O error
    NEOC_ERROR_TIMEOUT = -72,           ///< Operation timed out
    NEOC_ERROR_CANCELLED = -73,         ///< Operation cancelled
    NEOC_ERROR_FILE = -74,              ///< File operation failed
    NEOC_ERROR_FILE_NOT_FOUND = -75,    ///< File not found
    
    /* Internal errors */
    NEOC_ERROR_INTERNAL = -100          ///< Internal SDK error
} neoc_error_t;

/**
 * @brief Maximum length for error messages
 */
#define NEOC_MAX_ERROR_MESSAGE_LENGTH 512

/**
 * @brief Maximum length for error context information
 */
#define NEOC_MAX_ERROR_CONTEXT_LENGTH 256

/**
 * @brief Error information structure
 * 
 * Contains detailed information about an error including code,
 * message, file, line, and function where error occurred.
 */
typedef struct {
    neoc_error_t code;                                    ///< Error code
    char message[NEOC_MAX_ERROR_MESSAGE_LENGTH];          ///< Error message
    char context[NEOC_MAX_ERROR_CONTEXT_LENGTH];          ///< Additional context
    const char* file;                                     ///< Source file where error occurred
    int line;                                             ///< Line number where error occurred
    const char* function;                                 ///< Function where error occurred
} neoc_error_info_t;

/**
 * @brief Get string representation of error code
 * 
 * @param error_code The error code
 * @return String representation of the error code
 */
const char* neoc_error_string(neoc_error_t error_code);

/**
 * @brief Check if error code represents success
 * 
 * @param error_code The error code to check
 * @return true if success, false if error
 */
bool neoc_is_success(neoc_error_t error_code);

/**
 * @brief Check if error code represents failure
 * 
 * @param error_code The error code to check
 * @return true if error, false if success
 */
bool neoc_is_error(neoc_error_t error_code);

/**
 * @brief Set detailed error information
 * 
 * This function is typically used internally by the SDK.
 * 
 * @param info Pointer to error info structure to populate
 * @param code Error code
 * @param message Error message (can be NULL)
 * @param context Additional context (can be NULL)
 * @param file Source file name
 * @param line Line number
 * @param function Function name
 * @return NEOC_SUCCESS on success, error code on failure
 */
neoc_error_t neoc_set_error_info(neoc_error_info_t* info, 
                                 neoc_error_t code,
                                 const char* message,
                                 const char* context,
                                 const char* file,
                                 int line,
                                 const char* function);

/**
 * @brief Get the last error that occurred in the current thread
 * 
 * @return Pointer to error info structure, or NULL if no error
 */
const neoc_error_info_t* neoc_get_last_error(void);

/**
 * @brief Set error with message (convenience function)
 * 
 * @param code Error code
 * @param message Error message
 * @return The error code passed in
 */
neoc_error_t neoc_error_set(neoc_error_t code, const char* message);

/**
 * @brief Clear the last error for the current thread
 */
void neoc_clear_last_error(void);

/**
 * @brief Format error information into a human-readable string
 * 
 * @param info Error info structure
 * @param buffer Output buffer
 * @param buffer_size Size of output buffer
 * @return Number of characters written (excluding null terminator)
 */
size_t neoc_format_error(const neoc_error_info_t* info, char* buffer, size_t buffer_size);

/* Convenience macros for error handling */

/**
 * @brief Set error and return error code
 */
#define NEOC_SET_ERROR(code, msg, ctx) \
    do { \
        neoc_error_info_t error_info; \
        neoc_set_error_info(&error_info, (code), (msg), (ctx), __FILE__, __LINE__, __func__); \
        return (code); \
    } while(0)

/**
 * @brief Set error with formatted message and return error code
 */
#define NEOC_SET_ERROR_FMT(code, fmt, ...) \
    do { \
        char error_msg[NEOC_MAX_ERROR_MESSAGE_LENGTH]; \
        snprintf(error_msg, sizeof(error_msg), (fmt), __VA_ARGS__); \
        NEOC_SET_ERROR((code), error_msg, NULL); \
    } while(0)

/**
 * @brief Check condition and set error if false
 */
#define NEOC_CHECK(condition, code, msg) \
    do { \
        if (!(condition)) { \
            NEOC_SET_ERROR((code), (msg), NULL); \
        } \
    } while(0)

/**
 * @brief Check for null pointer and set error if null
 */
#define NEOC_CHECK_NULL(ptr) \
    do { \
        if ((ptr) == NULL) { \
            NEOC_SET_ERROR(NEOC_ERROR_NULL_POINTER, "Null pointer: " #ptr, NULL); \
        } \
    } while(0)

/**
 * @brief Propagate error from called function
 */
#define NEOC_PROPAGATE_ERROR(result) \
    do { \
        neoc_error_t _err = (result); \
        if (neoc_is_error(_err)) { \
            return _err; \
        } \
    } while(0)

#ifdef __cplusplus
}
#endif

#endif /* NEOC_ERROR_H */
