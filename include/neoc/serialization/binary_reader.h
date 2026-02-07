#ifndef NEOC_BINARY_READER_H
#define NEOC_BINARY_READER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Binary reader for Neo protocol deserialization
 */
#ifndef NEOC_FORWARD_DECLARATIONS
#define NEOC_FORWARD_DECLARATIONS
typedef struct neoc_binary_reader neoc_binary_reader_t;
typedef struct neoc_binary_writer neoc_binary_writer_t;
#endif

struct neoc_binary_reader {
    const uint8_t *data;  // Data being read
    size_t size;          // Total size of data
    size_t position;      // Current read position
    size_t marker;        // Marked position for reset (-1 if not set)
    uint8_t *owned_data;  // Optional owned copy of data
};

/**
 * @brief Create a new binary reader
 * 
 * @param data Data to read from
 * @param size Size of data
 * @param reader Output reader (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_create(const uint8_t *data,
                                        size_t size,
                                        neoc_binary_reader_t **reader);

/**
 * @brief Read a single byte
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_byte(neoc_binary_reader_t *reader,
                                           uint8_t *value);

/**
 * @brief Read bytes
 * 
 * @param reader The reader
 * @param buffer Buffer to read into
 * @param len Number of bytes to read
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_bytes(neoc_binary_reader_t *reader,
                                            uint8_t *buffer,
                                            size_t len);

/**
 * @brief Read a boolean
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_bool(neoc_binary_reader_t *reader,
                                           bool *value);

/**
 * @brief Read uint16 (little-endian)
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_uint16(neoc_binary_reader_t *reader,
                                             uint16_t *value);

/**
 * @brief Read uint32 (little-endian)
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_uint32(neoc_binary_reader_t *reader,
                                             uint32_t *value);

/**
 * @brief Read uint64 (little-endian)
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_uint64(neoc_binary_reader_t *reader,
                                             uint64_t *value);

/**
 * @brief Read int16 (little-endian)
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_int16(neoc_binary_reader_t *reader,
                                            int16_t *value);

/**
 * @brief Read int32 (little-endian)
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_int32(neoc_binary_reader_t *reader,
                                            int32_t *value);

/**
 * @brief Read int64 (little-endian)
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_int64(neoc_binary_reader_t *reader,
                                            int64_t *value);

/**
 * @brief Read variable-length integer
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_var_int(neoc_binary_reader_t *reader,
                                              uint64_t *value);

/**
 * @brief Read variable-length bytes
 * 
 * @param reader The reader
 * @param data Output data (caller must free when non-NULL)
 * @param len Output length
 * @note Returns `NEOC_SUCCESS` with `*len == 0` and `*data == NULL` for empty payloads.
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_var_bytes(neoc_binary_reader_t *reader,
                                                uint8_t **data,
                                                size_t *len);

/**
 * @brief Read variable-length string
 * 
 * @param reader The reader
 * @param str Output string (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_var_string(neoc_binary_reader_t *reader,
                                                 char **str);

/**
 * @brief Get current position in reader
 * 
 * @param reader The reader
 * @return Current position
 */
size_t neoc_binary_reader_get_position(const neoc_binary_reader_t *reader);

/**
 * @brief Get remaining bytes
 * 
 * @param reader The reader
 * @return Number of bytes remaining
 */
size_t neoc_binary_reader_get_remaining(const neoc_binary_reader_t *reader);

/**
 * @brief Check if at end of data
 * 
 * @param reader The reader
 * @return true if at end
 */
bool neoc_binary_reader_is_at_end(const neoc_binary_reader_t *reader);

/**
 * @brief Seek to position
 * 
 * @param reader The reader
 * @param position Position to seek to
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_seek(neoc_binary_reader_t *reader,
                                      size_t position);

/**
 * @brief Skip bytes
 * 
 * @param reader The reader
 * @param count Number of bytes to skip
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_skip(neoc_binary_reader_t *reader,
                                      size_t count);

/**
 * @brief Mark current position for reset
 * 
 * @param reader The reader
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_mark(neoc_binary_reader_t *reader);

/**
 * @brief Reset to marked position
 * 
 * @param reader The reader
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_reset(neoc_binary_reader_t *reader);

/**
 * @brief Read encoded EC point
 * 
 * @param reader The reader
 * @param data Output EC point data (caller must free)
 * @param len Output length
 * @note Returns `NEOC_SUCCESS` with `*len == 0` and `*data == NULL` for empty payloads.
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_encoded_ec_point(neoc_binary_reader_t *reader,
                                                      uint8_t **data,
                                                      size_t *len);

/**
 * @brief Read PUSH data
 * 
 * @param reader The reader
 * @param data Output data (caller must free when non-NULL)
 * @param len Output length
 * @note Returns `NEOC_SUCCESS` with `*len == 0` and `*data == NULL` for empty payloads.
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_push_data(neoc_binary_reader_t *reader,
                                                uint8_t **data,
                                                size_t *len);

/**
 * @brief Read variable bytes with maximum limit
 * 
 * @param reader The reader
 * @param max_length Maximum length to read
 * @param data Output data (caller must free when non-NULL)
 * @param len Output length
 * @note Returns `NEOC_SUCCESS` with `*len == 0` and `*data == NULL` for empty payloads.
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_var_bytes_max(neoc_binary_reader_t *reader,
                                                    size_t max_length,
                                                    uint8_t **data,
                                                    size_t *len);

/**
 * @brief Read variable-length integer with maximum value
 * 
 * @param reader The reader
 * @param max_value Maximum value allowed
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_var_int_max(neoc_binary_reader_t *reader,
                                                  uint64_t max_value,
                                                  uint64_t *value);

/**
 * @brief Read PUSH string
 * 
 * @param reader The reader
 * @param str Output string (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_push_string(neoc_binary_reader_t *reader,
                                                  char **str);

/**
 * @brief Read PUSH integer (32-bit)
 * 
 * @param reader The reader
 * @param value Output value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_push_int(neoc_binary_reader_t *reader,
                                               int32_t *value);

/**
 * @brief Read PUSH big integer
 * 
 * @param reader The reader
 * @param data Output big integer data (caller must free)
 * @param len Output length
 * @note Returns `NEOC_SUCCESS` with `*len == 0` and `*data == NULL` for empty payloads.
 * @param is_negative Output sign flag
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_reader_read_push_big_int(neoc_binary_reader_t *reader,
                                                   uint8_t **data,
                                                   size_t *len,
                                                   bool *is_negative);

/**
 * @brief Free a binary reader
 * 
 * @param reader The reader to free
 */
void neoc_binary_reader_free(neoc_binary_reader_t *reader);

#ifdef __cplusplus
}
#endif

#endif // NEOC_BINARY_READER_H
