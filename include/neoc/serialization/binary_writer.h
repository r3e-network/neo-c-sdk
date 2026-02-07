#ifndef NEOC_BINARY_WRITER_H
#define NEOC_BINARY_WRITER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Binary writer for Neo protocol serialization
 */
#ifndef NEOC_FORWARD_DECLARATIONS
#define NEOC_FORWARD_DECLARATIONS
typedef struct neoc_binary_reader neoc_binary_reader_t;
typedef struct neoc_binary_writer neoc_binary_writer_t;
#endif

struct neoc_binary_writer {
    uint8_t *data;      // Buffer for written data
    size_t capacity;    // Allocated capacity
    size_t position;    // Current write position
    bool auto_grow;     // Auto-grow buffer when needed
};

/**
 * @brief Create a new binary writer
 * 
 * @param initial_capacity Initial buffer capacity
 * @param auto_grow Whether to auto-grow buffer
 * @param writer Output writer (caller must free)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_create(size_t initial_capacity,
                                        bool auto_grow,
                                        neoc_binary_writer_t **writer);

/**
 * @brief Write a single byte
 * 
 * @param writer The writer
 * @param value Byte value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_byte(neoc_binary_writer_t *writer,
                                            uint8_t value);

/**
 * @brief Write bytes
 * 
 * @param writer The writer
 * @param data Data to write
 * @param len Length of data
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_bytes(neoc_binary_writer_t *writer,
                                             const uint8_t *data,
                                             size_t len);

/**
 * @brief Write a boolean
 * 
 * @param writer The writer
 * @param value Boolean value
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_bool(neoc_binary_writer_t *writer,
                                            bool value);

/**
 * @brief Write uint16 (little-endian)
 * 
 * @param writer The writer
 * @param value Value to write
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_uint16(neoc_binary_writer_t *writer,
                                              uint16_t value);

/**
 * @brief Write uint32 (little-endian)
 * 
 * @param writer The writer
 * @param value Value to write
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_uint32(neoc_binary_writer_t *writer,
                                              uint32_t value);

/**
 * @brief Write uint64 (little-endian)
 * 
 * @param writer The writer
 * @param value Value to write
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_uint64(neoc_binary_writer_t *writer,
                                              uint64_t value);

/**
 * @brief Write int16 (little-endian)
 * 
 * @param writer The writer
 * @param value Value to write
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_int16(neoc_binary_writer_t *writer,
                                             int16_t value);

/**
 * @brief Write int32 (little-endian)
 * 
 * @param writer The writer
 * @param value Value to write
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_int32(neoc_binary_writer_t *writer,
                                             int32_t value);

/**
 * @brief Write int64 (little-endian)
 * 
 * @param writer The writer
 * @param value Value to write
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_int64(neoc_binary_writer_t *writer,
                                             int64_t value);

/**
 * @brief Write variable-length integer
 * 
 * @param writer The writer
 * @param value Value to write
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_var_int(neoc_binary_writer_t *writer,
                                               uint64_t value);

/**
 * @brief Write variable-length bytes with length prefix
 * 
 * @param writer The writer
 * @param data Data to write
 * @param len Length of data
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_var_bytes(neoc_binary_writer_t *writer,
                                                 const uint8_t *data,
                                                 size_t len);

/**
 * @brief Write variable-length string
 * 
 * @param writer The writer
 * @param str String to write (UTF-8)
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_write_var_string(neoc_binary_writer_t *writer,
                                                  const char *str);

/**
 * @brief Get current position in writer
 * 
 * @param writer The writer
 * @return Current position
 */
size_t neoc_binary_writer_get_position(const neoc_binary_writer_t *writer);

/**
 * @brief Get written data
 * 
 * @param writer The writer
 * @param data Output pointer to data (do not free)
 * @param len Output length
 * @note When the writer is empty, returns `NEOC_SUCCESS` with `*len == 0` and `*data == NULL`.
 *  When the writer is empty, returns `NEOC_SUCCESS` with `*len == 0` and `*data == NULL`.
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_get_data(const neoc_binary_writer_t *writer,
                                          const uint8_t **data,
                                          size_t *len);

/**
 * @brief Convert writer data to allocated buffer
 * 
 * @param writer The writer
 * @param data Output data (caller must free when non-NULL)
 * @param len Output length
 * @note When the writer is empty, returns `NEOC_SUCCESS` with `*len == 0` and `*data == NULL`.
 * @return NEOC_SUCCESS on success, error code otherwise
 */
neoc_error_t neoc_binary_writer_to_array(const neoc_binary_writer_t *writer,
                                          uint8_t **data,
                                          size_t *len);

/**
 * @brief Reset writer to beginning
 * 
 * @param writer The writer
 */
void neoc_binary_writer_reset(neoc_binary_writer_t *writer);

/**
 * @brief Free a binary writer
 * 
 * @param writer The writer to free
 */
void neoc_binary_writer_free(neoc_binary_writer_t *writer);

#ifdef __cplusplus
}
#endif

#endif // NEOC_BINARY_WRITER_H
