#ifndef NEOC_NEO_SERIALIZABLE_H
#define NEOC_NEO_SERIALIZABLE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "neoc/neoc_error.h"
#include "neoc/serialization/binary_reader.h"
#include "neoc/serialization/binary_writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file neo_serializable.h
 * @brief Neo serialization protocol interface for C implementation
 * 
 * This header defines the interface for serializable objects in the Neo C SDK.
 * It provides function pointers for serialization operations that types can implement
 * to support binary serialization and deserialization compatible with the Neo protocol.
 * 
 * The interface is designed to be memory-safe and thread-safe, with proper error handling
 * and resource management. All serializable types must implement the required function
 * pointers and provide proper cleanup mechanisms.
 * 
 * @author NeoC SDK Team
 * @version 1.1.0
 * @date 2024
 */

/**
 * @brief Forward declaration for serializable object
 */
typedef struct neoc_serializable neoc_serializable_t;

/**
 * @brief Serialization function type
 * 
 * Function pointer type for serializing an object to a binary writer.
 * Implementations should write the object's data in Neo protocol format.
 * 
 * @param obj The object to serialize (must not be NULL)
 * @param writer The binary writer to write to (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 */
typedef neoc_error_t (*neoc_serialize_func_t)(const neoc_serializable_t *obj, 
                                               neoc_binary_writer_t *writer);

/**
 * @brief Deserialization function type
 * 
 * Function pointer type for deserializing an object from a binary reader.
 * Implementations should read data in Neo protocol format and construct the object.
 * The caller is responsible for freeing the returned object.
 * 
 * @param reader The binary reader to read from (must not be NULL)
 * @param obj Output object pointer (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 */
typedef neoc_error_t (*neoc_deserialize_func_t)(neoc_binary_reader_t *reader, 
                                                 neoc_serializable_t **obj);

/**
 * @brief Get size function type
 * 
 * Function pointer type for getting the serialized size of an object.
 * This should return the number of bytes that would be written by serialize().
 * 
 * @param obj The object to measure (must not be NULL)
 * @param size Output size in bytes (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 */
typedef neoc_error_t (*neoc_get_size_func_t)(const neoc_serializable_t *obj, 
                                              size_t *size);

/**
 * @brief Free function type
 * 
 * Function pointer type for freeing a serializable object and its resources.
 * Implementations must free all allocated memory associated with the object.
 * 
 * @param obj The object to free (may be NULL)
 */
typedef void (*neoc_serializable_free_func_t)(neoc_serializable_t *obj);

/**
 * @brief Clone function type
 * 
 * Function pointer type for creating a deep copy of a serializable object.
 * The caller is responsible for freeing the returned object.
 * 
 * @param obj The object to clone (must not be NULL)
 * @param clone Output cloned object (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 */
typedef neoc_error_t (*neoc_clone_func_t)(const neoc_serializable_t *obj, 
                                           neoc_serializable_t **clone);

/**
 * @brief Serializable object interface
 * 
 * Minimal set of function pointers each Neo-serializable type must expose.
 * The structure is typically embedded as the first field of user-defined
 * objects so it can be cast back to the concrete type inside callbacks.
 */
struct neoc_serializable {
    neoc_serialize_func_t serialize;       /**< Serialization function (required) */
    neoc_deserialize_func_t deserialize;   /**< Deserialization function (required) */
    neoc_get_size_func_t get_size;         /**< Size calculation function (required) */
    neoc_serializable_free_func_t free_obj;/**< Object cleanup function (required) */
    neoc_clone_func_t clone;               /**< Object cloning function (optional, may be NULL) */
};

/**
 * @brief Serialize object to byte array
 * 
 * Serializes a serializable object to a newly allocated byte array.
 * This is a convenience function that creates a binary writer internally.
 * The caller is responsible for freeing the returned data.
 * 
 * @param obj The object to serialize (must not be NULL and be valid)
 * @param data Output byte array (must not be NULL, caller must free when non-NULL)
 * @param len Output length of data (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 * 
 * @note Thread Safety: This function is thread-safe if the object's serialize
 *       function is thread-safe (which depends on the specific implementation).
 * 
 * @note Memory Management: The caller must call free() on the returned data when non-NULL.
 *       On success for zero-length serializations, `*len == 0` and `*data == NULL`.
 *       If this function fails, `*data` will be NULL and no cleanup is needed.
 */
neoc_error_t neoc_serializable_to_array(const neoc_serializable_t *obj,
                                         uint8_t **data,
                                         size_t *len);

/**
 * @brief Deserialize object from byte array
 * 
 * Deserializes an object from a byte array using the provided deserialize function.
 * This is a convenience function that creates a binary reader internally.
 * The caller is responsible for freeing the returned object.
 * 
 * @param data Input byte array (must not be NULL)
 * @param len Length of input data (must be > 0)
 * @param deserialize_func Deserialization function (must not be NULL)
 * @param obj Output object (must not be NULL, caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 * 
 * @note Thread Safety: This function is thread-safe if the deserialize_func
 *       is thread-safe (which depends on the specific implementation).
 * 
 * @note Memory Management: The caller must call the object's free function.
 *       If this function fails, *obj will be NULL and no cleanup is needed.
 */
neoc_error_t neoc_serializable_from_array(const uint8_t *data,
                                           size_t len,
                                           neoc_deserialize_func_t deserialize_func,
                                           neoc_serializable_t **obj);

/**
 * @brief Validate serializable object
 * 
 * Validates that a serializable object has all required function pointers
 * and is in a valid state for use. This should be called after object creation
 * to ensure the object is properly initialized.
 * 
 * @param obj The object to validate (may be NULL)
 * @return NEOC_SUCCESS if valid, NEOC_INVALID_ARGUMENT if invalid
 * 
 * @note This function is thread-safe and can be called concurrently.
 */
neoc_error_t neoc_serializable_validate(const neoc_serializable_t *obj);

/**
 * @brief Get serialized size of object
 * 
 * Gets the serialized size of an object without actually serializing it.
 * This is useful for pre-allocating buffers or calculating total sizes.
 * 
 * @param obj The object to measure (must not be NULL and be valid)
 * @param size Output size in bytes (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 * 
 * @note Thread Safety: This function is thread-safe if the object's get_size
 *       function is thread-safe (which depends on the specific implementation).
 */
neoc_error_t neoc_serializable_get_size(const neoc_serializable_t *obj,
                                         size_t *size);

/**
 * @brief Serialize object to writer
 * 
 * Serializes an object to a binary writer. This is the primary serialization
 * function and delegates to the object's serialize function pointer.
 * 
 * @param obj The object to serialize (must not be NULL and be valid)
 * @param writer The binary writer (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 * 
 * @note Thread Safety: This function is thread-safe if the object's serialize
 *       function is thread-safe (which depends on the specific implementation).
 */
neoc_error_t neoc_serializable_serialize(const neoc_serializable_t *obj,
                                          neoc_binary_writer_t *writer);

/**
 * @brief Clone a serializable object
 * 
 * Creates a deep copy of a serializable object. The returned object is
 * completely independent of the original and must be freed separately.
 * 
 * @param obj The object to clone (must not be NULL and be valid)
 * @param clone Output cloned object (must not be NULL, caller must free)
 * @return NEOC_SUCCESS on success, error code on failure
 * 
 * @note If the object doesn't implement cloning (clone function is NULL),
 *       this will return NEOC_NOT_SUPPORTED.
 * 
 * @note Thread Safety: This function is thread-safe if the object's clone
 *       function is thread-safe (which depends on the specific implementation).
 */
neoc_error_t neoc_serializable_clone(const neoc_serializable_t *obj,
                                      neoc_serializable_t **clone);

/**
 * @brief Free a serializable object
 * 
 * Frees a serializable object and all its associated resources.
 * This function delegates to the object's free function pointer.
 * 
 * @param obj The object to free (may be NULL, in which case this is a no-op)
 * 
 * @note This function is always safe to call, even with NULL pointers.
 * @note After calling this function, the object pointer becomes invalid.
 */
void neoc_serializable_free(neoc_serializable_t *obj);

/**
 * @brief Serialize array of objects
 * 
 * Serializes an array of serializable objects to a binary writer.
 * This includes a variable-length count prefix followed by each object's data.
 * This follows the Neo protocol format for serializable arrays.
 * 
 * @param objects Array of object pointers (must not be NULL if count > 0)
 * @param count Number of objects in array
 * @param writer Binary writer to write to (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 * 
 * @note All objects in the array must be valid serializable objects.
 * @note Thread Safety: This function is thread-safe if all objects' serialize
 *       functions are thread-safe.
 */
neoc_error_t neoc_serializable_array_serialize(neoc_serializable_t **objects,
                                                size_t count,
                                                neoc_binary_writer_t *writer);

/**
 * @brief Deserialize array of objects
 * 
 * Deserializes an array of objects from a binary reader.
 * This reads a variable-length count prefix followed by each object's data.
 * The caller is responsible for freeing all returned objects.
 * 
 * @param reader Binary reader to read from (must not be NULL)
 * @param deserialize_func Deserialization function for objects (must not be NULL)
 * @param objects Output array of object pointers (must not be NULL, caller must free each)
 * @param count Output number of objects (must not be NULL)
 * @param max_count Maximum number of objects to read (0 for no limit)
 * @return NEOC_SUCCESS on success, error code on failure
 * 
 * @note If this function fails, any successfully deserialized objects will be
 *       freed automatically, and *objects will be NULL.
 * 
 * @note Thread Safety: This function is thread-safe if deserialize_func
 *       is thread-safe.
 */
neoc_error_t neoc_serializable_array_deserialize(neoc_binary_reader_t *reader,
                                                  neoc_deserialize_func_t deserialize_func,
                                                  neoc_serializable_t ***objects,
                                                  size_t *count,
                                                  size_t max_count);

/**
 * @brief Free array of serializable objects
 * 
 * Frees an array of serializable objects and the array itself.
 * Each object is freed using its free function, then the array is freed.
 * 
 * @param objects Array of object pointers (may be NULL)
 * @param count Number of objects in array
 * 
 * @note This function is safe to call with NULL objects pointer.
 * @note Individual object pointers in the array may be NULL and will be skipped.
 */
void neoc_serializable_array_free(neoc_serializable_t **objects, size_t count);

/**
 * @brief Get total size of serializable array
 * 
 * Calculates the total serialized size of an array of objects.
 * This includes the variable-length count prefix plus all object sizes.
 * 
 * @param objects Array of object pointers (must not be NULL if count > 0)
 * @param count Number of objects in array
 * @param total_size Output total size (must not be NULL)
 * @return NEOC_SUCCESS on success, error code on failure
 * 
 * @note All objects in the array must be valid serializable objects.
 * @note Thread Safety: This function is thread-safe if all objects' get_size
 *       functions are thread-safe.
 */
neoc_error_t neoc_serializable_array_get_size(neoc_serializable_t **objects,
                                               size_t count,
                                               size_t *total_size);

// Common type IDs for built-in serializable types
#define NEOC_SERIALIZABLE_TYPE_UNKNOWN        0x00000000
#define NEOC_SERIALIZABLE_TYPE_TRANSACTION    0x00000001
#define NEOC_SERIALIZABLE_TYPE_WITNESS        0x00000002
#define NEOC_SERIALIZABLE_TYPE_SIGNER         0x00000003
#define NEOC_SERIALIZABLE_TYPE_STACK_ITEM     0x00000004
#define NEOC_SERIALIZABLE_TYPE_CONTRACT_PARAM 0x00000005
#define NEOC_SERIALIZABLE_TYPE_CONTRACT_STATE 0x00000006
#define NEOC_SERIALIZABLE_TYPE_NEF_FILE       0x00000007
#define NEOC_SERIALIZABLE_TYPE_BLOCK          0x00000008
#define NEOC_SERIALIZABLE_TYPE_HEADER         0x00000009
#define NEOC_SERIALIZABLE_TYPE_MANIFEST       0x0000000A

// Version constants
#define NEOC_SERIALIZABLE_VERSION_1           0x00000001
#define NEOC_SERIALIZABLE_VERSION_CURRENT     NEOC_SERIALIZABLE_VERSION_1

#ifdef __cplusplus
}
#endif

#endif // NEOC_NEO_SERIALIZABLE_H
