#include "neoc/serialization/binary_writer.h"
#include "neoc/neoc_memory.h"
#include <stdlib.h>
#include <string.h>

#define MIN_CAPACITY 16
#define GROWTH_FACTOR 2

static neoc_error_t ensure_capacity(neoc_binary_writer_t *writer, size_t required) {
    if (writer->position + required <= writer->capacity) {
        return NEOC_SUCCESS;
    }
    
    if (!writer->auto_grow) {
        return neoc_error_set(NEOC_ERROR_BUFFER_OVERFLOW, "Binary writer buffer overflow");
    }
    
    size_t new_capacity = writer->capacity * GROWTH_FACTOR;
    while (new_capacity < writer->position + required) {
        new_capacity *= GROWTH_FACTOR;
    }
    
    uint8_t *new_data = neoc_realloc(writer->data, new_capacity);
    if (!new_data) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to grow binary writer buffer");
    }
    
    writer->data = new_data;
    writer->capacity = new_capacity;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_create(size_t initial_capacity,
                                        bool auto_grow,
                                        neoc_binary_writer_t **writer) {
    if (!writer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid writer pointer");
    }
    
    *writer = neoc_calloc(1, sizeof(neoc_binary_writer_t));
    if (!*writer) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate binary writer");
    }
    
    size_t capacity = initial_capacity > MIN_CAPACITY ? initial_capacity : MIN_CAPACITY;
    (*writer)->data = neoc_calloc(capacity, 1);
    if (!(*writer)->data) {
        neoc_free(*writer);
        *writer = NULL;
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate writer buffer");
    }
    
    (*writer)->capacity = capacity;
    (*writer)->position = 0;
    (*writer)->auto_grow = auto_grow;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_write_byte(neoc_binary_writer_t *writer,
                                            uint8_t value) {
    if (!writer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid writer");
    }
    
    neoc_error_t err = ensure_capacity(writer, 1);
    if (err != NEOC_SUCCESS) return err;
    
    writer->data[writer->position++] = value;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_write_bytes(neoc_binary_writer_t *writer,
                                             const uint8_t *data,
                                             size_t len) {
    if (!writer || !data) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (len == 0) return NEOC_SUCCESS;
    
    neoc_error_t err = ensure_capacity(writer, len);
    if (err != NEOC_SUCCESS) return err;
    
    memcpy(writer->data + writer->position, data, len);
    writer->position += len;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_write_bool(neoc_binary_writer_t *writer,
                                            bool value) {
    return neoc_binary_writer_write_byte(writer, value ? 1 : 0);
}

neoc_error_t neoc_binary_writer_write_uint16(neoc_binary_writer_t *writer,
                                              uint16_t value) {
    if (!writer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid writer");
    }
    
    neoc_error_t err = ensure_capacity(writer, 2);
    if (err != NEOC_SUCCESS) return err;
    
    // Little-endian
    writer->data[writer->position++] = (uint8_t)(value & 0xFF);
    writer->data[writer->position++] = (uint8_t)((value >> 8) & 0xFF);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_write_uint32(neoc_binary_writer_t *writer,
                                              uint32_t value) {
    if (!writer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid writer");
    }
    
    neoc_error_t err = ensure_capacity(writer, 4);
    if (err != NEOC_SUCCESS) return err;
    
    // Little-endian
    writer->data[writer->position++] = (uint8_t)(value & 0xFF);
    writer->data[writer->position++] = (uint8_t)((value >> 8) & 0xFF);
    writer->data[writer->position++] = (uint8_t)((value >> 16) & 0xFF);
    writer->data[writer->position++] = (uint8_t)((value >> 24) & 0xFF);
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_write_uint64(neoc_binary_writer_t *writer,
                                              uint64_t value) {
    if (!writer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid writer");
    }
    
    neoc_error_t err = ensure_capacity(writer, 8);
    if (err != NEOC_SUCCESS) return err;
    
    // Little-endian
    for (int i = 0; i < 8; i++) {
        writer->data[writer->position++] = (uint8_t)((value >> (i * 8)) & 0xFF);
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_write_int16(neoc_binary_writer_t *writer,
                                             int16_t value) {
    return neoc_binary_writer_write_uint16(writer, (uint16_t)value);
}

neoc_error_t neoc_binary_writer_write_int32(neoc_binary_writer_t *writer,
                                             int32_t value) {
    return neoc_binary_writer_write_uint32(writer, (uint32_t)value);
}

neoc_error_t neoc_binary_writer_write_int64(neoc_binary_writer_t *writer,
                                             int64_t value) {
    return neoc_binary_writer_write_uint64(writer, (uint64_t)value);
}

neoc_error_t neoc_binary_writer_write_var_int(neoc_binary_writer_t *writer,
                                               uint64_t value) {
    if (!writer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid writer");
    }
    
    if (value < 0xFD) {
        return neoc_binary_writer_write_byte(writer, (uint8_t)value);
    } else if (value <= 0xFFFF) {
        neoc_error_t err = neoc_binary_writer_write_byte(writer, 0xFD);
        if (err != NEOC_SUCCESS) return err;
        return neoc_binary_writer_write_uint16(writer, (uint16_t)value);
    } else if (value <= 0xFFFFFFFF) {
        neoc_error_t err = neoc_binary_writer_write_byte(writer, 0xFE);
        if (err != NEOC_SUCCESS) return err;
        return neoc_binary_writer_write_uint32(writer, (uint32_t)value);
    } else {
        neoc_error_t err = neoc_binary_writer_write_byte(writer, 0xFF);
        if (err != NEOC_SUCCESS) return err;
        return neoc_binary_writer_write_uint64(writer, value);
    }
}

neoc_error_t neoc_binary_writer_write_var_bytes(neoc_binary_writer_t *writer,
                                                 const uint8_t *data,
                                                 size_t len) {
    if (!writer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid writer");
    }
    
    neoc_error_t err = neoc_binary_writer_write_var_int(writer, len);
    if (err != NEOC_SUCCESS) return err;
    
    if (len > 0 && data) {
        return neoc_binary_writer_write_bytes(writer, data, len);
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_write_var_string(neoc_binary_writer_t *writer,
                                                  const char *str) {
    if (!writer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid writer");
    }
    
    if (!str) {
        return neoc_binary_writer_write_var_int(writer, 0);
    }
    
    size_t len = strlen(str);
    return neoc_binary_writer_write_var_bytes(writer, (const uint8_t*)str, len);
}

size_t neoc_binary_writer_get_position(const neoc_binary_writer_t *writer) {
    return writer ? writer->position : 0;
}

neoc_error_t neoc_binary_writer_get_data(const neoc_binary_writer_t *writer,
                                          const uint8_t **data,
                                          size_t *len) {
    if (!writer || !data || !len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *data = writer->data;
    *len = writer->position;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_writer_to_array(const neoc_binary_writer_t *writer,
                                          uint8_t **data,
                                          size_t *len) {
    if (!writer || !data || !len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
        *len = writer->position;
    if (*len == 0) {
        *data = NULL;
        return NEOC_SUCCESS;
    }

    *data = neoc_malloc(*len);
    if (!*data) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate output array");
    }

    memcpy(*data, writer->data, *len);
    
    return NEOC_SUCCESS;
}

void neoc_binary_writer_reset(neoc_binary_writer_t *writer) {
    if (writer) {
        writer->position = 0;
    }
}

void neoc_binary_writer_free(neoc_binary_writer_t *writer) {
    if (!writer) return;
    
    if (writer->data) {
        neoc_free(writer->data);
    }
    
    neoc_free(writer);
}
