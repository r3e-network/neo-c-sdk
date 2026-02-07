#include "neoc/serialization/binary_reader.h"
#include "neoc/script/opcode.h"
#include "neoc/neoc_memory.h"
#include <stdlib.h>
#include <string.h>

neoc_error_t neoc_binary_reader_create(const uint8_t *data,
                                        size_t size,
                                        neoc_binary_reader_t **reader) {
    if (!data || !reader) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *reader = neoc_calloc(1, sizeof(neoc_binary_reader_t));
    if (!*reader) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate binary reader");
    }
    
    uint8_t *copy = neoc_malloc(size);
    if (!copy) {
        neoc_free(*reader);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate reader buffer");
    }
    memcpy(copy, data, size);

    (*reader)->data = copy;
    (*reader)->owned_data = copy;
    (*reader)->size = size;
    (*reader)->position = 0;
    (*reader)->marker = SIZE_MAX; // No marker set initially
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_byte(neoc_binary_reader_t *reader,
                                           uint8_t *value) {
    if (!reader || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (reader->position >= reader->size) {
        return neoc_error_set(NEOC_ERROR_END_OF_STREAM, "End of stream reached");
    }
    
    *value = reader->data[reader->position++];
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_bytes(neoc_binary_reader_t *reader,
                                            uint8_t *buffer,
                                            size_t len) {
    if (!reader || !buffer) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (len == 0) return NEOC_SUCCESS;
    
    if (reader->position + len > reader->size) {
        return neoc_error_set(NEOC_ERROR_END_OF_STREAM, "Not enough data to read");
    }
    
    memcpy(buffer, reader->data + reader->position, len);
    reader->position += len;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_bool(neoc_binary_reader_t *reader,
                                           bool *value) {
    if (!reader || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint8_t byte_val = 0;
    neoc_error_t err = neoc_binary_reader_read_byte(reader, &byte_val);
    if (err != NEOC_SUCCESS) return err;
    
    *value = (byte_val != 0);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_uint16(neoc_binary_reader_t *reader,
                                             uint16_t *value) {
    if (!reader || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (reader->position + 2 > reader->size) {
        return neoc_error_set(NEOC_ERROR_END_OF_STREAM, "Not enough data to read uint16");
    }
    
    // Little-endian
    *value = (uint16_t)reader->data[reader->position] |
             ((uint16_t)reader->data[reader->position + 1] << 8);
    reader->position += 2;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_uint32(neoc_binary_reader_t *reader,
                                             uint32_t *value) {
    if (!reader || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (reader->position + 4 > reader->size) {
        return neoc_error_set(NEOC_ERROR_END_OF_STREAM, "Not enough data to read uint32");
    }
    
    // Little-endian
    *value = (uint32_t)reader->data[reader->position] |
             ((uint32_t)reader->data[reader->position + 1] << 8) |
             ((uint32_t)reader->data[reader->position + 2] << 16) |
             ((uint32_t)reader->data[reader->position + 3] << 24);
    reader->position += 4;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_uint64(neoc_binary_reader_t *reader,
                                             uint64_t *value) {
    if (!reader || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    if (reader->position + 8 > reader->size) {
        return neoc_error_set(NEOC_ERROR_END_OF_STREAM, "Not enough data to read uint64");
    }
    
    // Little-endian
    *value = 0;
    for (int i = 0; i < 8; i++) {
        *value |= ((uint64_t)reader->data[reader->position + i] << (i * 8));
    }
    reader->position += 8;
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_int16(neoc_binary_reader_t *reader,
                                            int16_t *value) {
    return neoc_binary_reader_read_uint16(reader, (uint16_t*)value);
}

neoc_error_t neoc_binary_reader_read_int32(neoc_binary_reader_t *reader,
                                            int32_t *value) {
    return neoc_binary_reader_read_uint32(reader, (uint32_t*)value);
}

neoc_error_t neoc_binary_reader_read_int64(neoc_binary_reader_t *reader,
                                            int64_t *value) {
    return neoc_binary_reader_read_uint64(reader, (uint64_t*)value);
}

neoc_error_t neoc_binary_reader_read_var_int(neoc_binary_reader_t *reader,
                                              uint64_t *value) {
    if (!reader || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint8_t prefix = 0;
    neoc_error_t err = neoc_binary_reader_read_byte(reader, &prefix);
    if (err != NEOC_SUCCESS) return err;
    
    if (prefix < 0xFD) {
        *value = prefix;
        return NEOC_SUCCESS;
    } else if (prefix == 0xFD) {
        uint16_t val = 0;
        err = neoc_binary_reader_read_uint16(reader, &val);
        if (err != NEOC_SUCCESS) return err;
        *value = val;
        return NEOC_SUCCESS;
    } else if (prefix == 0xFE) {
        uint32_t val = 0;
        err = neoc_binary_reader_read_uint32(reader, &val);
        if (err != NEOC_SUCCESS) return err;
        *value = val;
        return NEOC_SUCCESS;
    } else { // 0xFF
        return neoc_binary_reader_read_uint64(reader, value);
    }
}

neoc_error_t neoc_binary_reader_read_var_bytes(neoc_binary_reader_t *reader,
                                                uint8_t **data,
                                                size_t *len) {
    if (!reader || !data || !len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint64_t length = 0;
    neoc_error_t err = neoc_binary_reader_read_var_int(reader, &length);
    if (err != NEOC_SUCCESS) return err;
    
    if (length > SIZE_MAX) {
        return neoc_error_set(NEOC_ERROR_INVALID_FORMAT, "Variable bytes length too large");
    }
    
    *len = (size_t)length;
    
    if (*len == 0) {
        *data = NULL;
        return NEOC_SUCCESS;
    }
    
    *data = neoc_malloc(*len);
    if (!*data) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate data buffer");
    }
    
    err = neoc_binary_reader_read_bytes(reader, *data, *len);
    if (err != NEOC_SUCCESS) {
        neoc_free(*data);
        *data = NULL;
        *len = 0;
        return err;
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_var_string(neoc_binary_reader_t *reader,
                                                 char **str) {
    if (!reader || !str) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint8_t *data;
    size_t len;
    neoc_error_t err = neoc_binary_reader_read_var_bytes(reader, &data, &len);
    if (err != NEOC_SUCCESS) return err;
    
    if (len == 0) {
        *str = neoc_calloc(1, 1);  // Empty string
        if (!*str) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate empty string");
        }
        return NEOC_SUCCESS;
    }
    
    *str = neoc_malloc(len + 1);
    if (!*str) {
        neoc_free(data);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate string");
    }
    
    memcpy(*str, data, len);
    (*str)[len] = '\0';
    
    neoc_free(data);
    return NEOC_SUCCESS;
}

size_t neoc_binary_reader_get_position(const neoc_binary_reader_t *reader) {
    return reader ? reader->position : 0;
}

size_t neoc_binary_reader_get_remaining(const neoc_binary_reader_t *reader) {
    if (!reader || reader->position >= reader->size) {
        return 0;
    }
    return reader->size - reader->position;
}

bool neoc_binary_reader_is_at_end(const neoc_binary_reader_t *reader) {
    return !reader || reader->position >= reader->size;
}

neoc_error_t neoc_binary_reader_seek(neoc_binary_reader_t *reader,
                                      size_t position) {
    if (!reader) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid reader");
    }
    
    if (position > reader->size) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Position beyond data size");
    }
    
    reader->position = position;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_skip(neoc_binary_reader_t *reader,
                                      size_t count) {
    if (!reader) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid reader");
    }
    
    if (reader->position + count > reader->size) {
        return neoc_error_set(NEOC_ERROR_END_OF_STREAM, "Not enough data to skip");
    }
    
    reader->position += count;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_mark(neoc_binary_reader_t *reader) {
    if (!reader) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid reader");
    }
    
    reader->marker = reader->position;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_reset(neoc_binary_reader_t *reader) {
    if (!reader) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid reader");
    }
    
    if (reader->marker == SIZE_MAX) {
        return neoc_error_set(NEOC_ERROR_INVALID_STATE, "No marker set");
    }
    
    reader->position = reader->marker;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_encoded_ec_point(neoc_binary_reader_t *reader,
                                                      uint8_t **data,
                                                      size_t *len) {
    if (!reader || !data || !len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *data = NULL;
    *len = 0;
    
    uint8_t byte = 0;
    neoc_error_t err = neoc_binary_reader_read_byte(reader, &byte);
    if (err != NEOC_SUCCESS) return err;
    
    if (byte == 0x02 || byte == 0x03) {
        // Compressed point: 1 byte prefix + 32 bytes
        *len = 33;
        *data = neoc_malloc(*len);
        if (!*data) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate EC point data");
        }
        
        (*data)[0] = byte;
        err = neoc_binary_reader_read_bytes(reader, *data + 1, 32);
        if (err != NEOC_SUCCESS) {
            neoc_free(*data);
            *data = NULL;
            *len = 0;
        }
        return err;
    }
    
    return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Invalid EC point encoding");
}

neoc_error_t neoc_binary_reader_read_push_data(neoc_binary_reader_t *reader,
                                                uint8_t **data,
                                                size_t *len) {
    if (!reader || !data || !len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *data = NULL;
    *len = 0;
    
    uint8_t byte = 0;
    neoc_error_t err = neoc_binary_reader_read_byte(reader, &byte);
    if (err != NEOC_SUCCESS) return err;

    size_t size = 0;
    switch (byte) {
        case 0x0C: // PUSHDATA1
            {
                uint8_t size8 = 0;
                err = neoc_binary_reader_read_byte(reader, &size8);
                if (err != NEOC_SUCCESS) return err;
                size = size8;
            }
            break;
        case 0x0D: // PUSHDATA2
            {
                uint16_t size16 = 0;
                err = neoc_binary_reader_read_uint16(reader, &size16);
                if (err != NEOC_SUCCESS) return err;
                size = size16;
            }
            break;
        case 0x0E: // PUSHDATA4
            {
                uint32_t size32 = 0;
                err = neoc_binary_reader_read_uint32(reader, &size32);
                if (err != NEOC_SUCCESS) return err;
                size = size32;
            }
            break;
        default:
            return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Not a PUSHDATA opcode");
    }
    
    if (size == 0) {
        *data = neoc_malloc(1); // Empty but valid pointer
        if (!*data) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate empty buffer");
        }
        *len = 0;
        return NEOC_SUCCESS;
    }
    
    *data = neoc_malloc(size);
    if (!*data) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate buffer");
    }
    
    err = neoc_binary_reader_read_bytes(reader, *data, size);
    if (err != NEOC_SUCCESS) {
        neoc_free(*data);
        *data = NULL;
        return err;
    }
    
    *len = size;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_var_bytes_max(neoc_binary_reader_t *reader,
                                                    size_t max_length,
                                                    uint8_t **data,
                                                    size_t *len) {
    if (!reader || !data || !len) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint64_t length = 0;
    neoc_error_t err = neoc_binary_reader_read_var_int(reader, &length);
    if (err != NEOC_SUCCESS) return err;
    
    if (length > max_length) {
        return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Length exceeds maximum");
    }
    
    *len = (size_t)length;
    if (*len == 0) {
        *data = neoc_malloc(1); // Empty but valid pointer
        if (!*data) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate empty buffer");
        }
        return NEOC_SUCCESS;
    }
    
    *data = neoc_malloc(*len);
    if (!*data) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate buffer");
    }
    
    err = neoc_binary_reader_read_bytes(reader, *data, *len);
    if (err != NEOC_SUCCESS) {
        neoc_free(*data);
        *data = NULL;
        *len = 0;
    }
    
    return err;
}

neoc_error_t neoc_binary_reader_read_var_int_max(neoc_binary_reader_t *reader,
                                                  uint64_t max_value,
                                                  uint64_t *value) {
    if (!reader || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    neoc_error_t err = neoc_binary_reader_read_var_int(reader, value);
    if (err != NEOC_SUCCESS) return err;
    
    if (*value > max_value) {
        return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Value exceeds maximum");
    }
    
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_push_string(neoc_binary_reader_t *reader,
                                                  char **str) {
    if (!reader || !str) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint8_t *data;
    size_t len;
    neoc_error_t err = neoc_binary_reader_read_push_data(reader, &data, &len);
    if (err != NEOC_SUCCESS) return err;
    
    *str = neoc_malloc(len + 1);
    if (!*str) {
        neoc_free(data);
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate string");
    }
    
    if (len > 0) {
        memcpy(*str, data, len);
    }
    (*str)[len] = '\0';
    
    neoc_free(data);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_push_int(neoc_binary_reader_t *reader,
                                               int32_t *value) {
    if (!reader || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    uint8_t *data;
    size_t len;
    bool is_negative;
    
    neoc_error_t err = neoc_binary_reader_read_push_big_int(reader, &data, &len, &is_negative);
    if (err != NEOC_SUCCESS) return err;
    
    if (len > 4) {
        neoc_free(data);
        return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Integer too large for 32-bit");
    }
    
    uint32_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= (uint32_t)data[i] << (i * 8);
    }
    
    *value = is_negative ? -(int32_t)result : (int32_t)result;
    neoc_free(data);
    return NEOC_SUCCESS;
}

neoc_error_t neoc_binary_reader_read_push_big_int(neoc_binary_reader_t *reader,
                                                   uint8_t **data,
                                                   size_t *len,
                                                   bool *is_negative) {
    if (!reader || !data || !len || !is_negative) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    
    *data = NULL;
    *len = 0;
    *is_negative = false;
    
    uint8_t byte = 0;
    neoc_error_t err = neoc_binary_reader_read_byte(reader, &byte);
    if (err != NEOC_SUCCESS) return err;
    
    // Handle simple push opcodes (PUSH0/PUSH1-PUSH16, PUSHM1)
    if (byte == NEOC_OP_PUSH0) {
        *data = NULL;
        *len = 0;
        *is_negative = false;
        return NEOC_SUCCESS;
    }
    if (byte >= NEOC_OP_PUSH1 && byte <= NEOC_OP_PUSH16) { // 0x11 - 0x20
        int32_t val = (int32_t)(byte - NEOC_OP_PUSH1 + 1);
        *len = sizeof(int32_t);
        *data = neoc_malloc(*len);
        if (!*data) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate integer data");
        }
        *(int32_t*)*data = val;
        return NEOC_SUCCESS;
    }
    
    if (byte == NEOC_OP_PUSHM1) { // 0x0F
        *is_negative = true;
        *len = sizeof(int32_t);
        *data = neoc_malloc(*len);
        if (!*data) {
            return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate integer data");
        }
        *(int32_t*)*data = 1;
        return NEOC_SUCCESS;
    }
    
    // Handle PUSHINT opcodes
    int count = -1;
    switch (byte) {
        case NEOC_OP_PUSHINT8: // 0x00
            count = 1;
            break;
        case NEOC_OP_PUSHINT16:
            count = 2;
            break;
        case NEOC_OP_PUSHINT32:
            count = 4;
            break;
        case NEOC_OP_PUSHINT64:
            count = 8;
            break;
        case NEOC_OP_PUSHINT128:
            count = 16;
            break;
        case NEOC_OP_PUSHINT256:
            count = 32;
            break;
        default:
            return neoc_error_set(NEOC_ERROR_INVALID_DATA, "Not a PUSHINT opcode");
    }
    
    *data = neoc_malloc((size_t)count);
    if (!*data) {
        return neoc_error_set(NEOC_ERROR_MEMORY, "Failed to allocate integer data");
    }
    
    err = neoc_binary_reader_read_bytes(reader, *data, count);
    if (err != NEOC_SUCCESS) {
        neoc_free(*data);
        *data = NULL;
        return err;
    }
    
    *len = count;
    
    // Check if the number is negative (most significant bit set)
    if (count > 0 && (*data)[count - 1] & 0x80) {
        *is_negative = true;
    }
    
    return NEOC_SUCCESS;
}

void neoc_binary_reader_free(neoc_binary_reader_t *reader) {
    if (reader) {
        if (reader->owned_data) {
            neoc_free(reader->owned_data);
            reader->owned_data = NULL;
        }
        neoc_free(reader);
    }
}
