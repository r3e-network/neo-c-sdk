/**
 * @file test_binary_reader.c
 * @brief Binary reader serialization tests
 */

#include "unity.h"
#include <neoc/neoc.h>
#include <neoc/serialization/binary_reader.h>
#include <string.h>
#include <stdio.h>

void setUp(void) {
    neoc_init();
}

void tearDown(void) {
    neoc_cleanup();
}

/* ===== BINARY READER TESTS ===== */

void test_read_byte(void) {
    uint8_t data[] = {0x42, 0xFF, 0x00, 0x7F};
    
    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(data, sizeof(data), &reader);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(reader);
    
    uint8_t value;
    
    // Read first byte
    err = neoc_binary_reader_read_byte(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT8(0x42, value);
    
    // Read second byte
    err = neoc_binary_reader_read_byte(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT8(0xFF, value);
    
    // Read third byte
    err = neoc_binary_reader_read_byte(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT8(0x00, value);
    
    // Read fourth byte
    err = neoc_binary_reader_read_byte(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT8(0x7F, value);
    
    // Try to read past end
    err = neoc_binary_reader_read_byte(reader, &value);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    neoc_binary_reader_free(reader);
}

void test_read_bytes(void) {
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    
    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(data, sizeof(data), &reader);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t buffer[4];
    
    // Read first 4 bytes
    err = neoc_binary_reader_read_bytes(reader, buffer, 4);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_MEMORY(data, buffer, 4);
    
    // Read next 4 bytes
    err = neoc_binary_reader_read_bytes(reader, buffer, 4);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_MEMORY(data + 4, buffer, 4);
    
    // Try to read past end
    err = neoc_binary_reader_read_bytes(reader, buffer, 1);
    TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
    
    neoc_binary_reader_free(reader);
}

void test_read_uint16(void) {
    // Little-endian: 0x3412 = 4660
    uint8_t data[] = {0x12, 0x34, 0xFF, 0xFF};
    
    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(data, sizeof(data), &reader);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint16_t value;
    
    // Read first uint16
    err = neoc_binary_reader_read_uint16(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT16(0x3412, value);
    
    // Read second uint16
    err = neoc_binary_reader_read_uint16(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT16(0xFFFF, value);
    
    neoc_binary_reader_free(reader);
}

void test_read_uint32(void) {
    // Little-endian tests
    uint8_t data[] = {
        0xFF, 0xFF, 0xFF, 0xFF,  // 4294967295
        0x01, 0x00, 0x00, 0x00,  // 1
        0x00, 0x00, 0x00, 0x00,  // 0
        0x8C, 0xAE, 0x00, 0x00   // 44684
    };
    
    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(data, sizeof(data), &reader);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint32_t value;
    
    // Test 0xFFFFFFFF
    err = neoc_binary_reader_read_uint32(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT32(4294967295U, value);
    
    // Test 1
    err = neoc_binary_reader_read_uint32(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT32(1, value);
    
    // Test 0
    err = neoc_binary_reader_read_uint32(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT32(0, value);
    
    // Test 44684
    err = neoc_binary_reader_read_uint32(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT32(44684, value);
    
    neoc_binary_reader_free(reader);
}

void test_read_int64(void) {
    // Little-endian tests
    uint8_t data[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,  // INT64_MIN
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,  // INT64_MAX
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 0
        0x11, 0x33, 0x22, 0x8C, 0xAE, 0x00, 0x00, 0x00   // 749675361041
    };
    
    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(data, sizeof(data), &reader);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    int64_t value;
    
    // Test INT64_MIN
    err = neoc_binary_reader_read_int64(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT64(INT64_MIN, value);
    
    // Test INT64_MAX
    err = neoc_binary_reader_read_int64(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT64(INT64_MAX, value);
    
    // Test 0
    err = neoc_binary_reader_read_int64(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT64(0, value);
    
    // Test 749675361041
    err = neoc_binary_reader_read_int64(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_INT64(749675361041LL, value);
    
    neoc_binary_reader_free(reader);
}

void test_read_bool(void) {
    uint8_t data[] = {0x00, 0x01, 0xFF, 0x42};
    
    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(data, sizeof(data), &reader);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    bool value;
    
    // Test false (0x00)
    err = neoc_binary_reader_read_bool(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_FALSE(value);
    
    // Test true (0x01)
    err = neoc_binary_reader_read_bool(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_TRUE(value);
    
    // Test true (0xFF)
    err = neoc_binary_reader_read_bool(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_TRUE(value);
    
    // Test true (0x42)
    err = neoc_binary_reader_read_bool(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_TRUE(value);
    
    neoc_binary_reader_free(reader);
}

void test_reader_position(void) {
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(data, sizeof(data), &reader);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Check initial position
    TEST_ASSERT_EQUAL_UINT32(0, reader->position);
    
    uint8_t value;
    
    // Read one byte
    err = neoc_binary_reader_read_byte(reader, &value);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT32(1, reader->position);
    
    // Read two more bytes
    uint8_t buffer[2];
    err = neoc_binary_reader_read_bytes(reader, buffer, 2);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT32(3, reader->position);
    
    // Read uint16 (2 bytes)
    uint16_t value16;
    err = neoc_binary_reader_read_uint16(reader, &value16);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT32(5, reader->position);
    
    neoc_binary_reader_free(reader);
}

void test_empty_reader(void) {
    neoc_binary_reader_t *reader = NULL;
    neoc_error_t err = neoc_binary_reader_create(NULL, 0, &reader);
    
    // This might fail or succeed depending on implementation
    if (err == NEOC_SUCCESS && reader != NULL) {
        uint8_t value;
        err = neoc_binary_reader_read_byte(reader, &value);
        TEST_ASSERT_TRUE(err != NEOC_SUCCESS);
        neoc_binary_reader_free(reader);
    }
}

/* ===== MAIN TEST RUNNER ===== */

int main(void) {
    UNITY_BEGIN();
    
    printf("\n=== BINARY READER TESTS ===\n");
    
    RUN_TEST(test_read_byte);
    RUN_TEST(test_read_bytes);
    RUN_TEST(test_read_uint16);
    RUN_TEST(test_read_uint32);
    RUN_TEST(test_read_int64);
    RUN_TEST(test_read_bool);
    RUN_TEST(test_reader_position);
    RUN_TEST(test_empty_reader);
    
    UNITY_END();
    return 0;
}
