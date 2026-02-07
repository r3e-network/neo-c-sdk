/**
 * @file test_binary_writer.c
 * @brief Binary writer serialization tests
 */

#include "unity.h"
#include <neoc/neoc.h>
#include <neoc/serialization/binary_writer.h>
#include <neoc/utils/neoc_hex.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

void setUp(void) {
    neoc_init();
}

void tearDown(void) {
    neoc_cleanup();
}

/* ===== HELPER FUNCTIONS ===== */

void test_and_compare(neoc_binary_writer_t *writer, const uint8_t *expected, size_t expected_len) {
    TEST_ASSERT_EQUAL_UINT32(expected_len, writer->position);
    TEST_ASSERT_EQUAL_MEMORY(expected, writer->data, expected_len);
}

/* ===== BINARY WRITER TESTS ===== */

void test_write_uint32(void) {
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(128, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_NOT_NULL(writer);
    
    // Test max uint32
    err = neoc_binary_writer_write_uint32(writer, 0xFFFFFFFF);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected1[] = {0xFF, 0xFF, 0xFF, 0xFF};
    test_and_compare(writer, expected1, 4);
    
    // Reset for next test
    writer->position = 0;
    
    // Test 0
    err = neoc_binary_writer_write_uint32(writer, 0);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected2[] = {0x00, 0x00, 0x00, 0x00};
    test_and_compare(writer, expected2, 4);
    
    // Reset for next test
    writer->position = 0;
    
    // Test 12345
    err = neoc_binary_writer_write_uint32(writer, 12345);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected3[] = {0x39, 0x30, 0x00, 0x00};
    test_and_compare(writer, expected3, 4);
    
    neoc_binary_writer_free(writer);
}

void test_write_int64(void) {
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(128, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Test INT64_MAX
    err = neoc_binary_writer_write_int64(writer, INT64_MAX);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected1[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};
    test_and_compare(writer, expected1, 8);
    
    // Reset for next test
    writer->position = 0;
    
    // Test INT64_MIN
    err = neoc_binary_writer_write_int64(writer, INT64_MIN);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80};
    test_and_compare(writer, expected2, 8);
    
    // Reset for next test
    writer->position = 0;
    
    // Test 0
    err = neoc_binary_writer_write_int64(writer, 0);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected3[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    test_and_compare(writer, expected3, 8);
    
    // Reset for next test
    writer->position = 0;
    
    // Test 1234567890
    err = neoc_binary_writer_write_int64(writer, 1234567890);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected4[] = {0xD2, 0x02, 0x96, 0x49, 0x00, 0x00, 0x00, 0x00};
    test_and_compare(writer, expected4, 8);
    
    neoc_binary_writer_free(writer);
}

void test_write_uint16(void) {
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(128, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Test max uint16
    err = neoc_binary_writer_write_uint16(writer, 0xFFFF);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected1[] = {0xFF, 0xFF};
    test_and_compare(writer, expected1, 2);
    
    // Reset for next test
    writer->position = 0;
    
    // Test 0
    err = neoc_binary_writer_write_uint16(writer, 0);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected2[] = {0x00, 0x00};
    test_and_compare(writer, expected2, 2);
    
    // Reset for next test
    writer->position = 0;
    
    // Test 12345
    err = neoc_binary_writer_write_uint16(writer, 12345);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected3[] = {0x39, 0x30};
    test_and_compare(writer, expected3, 2);
    
    neoc_binary_writer_free(writer);
}

void test_write_var_int(void) {
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(256, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Test 0 (encoded as single byte)
    err = neoc_binary_writer_write_var_int(writer, 0);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected1[] = {0x00};
    test_and_compare(writer, expected1, 1);
    
    // Test 252 (encoded as single byte)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 252);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected2[] = {0xFC};
    test_and_compare(writer, expected2, 1);
    
    // Test 253 (encoded with uint16)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 253);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected3[] = {0xFD, 0xFD, 0x00};
    test_and_compare(writer, expected3, 3);
    
    // Test 254 (encoded with uint16)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 254);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected4[] = {0xFD, 0xFE, 0x00};
    test_and_compare(writer, expected4, 3);
    
    // Test 65534 (encoded with uint16)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 65534);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected5[] = {0xFD, 0xFE, 0xFF};
    test_and_compare(writer, expected5, 3);
    
    // Test 65535 (encoded with uint16)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 65535);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected6[] = {0xFD, 0xFF, 0xFF};
    test_and_compare(writer, expected6, 3);
    
    // Test 65536 (encoded with uint32)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 65536);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected7[] = {0xFE, 0x00, 0x00, 0x01, 0x00};
    test_and_compare(writer, expected7, 5);
    
    // Test 4294967294 (encoded with uint32)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 4294967294ULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected8[] = {0xFE, 0xFE, 0xFF, 0xFF, 0xFF};
    test_and_compare(writer, expected8, 5);
    
    // Test 4294967295 (encoded with uint32)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 4294967295ULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected9[] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF};
    test_and_compare(writer, expected9, 5);
    
    // Test 4294967296 (encoded with uint64)
    writer->position = 0;
    err = neoc_binary_writer_write_var_int(writer, 4294967296ULL);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected10[] = {0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    test_and_compare(writer, expected10, 9);
    
    neoc_binary_writer_free(writer);
}

void test_write_var_bytes(void) {
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(512, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Test small byte array
    uint8_t data1[] = {0x01, 0x02, 0x03};
    err = neoc_binary_writer_write_var_bytes(writer, data1, sizeof(data1));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    uint8_t expected1[] = {0x03, 0x01, 0x02, 0x03};
    test_and_compare(writer, expected1, 4);
    
    // Test larger byte array (> 252 bytes)
    writer->position = 0;
    uint8_t data2[262];
    memset(data2, 0x42, sizeof(data2));
    err = neoc_binary_writer_write_var_bytes(writer, data2, sizeof(data2));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Should write: 0xFD, 0x06, 0x01 (262 in little-endian), then 262 bytes of 0x42
    TEST_ASSERT_EQUAL_UINT8(0xFD, writer->data[0]);
    TEST_ASSERT_EQUAL_UINT8(0x06, writer->data[1]);
    TEST_ASSERT_EQUAL_UINT8(0x01, writer->data[2]);
    TEST_ASSERT_EQUAL_MEMORY(data2, writer->data + 3, 262);
    TEST_ASSERT_EQUAL_UINT32(265, writer->position);
    
    neoc_binary_writer_free(writer);
}

void test_write_bytes(void) {
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(128, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    err = neoc_binary_writer_write_bytes(writer, data, sizeof(data));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    test_and_compare(writer, data, 4);
    
    // Write more data
    uint8_t data2[] = {0xCA, 0xFE, 0xBA, 0xBE};
    err = neoc_binary_writer_write_bytes(writer, data2, sizeof(data2));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    uint8_t expected[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    test_and_compare(writer, expected, 8);
    
    neoc_binary_writer_free(writer);
}

void test_write_bool(void) {
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(128, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Write false
    err = neoc_binary_writer_write_bool(writer, false);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT8(0x00, writer->data[0]);
    
    // Write true
    err = neoc_binary_writer_write_bool(writer, true);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT8(0x01, writer->data[1]);
    
    uint8_t expected[] = {0x00, 0x01};
    test_and_compare(writer, expected, 2);
    
    neoc_binary_writer_free(writer);
}

void test_writer_auto_grow(void) {
    // Create a small writer with auto-grow enabled
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(4, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    // Write more than initial capacity
    uint8_t data[16];
    memset(data, 0xAA, sizeof(data));
    
    err = neoc_binary_writer_write_bytes(writer, data, sizeof(data));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    
    TEST_ASSERT_TRUE(writer->capacity >= 16);
    test_and_compare(writer, data, 16);
    
    neoc_binary_writer_free(writer);
}

void test_writer_to_array_after_reset_returns_empty_success(void) {
    neoc_binary_writer_t *writer = NULL;
    neoc_error_t err = neoc_binary_writer_create(16, true, &writer);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);

    err = neoc_binary_writer_write_uint32(writer, 12345);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);

    neoc_binary_writer_reset(writer);

    uint8_t *data = (uint8_t*)0x1;
    size_t len = 999;
    err = neoc_binary_writer_to_array(writer, &data, &len);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, err);
    TEST_ASSERT_EQUAL_UINT(0, len);
    TEST_ASSERT_NULL(data);

    neoc_binary_writer_free(writer);
}

/* ===== MAIN TEST RUNNER ===== */

int main(void) {
    UNITY_BEGIN();
    
    printf("\n=== BINARY WRITER TESTS ===\n");
    
    RUN_TEST(test_write_uint32);
    RUN_TEST(test_write_int64);
    RUN_TEST(test_write_uint16);
    RUN_TEST(test_write_var_int);
    RUN_TEST(test_write_var_bytes);
    RUN_TEST(test_write_bytes);
    RUN_TEST(test_write_bool);
    RUN_TEST(test_writer_auto_grow);
    RUN_TEST(test_writer_to_array_after_reset_returns_empty_success);
    
    UNITY_END();
    return 0;
}
