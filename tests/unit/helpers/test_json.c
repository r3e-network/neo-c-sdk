/**
 * @file test_json.c
 * @brief Unit tests converted from JSON.swift
 */

#include "unity.h"
#include <string.h>
#include <math.h>
#include "neoc/neoc.h"
#include "neoc/utils/json.h"

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
}

void tearDown(void) {
    neoc_cleanup();
}

static void assert_string_field(const neoc_json_t *obj,
                                const char *name,
                                const char *expected) {
    const char *value = neoc_json_get_string(obj, name);
    TEST_ASSERT_NOT_NULL(value);
    TEST_ASSERT_EQUAL_STRING(expected, value);
}

void test_parse_basic_object(void) {
    const char *json = "{\"name\":\"Neo\",\"height\":1234,\"active\":true}";
    neoc_json_t *root = neoc_json_parse(json);
    TEST_ASSERT_NOT_NULL(root);

    assert_string_field(root, "name", "Neo");

    double height = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_json_get_number(root, "height", &height));
    TEST_ASSERT_TRUE(fabs(height - 1234.0) < 1e-6);

    bool active = false;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_json_get_bool(root, "active", &active));
    TEST_ASSERT_TRUE(active);

    neoc_json_free(root);
}

void test_create_object_and_stringify(void) {
    neoc_json_t *root = neoc_json_create_object();
    TEST_ASSERT_NOT_NULL(root);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_json_add_string(root, "network", "MainNet"));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_json_add_int(root, "magic", 860833102));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_json_add_bool(root, "syncing", false));

    neoc_json_t *inner = neoc_json_create_object();
    TEST_ASSERT_NOT_NULL(inner);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_json_add_number(inner, "height", 123456));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_json_add_object(root, "status", inner));

    char *serialized = neoc_json_to_string(root);
    TEST_ASSERT_NOT_NULL(serialized);

    neoc_json_t *parsed = neoc_json_parse(serialized);
    TEST_ASSERT_NOT_NULL(parsed);
    assert_string_field(parsed, "network", "MainNet");

    neoc_json_t *status = neoc_json_get_object(parsed, "status");
    TEST_ASSERT_NOT_NULL(status);
    double height = 0;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_json_get_number(status, "height", &height));
    TEST_ASSERT_TRUE(fabs(height - 123456.0) < 1e-6);

    neoc_free(serialized);
    neoc_json_free(parsed);
    neoc_json_free(root);
}

void test_array_operations(void) {
    neoc_json_t *array = neoc_json_create_array();
    TEST_ASSERT_NOT_NULL(array);

    for (int i = 0; i < 3; ++i) {
        neoc_json_t *entry = neoc_json_create_object();
        TEST_ASSERT_NOT_NULL(entry);
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                              neoc_json_add_int(entry, "index", i));
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                              neoc_json_array_add(array, entry));
    }

    TEST_ASSERT_TRUE(neoc_json_is_array(array));
    TEST_ASSERT_EQUAL_UINT(3, neoc_json_array_size(array));

    for (size_t i = 0; i < neoc_json_array_size(array); ++i) {
        neoc_json_t *entry = neoc_json_array_get(array, i);
        TEST_ASSERT_NOT_NULL(entry);
        int64_t index = -1;
        TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                              neoc_json_get_int(entry, "index", &index));
        TEST_ASSERT_EQUAL_INT((int)i, (int)index);
    }

    neoc_json_free(array);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_parse_basic_object);
    RUN_TEST(test_create_object_and_stringify);
    RUN_TEST(test_array_operations);
    return UnityEnd();
}
