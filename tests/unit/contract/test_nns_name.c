/**
 * @file test_nns_name.c
 * @brief Unit tests for NNS name helpers
 */

#include <stddef.h>
#include "unity.h"
#include <string.h>
#include <time.h>
#include "neoc/neoc.h"
#include "neoc/contract/nns_name.h"

static void fill_hash(neoc_hash160_t *hash, uint8_t seed) {
    for (size_t i = 0; i < NEOC_HASH160_SIZE; ++i) {
        hash->data[i] = (uint8_t)(seed + i);
    }
}

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
}

void tearDown(void) {
    neoc_cleanup();
}

void test_nns_name_create_and_accessors(void) {
    neoc_hash160_t owner = {{0}};
    neoc_hash160_t fetched_owner = {{0}};
    neoc_nns_name_t *record = NULL;
    const uint64_t expiration = ((uint64_t)time(NULL) * 1000) + 60000;
    char *name_copy = NULL;
    char *parent = NULL;
    bool flag = true;
    uint64_t fetched_expiration = 0;

    fill_hash(&owner, 0x33);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nns_name_create("example.neo", &owner, expiration, &record));
    TEST_ASSERT_NOT_NULL(record);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_nns_name_get_name(record, &name_copy));
    TEST_ASSERT_NOT_NULL(name_copy);
    TEST_ASSERT_EQUAL_STRING("example.neo", name_copy);
    neoc_free(name_copy);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_nns_name_get_owner(record, &fetched_owner));
    TEST_ASSERT_EQUAL_MEMORY(owner.data, fetched_owner.data, sizeof(owner.data));

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nns_name_get_expiration(record, &fetched_expiration));
    TEST_ASSERT_EQUAL_UINT64(expiration, fetched_expiration);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_nns_name_is_expired(record, &flag));
    TEST_ASSERT_FALSE(flag);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_nns_name_is_root(record, &flag));
    TEST_ASSERT_FALSE(flag);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_nns_name_get_parent(record, &parent));
    TEST_ASSERT_NOT_NULL(parent);
    TEST_ASSERT_EQUAL_STRING("example", parent);
    neoc_free(parent);

    neoc_nns_name_free(record);
}

void test_nns_name_root_and_parent_logic(void) {
    neoc_hash160_t owner = {{0}};
    neoc_nns_name_t *root = NULL;
    bool flag = false;
    char *parent = (char *)0x1;

    fill_hash(&owner, 0x7A);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_nns_name_create("neo", &owner, 0, &root));
    TEST_ASSERT_NOT_NULL(root);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_nns_name_is_root(root, &flag));
    TEST_ASSERT_TRUE(flag);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_nns_name_get_parent(root, &parent));
    TEST_ASSERT_NULL(parent);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_nns_name_is_expired(root, &flag));
    TEST_ASSERT_TRUE(flag);

    neoc_nns_name_free(root);
}

void test_nns_name_invalid_arguments(void) {
    neoc_hash160_t owner = {{0}};
    neoc_nns_name_t *record = NULL;
    char *name_out = NULL;
    uint64_t expiration = 0;
    bool flag = false;

    fill_hash(&owner, 0x55);

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_create(NULL, &owner, 0, &record));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_create("name", NULL, 0, &record));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_create("name", &owner, 0, NULL));

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_get_name(NULL, &name_out));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_get_owner(NULL, &owner));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_get_expiration(NULL, &expiration));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_is_expired(NULL, &flag));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_is_root(NULL, &flag));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_nns_name_get_parent(NULL, &name_out));

    neoc_nns_name_free(NULL);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_nns_name_create_and_accessors);
    RUN_TEST(test_nns_name_root_and_parent_logic);
    RUN_TEST(test_nns_name_invalid_arguments);
    return UnityEnd();
}
