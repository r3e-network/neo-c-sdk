/**
 * @file test_neo_uri.c
 * @brief Unit tests for Neo URI parsing helpers
 */

#include <stddef.h>
#include "unity.h"
#include <string.h>
#include <stdlib.h>
#include "neoc/neoc.h"
#include "neoc/contract/neoc_uri.h"

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
}

void tearDown(void) {
    neoc_cleanup();
}

void test_neo_uri_parse_with_all_parameters(void) {
    const char *uri_str =
        "neo:Nb2cX3bCkTsPH5QmUxeuuQB3LtEPPYUqmP?"
        "asset=0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5&"
        "amount=42&"
        "description=Donation";
    neoc_neo_uri_t *uri = NULL;
    char *address = NULL;
    char *asset = NULL;
    char *description = NULL;
    uint64_t amount = 0;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_parse(uri_str, &uri));
    TEST_ASSERT_NOT_NULL(uri);
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_get_address(uri, &address));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_get_asset(uri, &asset));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_get_amount(uri, &amount));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_get_description(uri, &description));

    TEST_ASSERT_EQUAL_STRING("Nb2cX3bCkTsPH5QmUxeuuQB3LtEPPYUqmP", address);
    TEST_ASSERT_EQUAL_STRING("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5", asset);
    TEST_ASSERT_EQUAL_UINT64(42, amount);
    TEST_ASSERT_EQUAL_STRING("Donation", description);

    neoc_free(address);
    neoc_free(asset);
    neoc_free(description);
    neoc_neo_uri_free(uri);
}

void test_neo_uri_parse_minimal_and_invalid(void) {
    const char *minimal = "neo:NWb2ETG5DPZb9rdeChHgNsx3Rp3XJ2nK8B";
    neoc_neo_uri_t *uri = NULL;
    char *address = NULL;
    char *asset = (char *)0x1;
    char *description = (char *)0x1;
    uint64_t amount = 999;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_parse(minimal, &uri));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_get_address(uri, &address));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_get_asset(uri, &asset));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_get_amount(uri, &amount));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_uri_get_description(uri, &description));

    TEST_ASSERT_EQUAL_STRING("NWb2ETG5DPZb9rdeChHgNsx3Rp3XJ2nK8B", address);
    TEST_ASSERT_NULL(asset);
    TEST_ASSERT_EQUAL_UINT64(0, amount);
    TEST_ASSERT_NULL(description);

    neoc_free(address);
    neoc_free(asset);
    neoc_free(description);
    neoc_neo_uri_free(uri);

    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_FORMAT,
                          neoc_neo_uri_parse("http://example.com", &uri));
}

void test_neo_uri_build_variations(void) {
    char *uri = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_uri_build("NS1qGgLcsLVJQFELfVwDSiBjzYJGxLcazh",
                                             "0xd2a4cff31913016155e38e474a2c06d08be276cf",
                                             5000,
                                             "Fuel",
                                             &uri));
    TEST_ASSERT_EQUAL_STRING(
        "neo:NS1qGgLcsLVJQFELfVwDSiBjzYJGxLcazh?"
        "asset=0xd2a4cff31913016155e38e474a2c06d08be276cf&"
        "amount=5000&"
        "description=Fuel",
        uri);
    neoc_free(uri);

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_uri_build("NdQY1rFifH7dy2sSZFFP6Uu9gob5R1jeDy",
                                             NULL,
                                             0,
                                             NULL,
                                             &uri));
    TEST_ASSERT_EQUAL_STRING("neo:NdQY1rFifH7dy2sSZFFP6Uu9gob5R1jeDy", uri);
    neoc_free(uri);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_neo_uri_parse_with_all_parameters);
    RUN_TEST(test_neo_uri_parse_minimal_and_invalid);
    RUN_TEST(test_neo_uri_build_variations);
    UNITY_END();
}
