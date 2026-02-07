#include "unity.h"

#include "neoc/neoc.h"
#include "neoc/protocol/core/response/neo_get_version.h"

#include <string.h>

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
}

void tearDown(void) {
    neoc_cleanup();
}

void test_neo_get_version_protocol_and_success_helpers(void) {
    neoc_neo_version_t *version = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_version_create(&version));

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_set_protocol_info(version,
                                                             0x334F4554,
                                                             53,
                                                             15000,
                                                             512,
                                                             50000,
                                                             100,
                                                             5200000000000000ULL));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_version_set_validators_count(version, 7));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_hardfork(version,
                                                        "HF_Aspidochelone",
                                                        1730000));

    neoc_neo_get_version_response_t *response = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_get_version_response_create(1, version, NULL, 0, &response));

    TEST_ASSERT_TRUE(neoc_neo_get_version_response_is_success(response));
    TEST_ASSERT_EQUAL_HEX32(0x334F4554, neoc_neo_get_version_response_get_network(response));
    TEST_ASSERT_EQUAL_UINT32(7, response->result->protocol.validators_count);
    TEST_ASSERT_EQUAL_UINT(1, response->result->protocol.hardforks_count);
    TEST_ASSERT_EQUAL_STRING("HF_Aspidochelone",
                             response->result->protocol.hardforks[0].name);

    neoc_neo_get_version_response_free(response);
}

void test_neo_get_version_append_collection_helpers(void) {
    neoc_neo_version_t *version = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_version_create(&version));

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_valid_signer(version,
                                                            "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_valid_signer(version,
                                                            "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_committee_member(version,
                                                                "02cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_seed_node(version,
                                                         "seed1.neo.org:20333"));

    TEST_ASSERT_EQUAL_UINT(2, version->protocol.valid_signers_count);
    TEST_ASSERT_EQUAL_UINT(1, version->protocol.committee_members_count);
    TEST_ASSERT_EQUAL_UINT(1, version->protocol.seed_list_count);
    TEST_ASSERT_EQUAL_STRING("seed1.neo.org:20333", version->protocol.seed_list[0]);

    neoc_neo_version_free(version);
}

void test_neo_get_version_response_json_roundtrip_v391_fields(void) {
    neoc_neo_version_t *version = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_version_create(&version));

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_set_basic_info(version,
                                                          10333,
                                                          10334,
                                                          123456,
                                                          "/Neo:3.9.1/"));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_set_protocol_info(version,
                                                             0x334F454E,
                                                             53,
                                                             15000,
                                                             512,
                                                             50000,
                                                             100,
                                                             5200000000000000ULL));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_version_set_validators_count(version, 7));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_hardfork(version,
                                                        "HF_Aspidochelone",
                                                        1730000));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_valid_signer(version,
                                                            "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_committee_member(version,
                                                                "03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_version_add_seed_node(version,
                                                         "seed1.neo.org:10333"));

    neoc_neo_get_version_response_t *response = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_get_version_response_create(7, version, NULL, 0, &response));

    char *json = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_neo_get_version_response_to_json(response, &json));
    TEST_ASSERT_NOT_NULL(json);
    TEST_ASSERT_NOT_NULL(strstr(json, "\"validatorscount\":7"));
    TEST_ASSERT_NOT_NULL(strstr(json, "\"hardforks\""));

    neoc_neo_get_version_response_t *parsed = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_get_version_response_from_json(json, &parsed));
    TEST_ASSERT_NOT_NULL(parsed);
    TEST_ASSERT_TRUE(neoc_neo_get_version_response_is_success(parsed));
    TEST_ASSERT_EQUAL_HEX32(0x334F454E, neoc_neo_get_version_response_get_network(parsed));
    TEST_ASSERT_NOT_NULL(parsed->result);
    TEST_ASSERT_EQUAL_UINT32(7, parsed->result->protocol.validators_count);
    TEST_ASSERT_EQUAL_UINT(1, parsed->result->protocol.hardforks_count);
    TEST_ASSERT_EQUAL_STRING("HF_Aspidochelone", parsed->result->protocol.hardforks[0].name);

    neoc_neo_get_version_response_free(parsed);
    neoc_free(json);
    neoc_neo_get_version_response_free(response);
}

void test_neo_get_version_response_error_json_parse(void) {
    const char *json = "{\"jsonrpc\":\"2.0\",\"id\":11,\"error\":{\"code\":-32602,\"message\":\"Invalid params\"}}";
    neoc_neo_get_version_response_t *response = NULL;

    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_neo_get_version_response_from_json(json, &response));
    TEST_ASSERT_NOT_NULL(response);
    TEST_ASSERT_FALSE(neoc_neo_get_version_response_is_success(response));
    TEST_ASSERT_NOT_NULL(response->error);
    TEST_ASSERT_EQUAL_STRING("Invalid params", response->error);
    TEST_ASSERT_EQUAL_INT(-32602, response->error_code);
    TEST_ASSERT_EQUAL_UINT32(0, neoc_neo_get_version_response_get_network(response));

    neoc_neo_get_version_response_free(response);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_neo_get_version_protocol_and_success_helpers);
    RUN_TEST(test_neo_get_version_append_collection_helpers);
    RUN_TEST(test_neo_get_version_response_json_roundtrip_v391_fields);
    RUN_TEST(test_neo_get_version_response_error_json_parse);
    UNITY_END();
    return 0;
}

