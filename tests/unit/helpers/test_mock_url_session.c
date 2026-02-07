/**
 * @file test_mock_url_session.c
 * @brief URL session unit tests (mocked, no network)
 */

#include <stddef.h>
#include "unity.h"
#include <string.h>
#include "neoc/neoc.h"
#include "neoc/utils/url_session.h"
#include "neoc/utils/array.h"

static neoc_url_session_t *session = NULL;
static neoc_http_request_t *request = NULL;

void setUp(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_init());
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS, neoc_url_session_create(&session));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_http_request_create("https://example.com",
                                                   NEOC_HTTP_POST,
                                                   &request));
}

void tearDown(void) {
    neoc_http_request_free(request);
    neoc_url_session_free(session);
    request = NULL;
    session = NULL;
    neoc_cleanup();
}

void test_http_request_headers_and_body_string(void) {
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_http_request_add_header(request,
                                                       "Content-Type",
                                                       "application/json"));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_http_request_add_header(request,
                                                       "X-Request-ID",
                                                       "abc123"));
    const char *body = "{\"ping\":true}";
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_http_request_set_body_string(request, body));

    TEST_ASSERT_EQUAL_UINT(2, request->header_count);
    TEST_ASSERT_EQUAL_STRING("Content-Type", request->headers[0].name);
    TEST_ASSERT_EQUAL_STRING("application/json", request->headers[0].value);
    TEST_ASSERT_EQUAL_STRING("X-Request-ID", request->headers[1].name);
    TEST_ASSERT_EQUAL_STRING("abc123", request->headers[1].value);
    TEST_ASSERT_NOT_NULL(request->body);
    TEST_ASSERT_EQUAL_UINT(strlen(body), request->body->length);
    TEST_ASSERT_EQUAL_MEMORY(body, request->body->data, request->body->length);
}

void test_http_request_body_from_byte_array(void) {
    const uint8_t raw[] = {0xDE, 0xAD, 0xBE, 0xEF};
    neoc_byte_array_t *byte_array = NULL;
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_byte_array_from_data(raw, sizeof(raw), &byte_array));
    TEST_ASSERT_EQUAL_INT(NEOC_SUCCESS,
                          neoc_http_request_set_body(request, byte_array));

    TEST_ASSERT_NOT_NULL(request->body);
    TEST_ASSERT_EQUAL_UINT(sizeof(raw), request->body->length);
    TEST_ASSERT_EQUAL_MEMORY(raw, request->body->data, sizeof(raw));

    byte_array->data[0] = 0x00;
    TEST_ASSERT_EQUAL_UINT8(0xDE, request->body->data[0]);

    neoc_free(byte_array->data);
    neoc_free(byte_array);
}

void test_http_request_invalid_arguments(void) {
    neoc_byte_array_t array = {0};
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_http_request_add_header(NULL, "A", "B"));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_http_request_set_body(NULL, &array));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_http_request_set_body(request, NULL));
    TEST_ASSERT_EQUAL_INT(NEOC_ERROR_INVALID_ARGUMENT,
                          neoc_http_request_set_body_string(request, NULL));
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_http_request_headers_and_body_string);
    RUN_TEST(test_http_request_body_from_byte_array);
    RUN_TEST(test_http_request_invalid_arguments);
    return UnityEnd();
}
