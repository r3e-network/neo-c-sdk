/**
 * @file url_session.c
 * @brief Minimal HTTP request adapter used by the SDK
 *
 * Mirrors the behaviour of Swift's URLSession extension by exposing a
 * thin wrapper around libcurl for POST requests. The implementation keeps
 * track of default headers, the include-raw-response flag, and maps common
 * transport failures to ProtocolError-like error codes.
 */

#include "neoc/utils/url_session.h"
#include "neoc/neoc_error.h"
#include "neoc/neoc_memory.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct neoc_url_session_t {
    neoc_url_session_config_t config;
};

static neoc_error_t ensure_curl_init(void) {
    static atomic_int curl_init_state = ATOMIC_VAR_INIT(0); /* 0=uninit, 1=initializing, 2=initialized */

    int state = atomic_load(&curl_init_state);
    if (state == 2) {
        return NEOC_SUCCESS;
    }

    int expected = 0;
    if (atomic_compare_exchange_strong(&curl_init_state, &expected, 1)) {
        CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
        if (rc != CURLE_OK) {
            atomic_store(&curl_init_state, 0);
            return neoc_error_set(NEOC_ERROR_NETWORK, "Failed to initialise libcurl");
        }
        atomic_store(&curl_init_state, 2);
        return NEOC_SUCCESS;
    }

    while ((state = atomic_load(&curl_init_state)) == 1) {
        /* spin */
    }

    return state == 2
        ? NEOC_SUCCESS
        : neoc_error_set(NEOC_ERROR_NETWORK, "Failed to initialise libcurl");
}

static void free_headers(neoc_http_header_t *headers, size_t count) {
    if (!headers) return;
    for (size_t i = 0; i < count; ++i) {
        neoc_free(headers[i].name);
        neoc_free(headers[i].value);
    }
    neoc_free(headers);
}

static neoc_error_t duplicate_headers(const neoc_http_header_t *src,
                                      size_t count,
                                      neoc_http_header_t **dst) {
    if (count == 0) {
        *dst = NULL;
        return NEOC_SUCCESS;
    }
    neoc_http_header_t *copy = neoc_calloc(count, sizeof(neoc_http_header_t));
    if (!copy) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate headers");
    }
    for (size_t i = 0; i < count; ++i) {
        if (src[i].name) {
            copy[i].name = neoc_strdup(src[i].name);
            if (!copy[i].name) {
                free_headers(copy, count);
                return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to duplicate header name");
            }
        }
        if (src[i].value) {
            copy[i].value = neoc_strdup(src[i].value);
            if (!copy[i].value) {
                free_headers(copy, count);
                return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to duplicate header value");
            }
        }
    }
    *dst = copy;
    return NEOC_SUCCESS;
}

static size_t write_body_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    neoc_byte_array_t *body = (neoc_byte_array_t *)userp;
    size_t total = size * nmemb;

    if (!body->data) {
        uint8_t *buffer = neoc_malloc(total);
        if (!buffer) {
            return 0;
        }
        memcpy(buffer, contents, total);
        body->data = buffer;
        body->length = total;
        body->capacity = total;
        return total;
    }

    uint8_t *new_data = neoc_realloc(body->data, body->length + total);
    if (!new_data) {
        return 0;
    }
    memcpy(new_data + body->length, contents, total);
    body->data = new_data;
    body->length += total;
    body->capacity = body->length;
    return total;
}

static neoc_error_t fill_curl_headers(const neoc_http_request_t *request,
                                      const neoc_url_session_config_t *config,
                                      struct curl_slist **out) {
    struct curl_slist *list = NULL;
    if (config && config->default_headers) {
        for (size_t i = 0; i < config->default_header_count; ++i) {
            if (!config->default_headers[i].name || !config->default_headers[i].value) continue;
            char buffer[512];
            snprintf(buffer, sizeof(buffer), "%s: %s",
                     config->default_headers[i].name,
                     config->default_headers[i].value);
            struct curl_slist *temp = curl_slist_append(list, buffer);
            if (!temp) {
                curl_slist_free_all(list);
                return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to append header");
            }
            list = temp;
        }
    }
    if (request && request->headers) {
        for (size_t i = 0; i < request->header_count; ++i) {
            if (!request->headers[i].name || !request->headers[i].value) continue;
            char buffer[512];
            snprintf(buffer, sizeof(buffer), "%s: %s",
                     request->headers[i].name,
                     request->headers[i].value);
            struct curl_slist *temp = curl_slist_append(list, buffer);
            if (!temp) {
                curl_slist_free_all(list);
                return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to append header");
            }
            list = temp;
        }
    }
    *out = list;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_url_session_create(neoc_url_session_t **session) {
    if (!session) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid session pointer");
    }
    neoc_url_session_config_t config;
    config.timeout_seconds = 60;
    config.follow_redirects = true;
    config.verify_ssl = true;
    config.user_agent = NULL;
    config.default_headers = NULL;
    config.default_header_count = 0;
    return neoc_url_session_create_with_config(&config, session);
}

neoc_error_t neoc_url_session_create_with_config(const neoc_url_session_config_t *config,
                                                 neoc_url_session_t **session) {
    if (!session) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid session pointer");
    }
    neoc_error_t err = ensure_curl_init();
    if (err != NEOC_SUCCESS) {
        return err;
    }
    neoc_url_session_t *new_session = neoc_calloc(1, sizeof(neoc_url_session_t));
    if (!new_session) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate session");
    }
    if (config) {
        new_session->config.timeout_seconds = config->timeout_seconds;
        new_session->config.follow_redirects = config->follow_redirects;
        new_session->config.verify_ssl = config->verify_ssl;
        if (config->user_agent) {
            new_session->config.user_agent = neoc_strdup(config->user_agent);
            if (!new_session->config.user_agent) {
                neoc_free(new_session);
                return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to duplicate user agent");
            }
        }
        if (config->default_header_count > 0 && config->default_headers) {
            err = duplicate_headers(config->default_headers,
                                    config->default_header_count,
                                    &new_session->config.default_headers);
            if (err != NEOC_SUCCESS) {
                if (new_session->config.user_agent) neoc_free(new_session->config.user_agent);
                neoc_free(new_session);
                return err;
            }
            new_session->config.default_header_count = config->default_header_count;
        }
    } else {
        new_session->config.timeout_seconds = 60;
        new_session->config.follow_redirects = true;
        new_session->config.verify_ssl = true;
    }
    *session = new_session;
    return NEOC_SUCCESS;
}

void neoc_url_session_free(neoc_url_session_t *session) {
    if (!session) return;
    free_headers(session->config.default_headers, session->config.default_header_count);
    if (session->config.user_agent) {
        neoc_free(session->config.user_agent);
    }
    neoc_free(session);
}

static neoc_error_t set_request_body(neoc_http_request_t *request, const uint8_t *data, size_t len) {
    if (!request) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid request");
    }
    if (!request->body) {
        request->body = neoc_calloc(1, sizeof(neoc_byte_array_t));
        if (!request->body) {
            return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate body");
        }
    } else {
        if (request->body->data) {
            neoc_free(request->body->data);
            request->body->data = NULL;
        }
        request->body->length = 0;
        request->body->capacity = 0;
    }
    if (len == 0) {
        return NEOC_SUCCESS;
    }
    uint8_t *copy = neoc_malloc(len);
    if (!copy) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate body buffer");
    }
    memcpy(copy, data, len);
    request->body->data = copy;
    request->body->length = len;
    request->body->capacity = len;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_http_request_create(const char *url,
                                      neoc_http_method_t method,
                                      neoc_http_request_t **request) {
    if (!url || !request) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    neoc_http_request_t *req = neoc_calloc(1, sizeof(neoc_http_request_t));
    if (!req) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate request");
    }
    req->url = neoc_strdup(url);
    if (!req->url) {
        neoc_http_request_free(req);
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to duplicate URL");
    }
    req->method = method;
    req->verify_ssl = true;
    req->follow_redirects = true;
    req->timeout_seconds = 60;
    *request = req;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_http_request_add_header(neoc_http_request_t *request,
                                          const char *name,
                                          const char *value) {
    if (!request || !name || !value) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    size_t new_count = request->header_count + 1;
    neoc_http_header_t *headers = neoc_realloc(request->headers,
                                              new_count * sizeof(neoc_http_header_t));
    if (!headers) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to grow headers array");
    }
    request->headers = headers;
    request->headers[request->header_count].name = neoc_strdup(name);
    request->headers[request->header_count].value = neoc_strdup(value);
    if (!request->headers[request->header_count].name || !request->headers[request->header_count].value) {
        neoc_free(request->headers[request->header_count].name);
        neoc_free(request->headers[request->header_count].value);
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to duplicate header");
    }
    request->header_count = new_count;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_http_request_set_body(neoc_http_request_t *request,
                                        const neoc_byte_array_t *body) {
    if (!request || !body) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }
    return set_request_body(request, body->data, body->length);
}

neoc_error_t neoc_http_request_set_body_string(neoc_http_request_t *request,
                                               const char *body_string) {
    if (!body_string) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid body string");
    }
    return set_request_body(request, (const uint8_t *)body_string, strlen(body_string));
}

void neoc_http_request_free(neoc_http_request_t *request) {
    if (!request) return;
    free_headers(request->headers, request->header_count);
    if (request->body) {
        if (request->body->data) neoc_free(request->body->data);
        neoc_free(request->body);
    }
    neoc_free(request->url);
    neoc_free(request);
}

void neoc_http_response_free(neoc_http_response_t *response) {
    if (!response) return;
    free_headers(response->headers, response->header_count);
    if (response->body) {
        if (response->body->data) neoc_free(response->body->data);
        neoc_free(response->body);
    }
    if (response->error_message) neoc_free(response->error_message);
    neoc_free(response);
}

static neoc_error_t map_curl_error(CURLcode code) {
    switch (code) {
        case CURLE_OK:
            return NEOC_SUCCESS;
        case CURLE_OPERATION_TIMEDOUT:
            return neoc_error_set(NEOC_ERROR_TIMEOUT, "HTTP request timed out");
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_CONNECT:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
            return neoc_error_set(NEOC_ERROR_NETWORK, "Network error during HTTP request");
        case CURLE_SSL_CONNECT_ERROR:
        case CURLE_PEER_FAILED_VERIFICATION:
            return neoc_error_set(NEOC_ERROR_NETWORK, "SSL verification failed");
        default:
            return neoc_error_set(NEOC_ERROR_NETWORK, "HTTP transport error");
    }
}

neoc_error_t neoc_url_session_perform_request(neoc_url_session_t *session,
                                              const neoc_http_request_t *request,
                                              neoc_http_response_t **response) {
    if (!session || !request || !response) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    *response = NULL;

    CURL *curl = curl_easy_init();
    if (!curl) {
        return neoc_error_set(NEOC_ERROR_NETWORK, "Failed to initialise CURL easy handle");
    }

    neoc_http_response_t *resp = neoc_calloc(1, sizeof(neoc_http_response_t));
    if (!resp) {
        curl_easy_cleanup(curl);
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate response");
    }

    neoc_error_t err = NEOC_SUCCESS;

    curl_easy_setopt(curl, CURLOPT_URL, request->url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,
                     request->follow_redirects ? 1L : (session->config.follow_redirects ? 1L : 0L));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,
                     request->timeout_seconds > 0 ? request->timeout_seconds : session->config.timeout_seconds);

    if (!(request->verify_ssl && session->config.verify_ssl)) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if (session->config.user_agent) {
        curl_easy_setopt(curl, CURLOPT_USERAGENT, session->config.user_agent);
    }

    struct curl_slist *headers = NULL;
    err = fill_curl_headers(request, &session->config, &headers);
    if (err != NEOC_SUCCESS) {
        neoc_http_response_free(resp);
        curl_easy_cleanup(curl);
        return err;
    }
    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    if (request->method == NEOC_HTTP_POST || request->method == NEOC_HTTP_PUT || request->method == NEOC_HTTP_PATCH) {
        const char *post_fields = "";
        size_t post_length = 0;
        if (request->body && request->body->data && request->body->length > 0) {
            post_fields = (const char *)request->body->data;
            post_length = request->body->length;
        }

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)post_length);
    } else if (request->method == NEOC_HTTP_DELETE) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    } else if (request->method == NEOC_HTTP_HEAD) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    } else if (request->method == NEOC_HTTP_GET) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    }

    neoc_byte_array_t response_body = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

    CURLcode code = curl_easy_perform(curl);
    if (code != CURLE_OK) {
        err = map_curl_error(code);
        resp->error_message = neoc_strdup(curl_easy_strerror(code));
        if (!resp->error_message) {
            err = neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to duplicate error message");
        }
    } else {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp->status_code);
        resp->body = neoc_calloc(1, sizeof(neoc_byte_array_t));
        if (!resp->body) {
            err = neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate response body");
        } else {
            resp->body->data = response_body.data;
            resp->body->length = response_body.length;
            resp->body->capacity = response_body.capacity;
            response_body.data = NULL;
        }
    }

    curl_slist_free_all(headers);
    if (response_body.data) neoc_free(response_body.data);
    curl_easy_cleanup(curl);

    if (err != NEOC_SUCCESS) {
        neoc_http_response_free(resp);
        return err;
    }

    *response = resp;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_url_session_get(neoc_url_session_t *session,
                                  const char *url,
                                  neoc_http_response_t **response) {
    neoc_http_request_t *request = NULL;
    neoc_error_t err = neoc_http_request_create(url, NEOC_HTTP_GET, &request);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    err = neoc_url_session_perform_request(session, request, response);
    neoc_http_request_free(request);
    return err;
}

neoc_error_t neoc_url_session_post_json(neoc_url_session_t *session,
                                        const char *url,
                                        const char *json_body,
                                        neoc_http_response_t **response) {
    neoc_http_request_t *request = NULL;
    neoc_error_t err = neoc_http_request_create(url, NEOC_HTTP_POST, &request);
    if (err != NEOC_SUCCESS) {
        return err;
    }
    err = neoc_http_request_add_header(request, "Content-Type", "application/json");
    if (err == NEOC_SUCCESS) {
        err = neoc_http_request_set_body_string(request, json_body ? json_body : "");
    }
    if (err == NEOC_SUCCESS) {
        err = neoc_url_session_perform_request(session, request, response);
    }
    neoc_http_request_free(request);
    return err;
}

neoc_error_t neoc_url_session_get_default_config(neoc_url_session_config_t *config) {
    if (!config) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid config pointer");
    }
    memset(config, 0, sizeof(*config));
    config->timeout_seconds = 60;
    config->follow_redirects = true;
    config->verify_ssl = true;
    return NEOC_SUCCESS;
}

const char* neoc_http_method_to_string(neoc_http_method_t method) {
    switch (method) {
        case NEOC_HTTP_GET: return "GET";
        case NEOC_HTTP_POST: return "POST";
        case NEOC_HTTP_PUT: return "PUT";
        case NEOC_HTTP_DELETE: return "DELETE";
        case NEOC_HTTP_HEAD: return "HEAD";
        case NEOC_HTTP_OPTIONS: return "OPTIONS";
        case NEOC_HTTP_PATCH: return "PATCH";
        default: return "UNKNOWN";
    }
}
