/**
 * @file url_session_nocurl.c
 * @brief Fallback URLSession implementation when libcurl headers are unavailable.
 *
 * This keeps the SDK buildable in environments without libcurl development
 * headers by providing a minimal, non-networking implementation of the public
 * URLSession API surface.
 */

#include "neoc/utils/url_session.h"
#include "neoc/neoc_error.h"
#include "neoc/neoc_memory.h"

#include <string.h>

struct neoc_url_session_t {
    neoc_url_session_config_t config;
};

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
    if (!dst) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid header destination");
    }
    *dst = NULL;
    if (!src || count == 0) {
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

static neoc_error_t http_not_supported(void) {
    return neoc_error_set(NEOC_ERROR_NOT_IMPLEMENTED, "libcurl support not compiled in");
}

static neoc_error_t set_request_body_bytes(neoc_http_request_t *request,
                                           const uint8_t *data,
                                           size_t data_len) {
    if (!request) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid request");
    }

    if (request->body) {
        neoc_byte_array_free(request->body);
        request->body = NULL;
    }

    if (!data || data_len == 0) {
        return NEOC_SUCCESS;
    }

    return neoc_byte_array_from_data(data, data_len, &request->body);
}

neoc_error_t neoc_url_session_get_default_config(neoc_url_session_config_t *config) {
    if (!config) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid config");
    }

    memset(config, 0, sizeof(*config));
    config->timeout_seconds = 60;
    config->follow_redirects = true;
    config->verify_ssl = true;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_url_session_create(neoc_url_session_t **session) {
    if (!session) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid session pointer");
    }

    neoc_url_session_config_t config;
    neoc_error_t err = neoc_url_session_get_default_config(&config);
    if (err != NEOC_SUCCESS) {
        return err;
    }

    return neoc_url_session_create_with_config(&config, session);
}

neoc_error_t neoc_url_session_create_with_config(const neoc_url_session_config_t *config,
                                                 neoc_url_session_t **session) {
    if (!session) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid session pointer");
    }

    neoc_url_session_t *new_session = neoc_calloc(1, sizeof(neoc_url_session_t));
    if (!new_session) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate URL session");
    }

    neoc_error_t err = neoc_url_session_get_default_config(&new_session->config);
    if (err != NEOC_SUCCESS) {
        neoc_free(new_session);
        return err;
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

        if (config->default_headers && config->default_header_count > 0) {
            err = duplicate_headers(config->default_headers,
                                    config->default_header_count,
                                    &new_session->config.default_headers);
            if (err != NEOC_SUCCESS) {
                neoc_free(new_session->config.user_agent);
                neoc_free(new_session);
                return err;
            }
            new_session->config.default_header_count = config->default_header_count;
        }
    }

    *session = new_session;
    return NEOC_SUCCESS;
}

void neoc_url_session_free(neoc_url_session_t *session) {
    if (!session) {
        return;
    }
    free_headers(session->config.default_headers, session->config.default_header_count);
    neoc_free(session->config.user_agent);
    neoc_free(session);
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
        neoc_free(req);
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate request URL");
    }

    req->method = method;
    req->timeout_seconds = 60;
    req->follow_redirects = true;
    req->verify_ssl = true;

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
    neoc_http_header_t *new_headers = neoc_realloc(request->headers,
                                                   new_count * sizeof(neoc_http_header_t));
    if (!new_headers) {
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate headers");
    }

    request->headers = new_headers;
    request->headers[request->header_count].name = neoc_strdup(name);
    request->headers[request->header_count].value = neoc_strdup(value);
    if (!request->headers[request->header_count].name || !request->headers[request->header_count].value) {
        neoc_free(request->headers[request->header_count].name);
        neoc_free(request->headers[request->header_count].value);
        return neoc_error_set(NEOC_ERROR_OUT_OF_MEMORY, "Failed to allocate header");
    }

    request->header_count = new_count;
    return NEOC_SUCCESS;
}

neoc_error_t neoc_http_request_set_body(neoc_http_request_t *request,
                                        const neoc_byte_array_t *body) {
    if (!request || !body) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    return set_request_body_bytes(request, body->data, body->length);
}

neoc_error_t neoc_http_request_set_body_string(neoc_http_request_t *request,
                                               const char *body_string) {
    if (!request || !body_string) {
        return neoc_error_set(NEOC_ERROR_INVALID_ARGUMENT, "Invalid arguments");
    }

    return set_request_body_bytes(request, (const uint8_t *)body_string, strlen(body_string));
}

void neoc_http_request_free(neoc_http_request_t *request) {
    if (!request) {
        return;
    }

    neoc_free(request->url);
    for (size_t i = 0; i < request->header_count; ++i) {
        neoc_free(request->headers[i].name);
        neoc_free(request->headers[i].value);
    }
    neoc_free(request->headers);
    neoc_byte_array_free(request->body);
    neoc_free(request);
}

void neoc_http_response_free(neoc_http_response_t *response) {
    if (!response) {
        return;
    }

    for (size_t i = 0; i < response->header_count; ++i) {
        neoc_free(response->headers[i].name);
        neoc_free(response->headers[i].value);
    }
    neoc_free(response->headers);
    neoc_byte_array_free(response->body);
    neoc_free(response->error_message);
    neoc_free(response);
}

neoc_error_t neoc_url_session_perform_request(neoc_url_session_t *session,
                                              const neoc_http_request_t *request,
                                              neoc_http_response_t **response) {
    (void)session;
    (void)request;
    if (response) {
        *response = NULL;
    }
    return http_not_supported();
}

neoc_error_t neoc_url_session_get(neoc_url_session_t *session,
                                  const char *url,
                                  neoc_http_response_t **response) {
    (void)session;
    (void)url;
    if (response) {
        *response = NULL;
    }
    return http_not_supported();
}

neoc_error_t neoc_url_session_post_json(neoc_url_session_t *session,
                                        const char *url,
                                        const char *json_body,
                                        neoc_http_response_t **response) {
    (void)session;
    (void)url;
    (void)json_body;
    if (response) {
        *response = NULL;
    }
    return http_not_supported();
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
