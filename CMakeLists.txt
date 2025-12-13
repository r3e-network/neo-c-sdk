cmake_minimum_required(VERSION 3.16)
project(NeoC VERSION 1.1.1 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags (disable deprecated warnings for OpenSSL compatibility)
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic -Werror -Wno-deprecated-declarations -fsanitize=address")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -Wall -Wextra -Wpedantic -Werror -Wno-deprecated-declarations")

# Find required packages
find_package(OpenSSL REQUIRED)

# Try to find cJSON using pkg-config first, then manual search
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(CJSON libcjson)
endif()

# If pkg-config didn't find cJSON, try manual search
if(NOT CJSON_FOUND)
    find_path(CJSON_INCLUDE_DIR 
        NAMES cjson/cJSON.h cJSON.h
        PATHS /usr/include /usr/local/include /opt/homebrew/include
        PATH_SUFFIXES cjson
    )
    find_library(CJSON_LIBRARY 
        NAMES cjson libcjson
        PATHS /usr/lib /usr/local/lib /opt/homebrew/lib
    )
    
    if(CJSON_INCLUDE_DIR AND CJSON_LIBRARY)
        set(CJSON_FOUND TRUE)
        set(CJSON_INCLUDE_DIRS ${CJSON_INCLUDE_DIR})
        set(CJSON_LIBRARIES ${CJSON_LIBRARY})
        message(STATUS "Found cJSON: ${CJSON_LIBRARY}")
    endif()
endif()

# cJSON is required for full protocol support
if(NOT CJSON_FOUND)
    message(STATUS "cJSON not found in system - using bundled implementation")
    set(CJSON_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/third_party")
    set(CJSON_LIBRARIES "")
    set(CJSON_FOUND TRUE)
endif()

message(STATUS "cJSON include path: ${CJSON_INCLUDE_DIRS}")

# Find libcurl
find_package(CURL QUIET)
if(NOT CURL_FOUND)
    message(WARNING "libcurl not found - HTTP features will be disabled")
    set(CURL_INCLUDE_DIRS "")
    set(CURL_LIBRARIES "")
else()
    include(CheckIncludeFile)
    set(CMAKE_REQUIRED_INCLUDES ${CURL_INCLUDE_DIRS})
    check_include_file("curl/curl.h" NEOC_HAVE_CURL_HEADER)
    unset(CMAKE_REQUIRED_INCLUDES)

    if(NOT NEOC_HAVE_CURL_HEADER)
        message(WARNING "libcurl library found but curl headers are missing - HTTP features will be disabled")
        set(CURL_FOUND FALSE)
        set(CURL_INCLUDE_DIRS "")
        set(CURL_LIBRARIES "")
    endif()
endif()

# Include directories
include_directories(include)
include_directories(third_party)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CJSON_INCLUDE_DIRS})
include_directories(${CURL_INCLUDE_DIRS})

# Source files
file(GLOB_RECURSE SOURCES "src/*.c")
list(APPEND SOURCES src/script/script_builder_full.c)

set(USE_BUNDLED_CJSON OFF)
if(NOT CJSON_FOUND OR NOT CJSON_LIBRARIES)
    set(USE_BUNDLED_CJSON ON)
endif()

if(USE_BUNDLED_CJSON)
    include_directories(third_party/cjson)
    list(APPEND SOURCES third_party/cjson/cJSON.c)
endif()

# Only compile the libcurl-backed URL session when curl headers exist.
if(CURL_FOUND)
    list(FILTER SOURCES EXCLUDE REGEX "/src/utils/url_session_nocurl\\.c$")
else()
    list(FILTER SOURCES EXCLUDE REGEX "/src/utils/url_session\\.c$")
endif()

# Remove incomplete RPC response stubs until they are fully implemented
list(FILTER SOURCES EXCLUDE REGEX "/src/protocol/core/response/neo_get_.*\\.c$")
list(FILTER SOURCES EXCLUDE REGEX "/src/protocol/core/response/.*\\.c$")
list(FILTER SOURCES EXCLUDE REGEX "/src/protocol/response/.*\\.c$")
list(FILTER SOURCES EXCLUDE REGEX "/src/transaction/neo_transaction\\.c$")
list(FILTER SOURCES EXCLUDE REGEX "/src/crypto/sha256\\.c$")

set(NEOC_RESPONSE_SOURCES
    src/protocol/core/response/contract_manifest.c
    src/protocol/core/response/contract_method_token.c
    src/protocol/core/response/contract_nef.c
    src/protocol/core/response/contract_state.c
    src/protocol/core/response/contract_storage_entry.c
    src/protocol/core/response/diagnostics.c
    src/protocol/core/response/express_contract_state.c
    src/protocol/core/response/express_shutdown.c
    src/protocol/core/response/invocation_result.c
    src/protocol/core/response/name_state.c
    src/protocol/core/response/native_contract_state.c
    src/protocol/core/response/neo_account_state.c
    src/protocol/core/response/neo_address.c
    src/protocol/core/response/neo_application_log.c
    src/protocol/core/response/neo_block.c
    src/protocol/core/response/neo_get_mem_pool.c
    src/protocol/core/response/neo_get_nep17_balances.c
    src/protocol/core/response/neo_get_nep17_transfers.c
    src/protocol/core/response/neo_get_nep11_balances.c
    src/protocol/core/response/neo_get_nep11_transfers.c
    src/protocol/core/response/neo_get_next_block_validators.c
    src/protocol/core/response/neo_get_token_balances.c
    src/protocol/core/response/neo_get_token_transfers.c
    src/protocol/core/response/neo_get_unspents.c
    src/protocol/core/response/neo_get_claimable.c
    src/protocol/core/response/neo_network_fee.c
    src/protocol/core/response/neo_send_raw_transaction.c
    src/protocol/core/response/neo_response_aliases.c
    src/protocol/core/response/neo_list_plugins.c
    src/protocol/core/response/nep17_contract.c
    src/protocol/core/response/neo_witness.c
    src/protocol/core/response/transaction_send_token.c
    src/protocol/core/response/transaction_signer.c
    src/protocol/core/response/populated_blocks.c
    src/protocol/core/response/oracle_request.c
    src/protocol/core/response/record_state.c
    src/protocol/core/response/neo_get_state_root.c
    src/protocol/core/response/neo_get_state_height.c
    src/protocol/core/response/neo_get_unclaimed_gas.c
    src/protocol/core/response/neo_get_wallet_balance.c
    src/protocol/core/response/neo_validate_address.c
    src/protocol/core/response/neo_find_states.c
)

foreach(resp ${NEOC_RESPONSE_SOURCES})
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${resp})
endforeach()

# Create static library
add_library(neoc STATIC ${SOURCES})

if(CJSON_FOUND)
    target_compile_definitions(neoc PRIVATE HAVE_CJSON)
endif()

# Link libraries
target_link_libraries(neoc 
    ${OPENSSL_LIBRARIES}
    ${CJSON_LIBRARIES}
    ${CURL_LIBRARIES}
    m
)

# Compiler definitions
target_compile_definitions(neoc PRIVATE 
    ${CJSON_CFLAGS_OTHER}
)

# Define macros based on found libraries
if(CJSON_FOUND)
    target_compile_definitions(neoc PRIVATE HAVE_CJSON)
endif()

if(CURL_FOUND)
    target_compile_definitions(neoc PRIVATE HAVE_CURL)
endif()

# Installation
install(TARGETS neoc 
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

# Install headers
install(DIRECTORY include/neoc 
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Examples
option(BUILD_EXAMPLES "Build example programs" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Tests
option(BUILD_TESTS "Build test programs" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Export package
export(TARGETS neoc FILE NeoCConfig.cmake)

# Create pkg-config file
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/neoc.pc.in 
               ${CMAKE_CURRENT_BINARY_DIR}/neoc.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/neoc.pc 
        DESTINATION lib/pkgconfig)
