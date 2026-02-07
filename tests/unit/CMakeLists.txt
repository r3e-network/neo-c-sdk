# CMakeLists.txt for NeoC SDK Unit Tests

cmake_minimum_required(VERSION 3.10)
project(NeoC_Unit_Tests)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(CURL QUIET)
if(NOT CURL_FOUND)
    message(STATUS "libcurl not found - building unit tests without CURL")
endif()

# When building this test suite standalone, import the root NeoC static library.
if(NOT TARGET neoc)
    set(NEOC_ROOT_DIR ${CMAKE_SOURCE_DIR}/../..)
    set(NEOC_BUILD_DIR ${NEOC_ROOT_DIR}/build)
    set(NEOC_LIB_PATH ${NEOC_BUILD_DIR}/libneoc.a)
    if(NOT EXISTS ${NEOC_LIB_PATH})
        message(FATAL_ERROR "libneoc.a not found at ${NEOC_LIB_PATH}. Build NeoC (cmake -S . -B build && cmake --build build) before running unit tests.")
    endif()
    add_library(neoc STATIC IMPORTED)
    set_target_properties(neoc PROPERTIES IMPORTED_LOCATION ${NEOC_LIB_PATH})
    target_include_directories(neoc INTERFACE ${NEOC_ROOT_DIR}/include)
endif()

# Local Unity build for unit tests
add_library(unit_unity STATIC ../unity.c ../unity.h)
target_include_directories(unit_unity PUBLIC .. ../../include)

include_directories(..)
include_directories(../../include)

file(GLOB_RECURSE TEST_SOURCES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.c")
list(FILTER TEST_SOURCES EXCLUDE REGEX "^build/")
list(FILTER TEST_SOURCES EXCLUDE REGEX "^CMakeFiles/")
list(TRANSFORM TEST_SOURCES PREPEND "${CMAKE_CURRENT_SOURCE_DIR}/")

foreach(TEST_SOURCE ${TEST_SOURCES})
    get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
    if(TEST_SOURCE MATCHES "/types/")
        if(NOT (TEST_SOURCE MATCHES "test_hash160.c$" OR TEST_SOURCE MATCHES "test_hash256.c$"))
            message(STATUS "Skipping unit test ${TEST_SOURCE} (types suite requires legacy helpers)")
            continue()
        endif()
    endif()
    if(TEST_SOURCE MATCHES "/wallet/")
        if(NOT (TEST_SOURCE MATCHES "test_nep6_wallet_struct.c$" OR
                TEST_SOURCE MATCHES "test_account.c$"))
            message(STATUS "Skipping unit test ${TEST_SOURCE} (wallet unit tests require legacy API)")
            continue()
        endif()
    endif()
    if(TEST_SOURCE MATCHES "test_smart_contract.c$"
        OR TEST_SOURCE MATCHES "test_bip32_ec_key_pair.c$"
        OR TEST_SOURCE MATCHES "test_bip32_e_c_key_pair.c$")
        message(STATUS "Skipping unit test ${TEST_SOURCE} (requires legacy smart contract API)")
        continue()
    endif()
    set(TARGET_NAME unit_${TEST_NAME})

    add_executable(${TARGET_NAME} ${TEST_SOURCE})
    target_link_libraries(${TARGET_NAME}
        unit_unity
        neoc
        OpenSSL::SSL
        OpenSSL::Crypto)
    if(CURL_FOUND)
        target_link_libraries(${TARGET_NAME} CURL::libcurl)
    endif()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_link_options(${TARGET_NAME} PRIVATE -fsanitize=address)
    endif()
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${TARGET_NAME} PRIVATE -UNDEBUG)
    elseif(MSVC)
        target_compile_options(${TARGET_NAME} PRIVATE /UNDEBUG)
    endif()
    add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
endforeach()

enable_testing()
