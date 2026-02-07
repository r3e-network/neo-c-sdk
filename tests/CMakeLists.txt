# Test programs for NeoC SDK with Unity testing framework
cmake_minimum_required(VERSION 3.16)
project(NeoC_Tests)

# Compiler configuration
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enable coverage in debug builds
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(ENABLE_COVERAGE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fprofile-arcs -ftest-coverage")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
    endif()
    
    # Enable debug memory tracking
    add_definitions(-DNEOC_DEBUG_MEMORY)
    
    # Enable sanitizers but not leak sanitizer on ARM macOS
    if(APPLE)
        execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
        if(ARCH STREQUAL "arm64")
            # ARM macOS doesn't support leak sanitizer
            set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined")
            set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined")
        else()
            # Intel macOS supports leak sanitizer
            set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined,leak")
            set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined,leak")
        endif()
    elseif(UNIX)
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined,leak")
        set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address,undefined,leak")
    endif()
endif()

# Thread support for performance and thread safety tests
find_package(Threads REQUIRED)
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

# Find OpenSSL (required for crypto operations)
find_package(OpenSSL REQUIRED)

# libcurl is optional: only required when the NeoC library was built with HTTP support.
find_package(CURL QUIET)

# Prefer linking against the in-tree target when building NeoC from source.
if(TARGET neoc)
    include_directories(${CMAKE_SOURCE_DIR}/include)
    set(NEOC_LIBS neoc)
else()
    find_path(NEOC_INCLUDE_DIR neoc/neoc.h HINTS ../include)
    find_library(NEOC_LIBRARY neoc HINTS ../build)
    if(NOT NEOC_INCLUDE_DIR OR NOT NEOC_LIBRARY)
        message(FATAL_ERROR "NeoC headers/library not found. Build NeoC first or install the SDK.")
    endif()
    include_directories(${NEOC_INCLUDE_DIR})
    set(NEOC_LIBS ${NEOC_LIBRARY} ${CURL_LIBRARIES})
endif()

# Unity testing framework
add_library(unity STATIC unity.c unity.h)
target_include_directories(unity PUBLIC .)

# Test executables with Unity framework
add_executable(test_basic test_basic.c)
target_link_libraries(test_basic ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_memory test_memory.c)
target_link_libraries(test_memory unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(test_memory PRIVATE NEOC_DEBUG_MEMORY)

add_executable(test_comprehensive test_comprehensive.c)
target_link_libraries(test_comprehensive unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_performance test_performance.c)
target_link_libraries(test_performance unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

add_executable(test_transaction_builder test_transaction_builder.c)
target_link_libraries(test_transaction_builder unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_bip39 test_bip39.c)
target_link_libraries(test_bip39 unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_bip39_account test_bip39_account.c)
target_link_libraries(test_bip39_account unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_bip32 test_bip32.c)
target_link_libraries(test_bip32 unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_crypto_simple test_crypto_simple.c)
target_link_libraries(test_crypto_simple unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_account test_account.c)
target_link_libraries(test_account unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_signer test_signer.c)
target_link_libraries(test_signer unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_witness test_witness.c)
target_link_libraries(test_witness unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_witness_scope test_witness_scope.c)
target_link_libraries(test_witness_scope unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_base64 test_base64.c)
target_link_libraries(test_base64 unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_base58 test_base58.c)
target_link_libraries(test_base58 unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_wif test_wif.c)
target_link_libraries(test_wif unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_hash160 test_hash160.c)
target_link_libraries(test_hash160 unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_hash256 test_hash256.c)
target_link_libraries(test_hash256 unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_contract_parameter test_contract_parameter.c)
target_link_libraries(test_contract_parameter unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_script_builder test_script_builder.c)
target_link_libraries(test_script_builder unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ec_key_pair test_ec_key_pair.c)
target_link_libraries(test_ec_key_pair unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_sign test_sign.c)
target_link_libraries(test_sign unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_enum_types test_enum_types.c)
target_link_libraries(test_enum_types unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_ripemd160 test_ripemd160.c)
target_link_libraries(test_ripemd160 unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_nep2 test_nep2.c)
target_link_libraries(test_nep2 unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_constants test_neo_constants.c)
target_link_libraries(test_neo_constants unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_get_mem_pool test_neo_get_mem_pool.c)
target_link_libraries(test_neo_get_mem_pool unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_get_token_balances test_neo_get_token_balances.c)
target_link_libraries(test_neo_get_token_balances unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_get_nep17_balances test_neo_get_nep17_balances.c)
target_link_libraries(test_neo_get_nep17_balances unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_get_nep17_transfers test_neo_get_nep17_transfers.c)
target_link_libraries(test_neo_get_nep17_transfers unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_get_nep11_balances test_neo_get_nep11_balances.c)
target_link_libraries(test_neo_get_nep11_balances unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_get_nep11_transfers test_neo_get_nep11_transfers.c)
target_link_libraries(test_neo_get_nep11_transfers unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_get_next_block_validators test_neo_get_next_block_validators.c)
target_link_libraries(test_neo_get_next_block_validators unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_type_conversions test_type_conversions.c)
target_link_libraries(test_type_conversions unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_math_utils test_math_utils.c)
target_link_libraries(test_math_utils unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_scrypt_params test_scrypt_params.c)
target_link_libraries(test_scrypt_params unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_binary_reader test_binary_reader.c)
target_link_libraries(test_binary_reader unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_binary_writer test_binary_writer.c)
target_link_libraries(test_binary_writer unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_data_validation test_data_validation.c)
target_link_libraries(test_data_validation unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_c_express test_neo_c_express.c)
target_link_libraries(test_neo_c_express unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_neo_c_client test_neo_c_client.c)
target_link_libraries(test_neo_c_client unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_new_rpc_responses test_new_rpc_responses.c)
target_link_libraries(test_new_rpc_responses unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_integration test_integration.c)
target_link_libraries(test_integration unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

add_executable(test_find_states_response test_find_states_response.c)
target_link_libraries(test_find_states_response unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

# ===== COMPREHENSIVE TEST MODULES (Converted from Swift and Extended) =====

# NEP-2 comprehensive tests
add_executable(test_nep2_comprehensive test_nep2_comprehensive.c)
target_link_libraries(test_nep2_comprehensive unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

# WIF comprehensive tests
add_executable(test_wif_comprehensive test_wif_comprehensive.c)
target_link_libraries(test_wif_comprehensive unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

# GAS Token comprehensive tests
add_executable(test_gas_token_comprehensive test_gas_token_comprehensive.c)
target_link_libraries(test_gas_token_comprehensive unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

# Account comprehensive tests
add_executable(test_account_comprehensive test_account_comprehensive.c)
target_link_libraries(test_account_comprehensive unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

# Integration comprehensive tests
add_executable(test_integration_comprehensive test_integration_comprehensive.c)
target_link_libraries(test_integration_comprehensive unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

# Memory comprehensive tests
add_executable(test_memory_comprehensive test_memory_comprehensive.c)
target_link_libraries(test_memory_comprehensive unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(test_memory_comprehensive PRIVATE NEOC_DEBUG_MEMORY)

# Performance comprehensive tests
add_executable(test_performance_comprehensive test_performance_comprehensive.c)
target_link_libraries(test_performance_comprehensive unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# Additional comprehensive tests
# Temporarily disabled until test implementations are fixed
# add_executable(test_full_integration test_full_integration.c)
# target_link_libraries(test_full_integration unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

# add_executable(test_performance_benchmark test_performance_benchmark.c)
# target_link_libraries(test_performance_benchmark ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)

# add_executable(test_thread_safety test_thread_safety.c)
# target_link_libraries(test_thread_safety ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# Test runner configuration
# Basic functionality tests
add_test(NAME BasicTests COMMAND test_basic)
set_tests_properties(BasicTests PROPERTIES 
    TIMEOUT 30
    LABELS "basic;unit"
)

# Memory tests (debug builds only)
add_test(NAME MemoryTests COMMAND test_memory)
set_tests_properties(MemoryTests PROPERTIES 
    TIMEOUT 60
    LABELS "memory;debug"
)

# Comprehensive tests with all test vectors
add_test(NAME ComprehensiveTests COMMAND test_comprehensive)
set_tests_properties(ComprehensiveTests PROPERTIES 
    TIMEOUT 120
    LABELS "comprehensive;unit"
)

# Performance benchmarks
add_test(NAME PerformanceTests COMMAND test_performance)
set_tests_properties(PerformanceTests PROPERTIES 
    TIMEOUT 300
    LABELS "performance;benchmark"
)

# Transaction builder tests
add_test(NAME TransactionBuilderTests COMMAND test_transaction_builder)
set_tests_properties(TransactionBuilderTests PROPERTIES 
    TIMEOUT 60
    LABELS "transaction;unit"
)

# BIP-39 mnemonic tests
add_test(NAME BIP39Tests COMMAND test_bip39)
set_tests_properties(BIP39Tests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;bip39;unit"
)

# BIP-39 Account tests
add_test(NAME BIP39AccountTests COMMAND test_bip39_account)
set_tests_properties(BIP39AccountTests PROPERTIES 
    TIMEOUT 60
    LABELS "wallet;bip39;account;unit"
)

# BIP-32 HD Wallet tests
add_test(NAME BIP32Tests COMMAND test_bip32)
set_tests_properties(BIP32Tests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;bip32;hd;unit"
)

# Simple crypto tests
add_test(NAME CryptoSimpleTests COMMAND test_crypto_simple)
set_tests_properties(CryptoSimpleTests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;simple;unit"
)

# Account tests
add_test(NAME AccountTests COMMAND test_account)
set_tests_properties(AccountTests PROPERTIES 
    TIMEOUT 60
    LABELS "wallet;account;unit"
)

# Signer tests
add_test(NAME SignerTests COMMAND test_signer)
set_tests_properties(SignerTests PROPERTIES 
    TIMEOUT 60
    LABELS "transaction;signer;unit"
)

# Witness tests
add_test(NAME WitnessTests COMMAND test_witness)
set_tests_properties(WitnessTests PROPERTIES 
    TIMEOUT 60
    LABELS "transaction;witness;unit"
)

# Witness Scope tests
add_test(NAME WitnessScopeTests COMMAND test_witness_scope)
set_tests_properties(WitnessScopeTests PROPERTIES 
    TIMEOUT 60
    LABELS "transaction;witness_scope;unit"
)

# Base64 tests
add_test(NAME Base64Tests COMMAND test_base64)
set_tests_properties(Base64Tests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;base64;unit"
)

# Base58 tests
add_test(NAME Base58Tests COMMAND test_base58)
set_tests_properties(Base58Tests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;base58;unit"
)

# WIF tests
add_test(NAME WIFTests COMMAND test_wif)
set_tests_properties(WIFTests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;wif;unit"
)

# Hash160 tests
add_test(NAME Hash160Tests COMMAND test_hash160)
set_tests_properties(Hash160Tests PROPERTIES 
    TIMEOUT 60
    LABELS "types;hash160;unit"
)

# Hash256 tests
add_test(NAME Hash256Tests COMMAND test_hash256)
set_tests_properties(Hash256Tests PROPERTIES 
    TIMEOUT 60
    LABELS "types;hash256;unit"
)

# Contract Parameter tests
add_test(NAME ContractParameterTests COMMAND test_contract_parameter)
set_tests_properties(ContractParameterTests PROPERTIES 
    TIMEOUT 60
    LABELS "types;contract_parameter;unit"
)

# Script Builder tests
add_test(NAME ScriptBuilderTests COMMAND test_script_builder)
set_tests_properties(ScriptBuilderTests PROPERTIES 
    TIMEOUT 60
    LABELS "script;script_builder;unit"
)

# EC Key Pair tests
add_test(NAME ECKeyPairTests COMMAND test_ec_key_pair)
set_tests_properties(ECKeyPairTests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;ec_key_pair;unit"
)

# Sign tests
add_test(NAME SignTests COMMAND test_sign)
set_tests_properties(SignTests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;sign;unit"
)

# Enum Type tests
add_test(NAME EnumTypeTests COMMAND test_enum_types)
set_tests_properties(EnumTypeTests PROPERTIES 
    TIMEOUT 60
    LABELS "types;enum;unit"
)

# RIPEMD160 tests
add_test(NAME RIPEMD160Tests COMMAND test_ripemd160)
set_tests_properties(RIPEMD160Tests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;ripemd160;unit"
)

# NEP-2 tests
add_test(NAME NEP2Tests COMMAND test_nep2)
set_tests_properties(NEP2Tests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;nep2;unit"
)

# Neo Constants tests
add_test(NAME NeoConstantsTests COMMAND test_neo_constants)
set_tests_properties(NeoConstantsTests PROPERTIES 
    TIMEOUT 60
    LABELS "constants;unit"
)

add_test(NAME NeoGetMemPoolTests COMMAND test_neo_get_mem_pool)
set_tests_properties(NeoGetMemPoolTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;rpc;unit"
)

add_test(NAME NeoGetTokenBalancesTests COMMAND test_neo_get_token_balances)
set_tests_properties(NeoGetTokenBalancesTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;rpc;unit"
)

add_test(NAME NeoGetNep17BalancesTests COMMAND test_neo_get_nep17_balances)
set_tests_properties(NeoGetNep17BalancesTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;rpc;unit"
)

add_test(NAME NeoGetNep17TransfersTests COMMAND test_neo_get_nep17_transfers)
set_tests_properties(NeoGetNep17TransfersTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;rpc;unit"
)

add_test(NAME NeoGetNep11BalancesTests COMMAND test_neo_get_nep11_balances)
set_tests_properties(NeoGetNep11BalancesTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;rpc;unit"
)

add_test(NAME NeoGetNep11TransfersTests COMMAND test_neo_get_nep11_transfers)
set_tests_properties(NeoGetNep11TransfersTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;rpc;unit"
)

add_test(NAME NeoGetNextBlockValidatorsTests COMMAND test_neo_get_next_block_validators)
set_tests_properties(NeoGetNextBlockValidatorsTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;rpc;unit"
)

add_test(NAME NeoCExpressTests COMMAND test_neo_c_express)
set_tests_properties(NeoCExpressTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;express;unit"
)

add_test(NAME NeoCClientSendRequestTests COMMAND test_neo_c_client)
set_tests_properties(NeoCClientSendRequestTests PROPERTIES
    TIMEOUT 60
    LABELS "protocol;client;unit"
)

add_test(NAME NewRpcResponsesTests COMMAND test_new_rpc_responses)
set_tests_properties(NewRpcResponsesTests PROPERTIES
    TIMEOUT 120
    LABELS "protocol;rpc;unit"
)

# Type Conversion tests
add_test(NAME TypeConversionTests COMMAND test_type_conversions)
set_tests_properties(TypeConversionTests PROPERTIES 
    TIMEOUT 60
    LABELS "types;conversions;unit"
)

# Math Utility tests
add_test(NAME MathUtilTests COMMAND test_math_utils)
set_tests_properties(MathUtilTests PROPERTIES 
    TIMEOUT 60
    LABELS "math;utilities;unit"
)

# BIP-39 test vectors
add_executable(test_bip39_vectors test_bip39_vectors.c)
target_link_libraries(test_bip39_vectors unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME BIP39VectorTests COMMAND test_bip39_vectors)
set_tests_properties(BIP39VectorTests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;bip39;vectors"
)

# Multi-signature tests
add_executable(test_multi_sig test_multi_sig.c)
target_link_libraries(test_multi_sig unity ${NEOC_LIBS} OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME MultiSigTests COMMAND test_multi_sig)
set_tests_properties(MultiSigTests PROPERTIES 
    TIMEOUT 60
    LABELS "wallet;multisig;unit"
)

# Optional extra unit tests under tests/unit (off by default to avoid target duplication)
option(BUILD_EXTRA_UNIT_TESTS "Build additional unit tests under tests/unit" OFF)
if(BUILD_EXTRA_UNIT_TESTS)
    add_subdirectory(unit)
endif()

# Integration tests
add_test(NAME IntegrationTests COMMAND test_integration)
set_tests_properties(IntegrationTests PROPERTIES 
    TIMEOUT 120
    LABELS "integration;e2e"
)

# ===== COMPREHENSIVE TEST CASES =====

# NEP-2 comprehensive tests
add_test(NAME NEP2ComprehensiveTests COMMAND test_nep2_comprehensive)
set_tests_properties(NEP2ComprehensiveTests PROPERTIES 
    TIMEOUT 120
    LABELS "crypto;nep2;comprehensive"
)

# WIF comprehensive tests
add_test(NAME WIFComprehensiveTests COMMAND test_wif_comprehensive)
set_tests_properties(WIFComprehensiveTests PROPERTIES 
    TIMEOUT 60
    LABELS "crypto;wif;comprehensive"
)

# GAS Token comprehensive tests
add_test(NAME GasTokenComprehensiveTests COMMAND test_gas_token_comprehensive)
set_tests_properties(GasTokenComprehensiveTests PROPERTIES 
    TIMEOUT 60
    LABELS "contract;gas;comprehensive"
)

# Account comprehensive tests
add_test(NAME AccountComprehensiveTests COMMAND test_account_comprehensive)
set_tests_properties(AccountComprehensiveTests PROPERTIES 
    TIMEOUT 90
    LABELS "wallet;account;comprehensive"
)

# Integration comprehensive tests
add_test(NAME IntegrationComprehensiveTests COMMAND test_integration_comprehensive)
set_tests_properties(IntegrationComprehensiveTests PROPERTIES 
    TIMEOUT 180
    LABELS "integration;workflow;comprehensive"
)

# Memory comprehensive tests
add_test(NAME MemoryComprehensiveTests COMMAND test_memory_comprehensive)
set_tests_properties(MemoryComprehensiveTests PROPERTIES 
    TIMEOUT 120
    LABELS "memory;debug;comprehensive"
)

# Performance comprehensive tests
add_test(NAME PerformanceComprehensiveTests COMMAND test_performance_comprehensive)
set_tests_properties(PerformanceComprehensiveTests PROPERTIES 
    TIMEOUT 300
    LABELS "performance;benchmark;comprehensive"
)

# Valgrind tests (if available)
find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Memory leak tests with valgrind
    add_test(NAME ValgrindMemoryTest 
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/valgrind_test.sh -m ${CMAKE_CURRENT_BINARY_DIR}/test_memory)
    set_tests_properties(ValgrindMemoryTest PROPERTIES 
        TIMEOUT 300
        LABELS "valgrind;memory"
    )
    
    add_test(NAME ValgrindBasicTest 
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/valgrind_test.sh -m ${CMAKE_CURRENT_BINARY_DIR}/test_basic)
    set_tests_properties(ValgrindBasicTest PROPERTIES 
        TIMEOUT 300
        LABELS "valgrind;basic"
    )
    
    add_test(NAME ValgrindComprehensiveTest 
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/valgrind_test.sh -m ${CMAKE_CURRENT_BINARY_DIR}/test_comprehensive)
    set_tests_properties(ValgrindComprehensiveTest PROPERTIES 
        TIMEOUT 600
        LABELS "valgrind;comprehensive"
    )
endif()

# Custom test targets
add_custom_target(test_all
    COMMAND ${CMAKE_CTEST_COMMAND} --parallel 4 --output-on-failure
    DEPENDS test_basic test_memory test_comprehensive test_performance 
            test_nep2_comprehensive test_wif_comprehensive test_gas_token_comprehensive
            test_account_comprehensive test_integration_comprehensive 
            test_memory_comprehensive test_performance_comprehensive
    COMMENT "Running all NeoC SDK tests (including comprehensive test suite)"
)

add_custom_target(test_quick
    COMMAND ${CMAKE_CTEST_COMMAND} -L "basic" --output-on-failure
    DEPENDS test_basic
    COMMENT "Running quick basic tests"
)

add_custom_target(test_comprehensive_only
    COMMAND ${CMAKE_CTEST_COMMAND} -L "comprehensive" --output-on-failure
    DEPENDS test_nep2_comprehensive test_wif_comprehensive test_gas_token_comprehensive
            test_account_comprehensive test_integration_comprehensive 
            test_memory_comprehensive test_performance_comprehensive
    COMMENT "Running comprehensive test suite (converted from Swift + extended)"
)

add_custom_target(test_memory_only
    COMMAND ${CMAKE_CTEST_COMMAND} -L "memory" --output-on-failure
    DEPENDS test_memory test_memory_comprehensive
    COMMENT "Running memory-related tests"
)

add_custom_target(test_performance_only
    COMMAND ${CMAKE_CTEST_COMMAND} -L "performance" --output-on-failure
    DEPENDS test_performance test_performance_comprehensive
    COMMENT "Running performance benchmarks"
)

add_custom_target(test_crypto_comprehensive
    COMMAND ${CMAKE_CTEST_COMMAND} -L "crypto" -L "comprehensive" --output-on-failure
    DEPENDS test_nep2_comprehensive test_wif_comprehensive
    COMMENT "Running comprehensive crypto tests"
)

add_custom_target(test_integration_comprehensive_only
    COMMAND ${CMAKE_CTEST_COMMAND} -L "integration" -L "comprehensive" --output-on-failure
    DEPENDS test_integration_comprehensive
    COMMENT "Running comprehensive integration workflow tests"
)

# Test coverage target (if coverage enabled)
if(ENABLE_COVERAGE AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    find_program(LCOV_EXECUTABLE lcov)
    find_program(GENHTML_EXECUTABLE genhtml)
    
    if(LCOV_EXECUTABLE AND GENHTML_EXECUTABLE)
        add_custom_target(coverage
            COMMAND ${LCOV_EXECUTABLE} --directory . --zerocounters
            COMMAND ${CMAKE_CTEST_COMMAND} --parallel 4 -L "unit;crypto;wallet;contract;comprehensive"
            COMMAND ${LCOV_EXECUTABLE} --directory . --capture --output-file coverage.info
            COMMAND ${LCOV_EXECUTABLE} --remove coverage.info '/usr/*' --output-file coverage.info
            COMMAND ${LCOV_EXECUTABLE} --remove coverage.info '*/tests/*' --output-file coverage.info
            COMMAND ${GENHTML_EXECUTABLE} coverage.info --output-directory coverage_html
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            DEPENDS test_basic test_memory test_comprehensive 
                    test_nep2_comprehensive test_wif_comprehensive test_gas_token_comprehensive
                    test_account_comprehensive test_integration_comprehensive 
                    test_memory_comprehensive
            COMMENT "Generating comprehensive code coverage report (includes converted Swift tests)"
        )
    endif()
endif()

# Install test executables (optional)
if(INSTALL_TESTS)
    install(TARGETS test_basic test_memory test_comprehensive test_performance
                    test_nep2_comprehensive test_wif_comprehensive test_gas_token_comprehensive
                    test_account_comprehensive test_integration_comprehensive 
                    test_memory_comprehensive test_performance_comprehensive
        RUNTIME DESTINATION bin/tests
    )
    
    install(FILES 
        valgrind_test.sh
        run_tests.sh
        DESTINATION bin/tests
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    )
endif()

# Display test configuration summary
message(STATUS "NeoC SDK Test Configuration:")
message(STATUS "  Unity framework: Enabled")
message(STATUS "  Basic tests: 30+ modules")
message(STATUS "  Comprehensive tests: 7 modules (converted from Swift + extended)")
message(STATUS "  Memory tests: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Coverage: ${ENABLE_COVERAGE}")
message(STATUS "  Valgrind: ${VALGRIND_EXECUTABLE}")
message(STATUS "  Thread support: ${CMAKE_THREAD_LIBS_INIT}")
message(STATUS "")
message(STATUS "Available test targets:")
message(STATUS "  make test_all                    - Run all tests")
message(STATUS "  make test_comprehensive_only     - Run comprehensive test suite")
message(STATUS "  make test_crypto_comprehensive   - Run crypto comprehensive tests")
message(STATUS "  make test_memory_only            - Run memory tests")
message(STATUS "  make test_performance_only       - Run performance tests")
message(STATUS "  make test_quick                  - Run basic tests only")
