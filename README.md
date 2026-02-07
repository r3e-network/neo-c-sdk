# NeoC SDK

A comprehensive C library for Neo blockchain development providing core functionality for building Neo applications, smart contracts, wallets, and blockchain integrations. This is a complete C implementation converted from the NeoSwift SDK.

## Repository

- **GitHub**: https://github.com/r3e-network/NeoC
- **Status**: Production Ready
- **Version**: 1.2.0

## Features

### Core Types

- **Hash160**: 20-byte hashes for script hashes and addresses
- **Hash256**: 32-byte hashes for transactions and blocks
- **Bytes**: Dynamic byte array management with memory safety
- **ECKeyPair**: Elliptic curve key pair operations
- **ECDSASignature**: Digital signature operations

### Cryptographic Operations

- SHA-256 and double SHA-256 hashing
- RIPEMD-160 hashing
- Hash160 computation (SHA-256 + RIPEMD-160)
- Hash256 computation
- HMAC-SHA256
- ECDSA signature generation and verification
- OpenSSL-based implementation for security and performance

### Encoding Utilities

- **Hexadecimal**: Encode/decode binary data to/from hex strings
- **Base58**: Bitcoin-style Base58 encoding/decoding
- **Base58Check**: Base58 with checksum validation
- **Base64**: Standard and URL-safe Base64 encoding/decoding

### Neo Blockchain Features

- **Wallet Management**: Account creation, WIF import/export, NEP-6 wallet support
- **Transaction Building**: Complete transaction construction and signing
- **Smart Contracts**: NEP-17 (fungible tokens), NEP-11 (non-fungible tokens)
- **Name Service**: Neo Name Service (NNS) integration
- **RPC Client**: Full Neo node RPC client with 45+ methods including block/transaction queries, contract invocation, NEP-17/NEP-11 token queries, state proofs, iterator traversal, and network fee calculation.
- **Native Contracts**: Complete wrappers for all 9 Neo N3 native contracts — NeoToken, GasToken, PolicyContract, OracleContract, LedgerContract, ContractManagement, CryptoLib, StdLib, and RoleManagement.
- **Neo N3 v3.9.1**: Full protocol compatibility including whitelist fee contracts, updated version response fields, and policy contract extensions.
- **Protocol Support**: Neo protocol message handling

### Memory Management

- Safe memory allocation with leak detection (debug mode)
- Secure memory clearing for sensitive data
- Custom allocator support
- Thread-safe operations
- Ownership rule of thumb: free opaque objects with their `*_free()` function; free returned buffers/strings with `neoc_free()`.

### Error Handling

- Comprehensive error codes and messages
- Thread-local error information
- Stack trace support for debugging
- Detailed error context

## Quick Start

### Installation on macOS

```bash
# Install dependencies
brew install cmake openssl cjson curl

# Clone the repository
git clone https://github.com/r3e-network/NeoC.git
cd NeoC

# Build the SDK
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j8

# Run tests
make test

# Install (optional)
sudo make install
```

### Installation on Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y cmake build-essential libssl-dev libcjson-dev libcurl4-openssl-dev

# Clone and build
git clone https://github.com/r3e-network/NeoC.git
cd NeoC
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j8

# Run tests
make test

# Install (optional)
sudo make install
```

## Building

### Prerequisites

- CMake 3.16 or later
- C99-compatible compiler (GCC 7+, Clang 3.4+, MSVC 2015+)
- OpenSSL 1.1.1+ or 3.x development libraries
- cJSON library (optional, for RPC client)
- libcurl library (optional, for HTTP support)

### Build Instructions

```bash
# Clone and navigate to NeoC directory
git clone https://github.com/r3e-network/NeoC.git
cd NeoC

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build the library
make

# Run tests
make test

# Install (optional)
sudo make install
```

### Build Options

```bash
# Debug build with memory leak detection
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release ..

# Disable examples
cmake -DBUILD_EXAMPLES=OFF ..

# Disable tests
cmake -DBUILD_TESTS=OFF ..
```

## Quick Start

### Basic Usage

```c
#include "neoc/neoc.h"

int main(void) {
    // Initialize NeoC SDK
    if (neoc_init() != NEOC_SUCCESS) {
        return 1;
    }

    // Create Hash160 from hex string
    neoc_hash160_t hash;
    if (neoc_hash160_from_hex(&hash, "17694821c6e3ea8b7a7d770952e7de86c73d94c3") == NEOC_SUCCESS) {
        // Convert to Neo address
        char address[64];
        if (neoc_hash160_to_address(&hash, address, sizeof(address)) == NEOC_SUCCESS) {
            printf("Address: %s\n", address);
        }
    }

    // Cleanup
    neoc_cleanup();
    return 0;
}
```

### Hash Operations

```c
// Create Hash256 from data
const char* data = "Hello, Neo!";
neoc_hash256_t hash;
neoc_hash256_from_data_hash(&hash, (const uint8_t*)data, strlen(data));

// Convert to hex string
char hex_string[65];
neoc_hash256_to_hex(&hash, hex_string, sizeof(hex_string), false);
printf("SHA-256: %s\n", hex_string);
```

### Wallet Operations

```c
// Create new account
neoc_account_t* account = neoc_account_create();
if (account) {
    // Get WIF
    char wif[64];
    neoc_account_to_wif(account, wif, sizeof(wif));
    printf("WIF: %s\n", wif);

    // Get address
    char address[64];
    neoc_account_get_address(account, address, sizeof(address));
    printf("Address: %s\n", address);

    neoc_account_free(account);
}
```

### Transaction Building

```c
// Create transaction builder
neoc_transaction_builder_t* builder = neoc_transaction_builder_create();
if (builder) {
    // Set expiry using current chain height when available
    neoc_rpc_client_t* rpc = NULL;
    if (neoc_rpc_client_create("http://localhost:10332", &rpc) == NEOC_SUCCESS) {
        neoc_transaction_builder_set_valid_until_block_from_rpc(builder, rpc, 1000);
        neoc_rpc_client_free(rpc);
    }

    // Add transfer
    neoc_hash160_t to_address;
    neoc_hash160_from_address(&to_address, "NQrFVj6NvW5z2wKb3m8X9pL1nR4sT7uY6v");

    neoc_error_t err = neoc_transaction_builder_add_transfer(
        builder,
        &to_address,
        100000000  // 1 NEO (in satoshis)
    );

    if (err == NEOC_SUCCESS) {
        // Build transaction
        neoc_transaction_t* tx = neoc_transaction_builder_build(builder);
        if (tx) {
            // Sign transaction
            neoc_account_t* account = neoc_account_from_wif("your_wif_here");
            if (account) {
                neoc_transaction_sign(tx, account);
                neoc_account_free(account);
            }
            neoc_transaction_free(tx);
        }
    }

    neoc_transaction_builder_free(builder);
}
```

### Encoding Examples

```c
// Hex encoding
const uint8_t data[] = {0xde, 0xad, 0xbe, 0xef};
char* hex = neoc_hex_encode_alloc(data, 4, false, false);
printf("Hex: %s\n", hex);  // Output: deadbeef
neoc_free(hex);

// Base58 encoding
char* base58 = neoc_base58_encode_alloc(data, 4);
printf("Base58: %s\n", base58);
neoc_free(base58);

// Base64 encoding
char* base64 = neoc_base64_encode_alloc(data, 4);
printf("Base64: %s\n", base64);
neoc_free(base64);
```

### Binary Serialization Example

```c
neoc_binary_writer_t *writer = NULL;
if (neoc_binary_writer_create(64, true, &writer) == NEOC_SUCCESS) {
    neoc_binary_writer_write_uint32(writer, 12345);

    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    if (neoc_binary_writer_to_array(writer, &serialized, &serialized_len) == NEOC_SUCCESS) {
        // When writer is empty: serialized_len == 0 and serialized == NULL
        if (serialized) {
            neoc_free(serialized);
        }
    }

    neoc_binary_writer_free(writer);
}
```

## Examples

The `examples/` directory contains comprehensive examples:

- `crypto_example.c`: Cryptographic operations
- `transaction_example.c`: Transaction building and signing
- `wallet_example.c`: Wallet management

Build and run examples:

```bash
cd build
./examples/crypto_example
./examples/transaction_example
./examples/wallet_example
```

## Testing

Run the test suite:

```bash
cd build
make test

# Or run tests directly
./tests/test_basic
./tests/test_crypto
./tests/test_wallet
```

Enable extended unit tests for native contract coverage:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXTRA_UNIT_TESTS=ON ..
make
ctest --output-on-failure
```

Debug builds include memory leak detection and AddressSanitizer:

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
./tests/test_memory
```

## API Reference

### Core Functions

```c
// SDK initialization
neoc_error_t neoc_init(void);
void neoc_cleanup(void);
const char* neoc_get_version(void);

// Error handling
const char* neoc_error_string(neoc_error_t error_code);
bool neoc_is_success(neoc_error_t error_code);
```

### Hash160 Operations

```c
// Creation
neoc_error_t neoc_hash160_from_hex(neoc_hash160_t* hash, const char* hex_string);
neoc_error_t neoc_hash160_from_address(neoc_hash160_t* hash, const char* address);
neoc_error_t neoc_hash160_from_script(neoc_hash160_t* hash, const uint8_t* script, size_t length);

// Conversion
neoc_error_t neoc_hash160_to_hex(const neoc_hash160_t* hash, char* buffer, size_t buffer_size, bool uppercase);
neoc_error_t neoc_hash160_to_address(const neoc_hash160_t* hash, char* buffer, size_t buffer_size);

// Comparison
bool neoc_hash160_equal(const neoc_hash160_t* a, const neoc_hash160_t* b);
int neoc_hash160_compare(const neoc_hash160_t* a, const neoc_hash160_t* b);
```

### Hash256 Operations

```c
// Creation
neoc_error_t neoc_hash256_from_hex(neoc_hash256_t* hash, const char* hex_string);
neoc_error_t neoc_hash256_from_data_hash(neoc_hash256_t* hash, const uint8_t* data, size_t length);
neoc_error_t neoc_hash256_from_data_double_hash(neoc_hash256_t* hash, const uint8_t* data, size_t length);

// Conversion
neoc_error_t neoc_hash256_to_hex(const neoc_hash256_t* hash, char* buffer, size_t buffer_size, bool uppercase);
```

### Account Operations

```c
// Account creation
neoc_account_t* neoc_account_create(void);
neoc_account_t* neoc_account_from_wif(const char* wif);
neoc_account_t* neoc_account_from_private_key(const uint8_t* private_key);

// Account operations
neoc_error_t neoc_account_to_wif(const neoc_account_t* account, char* buffer, size_t buffer_size);
neoc_error_t neoc_account_get_address(const neoc_account_t* account, char* buffer, size_t buffer_size);
neoc_error_t neoc_account_get_public_key(const neoc_account_t* account, uint8_t* buffer, size_t buffer_size);

// Memory management
void neoc_account_free(neoc_account_t* account);
```

### Transaction Operations

```c
// Transaction building
neoc_transaction_builder_t* neoc_transaction_builder_create(void);
neoc_error_t neoc_transaction_builder_add_transfer(neoc_transaction_builder_t* builder, const neoc_hash160_t* to, uint64_t amount);
neoc_transaction_t* neoc_transaction_builder_build(neoc_transaction_builder_t* builder);

// Transaction operations
neoc_error_t neoc_transaction_sign(neoc_transaction_t* transaction, const neoc_account_t* account);
neoc_error_t neoc_transaction_serialize(const neoc_transaction_t* transaction, uint8_t* buffer, size_t buffer_size, size_t* serialized_size);

// Memory management
void neoc_transaction_builder_free(neoc_transaction_builder_t* builder);
void neoc_transaction_free(neoc_transaction_t* transaction);
```

### Encoding Functions

```c
// Hexadecimal
neoc_error_t neoc_hex_encode(const uint8_t* data, size_t length, char* buffer, size_t buffer_size, bool uppercase, bool prefix);
neoc_error_t neoc_hex_decode(const char* hex_string, uint8_t* buffer, size_t buffer_size, size_t* decoded_length);

// Base58
char* neoc_base58_encode_alloc(const uint8_t* data, size_t length);
uint8_t* neoc_base58_decode_alloc(const char* base58_string, size_t* decoded_length);

// Base58Check
char* neoc_base58_check_encode_alloc(const uint8_t* data, size_t length);
uint8_t* neoc_base58_check_decode_alloc(const char* base58_string, size_t* decoded_length);

// Base64
char* neoc_base64_encode_alloc(const uint8_t* data, size_t length);
uint8_t* neoc_base64_decode_alloc(const char* base64_string, size_t* decoded_length);
```

## Memory Management

NeoC provides safe memory management:

```c
// Allocation
void* ptr = neoc_malloc(size);
void* array = neoc_calloc(count, size);

// Secure deallocation (clears memory)
neoc_secure_free(ptr, size);

// Regular deallocation
neoc_free(ptr);
```

## Error Handling

All functions return `neoc_error_t` codes:

```c
neoc_error_t result = neoc_hash160_from_hex(&hash, hex_string);
if (result != NEOC_SUCCESS) {
    printf("Error: %s\n", neoc_error_string(result));
    return result;
}
```

## Thread Safety

NeoC is designed to be thread-safe:

- Memory management functions are thread-safe
- Error handling uses thread-local storage
- Crypto functions can be used from multiple threads

## Project Structure

```
NeoC/
├── include/neoc/           # Header files
│   ├── crypto/            # Cryptographic operations
│   ├── types/             # Core data types
│   ├── wallet/            # Wallet management
│   ├── transaction/       # Transaction operations
│   ├── contract/          # Smart contract support
│   ├── protocol/          # Neo protocol implementation
│   └── utils/             # Utility functions
├── src/                   # Source code implementation
│   ├── crypto/            # Cryptographic implementations
│   ├── types/             # Type implementations
│   ├── wallet/            # Wallet implementations
│   ├── transaction/       # Transaction implementations
│   ├── contract/          # Contract implementations
│   ├── protocol/          # Protocol implementations
│   └── utils/             # Utility implementations
├── tests/                 # Test suite
├── examples/              # Example applications
├── tools/                 # Build and development tools
└── CMakeLists.txt         # Build configuration
```

## Contributing

1. Follow C11 standards
2. Include comprehensive tests
3. Document all public APIs
4. Use consistent naming conventions (`neoc_*` prefix)
5. Ensure memory safety and leak-free code
6. Maintain compatibility with the original Swift SDK API

## License

Licensed under the MIT License (see `LICENSE`).

## Support

For issues and questions:

- Check the examples in `examples/`
- Review test cases in `tests/`
- Consult the API documentation in header files
- See `CHANGELOG.md` for release notes
- Report issues on GitHub: https://github.com/r3e-network/NeoC/issues

## Changelog

See `CHANGELOG.md` for detailed release notes.
