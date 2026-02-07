# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2026-02-07

### Neo N3 v3.9.1 Protocol Compatibility

- Updated `getversion` RPC response parsing to include v3.9.1 fields (`tcpport`, `wsport`, `nonce`, `useragent`, `rpc`, `protocol` sub-objects).
- Completed `neo_get_version` public API coverage (`neoc_neo_version_set_protocol_info`, append helpers, JSON parse/serialize, success/network helpers) and added dedicated unit coverage.
- PolicyContract: added `setExecFeeFactor`, `setStoragePrice`, `blockAccount`, `unblockAccount` methods.
- PolicyContract: aligned whitelist fee API to v3.9.1 signatures (`getWhitelistFeeContracts`, `setWhitelistFeeContract(contract, method, argCount, fixedFee)`, `removeWhitelistFeeContract(contract, method, argCount)`).
- Native contract hash resolution corrected for all Neo N3 contracts in `smart_contract` helpers.
- Network magic constants corrected to Neo N3 values (`0x334F454E`, `0x334F4554`).
- RPC client `submitblock` path hardened against duplicate-free regressions.
- Binary serialization: fixed `neoc_binary_writer_to_array` empty-buffer behavior (`*len == 0`, `*data == NULL`) and aligned serialization API docs/examples.

### New Native Contract Wrappers

- **OracleContract**: `getPrice`, `setPrice` with correct default (0.5 GAS).
- **LedgerContract**: `currentHash`, `currentIndex`, `getBlock`, `getTransaction`, `getTransactionHeight`.
- **ContractManagement**: `getMinimumDeploymentFee`, `hasMethod`, `getContract`.
- **CryptoLib**: `sha256`, `ripemd160`, `murmur32`, `verifyWithECDsa`.
- **StdLib**: `serialize`, `deserialize`, `jsonSerialize`, `jsonDeserialize`, `base64Encode/Decode`, `base58Encode/Decode`, `itoa`, `atoi`, `memoryCompare`, `memorySearch`.

### New RPC Method Implementations

- Added 20 RPC methods: `getblockheader`, `getblockheadercount`, `invokecontractverify`, `getunclaimedgas`, `calculatenetworkfee`, `getnep17transfers`, `getnep11balances`, `getnep11transfers`, `getnep11properties`, `listplugins`, `submitblock`, `validateaddress`, `getcandidates`, `traverseiterator`, `terminatesession`, `getstateroot`, `getstate`, `findstates`, `getproof`, `verifyproof`.

### Tests

- Added 50 unit tests across 6 new native contract test suites (policy, oracle, ledger, contract management, crypto lib, std lib).

### Housekeeping

- Synchronized SDK version to 1.2.0 across `CMakeLists.txt`, `src/neoc.c`, and `neoc.pc.in`.
- Added `NEOC_PROTOCOL_VERSION_391` constant in `neo_constants.h`.

## [1.1.1] - 2025-12-14

- Normalized NEP/URI/NNS naming across the codebase and tests (removed misnamed `n_e_p*`, `neo_u_r_i`, `n_n_s_name`, `r_i_p_e_m_d160`, `w_i_f` artifacts).
- Fixed LeakSanitizer failures in integration tests by enforcing explicit ownership/freeing of copied key pairs.
- Standardized internal allocation to the NeoC allocator (`neoc_*`) for binary reader/writer and several wallet/contract helpers.
- Improved optional dependency behavior (curl/cJSON) and added compatibility wrappers for response headers.

## [1.1.0] - 2025-11-20

- Restored public response alias helpers for Neo RPC parity (block count/hash, connection count, boolean/string/transaction/address list).
- Implemented and covered additional RPC responses: calculate network fee, send raw transaction, token transfers/unspents, oracle request, populated blocks, plugin listing, record state, transaction signer/send token, NEP-17 contract, Neo witness.
- Expanded unit test coverage for the new responses and documentation updates.
- Updated SDK and tool version reporting to 1.1.0.

## [1.0.0] - 2024-11-01

- Initial release of NeoC SDK (C implementation of NeoSwift) with complete core functionality and test suite.
