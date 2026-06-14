# Test suite — SoftHSM2 KSP

## Test strategy — Three-layer pyramid

```
                    ┌─────────────────────────────────┐
                    │  Layer 3 — PowerShell functional │  (Windows, KSP registered)
                    │  test_ksp.ps1       9 scenarios  │
                    │  test_cng_hlk.ps1  61 HLK tests  │
                    └──────────────┬──────────────────┘
                                   │
               ┌───────────────────┴────────────────────┐
               │   Layer 2 — KSP integration tests       │  (Windows, direct link)
               │   test_ksp_integration.exe  21 tests    │
               │   Tests 1-14: original suite            │
               │   Tests 15-21: HLK-conformant scenarios │
               └───────────────────┬────────────────────┘
                                   │
   ┌───────────────────────────────┴────────────────────────────────┐
   │         Layer 1 — Unit tests (Linux/GCC, no SoftHSM2 needed)   │
   │         10 test suites · 281 assertions · gcov coverage         │
   │         Lines: 91.0 %    Functions: 100 %                       │
   └────────────────────────────────────────────────────────────────┘
```

Each layer builds on the previous:
- **Layer 1** — Isolated unit tests with PKCS#11 mocks; fast, run on Linux CI without Windows SDK or SoftHSM2.
- **Layer 2** — End-to-end integration against the full KSP stack; requires Windows and a live SoftHSM2 token.
- **Layer 3** — Full Windows NCrypt API exercised through PowerShell P/Invoke + BCrypt verification; requires the KSP to be registered in the Windows registry.

---

## Layer 1 — Unit tests

### Running

```powershell
# On Linux/macOS (GCC + gcov):
cd tests/unit
make

# Run each suite:
./test_p11rv_mapping
./test_logging
./test_mechanism_resolve
./test_export_blobs
./test_ksp_provider
./test_ksp_key_ops
./test_ksp_crypto
./test_ksp_key_props
./test_memory
./test_ecdsa_decode
```

### Test suites

| Suite | File | Assertions | What is tested |
|-------|------|:----------:|----------------|
| PKCS#11 error mapping | `test_p11rv_mapping.c` | 22 | `P11RvToSecStatus()` — all CK_RV codes → SECURITY_STATUS |
| Logging | `test_logging.c` | 9 | `Log_Initialize`, `Log_Debug`, `Log_Error`, `KSP_DEBUG` toggle |
| Mechanism resolution | `test_mechanism_resolve.c` | 18 | `P11_ResolveMechanism()` for all algorithm/flag combinations |
| Export blobs | `test_export_blobs.c` | 23 | `P11_ExportRsaPublicKey`, `P11_ExportEcPublicKey`, `P11_FindObjectByLabel`, `P11_GetUlongAttr` |
| KSP provider | `test_ksp_provider.c` | 27 | `KSP_OpenProvider`, `KSP_FreeProvider`, `KSP_GetProviderProperty`, `KSP_SetProviderProperty`, `KSP_FreeBuffer` |
| KSP key operations | `test_ksp_key_ops.c` | 65 | `KSP_OpenKey`, `KSP_CreatePersistedKey`, `KSP_FinalizeKey`, `KSP_DeleteKey`, `KSP_FreeKey`, `KSP_EnumKeys` |
| KSP crypto | `test_ksp_crypto.c` | 60 | `KSP_SignHash` (RSA/ECDSA), `KSP_Decrypt` (PKCS1/OAEP), `KSP_ExportKey`, `KSP_ImportKey` |
| KSP key properties | `test_ksp_key_props.c` | 25 | `KSP_GetKeyProperty`, `KSP_SetKeyProperty` for all property types |
| Memory | `test_memory.c` | 13 | `KSP_Alloc`, `KSP_AllocZero`, `KSP_Free`, `KSP_WStrDup` |
| ECDSA DER decode | `test_ecdsa_decode.c` | 19 | `P11_DecodeDerEcdsaSignature()` DER parsing, `P11_EcCoordSize()` for P-256 and P-384 |
| **Total** | | **281** | |

### Coverage (gcov / lcov — 2026-06-13)

| Module | Lines | Hit | Line % | Functions | Hit | Func % |
|--------|------:|----:|:------:|----------:|----:|:------:|
| `common/` | 38 | 33 | **86.8 %** | 7 | 7 | **100 %** |
| `ksp/` | 716 | 652 | **91.1 %** | 27 | 27 | **100 %** |
| `pkcs11/` | 193 | 177 | **91.7 %** | 9 | 9 | **100 %** |
| **Total** | **947** | **862** | **91.0 %** | **43** | **43** | **100 %** |

> Full HTML report: `tests/unit/coverage_html/index.html`

#### Uncovered lines (9 %)

The 85 lines not hit by unit tests fall into three categories:

| Category | Examples | Covered by |
|----------|---------|------------|
| PKCS#11 error branches | `C_Finalize` failure paths | Manual integration tests |
| Large key generation (RSA 3072/4096) | Slow paths skipped in unit | Integration test 14, 19 (HLK) |
| Session pool exhaustion | `WAIT_TIMEOUT` after 5 s | Concurrency stress test |

---

## Layer 2 — KSP integration tests

### Running

```powershell
# Build (Visual Studio x64 Developer Command Prompt):
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# Prerequisites:
set SOFTHSM2_LIB=C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll
set SOFTHSM2_PIN=1234

.\build\Release\test_ksp_integration.exe
```

### Original suite (Tests 1–14)

| Test | Name | What is verified |
|------|------|-----------------|
| 1 | `OpenProvider` | `KSP_OpenProvider` succeeds; handle is non-null |
| 2 | `GetProviderProperty` | NAME, VERSION (=1), IMPL_TYPE (hardware flag set) |
| 3 | `CreatePersistedKey RSA 2048` | Key created with unique label |
| 4 | `FinalizeKey RSA` | Key pair generated in SoftHSM2 token |
| 5 | `GetKeyProperty` | ALGORITHM = "RSA", LENGTH = 2048 |
| 6 | `SignHash RSA PKCS1` | Double-call pattern (size query + actual sign) |
| 7 | `ExportKey BCRYPT_RSAPUBLIC_BLOB` | Blob size and `BCRYPT_RSAPUBLIC_MAGIC` header |
| 8 | `ExportKey private → NTE_NOT_SUPPORTED` | Private key export refused |
| 9 | `OpenKey (reopen)` | Existing key retrieved by label from token |
| 10 | `CreatePersistedKey ECDSA P-256` | ECDSA_P256 key created |
| 11 | `SignHash ECDSA` | 64-byte raw r‖s signature |
| 12 | `EnumKeys` | Both test keys appear in enumeration |
| 13 | `DeleteKey` | Keys destroyed; subsequent OpenKey fails |
| 14 | `SetKeyProperty NCRYPT_LENGTH` | PERSIST_ONLY → SetProperty(4096) → FinalizeKey generates RSA 4096 |

### HLK-conformant scenarios (Tests 15–21)

Mirrors Microsoft's **TPM 2.0 Platform Crypto Provider KSP Test**
(HLK ID: `7c938be0-ff4a-44f9-916c-b578f027f0ca`).

| Test | Name | What is verified |
|------|------|-----------------|
| 15 | `RSA PSS sign + BCrypt verify` | `BCRYPT_PSS_PADDING_INFO` (SHA-256, cbSalt=32); BCrypt imports KSP public blob and verifies signature |
| 16 | `RSA PKCS1 BCrypt verify + properties` | End-to-end PKCS1 verify; KEY_USAGE=ALLOW_SIGNING, EXPORT_POLICY=0, ALG_GROUP="RSA", UNIQUE_NAME=label |
| 17 | `ECDSA P-256 BCrypt verify` | 64-byte raw signature; `BCryptImportKeyPair(ECCPUBLICBLOB)` + `BCryptVerifySignature`; ALG_GROUP="ECDSA" |
| 18 | `ECDSA P-384` | 96-byte r‖s (P-384); SHA-384 hash (48 bytes); full BCrypt round-trip |
| 19 | `RSA 3072 deferred` | PERSIST_ONLY → SetProperty(3072) → FinalizeKey; 384-byte sig; BCrypt PKCS1 verify |
| 20 | `RSA OAEP decrypt` | AT_KEYEXCHANGE key; `BCryptEncrypt(OAEP/SHA-1)` → `KSP_Decrypt(OAEP)`; plaintext equality |
| 21 | `Error conditions` | Invalid handle, non-existent key, forbidden private export, NULL provider |

### Assertion summary

| Suite | Tests | Assertions |
|-------|------:|----------:|
| Original (1–14) | 14 | 40 |
| HLK scenarios (15–21) | 7 | 51 |
| **Total** | **21** | **91** |

---

## Layer 3 — PowerShell functional tests

These tests run against the fully registered KSP (`regsvr32 softhsm_ksp.dll`) using
the official Windows `NCrypt*` API and `BCrypt*` API through PowerShell P/Invoke.

### Running

```powershell
# Both scripts require Administrator and the KSP registered:
.\tools\test_ksp.ps1
.\tools\test_cng_hlk.ps1
```

### `test_ksp.ps1` — Basic functional tests (9 tests)

| # | Test | API exercised |
|---|------|---------------|
| 1 | KSP enumeration | `certutil -csplist` |
| 2 | RSA 2048 key generation | `NCryptCreatePersistedKey` + `NCryptFinalizeKey` |
| 3 | RSA PKCS1 signing | `NCryptSignHash` (`NCRYPT_PAD_PKCS1_FLAG`) |
| 4 | RSA signature verification | Implicit (non-null signature = PKCS#11 success) |
| 5 | ECDSA P-256 key generation | `NCryptCreatePersistedKey("ECDSA_P256")` |
| 6 | ECDSA signing | `NCryptSignHash` (no padding) |
| 7 | ECDSA verification | Implicit |
| 8 | EnumKeys | `NCryptEnumKeys` with state loop |
| 9 | Key deletion | `NCryptDeleteKey` for both test keys |

### `test_cng_hlk.ps1` — HLK-conformant test suite (61 tests)

| Section | Description | Tests |
|---------|-------------|------:|
| S1 | Provider enumeration and properties (Name, Version, ImplType) | 4 |
| S2 | RSA 2048 AT_SIGNATURE: PKCS1 + PSS signing, BCrypt verification, 6 property queries, private export rejection | 14 |
| S3 | RSA 2048 AT_KEYEXCHANGE: BCrypt OAEP encrypt → `NCryptDecrypt` round-trip | 6 |
| S4 | RSA 3072 deferred creation (`SetProperty` + `FinalizeKey`), BCrypt PKCS1 verify | 6 |
| S5 | ECDSA P-256: create, sign, BCrypt verify, property queries (ALGORITHM, LENGTH, KEY_USAGE, ALG_GROUP) | 9 |
| S6 | ECDSA P-384: sign SHA-384 (48-byte hash), 96-byte r‖s signature, BCrypt verify | 6 |
| S7 | `NCryptEnumKeys` (5 test keys found) + `NCryptOpenKey` round-trip | 7 |
| S8 | Error conditions: invalid handle, private blob, non-existent key, NULL property handle | 4 |
| S9 | Cleanup: `NCryptDeleteKey` for all 5 test keys | 5 |
| **Total** | | **61** |

#### BCrypt verification helpers (C# P/Invoke inside `Add-Type`)

The HLK script includes managed C# helper methods to avoid raw pointer marshalling in PowerShell:

| Helper | Description |
|--------|-------------|
| `Hlk.VerifyRsaPkcs1()` | `BCryptImportKeyPair(RSAPUBLICBLOB)` + `BCryptVerifySignature(BCRYPT_PAD_PKCS1)` |
| `Hlk.VerifyRsaPss()` | Same + `BCryptVerifySignature(BCRYPT_PAD_PSS)` with marshalled `BCRYPT_PSS_PADDING_INFO` |
| `Hlk.VerifyEcdsa()` | `BCryptImportKeyPair(ECCPUBLICBLOB)` + `BCryptVerifySignature` (no padding) |
| `Hlk.EncryptRsaOaep()` | `BCryptEncrypt` with marshalled `BCRYPT_OAEP_PADDING_INFO` |
| `Hlk.DecryptOaep()` | `NCryptDecrypt` with marshalled `BCRYPT_OAEP_PADDING_INFO` |
| `Hlk.ExportPublicKey()` | `NCryptExportKey` double-call pattern |
| `Hlk.GetStringProperty()` / `GetDwordProperty()` | `NCryptGetProperty` wrappers |
| `Hlk.SignPkcs1()` / `SignPss()` / `SignEcdsa()` | `NCryptSignHash` wrappers |

---

## Test coverage overview — All layers combined

| Scenario | Unit | Integration | HLK (PS) |
|----------|:----:|:-----------:|:--------:|
| Provider open/close | ✓ | ✓ | ✓ |
| Provider properties (Name, Version, ImplType) | ✓ | ✓ | ✓ |
| RSA 2048 key creation | ✓ | ✓ | ✓ |
| RSA 3072 key creation (deferred) | — | ✓ | ✓ |
| RSA 4096 key creation (deferred) | — | ✓ | — |
| ECDSA P-256 key creation | ✓ | ✓ | ✓ |
| ECDSA P-384 key creation | — | ✓ | ✓ |
| RSA PKCS1 signing | ✓ | ✓ | ✓ |
| RSA PSS signing (SHA-256/384/512) | ✓ | ✓ | ✓ |
| ECDSA P-256 signing + BCrypt verify | ✓ | ✓ | ✓ |
| ECDSA P-384 signing + BCrypt verify | — | ✓ | ✓ |
| RSA OAEP decryption | ✓ | ✓ | ✓ |
| RSA PKCS1 BCrypt end-to-end verify | — | ✓ | ✓ |
| RSA PSS BCrypt end-to-end verify | — | ✓ | ✓ |
| Public key export (RSA + EC blobs) | ✓ | ✓ | ✓ |
| Private key export → NTE_NOT_SUPPORTED | ✓ | ✓ | ✓ |
| Key enumeration | ✓ | ✓ | ✓ |
| OpenKey round-trip | ✓ | ✓ | ✓ |
| Key deletion | ✓ | ✓ | ✓ |
| KEY_USAGE / EXPORT_POLICY / ALG_GROUP | ✓ | ✓ | ✓ |
| Invalid handle error conditions | ✓ | ✓ | ✓ |
| Session pool concurrency | — | — | — |
| Missing SoftHSM2 DLL | — | — | — |
