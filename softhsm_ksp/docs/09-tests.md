# Test suite — SoftHSM2 KSP

## Test strategy — Four-layer pyramid

```
                 ┌──────────────────────────────────────┐
                 │  Layer 4 — Official Microsoft HLK     │  (HLK controller + client)
                 │  HLK Studio, test 7c938be0-...        │
                 └──────────────┬───────────────────────┘
                                │
                 ┌──────────────┴───────────────────────┐
                 │  Layer 3 — PowerShell functional      │  (Windows, KSP registered)
                 │  test_ksp.ps1   9 scenarios / 17 chk  │
                 │  test_cng_hlk.ps1  ~150 HLK tests     │
                 └──────────────┬───────────────────────┘
                                │
               ┌────────────────┴───────────────────────┐
               │   Layer 2 — KSP integration tests       │  (Windows, direct link)
               │   test_ksp_integration.exe  40 tests    │
               │   Tests 1-14:  original suite           │
               │   Tests 15-21: HLK-conformant scenarios │
               │   Tests 22-40: 2.7.0 mechanism coverage │
               └────────────────┬───────────────────────┘
                                │
   ┌────────────────────────────┴───────────────────────────────────┐
   │         Layer 1 — Unit tests (Linux/GCC, no SoftHSM2 needed)   │
   │         14 test suites · 780 assertions · gcov coverage         │
   │         Lines: 89.8 %    Functions: 100 %                       │
   └────────────────────────────────────────────────────────────────┘
```

Each layer builds on the previous:
- **Layer 1** — Isolated unit tests with PKCS#11 mocks; fast, run on Linux CI without Windows SDK or SoftHSM2.
- **Layer 2** — End-to-end integration against the full KSP stack; requires Windows and a live SoftHSM2 token.
- **Layer 3** — Full Windows NCrypt API exercised through PowerShell P/Invoke + BCrypt verification; requires the KSP to be registered in the Windows registry.
- **Layer 4** — The official Microsoft HLK runner. Needs a controller and a separate test client; see [10 — Running the Microsoft HLK tests](./10-hlk-execution.md).

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
./test_oaep_params
./test_ecdh
./test_eddsa
./test_aes_keys

# Or simply:
make run          # builds and runs all 14 suites
make coverage     # plus an HTML coverage report
make syntax-check # parses the Windows-only integration test
```

### Test suites

| Suite | File | Assertions | What is tested |
|-------|------|:----------:|----------------|
| PKCS#11 error mapping | `test_p11rv_mapping.c` | 26 | `P11RvToSecStatus()` — all CK_RV codes → SECURITY_STATUS |
| Logging | `test_logging.c` | 7 | `Log_Initialize`, `Log_Debug`, `Log_Error`, `KSP_DEBUG` toggle |
| Mechanism resolution | `test_mechanism_resolve.c` | 35 | `P11_ResolveMechanism()` for all algorithm/flag combinations |
| Export blobs | `test_export_blobs.c` | 38 | `P11_ExportRsaPublicKey`, `P11_ExportEcPublicKey`, `P11_FindObjectByLabel`, `P11_GetUlongAttr` |
| KSP provider | `test_ksp_provider.c` | 31 | `KSP_OpenProvider`, `KSP_FreeProvider`, `KSP_GetProviderProperty`, `KSP_SetProviderProperty`, `KSP_FreeBuffer` |
| KSP key operations | `test_ksp_key_ops.c` | 154 | `KSP_OpenKey`, `KSP_CreatePersistedKey`, `KSP_FinalizeKey`, `KSP_DeleteKey`, `KSP_FreeKey`, `KSP_EnumKeys` |
| KSP crypto | `test_ksp_crypto.c` | 98 | `KSP_SignHash` (RSA/ECDSA), `KSP_Decrypt` (PKCS1/OAEP), `KSP_ExportKey`, `KSP_ImportKey` |
| KSP key properties | `test_ksp_key_props.c` | 87 | `KSP_GetKeyProperty`, `KSP_SetKeyProperty` for all property types |
| Memory | `test_memory.c` | 21 | `KSP_Alloc`, `KSP_AllocZero`, `KSP_Free`, `KSP_WStrDup` |
| ECDSA DER decode | `test_ecdsa_decode.c` | 47 | `P11_DecodeDerEcdsaSignature()` DER parsing, `P11_EcCoordSize()` for P-256 / P-384 / P-521 and the ECDH curves |
| OAEP parameters | `test_oaep_params.c` | 49 | `P11_MapHashAlg()` and `P11_BuildOaepParams()` across SHA-1/224/256/384/512, label pass-through, unsupported-hash rejection |
| ECDH agreement | `test_ecdh.c` | 41 | `KSP_SecretAgreement`, `KSP_DeriveKey`, `KSP_FreeSecret`, `KSP_IsValidSecret`; DER unwrapping of the peer point on all three curves |
| EdDSA | `test_eddsa.c` | 58 | Ed25519 / Ed448 classifiers, curve OIDs, `CKM_EDDSA` resolution, key generation, signing, public-key export |
| AES and HMAC | `test_aes_keys.c` | 88 | AES-128/192/256 generation, chaining mode + IV properties, `KSP_Encrypt`/`KSP_Decrypt` over ECB/CBC/CTR/GCM, HMAC generic secrets |
| **Total** | | **780** | |

Counts above are the assertions each suite reports, read back from a full
`make run`. The earlier figures (10 suites / 281 assertions) predate the
SoftHSM2 2.7.0 mechanism work; the jump from 676 to 780 is the small-gap
work described in `docs/11-market-comparison.md`.

### Coverage (gcov / gcovr — 2026-09-09)

| Module | Lines | Hit | Line % | Functions | Hit | Func % |
|--------|------:|----:|:------:|----------:|----:|:------:|
| `common/` | 38 | 33 | **86.8 %** | 7 | 7 | **100 %** |
| `ksp/` | 1280 | 1144 | **89.4 %** | 42 | 42 | **100 %** |
| `pkcs11/` | 335 | 307 | **91.6 %** | 14 | 14 | **100 %** |
| **Total** | **1653** | **1484** | **89.8 %** | **63** | **63** | **100 %** |

> Full HTML report: `tests/unit/coverage_html/index.html`

#### Uncovered lines (10.5 %)

The 168 lines not hit by unit tests fall into four categories:

| Category | Examples | Covered by |
|----------|---------|------------|
| Out-of-memory branches | `KSP_AllocZero` returning NULL | Not reachable without allocator injection |
| PKCS#11 error branches | `C_Finalize` failure paths | Manual integration tests |
| Large key generation (RSA 3072/4096) | Slow paths skipped in unit | Integration tests 14, 19 |
| Session pool exhaustion | `WAIT_TIMEOUT` after 5 s | Concurrency stress test |

Regenerate the report with `make coverage` (needs `lcov`), or with
`gcovr` if `lcov` is unavailable:

```bash
gcovr --root .. --filter '.*/src/.*' --print-summary \
      --html-details coverage_html/index.html
```

---

## Layer 2 — KSP integration tests

### Running

```powershell
# Build (Visual Studio x64 Developer Command Prompt):
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
      -DSOFTHSM2_DIR=..\softhsm2-install
cmake --build build --config Release

# Prerequisites:
set SOFTHSM2_LIB=C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll
set SOFTHSM2_PIN=1234

.\build\Release\test_ksp_integration.exe
```

The integration test only *runs* on Windows, but it can be parsed on any
platform to catch typos before a Windows build:

```bash
cd tests/unit && make syntax-check
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

### `test_cng_hlk.ps1` — HLK-conformant test suite (~150 tests)

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
| S9 | Cleanup: `NCryptDeleteKey` for every key the run created | 5+ |
| S10 | ECDSA P-521: create, sign SHA-512 (132-byte r‖s), export, blob layout, BCrypt verify | 11 |
| S11 | ECDH over P-256 / P-384 / P-521: export/import public keys, both parties agree on the same secret | 27 |
| S12 | EdDSA Ed25519 (64-byte sig) and Ed448 (114-byte sig): create, sign, export, blob layout | 18 |
| S13 | AES-256 across ECB / CBC / CTR / GCM: chaining mode, IV, encrypt-decrypt round-trip | 29 |
| S14 | Error conditions for the extended set: unsupported curve, bad AES length, cipher properties on RSA keys, mismatched-curve ECDH | 5 |
| **Total** | | **~150** |

Sections S10–S14 cover the mechanisms added for SoftHSM2 2.7.0. S11 is the
strongest test in the suite: it runs a full two-party key agreement and
asserts both sides derive **byte-identical** secrets.

#### Validating the suite without Windows

The suite compiles an embedded C# P/Invoke block at run time. Parse errors
and P/Invoke signature mistakes can be caught anywhere PowerShell 7+ runs:

```bash
pwsh -File tools/validate_hlk_script.ps1
```

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
| `Hlk.SetStringProperty()` / `SetBinaryProperty()` / `SetDwordProperty()` | `NCryptSetProperty` wrappers (chaining mode, IV, key length) |
| `Hlk.Encrypt()` / `DecryptSym()` | `NCryptEncrypt` / `NCryptDecrypt` double-call pattern for symmetric keys |
| `Hlk.AgreeAndDeriveRaw()` | `NCryptSecretAgreement` + `NCryptDeriveKey("TRUNCATE")`, freeing the secret handle |
| `Hlk.ImportPublic()` | `NCryptImportKey` for a public key blob |
| `Hlk.BytesEqual()` / `BytesDiffer()` | Byte-array comparison in C#, avoiding LINQ generic inference from PowerShell |

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
| ECDSA P-521 key creation and signing | ✓ | ✓ | ✓ |
| ECDH P-256 / P-384 / P-521 agreement | ✓ | ✓ | ✓ |
| Two-party ECDH secret equality | — | ✓ | ✓ |
| EdDSA Ed25519 / Ed448 signing | ✓ | ✓ | ✓ |
| AES-128/192/256 key generation | ✓ | ✓ | ✓ |
| AES ECB / CBC / CTR / GCM round-trip | ✓ | ✓ | ✓ |
| HMAC-SHA256 generic secret keys | ✓ | ✓ | — |
| RSA OAEP SHA-384 / SHA-512 | ✓ | ✓ | — |
| OAEP application label | ✓ | ✓ | — |
| EC public key import (real PKCS#11 object) | ✓ | ✓ | ✓ |
| Symmetric key reopen by name | ✓ | ✓ | — |
| Session pool concurrency | — | — | — |
| Missing SoftHSM2 DLL | — | — | — |
