# Documentation — SoftHSM2 KSP

Prototype of a **Microsoft CNG Key Storage Provider (KSP)** that delegates all
cryptographic operations to **SoftHSM2** via the **PKCS#11 v2.40** interface.

---

## Table of Contents

| Document | Content |
|----------|---------|
| [01 — Architecture](./01-architecture.md) | Overview, layers, data structures, threading model, memory management |
| [02 — Initialisation](./02-initialisation.md) | Loading softhsm2.dll, `InitOnceExecuteOnce` singleton, session pool, lifecycle |
| [03 — Key management](./03-key-management.md) | The five algorithm families, CreatePersistedKey, OpenKey, EnumKeys, DeleteKey, curve OIDs, symmetric keys |
| [04 — Cryptographic operations](./04-crypto-operations.md) | SignHash (PKCS1 / PSS / ECDSA / EdDSA / HMAC), Decrypt (PKCS1 / OAEP / AES), Encrypt, ECDH agreement, Export/Import, blob formats |
| [05 — Properties](./05-properties.md) | GetKeyProperty, SetKeyProperty, GetProviderProperty, chaining mode and IV, mapping table |
| [06 — Error mapping](./06-error-mapping.md) | CK_RV → SECURITY_STATUS, codes by function, mechanism dispatch, error flow diagram |
| [07 — Security and threading](./07-security-threading.md) | Concurrency, the three handle types, PIN management, secret zeroing, logging |
| [08 — Complete flows](./08-complete-flows.md) | TLS signing, code signing, enumeration, key rotation, ECDH agreement, AES encryption, missing-token recovery |
| [09 — Test suite](./09-tests.md) | Four-layer test pyramid: unit tests (676 assertions, 89.5 % coverage), integration tests (40 tests), PowerShell HLK suite (~150 tests) |
| [10 — Running the Microsoft HLK tests](./10-hlk-execution.md) | The in-repo HLK suite, the official HLK Studio procedure, and what blocks a real certification submission |
| [11 — CNG KSP market comparison](./11-market-comparison.md) | Capability audit against Microsoft, AWS, Utimaco, Thales, Entrust and Securosys providers, with evidence grades on every claim |

---

## Quick overview diagram

```
Windows Application
       │
       │ NCrypt*() API
       ▼
  ncrypt.dll ──── registry: HKLM\...\SoftHSM KSP\Image
       │                    GetKeyStorageInterface()
       │ NCRYPT_KEY_STORAGE_FUNCTION_TABLE
       ▼
softhsm_ksp.dll
  ├── ksp_*()          Implements the 22 functions of the CNG table
  ├── p11_context.c    PKCS#11 singleton (LoadLibrary + C_Initialize)
  ├── p11_session.c    Pool of 16 sessions (Windows semaphore)
  └── p11_utils.c      Mechanisms, format conversion, key export
       │
       │ C_XXX() via CK_FUNCTION_LIST
       │ LoadLibrary (no static link)
       ▼
softhsm2-x64.dll       PKCS#11 v2.40 — encrypted SQLite storage
```

---

## Supported algorithms

| Algorithm | Generation | Signing | Decryption | Key agreement | Public export |
|-----------|:---------:|:-------:|:----------:|:-------------:|:-------------:|
| RSA 2048 / 3072 / 4096 | ✓ | PKCS1 v1.5, PSS | PKCS1, OAEP (SHA-1/224/256/384/512) | — | ✓ |
| ECDSA P-256 / P-384 / P-521 | ✓ | ✓ (r‖s) | — | — | ✓ |
| ECDH P-256 / P-384 / P-521 | ✓ | — | — | ✓ | ✓ |
| EdDSA Ed25519 / Ed448 | ✓ | ✓ (raw) | — | — | ✓ |
| AES 128 / 192 / 256 | ✓ | — | ECB, CBC, CTR, GCM | — | — |
| HMAC SHA-1/256/384/512 | ✓ | ✓ (MAC) | — | — | — |

---

## CNG → PKCS#11 mapping summary

| CNG function | PKCS#11 mechanism | Notes |
|-------------|-------------------|-------|
| `SignHash` RSA PKCS1 | `CKM_RSA_PKCS` | Hash passed as-is |
| `SignHash` RSA PSS | `CKM_RSA_PKCS_PSS` | `CK_RSA_PKCS_PSS_PARAMS` mapped from `BCRYPT_PSS_PADDING_INFO` |
| `SignHash` ECDSA | `CKM_ECDSA` | DER result converted to r‖s |
| `Decrypt` PKCS1 | `CKM_RSA_PKCS` | — |
| `Decrypt` OAEP | `CKM_RSA_PKCS_OAEP` | `CK_RSA_PKCS_OAEP_PARAMS` mapped from `BCRYPT_OAEP_PADDING_INFO` |
| `SignHash` EdDSA | `CKM_EDDSA` | Raw signature, no DER conversion |
| `SignHash` HMAC | `CKM_SHA*_HMAC` | Secret-key MAC through `C_Sign` |
| `Decrypt` AES | `CKM_AES_ECB/CBC/CBC_PAD/CTR/GCM` | Mode from `NCRYPT_CHAINING_MODE_PROPERTY` |
| `Encrypt` AES | `CKM_AES_ECB/CBC/CBC_PAD/CTR/GCM` | IV from `NCRYPT_INITIALIZATION_VECTOR` |
| `SecretAgreement` | `CKM_ECDH1_DERIVE` | `CKD_NULL`; raw Z returned by `DeriveKey` |
| `CreateKey` RSA | `CKM_RSA_PKCS_KEY_PAIR_GEN` | `SENSITIVE=TRUE`, `EXTRACTABLE=FALSE` |
| `CreateKey` EC | `CKM_EC_KEY_PAIR_GEN` | P-256/P-384/P-521 DER OID in `CKA_EC_PARAMS` |
| `CreateKey` EdDSA | `CKM_EC_EDWARDS_KEY_PAIR_GEN` | Ed25519 or Ed448 OID in `CKA_EC_PARAMS` |
| `CreateKey` AES | `CKM_AES_KEY_GEN` | `CKA_VALUE_LEN` = 16 / 24 / 32 |
| `CreateKey` HMAC | `CKM_GENERIC_SECRET_KEY_GEN` | Generic secret sized to the hash |

---

## Code conventions

- **Comments**: in English
- **Warnings**: zero at `/W3` MSVC
- **Memory**: `HeapAlloc`/`HeapFree` on `GetProcessHeap()` only
- **Naming**: `KSP_` (KSP layer), `P11_` (PKCS#11 layer)
- **Handles**: direct cast `(KSP_PROVIDER *)hProvider`, validated by `dwMagic`
- **Thread-safety**: all functions are re-entrant
