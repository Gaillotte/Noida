# Documentation — SoftHSM2 KSP

Prototype of a **Microsoft CNG Key Storage Provider (KSP)** that delegates all
cryptographic operations to **SoftHSM2** via the **PKCS#11 v2.40** interface.

---

## Table of Contents

| Document | Content |
|----------|---------|
| [01 — Architecture](./01-architecture.md) | Overview, layers, data structures, threading model, memory management |
| [02 — Initialisation](./02-initialisation.md) | Loading softhsm2.dll, `InitOnceExecuteOnce` singleton, session pool, lifecycle |
| [03 — Key management](./03-gestion-cles.md) | CreatePersistedKey (RSA / ECDSA), OpenKey, EnumKeys, DeleteKey, DER OIDs |
| [04 — Cryptographic operations](./04-operations-crypto.md) | SignHash (PKCS1 / PSS / ECDSA), Decrypt (PKCS1 / OAEP), ExportKey, ImportKey, blob formats |
| [05 — Properties](./05-proprietes.md) | GetKeyProperty, SetKeyProperty, GetProviderProperty, mapping table |
| [06 — Error mapping](./06-mapping-erreurs.md) | CK_RV → SECURITY_STATUS, codes by function, error flow diagram |
| [07 — Security and threading](./07-securite-threading.md) | Concurrency, handle validation, PIN management, logging |
| [08 — Complete flows](./08-flux-complets.md) | TLS scenarios, code signing, enumeration, key rotation, missing token error |
| [09 — Test suite](./09-tests.md) | Three-layer test pyramid: unit tests (281 assertions, 91 % coverage), integration tests (21 tests incl. HLK scenarios 15–21), PowerShell HLK suite (61 tests) |

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

| Algorithm | Generation | Signing | Decryption | Public export |
|-----------|:---------:|:-------:|:----------:|:-------------:|
| RSA 2048 | ✓ | PKCS1 v1.5, PSS | PKCS1, OAEP | ✓ |
| RSA 3072 | ✓ | PKCS1 v1.5, PSS | PKCS1, OAEP | ✓ |
| RSA 4096 | ✓ | PKCS1 v1.5, PSS | PKCS1, OAEP | ✓ |
| ECDSA P-256 | ✓ | ✓ (r‖s) | — | ✓ |
| ECDSA P-384 | ✓ | ✓ (r‖s) | — | ✓ |

---

## CNG → PKCS#11 mapping summary

| CNG function | PKCS#11 mechanism | Notes |
|-------------|-------------------|-------|
| `SignHash` RSA PKCS1 | `CKM_RSA_PKCS` | Hash passed as-is |
| `SignHash` RSA PSS | `CKM_RSA_PKCS_PSS` | `CK_RSA_PKCS_PSS_PARAMS` mapped from `BCRYPT_PSS_PADDING_INFO` |
| `SignHash` ECDSA | `CKM_ECDSA` | DER result converted to r‖s |
| `Decrypt` PKCS1 | `CKM_RSA_PKCS` | — |
| `Decrypt` OAEP | `CKM_RSA_PKCS_OAEP` | `CK_RSA_PKCS_OAEP_PARAMS` mapped from `BCRYPT_OAEP_PADDING_INFO` |
| `CreateKey` RSA | `CKM_RSA_PKCS_KEY_PAIR_GEN` | `SENSITIVE=TRUE`, `EXTRACTABLE=FALSE` |
| `CreateKey` EC | `CKM_EC_KEY_PAIR_GEN` | P-256 or P-384 DER OID in `CKA_EC_PARAMS` |

---

## Code conventions

- **Comments**: in English
- **Warnings**: zero at `/W3` MSVC
- **Memory**: `HeapAlloc`/`HeapFree` on `GetProcessHeap()` only
- **Naming**: `KSP_` (KSP layer), `P11_` (PKCS#11 layer)
- **Handles**: direct cast `(KSP_PROVIDER *)hProvider`, validated by `dwMagic`
- **Thread-safety**: all functions are re-entrant
