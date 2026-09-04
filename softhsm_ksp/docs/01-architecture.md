# Architecture — SoftHSM2 KSP

## Overview

The SoftHSM2 KSP inserts itself into the Windows cryptographic stack as an adaptation
layer between the **CNG (Cryptography Next Generation)** API and the **SoftHSM2**
library exposed via the standard **PKCS#11 v2.40** interface.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        WINDOWS APPLICATION                          │
│          (certutil, PowerShell, .NET, IE/Edge, WinHTTP…)           │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ NCryptSignHash() / NCryptOpenKey()…
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     NCRYPT.DLL  (CNG runtime)                       │
│   Resolves the KSP via the registry, loads the DLL, dispatches      │
│   calls via the NCRYPT_KEY_STORAGE_FUNCTION_TABLE                   │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Function table → KSP_*()
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SOFTHSM_KSP.DLL  (this project)                  │
│                                                                     │
│  ┌─────────────────────┐   ┌──────────────────────────────────────┐ │
│  │    KSP layer         │   │         PKCS#11 layer                │ │
│  │  ksp_main.c          │   │  p11_context.c  (singleton)          │ │
│  │  ksp_provider.c      │──▶│  p11_session.c  (session pool)       │ │
│  │  ksp_key.c           │   │  p11_utils.c    (mechanisms, attrs)  │ │
│  │  ksp_crypto.c        │   └──────────────────┬───────────────────┘ │
│  │  ksp_properties.c    │                      │ C_XXX()             │
│  └─────────────────────┘                      │                     │
│  ┌─────────────────────┐                      │                     │
│  │    Common            │                      │                     │
│  │  config.h            │                      │                     │
│  │  logging.c           │                      │                     │
│  │  memory.c            │                      │                     │
│  └─────────────────────┘                      │                     │
└──────────────────────────────────────────────┬─┘                    │
                                               │ LoadLibrary +        │
                                               │ CK_FUNCTION_LIST     │
                                               ▼                      │
┌─────────────────────────────────────────────────────────────────────┐
│                 SOFTHSM2-X64.DLL  (SoftHSM2)                       │
│    Implements PKCS#11 v2.40; stores keys in an encrypted            │
│    SQLite database on disk                                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Internal components

### KSP layer

| File | Responsibility |
|------|---------------|
| `ksp_main.c` | `DllMain`, `GetKeyStorageInterface`, `NCRYPT_KEY_STORAGE_FUNCTION_TABLE` table |
| `ksp_provider.c` | `OpenProvider`, `FreeProvider`, provider properties, stubs |
| `ksp_key.c` | `CreatePersistedKey`, `OpenKey`, `FinalizeKey`, `DeleteKey`, `EnumKeys`; RSA / EC / EdDSA / symmetric generators and the algorithm classifiers |
| `ksp_crypto.c` | `SignHash`, `Decrypt`, `Encrypt`, `ExportKey`, `ImportKey`, `SecretAgreement`, `DeriveKey`, `FreeSecret` |
| `ksp_properties.c` | `GetKeyProperty`, `SetKeyProperty` — including the AES chaining mode and IV |

### PKCS#11 layer

| File | Responsibility |
|------|---------------|
| `pkcs11.h` | Standard OASIS v2.40 header (types, constants, `CK_FUNCTION_LIST`) |
| `p11_context.c` | Singleton — DLL loading, `C_Initialize`, slot selection |
| `p11_session.c` | Session pool with Windows semaphore |
| `p11_utils.c` | Mechanism resolution, curve OIDs, hash mapping, OAEP parameters, DER encode/decode, key export |

### Common

| File | Responsibility |
|------|---------------|
| `config.h` | Constants: paths, PIN, DER OIDs, algorithm names |
| `logging.c` | Conditional `OutputDebugString` (`KSP_DEBUG=1`) |
| `memory.c` | `KSP_Alloc`/`KSP_Free` on `GetProcessHeap()` |

---

## Internal data structures

### KSP_PROVIDER

```c
typedef struct _KSP_PROVIDER {
    DWORD  dwMagic;      // KSP_PROVIDER_MAGIC = 0x4B535050 ('KSPP')
    WCHAR  szName[256];  // "SoftHSM KSP"
} KSP_PROVIDER;
```

The `NCRYPT_PROV_HANDLE` handle is a direct cast of `KSP_PROVIDER *`.
The `dwMagic` field enables validation of incoming handles (defense in depth).

### KSP_KEY

```c
typedef struct _KSP_KEY {
    DWORD            dwMagic;         // KSP_KEY_MAGIC = 0x4B53504B ('KSPK')
    WCHAR            szKeyName[256];  // = CKA_LABEL in SoftHSM2
    WCHAR            szAlgId[64];     // "RSA", "ECDSA_P521", "ECDH_P256",
                                      // "EDDSA_ED25519", "AES", "HMAC_SHA256"...
    DWORD            dwKeyBitLen;     // RSA 2048/3072/4096; EC 256/384/521;
                                      // Ed 255/448; AES 128/192/256
    DWORD            dwKeySpec;       // AT_SIGNATURE | AT_KEYEXCHANGE
    CK_OBJECT_HANDLE hPrivKey;        // PKCS#11 private key handle
    CK_OBJECT_HANDLE hPubKey;         // PKCS#11 public key handle
    CK_SLOT_ID       slotId;          // Selected SoftHSM2 slot
    BOOL             bFinalized;      // FinalizeKey() called?
    BOOL             bPersistOnly;    // Deferred generation?

    /* Symmetric key support */
    DWORD            dwKeyClass;      // KSP_KEY_CLASS_ASYMMETRIC | _SYMMETRIC
    CK_OBJECT_HANDLE hSecretKey;      // AES / HMAC secret object
    BOOL             bSessionObject;  // Imported key — destroy on FreeKey

    /* AES cipher state, set through NCryptSetProperty */
    WCHAR            szChainingMode[64]; // NCRYPT_CHAINING_MODE_PROPERTY
    BYTE             pbIV[16];           // NCRYPT_INITIALIZATION_VECTOR
    DWORD            cbIV;
    BYTE             pbAuthData[256];    // GCM additional authenticated data
    DWORD            cbAuthData;
} KSP_KEY;
```

An asymmetric key uses `hPrivKey` / `hPubKey`; a symmetric key uses
`hSecretKey` and leaves the other two at `CK_INVALID_HANDLE`. `dwKeyClass`
is the discriminator every operation checks first.

### KSP_SECRET

ECDH agreement produces a separate handle type, returned as an
`NCRYPT_SECRET_HANDLE` and consumed by `NCryptDeriveKey`:

```c
typedef struct _KSP_SECRET {
    DWORD            dwMagic;      // KSP_SECRET_MAGIC = 0x4B535053 ('KSPS')
    CK_OBJECT_HANDLE hSecretObj;   // CKO_SECRET_KEY from C_DeriveKey
    DWORD            dwSecretLen;  // Raw shared secret length in bytes
} KSP_SECRET;
```

### P11_CONTEXT (singleton)

```c
typedef struct _P11_CONTEXT {
    HMODULE              hModule;       // softhsm2-x64.dll handle
    CK_FUNCTION_LIST_PTR pFunctionList; // PKCS#11 function table
    CK_SLOT_ID           slotId;        // First slot with token present
    BOOL                 bInitialized;  // TRUE after successful C_Initialize
} P11_CONTEXT;
```

### P11_SESSION_ENTRY (pool)

```c
typedef struct _P11_SESSION_ENTRY {
    CK_SESSION_HANDLE hSession;   // PKCS#11 handle (or CK_INVALID_HANDLE)
    BOOL              bInUse;     // Slot in use?
    BOOL              bLoggedIn;  // C_Login() performed?
    CRITICAL_SECTION  cs;         // Per-session lock
} P11_SESSION_ENTRY;
```

---

## Windows object lifecycle

### Registry registration

```
HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\
  └── SoftHSM KSP\
        Image = "C:\...\softhsm_ksp.dll"
        Type  = 0x00000001
```

### Loading by ncrypt.dll

```
ncrypt.dll
  ├── RegOpenKey("SoftHSM KSP")
  ├── RegQueryValueEx("Image") → DLL path
  ├── LoadLibrary(path)
  └── GetProcAddress("GetKeyStorageInterface")
         └── → NCRYPT_KEY_STORAGE_FUNCTION_TABLE *
```

---

## Threading model

```
Thread 1                   Thread 2                  Thread 3
────────                   ────────                  ────────
P11_Initialize()           P11_Initialize()
  InitOnceExecuteOnce ─────▶ (waits)                P11_Initialize()
  LoadLibrary()                                        (waits)
  C_Initialize()
  C_GetSlotList()
  ◀── return OK ─────────── return OK ────────────── return OK

P11_AcquireSession()       P11_AcquireSession()
  WaitForSingleObject(      WaitForSingleObject(
    Semaphore, 5000) ───────▶ semaphore)
  [slot 0 free]             [waits if pool full]
  ◀── hSession[0] ──────

                           [slot 1 free]
                           ◀── hSession[1] ──────

KSP_SignHash()             KSP_SignHash()
  C_Sign()                   C_Sign()
  (concurrent OK thanks      (distinct session)
   to CKF_OS_LOCKING_OK)

P11_ReleaseSession(s0)     P11_ReleaseSession(s1)
  ReleaseSemaphore           ReleaseSemaphore
```

---

## Memory management

All buffers returned to the CNG caller are allocated on `GetProcessHeap()`:

```
KSP_Alloc(n)    → HeapAlloc(GetProcessHeap(), 0, n)
KSP_AllocZero(n)→ HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n)
KSP_Free(p)     → HeapFree(GetProcessHeap(), 0, p)
```

`KSP_FreeBuffer(pvInput)` is the function exposed to the CNG runtime to free
all buffers it receives from the KSP (key names, key blobs, etc.).
