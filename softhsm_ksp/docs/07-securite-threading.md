# Security and threading

## Concurrency model

### Thread-safety guarantees

| Component | Mechanism | Scope |
|-----------|-----------|-------|
| Singleton initialisation | `InitOnceExecuteOnce` | Entire process |
| Session pool | `CreateSemaphore` (counter) | Pool access |
| Free slot search | `CRITICAL_SECTION csPool` | Slot list |
| Per-session operation | `CRITICAL_SECTION cs[i]` | Individual session |
| SoftHSM2 (internal) | `CKF_OS_LOCKING_OK` | PKCS#11 library |

### Key invariant

> Two threads can perform cryptographic operations **simultaneously**
> because each uses a distinct session from the pool (different `CK_SESSION_HANDLE`).
> `CKF_OS_LOCKING_OK` guarantees that SoftHSM2 itself is thread-safe internally.

---

## Diagram — Concurrent access to the session pool

```mermaid
sequenceDiagram
    participant T1 as Thread 1
    participant T2 as Thread 2
    participant T3 as Thread 3 (waiting)
    participant Sem as Semaphore (16)
    participant Pool as Pool[0..15]

    note over Sem: Initial state: count=16

    T1->>Sem: WaitForSingleObject → count=15
    T2->>Sem: WaitForSingleObject → count=14

    T1->>Pool: EnterCS(csPool), slot[0].bInUse=TRUE, LeaveCS
    T2->>Pool: EnterCS(csPool), slot[1].bInUse=TRUE, LeaveCS

    T1->>Pool: C_Sign() on session[0]
    T2->>Pool: C_Sign() on session[1]
    note over T1,T2: Concurrency OK — distinct sessions

    note over T3: Pool full (all 16 sessions in use)
    T3->>Sem: WaitForSingleObject(5000ms) → BLOCKED

    T1->>Pool: slot[0].bInUse=FALSE
    T1->>Sem: ReleaseSemaphore → count=1

    note over T3: Unblocked
    T3->>Sem: WaitForSingleObject → count=0
    T3->>Pool: slot[0].bInUse=TRUE
```

---

## Secure PIN handling

```mermaid
flowchart TD
    A["GetEnvironmentVariableA(SOFTHSM2_PIN_ENV,\nszPin, sizeof szPin)"]
    A --> B{Variable defined?}
    B -- No --> C["szPin = SOFTHSM2_PIN_DEFAULT\n= '1234'"]
    B -- Yes --> D["szPin = value read"]
    C --> E["C_Login(hSession, CKU_USER,\nszPin, strlen(szPin))"]
    D --> E
    E --> F["SecureZeroMemory(szPin, sizeof szPin)"]
    note right of F: Immediately erases the PIN<br/>from the stack/heap to prevent<br/>it from remaining accessible in memory
    F --> G["CK_RV result"]
```

> **Production recommendation**: never store the PIN in an environment variable
> in production. Use a secrets vault (Windows DPAPI, Azure Key Vault, etc.)

---

## Handle validation

Every KSP function validates incoming handles before any processing:

```mermaid
flowchart LR
    H["NCRYPT_PROV_HANDLE hProv"]
    A["(KSP_PROVIDER *)hProv"]
    B{"pProv != NULL\nand\npProv->dwMagic ==\nKSP_PROVIDER_MAGIC ?"}
    OK["Normal processing"]
    ERR["NTE_INVALID_HANDLE\nor NTE_INVALID_PARAMETER"]

    H --> A --> B
    B -- Yes --> OK
    B -- No --> ERR
```

```mermaid
flowchart LR
    H["NCRYPT_KEY_HANDLE hKey"]
    A["(KSP_KEY *)hKey"]
    B{"pKey != NULL\nand\npKey->dwMagic ==\nKSP_KEY_MAGIC ?"}
    OK["Normal processing"]
    ERR["NTE_INVALID_HANDLE"]

    H --> A --> B
    B -- Yes --> OK
    B -- No --> ERR
```

The magic numbers serve as canaries: if a caller passes an arbitrary pointer
or a handle from another provider, the magic check fails before any potentially
dangerous dereference.

---

## Complete lifecycle of a KSP_KEY object

```mermaid
stateDiagram-v2
    [*] --> Allocated : KSP_CreatePersistedKey()

    Allocated --> Generated : !PERSIST_ONLY\n(immediate C_GenerateKeyPair)
    Allocated --> Partial : PERSIST_ONLY_FLAG\n(deferred generation)

    Partial --> Modifiable : SetKeyProperty(LENGTH)
    Modifiable --> Partial : (can modify multiple times)
    Partial --> Generated : KSP_FinalizeKey()\n→ C_GenerateKeyPair

    Generated --> InUse : KSP_SignHash / KSP_Decrypt / KSP_ExportKey
    InUse --> Generated : (after each operation)

    Generated --> [*] : KSP_DeleteKey()\n→ C_DestroyObject × 2\n→ HeapFree

    Generated --> [*] : KSP_FreeKey()\n→ HeapFree (PKCS#11 object remains on token)
```

---

## Security countermeasures

### Non-exportable keys

All private keys are created with:
```c
{ CKA_EXTRACTABLE, &bFalse, sizeof(bFalse) }  // FALSE
{ CKA_SENSITIVE,   &bTrue,  sizeof(bTrue)  }  // TRUE
```

Attempting to export a private key → immediate `NTE_NOT_SUPPORTED` (without any PKCS#11 call).

### No static link to softhsm2.dll

The DLL is loaded via `LoadLibrary` only, which avoids:
- Build-time dependency
- ABI compatibility issues between versions
- Unnecessary loading when SoftHSM2 is absent

### Sensitive memory zeroing

- PIN: `SecureZeroMemory()` after `C_Login()`
- Hash and signature buffers are **not** zeroed because they are not secret

---

## Logging and debugging

```mermaid
sequenceDiagram
    participant App as Application
    participant KSP as KSP (any function)
    participant Log as logging.c
    participant DBG as DebugView (Sysinternals)

    note over App: KSP_DEBUG=1 in the environment

    App->>KSP: Any call
    KSP->>Log: LOG_ENTER("KSP_SignHash")
    Log->>Log: g_bDebugEnabled == TRUE
    Log->>DBG: OutputDebugStringA("[SOFTHSM_KSP] KSP_SignHash: enter\n")

    KSP->>KSP: Processing...

    KSP->>Log: LOG_INFO("hPrivKey=0x%lX", hPrivKey)
    Log->>DBG: OutputDebugStringA("[SOFTHSM_KSP] hPrivKey=0x6\n")

    KSP->>Log: LOG_LEAVE("KSP_SignHash", ERROR_SUCCESS)
    Log->>DBG: OutputDebugStringA("[SOFTHSM_KSP] KSP_SignHash: leave status=0x00000000\n")
```

### Log message format

```
[SOFTHSM_KSP] <FunctionName>: enter
[SOFTHSM_KSP] <FunctionName>: <key>=<value>
[SOFTHSM_KSP] <FunctionName>: leave status=0x00000000
[SOFTHSM_KSP] <FunctionName>: ERROR status=0x80090009
```
