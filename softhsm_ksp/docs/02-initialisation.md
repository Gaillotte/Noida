# Initialisation — Loading and connecting to SoftHSM2

## Overview

Initialisation is **lazy and idempotent**: it occurs only once per process,
on the first call to `KSP_OpenProvider()`.
Windows `InitOnceExecuteOnce` guarantees that even with N threads calling
simultaneously, the initialisation code runs exactly once.

---

## Sequence diagram — First OpenProvider

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant P11Ctx as p11_context.c
    participant Pool as p11_session.c
    participant HSM as softhsm2-x64.dll

    App->>NCrypt: NCryptOpenStorageProvider("SoftHSM KSP")
    NCrypt->>KSP: GetKeyStorageInterface("SoftHSM KSP", &ppFn, 0)
    KSP-->>NCrypt: &g_KspFunctionTable

    NCrypt->>KSP: KSP_OpenProvider(&hProv, "SoftHSM KSP", 0)

    KSP->>P11Ctx: P11_Initialize()
    note over P11Ctx: InitOnceExecuteOnce<br/>(one-shot, thread-safe)

    P11Ctx->>P11Ctx: GetEnvironmentVariable("SOFTHSM2_LIB")
    note over P11Ctx: Fallback: C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll

    P11Ctx->>HSM: LoadLibrary(wszLibPath)
    HSM-->>P11Ctx: HMODULE

    P11Ctx->>HSM: GetProcAddress("C_GetFunctionList")
    HSM-->>P11Ctx: pfnGetFunctionList

    P11Ctx->>HSM: C_GetFunctionList(&pFunctionList)
    HSM-->>P11Ctx: CK_FUNCTION_LIST *

    P11Ctx->>HSM: C_Initialize({flags=CKF_OS_LOCKING_OK})
    note over HSM: Thread-safe mode enabled<br/>SoftHSM2 manages its own mutexes
    HSM-->>P11Ctx: CKR_OK

    P11Ctx->>HSM: C_GetSlotList(tokenPresent=TRUE, NULL, &n)
    HSM-->>P11Ctx: ulCount = N

    P11Ctx->>HSM: C_GetSlotList(tokenPresent=TRUE, slots[], &n)
    HSM-->>P11Ctx: [slotId0, slotId1, …]

    P11Ctx->>P11Ctx: slotId = slots[0]  ← first available slot
    P11Ctx-->>KSP: ERROR_SUCCESS

    KSP->>Pool: P11_SessionPool_Initialize()
    Pool->>Pool: InitializeCriticalSection(csPool)
    Pool->>Pool: InitializeCriticalSection(cs[i]) × 16
    Pool->>Pool: CreateSemaphore(NULL, 16, 16, NULL)
    Pool-->>KSP: ERROR_SUCCESS

    KSP->>KSP: AllocZero(sizeof KSP_PROVIDER)<br/>magic=KSP_PROVIDER_MAGIC<br/>szName="SoftHSM KSP"
    KSP-->>NCrypt: hProvider = (NCRYPT_PROV_HANDLE)pProv
    NCrypt-->>App: hProvider, ERROR_SUCCESS
```

---

## Sequence diagram — Session acquisition (first time)

```mermaid
sequenceDiagram
    participant KSP as KSP (caller)
    participant Pool as p11_session.c
    participant HSM as softhsm2-x64.dll

    KSP->>Pool: P11_AcquireSession(&hSession)

    Pool->>Pool: WaitForSingleObject(hSemaphore, 5000ms)
    note over Pool: Blocks if all 16 sessions are in use

    Pool->>Pool: EnterCriticalSection(csPool)
    Pool->>Pool: Search for slot[i].bInUse == FALSE
    Pool->>Pool: slot[i].bInUse = TRUE
    Pool->>Pool: LeaveCriticalSection(csPool)

    Pool->>Pool: EnterCriticalSection(slot[i].cs)
    note over Pool: slot[i].hSession == CK_INVALID_HANDLE<br/>(first use of this slot)

    Pool->>Pool: GetEnvironmentVariable("SOFTHSM2_PIN")
    note over Pool: Fallback: "1234"

    Pool->>HSM: C_OpenSession(slotId, CKF_SERIAL|CKF_RW, NULL, NULL, &hSess)
    HSM-->>Pool: CKR_OK, hSession

    Pool->>HSM: C_Login(hSession, CKU_USER, pin, pinLen)
    HSM-->>Pool: CKR_OK  (or CKR_USER_ALREADY_LOGGED_IN → ignored)

    Pool->>Pool: SecureZeroMemory(szPin, sizeof szPin)
    Pool->>Pool: slot[i].hSession = hSession<br/>slot[i].bLoggedIn = TRUE
    Pool->>Pool: LeaveCriticalSection(slot[i].cs)

    Pool-->>KSP: hSession, ERROR_SUCCESS
```

---

## Sequence diagram — Acquisition (session already open)

```mermaid
sequenceDiagram
    participant KSP as KSP (caller)
    participant Pool as p11_session.c

    KSP->>Pool: P11_AcquireSession(&hSession)
    Pool->>Pool: WaitForSingleObject(hSemaphore, 5000ms)
    Pool->>Pool: slot[i].bInUse = TRUE
    Pool->>Pool: EnterCriticalSection(slot[i].cs)
    note over Pool: slot[i].hSession != INVALID_HANDLE<br/>→ session already open and logged in
    Pool->>Pool: LeaveCriticalSection(slot[i].cs)
    Pool-->>KSP: slot[i].hSession, ERROR_SUCCESS
```

---

## Sequence diagram — Release and FreeProvider

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as softhsm_ksp.dll
    participant Pool as p11_session.c
    participant P11Ctx as p11_context.c
    participant HSM as softhsm2-x64.dll

    App->>NCrypt: NCryptFreeObject(hProvider)
    NCrypt->>KSP: KSP_FreeProvider(hProvider)
    KSP->>KSP: pProv->dwMagic = 0
    KSP->>KSP: HeapFree(pProv)
    KSP-->>NCrypt: ERROR_SUCCESS

    note over KSP: On PROCESS_DETACH (DllMain)

    KSP->>Pool: P11_SessionPool_Finalize()
    loop for each open slot[i]
        Pool->>HSM: C_CloseSession(slot[i].hSession)
        Pool->>Pool: DeleteCriticalSection(slot[i].cs)
    end
    Pool->>Pool: CloseHandle(hSemaphore)
    Pool->>Pool: DeleteCriticalSection(csPool)

    KSP->>P11Ctx: P11_Finalize()
    P11Ctx->>HSM: C_Finalize(NULL)
    P11Ctx->>P11Ctx: FreeLibrary(hModule)
```

---

## Initialisation return codes

| Condition | SECURITY_STATUS code |
|-----------|---------------------|
| `LoadLibrary` fails (DLL not found) | `NTE_PROVIDER_DLL_FAIL` |
| `C_GetFunctionList` not found | `NTE_PROVIDER_DLL_FAIL` |
| `C_Initialize` fails | `P11RvToSecStatus(rv)` |
| No slot with token present | `NTE_NO_KEY` |
| `CreateSemaphore` fails | `NTE_NO_MEMORY` |
| Success | `ERROR_SUCCESS` |

---

## Environment variables

| Variable | Default | Usage |
|----------|---------|-------|
| `SOFTHSM2_LIB` | `C:\Program Files\SoftHSM2\lib\softhsm2-x64.dll` | Full path to the DLL |
| `SOFTHSM2_PIN` | `1234` | Token user PIN |
| `KSP_DEBUG` | `0` | `1` = enables `OutputDebugString` |

> **Security**: the PIN is erased from memory immediately after `C_Login()`
> via `SecureZeroMemory()` to prevent it from lingering on the heap.
