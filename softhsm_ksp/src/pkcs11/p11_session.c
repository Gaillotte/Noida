/* p11_session.c — PKCS#11 session pool implementation */
#include "p11_session.h"
#include "p11_context.h"
#include "p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <string.h>
#include <stdlib.h>

/* Static session pool */
static P11_SESSION_ENTRY g_aPool[P11_SESSION_POOL_SIZE];
static HANDLE            g_hSemaphore = NULL;
static CRITICAL_SECTION  g_csPool;
static BOOL              g_bPoolInit  = FALSE;

/* PIN override set through NCryptSetProperty(NCRYPT_PIN_PROPERTY).
 * Guarded by g_csPin because it is read on every lazy session open and can
 * be written from any thread. Zeroed, not just freed, when cleared. */
static char              g_szPin[P11_MAX_PIN_LEN + 1];
static BOOL              g_bPinSet    = FALSE;
static CRITICAL_SECTION  g_csPin;
static INIT_ONCE         g_pinOnce    = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK InitPinLock(PINIT_ONCE o, PVOID p, PVOID *c)
{
    (void)o; (void)p; (void)c;
    InitializeCriticalSection(&g_csPin);
    return TRUE;
}

SECURITY_STATUS P11_SetPin(const char *szPin)
{
    size_t cb;

    InitOnceExecuteOnce(&g_pinOnce, InitPinLock, NULL, NULL);

    if (!szPin) {
        P11_ClearPin();
        return ERROR_SUCCESS;
    }

    cb = strlen(szPin);
    if (cb > P11_MAX_PIN_LEN)
        return NTE_INVALID_PARAMETER;

    EnterCriticalSection(&g_csPin);
    SecureZeroMemory(g_szPin, sizeof(g_szPin));
    memcpy(g_szPin, szPin, cb);
    g_szPin[cb] = '\0';
    g_bPinSet   = TRUE;
    LeaveCriticalSection(&g_csPin);

    /* Deliberately not logged, not even its length. */
    LOG_INFO("PIN set through the provider property");
    return ERROR_SUCCESS;
}

void P11_ClearPin(void)
{
    InitOnceExecuteOnce(&g_pinOnce, InitPinLock, NULL, NULL);

    EnterCriticalSection(&g_csPin);
    SecureZeroMemory(g_szPin, sizeof(g_szPin));
    g_bPinSet = FALSE;
    LeaveCriticalSection(&g_csPin);
}

/* Copy the PIN to use into the caller's buffer.
 *
 * Preference: the value set through the provider property, then
 * SOFTHSM2_PIN, then the compiled-in default. */
static void GetEffectivePin(char *pszOut, size_t cbOut)
{
    DWORD dwLen;

    InitOnceExecuteOnce(&g_pinOnce, InitPinLock, NULL, NULL);

    EnterCriticalSection(&g_csPin);
    if (g_bPinSet) {
        strcpy_s(pszOut, cbOut, g_szPin);
        LeaveCriticalSection(&g_csPin);
        return;
    }
    LeaveCriticalSection(&g_csPin);

    dwLen = GetEnvironmentVariableA(SOFTHSM2_PIN_ENV, pszOut, (DWORD)cbOut);
    if (dwLen == 0 || dwLen >= cbOut)
        strcpy_s(pszOut, cbOut, SOFTHSM2_PIN_DEFAULT);
}

/* Initialise the session pool */
SECURITY_STATUS P11_SessionPool_Initialize(void)
{
    int i;

    if (g_bPoolInit)
        return ERROR_SUCCESS;

    InitializeCriticalSection(&g_csPool);
    memset(g_aPool, 0, sizeof(g_aPool));

    for (i = 0; i < P11_SESSION_POOL_SIZE; i++)
        InitializeCriticalSection(&g_aPool[i].cs);

    g_hSemaphore = CreateSemaphoreW(NULL, P11_SESSION_POOL_SIZE,
                                    P11_SESSION_POOL_SIZE, NULL);
    if (!g_hSemaphore) {
        DeleteCriticalSection(&g_csPool);
        return NTE_NO_MEMORY;
    }

    g_bPoolInit = TRUE;
    return ERROR_SUCCESS;
}

/* Destroy the session pool */
void P11_SessionPool_Finalize(void)
{
    int i;
    P11_CONTEXT *pCtx;

    if (!g_bPoolInit)
        return;

    pCtx = P11_GetContext();

    for (i = 0; i < P11_SESSION_POOL_SIZE; i++) {
        if (g_aPool[i].hSession != CK_INVALID_HANDLE && pCtx->pFunctionList) {
            pCtx->pFunctionList->C_CloseSession(g_aPool[i].hSession);
            g_aPool[i].hSession = CK_INVALID_HANDLE;
        }
        DeleteCriticalSection(&g_aPool[i].cs);
    }

    if (g_hSemaphore) {
        CloseHandle(g_hSemaphore);
        g_hSemaphore = NULL;
    }

    DeleteCriticalSection(&g_csPool);
    P11_ClearPin();
    g_bPoolInit = FALSE;
}

/* Open a new PKCS#11 session and perform login */
static SECURITY_STATUS OpenAndLoginSession(P11_SESSION_ENTRY *pEntry)
{
    P11_CONTEXT *pCtx = P11_GetContext();
    CK_RV        rv;
    char         szPin[P11_MAX_PIN_LEN + 1] = {0};

    rv = pCtx->pFunctionList->C_OpenSession(
        pCtx->slotId,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL,
        &pEntry->hSession);

    if (rv != CKR_OK) {
        LOG_ERROR("C_OpenSession", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    GetEffectivePin(szPin, sizeof(szPin));

    rv = pCtx->pFunctionList->C_Login(
        pEntry->hSession,
        CKU_USER,
        (CK_UTF8CHAR_PTR)szPin,
        (CK_ULONG)strlen(szPin));

    SecureZeroMemory(szPin, sizeof(szPin));

    /* Ignore if already logged in (can happen with shared sessions) */
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        LOG_ERROR("C_Login", P11RvToSecStatus(rv));
        pCtx->pFunctionList->C_CloseSession(pEntry->hSession);
        pEntry->hSession = CK_INVALID_HANDLE;
        return P11RvToSecStatus(rv);
    }

    pEntry->bLoggedIn = TRUE;
    LOG_INFO("Session opened: handle=0x%lX", (unsigned long)pEntry->hSession);
    return ERROR_SUCCESS;
}

/* Acquire a session from the pool */
SECURITY_STATUS P11_AcquireSession(CK_SESSION_HANDLE *phSession)
{
    DWORD  dwWait;
    int    i;
    SECURITY_STATUS ss;

    if (!phSession)
        return NTE_INVALID_PARAMETER;

    /* Wait for a session to become available (5 s timeout) */
    dwWait = WaitForSingleObject(g_hSemaphore, 5000);
    if (dwWait != WAIT_OBJECT_0) {
        LOG_ERROR("P11_AcquireSession - timeout", NTE_NO_MEMORY);
        return NTE_NO_MEMORY;
    }

    EnterCriticalSection(&g_csPool);

    /* Find a free entry */
    for (i = 0; i < P11_SESSION_POOL_SIZE; i++) {
        if (!g_aPool[i].bInUse) {
            g_aPool[i].bInUse = TRUE;
            LeaveCriticalSection(&g_csPool);

            /* Open the session if it does not exist yet */
            EnterCriticalSection(&g_aPool[i].cs);
            if (g_aPool[i].hSession == CK_INVALID_HANDLE) {
                ss = OpenAndLoginSession(&g_aPool[i]);
                if (ss != ERROR_SUCCESS) {
                    g_aPool[i].bInUse = FALSE;
                    LeaveCriticalSection(&g_aPool[i].cs);
                    ReleaseSemaphore(g_hSemaphore, 1, NULL);
                    return ss;
                }
            }
            LeaveCriticalSection(&g_aPool[i].cs);

            *phSession = g_aPool[i].hSession;
            return ERROR_SUCCESS;
        }
    }

    LeaveCriticalSection(&g_csPool);
    /* Should not happen thanks to the semaphore */
    ReleaseSemaphore(g_hSemaphore, 1, NULL);
    return NTE_NO_MEMORY;
}

/* Return the session to the pool */
void P11_ReleaseSession(CK_SESSION_HANDLE hSession)
{
    int i;

    EnterCriticalSection(&g_csPool);
    for (i = 0; i < P11_SESSION_POOL_SIZE; i++) {
        if (g_aPool[i].hSession == hSession && g_aPool[i].bInUse) {
            g_aPool[i].bInUse = FALSE;
            ReleaseSemaphore(g_hSemaphore, 1, NULL);
            break;
        }
    }
    LeaveCriticalSection(&g_csPool);
}
