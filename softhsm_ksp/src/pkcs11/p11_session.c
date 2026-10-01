/* p11_session.c — PKCS#11 session pool implementation */
#include "p11_session.h"
#include "p11_context.h"
#include "p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <string.h>
#include <stdlib.h>

/* Static session pools — one per scope (LIFE-08).
 *
 * A session belongs to a token, so two scopes on two tokens cannot share a
 * pool: a pooled session logged in to the user token can never serve a
 * machine-scope operation, and handing it over would read the wrong token's
 * keys under a successful status.
 *
 * Both pools exist unconditionally and the second is simply unused when the
 * deployment has one token — PoolFor() collapses every scope onto pool 0.
 * That collapse is the reason a single-token deployment still opens at most
 * P11_SESSION_POOL_SIZE sessions rather than twice that, and the reason it
 * is a property of one function instead of a rule to remember at every call
 * site. */
static P11_SESSION_ENTRY g_aPool[P11_SCOPE_COUNT][P11_SESSION_POOL_SIZE];
static HANDLE            g_ahSemaphore[P11_SCOPE_COUNT];
static CRITICAL_SECTION  g_csPool;
static BOOL              g_bPoolInit  = FALSE;

/* Which pool serves a scope.
 *
 * Without per-scope tokens every scope uses pool 0, because there is only
 * one token and splitting the pool would halve the concurrency for no
 * reason. P11_SCOPE_USER is 0 precisely so this is the identity in the
 * common case. */
static int PoolFor(int nScope)
{
    if (nScope < 0 || nScope >= P11_SCOPE_COUNT)
        return P11_SCOPE_USER;
    if (!P11_HasPerScopeTokens())
        return P11_SCOPE_USER;
    return nScope;
}

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

/* Copy the PIN to use for a scope into the caller's buffer.
 *
 * Preference: the scope's own PIN variable, then the value set through the
 * provider property, then SOFTHSM2_PIN, then the compiled-in default.
 *
 * The scope's own variable comes FIRST, ahead of the provider property. That
 * ordering is deliberate and is the opposite of the usual rule here, where a
 * property outranks the environment because a property is a deliberate act
 * by the process and a variable is ambient. It is inverted because the two
 * are not answers to the same question: the property carries ONE PIN and
 * cannot distinguish the scopes, so treating it as an override would send
 * the user PIN to the machine token — exactly the failure that per-scope
 * tokens exist to prevent, and it would fail closed as a login error rather
 * than loudly.
 *
 * With per-scope tokens configured and no per-scope PINs, both tokens are
 * logged into with the same credential. That is correct for two tokens
 * initialised identically and is NOT isolation: two tokens sharing one PIN
 * share one credential. The documentation says so rather than the code
 * guessing. */
static void GetEffectivePin(int nScope, char *pszOut, size_t cbOut)
{
    DWORD       dwLen;
    const char *szVar;

    InitOnceExecuteOnce(&g_pinOnce, InitPinLock, NULL, NULL);

    if (P11_HasPerScopeTokens()) {
        szVar = (nScope == P11_SCOPE_MACHINE) ? KSP_MACHINE_PIN_ENV
                                              : KSP_USER_PIN_ENV;
        dwLen = GetEnvironmentVariableA(szVar, pszOut, (DWORD)cbOut);
        if (dwLen > 0 && dwLen < cbOut)
            return;
    }

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
    int i, p;

    if (g_bPoolInit)
        return ERROR_SUCCESS;

    InitializeCriticalSection(&g_csPool);
    memset(g_aPool, 0, sizeof(g_aPool));

    for (p = 0; p < P11_SCOPE_COUNT; p++) {
        for (i = 0; i < P11_SESSION_POOL_SIZE; i++)
            InitializeCriticalSection(&g_aPool[p][i].cs);

        g_ahSemaphore[p] = CreateSemaphoreW(NULL, P11_SESSION_POOL_SIZE,
                                            P11_SESSION_POOL_SIZE, NULL);
        if (!g_ahSemaphore[p]) {
            /* Unwind what this call created, so a failed initialise leaves
             * nothing behind for the retry OPS-08 exists to allow. */
            int q, j;
            for (q = 0; q <= p; q++) {
                for (j = 0; j < P11_SESSION_POOL_SIZE; j++)
                    DeleteCriticalSection(&g_aPool[q][j].cs);
                if (g_ahSemaphore[q]) {
                    CloseHandle(g_ahSemaphore[q]);
                    g_ahSemaphore[q] = NULL;
                }
            }
            DeleteCriticalSection(&g_csPool);
            return NTE_NO_MEMORY;
        }
    }

    g_bPoolInit = TRUE;
    return ERROR_SUCCESS;
}

/* Destroy the session pool */
void P11_SessionPool_Finalize(void)
{
    int i, p;
    P11_CONTEXT *pCtx;

    if (!g_bPoolInit)
        return;

    pCtx = P11_GetContext();

    for (p = 0; p < P11_SCOPE_COUNT; p++) {
        for (i = 0; i < P11_SESSION_POOL_SIZE; i++) {
            if (g_aPool[p][i].hSession != CK_INVALID_HANDLE &&
                pCtx->pFunctionList) {
                pCtx->pFunctionList->C_CloseSession(g_aPool[p][i].hSession);
                g_aPool[p][i].hSession = CK_INVALID_HANDLE;
            }
            DeleteCriticalSection(&g_aPool[p][i].cs);
        }
        if (g_ahSemaphore[p]) {
            CloseHandle(g_ahSemaphore[p]);
            g_ahSemaphore[p] = NULL;
        }
    }

    DeleteCriticalSection(&g_csPool);
    P11_ClearPin();
    g_bPoolInit = FALSE;
}

/* Open a new PKCS#11 session and perform login */
static SECURITY_STATUS OpenAndLoginSession(P11_SESSION_ENTRY *pEntry,
                                           int nScope)
{
    P11_CONTEXT *pCtx = P11_GetContext();
    CK_RV        rv;
    char         szPin[P11_MAX_PIN_LEN + 1] = {0};

    /* The scope's token, not the context's. With one token these are the
     * same slot; with two, using pCtx->slotId here would put every machine
     * key on the user token and report success. */
    rv = pCtx->pFunctionList->C_OpenSession(
        P11_GetScopeSlot(nScope),
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL,
        &pEntry->hSession);

    if (rv != CKR_OK) {
        LOG_ERROR("C_OpenSession", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    GetEffectivePin(nScope, szPin, sizeof(szPin));

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
    LOG_INFO("Session opened: handle=0x%lX on slot %lu (scope %d)",
             (unsigned long)pEntry->hSession,
             (unsigned long)P11_GetScopeSlot(nScope), nScope);
    return ERROR_SUCCESS;
}

/* Is this pooled session still usable?
 *
 * A pooled session is long-lived, and plenty can happen to it between one
 * operation and the next: the token can be removed and reinserted, another
 * process can call C_Finalize, or an administrator can log the token out.
 * The handle stays numerically valid through all of that, so the first
 * symptom used to be a confusing CKR_USER_NOT_LOGGED_IN from whatever
 * operation happened to run next.
 *
 * C_GetSessionInfo is cheap and answers both questions at once: whether
 * the handle still resolves, and whether it is still logged in. */
static BOOL SessionIsUsable(P11_SESSION_ENTRY *pEntry)
{
    P11_CONTEXT     *pCtx = P11_GetContext();
    CK_SESSION_INFO  info;
    CK_RV            rv;

    if (pEntry->hSession == CK_INVALID_HANDLE)
        return FALSE;

    memset(&info, 0, sizeof(info));
    rv = pCtx->pFunctionList->C_GetSessionInfo(pEntry->hSession, &info);
    if (rv != CKR_OK) {
        LOG_INFO("Session 0x%lX no longer valid (rv=0x%lX)",
                 (unsigned long)pEntry->hSession, (unsigned long)rv);
        return FALSE;
    }

    /* A read-write user session is what OpenAndLoginSession creates. The
     * public states mean the token logged out underneath us. */
    if (info.state != CKS_RW_USER_FUNCTIONS &&
        info.state != CKS_RO_USER_FUNCTIONS) {
        LOG_INFO("Session 0x%lX is no longer logged in (state=%lu)",
                 (unsigned long)pEntry->hSession, (unsigned long)info.state);
        return FALSE;
    }

    return TRUE;
}

/* Drop a session that has gone bad, so the next acquire reopens it.
 *
 * C_CloseSession is attempted but its result ignored: the usual reason for
 * being here is that the handle is already invalid, and failing to close
 * something that is already gone is not an error worth propagating. */
static void DiscardSession(P11_SESSION_ENTRY *pEntry)
{
    P11_CONTEXT *pCtx = P11_GetContext();

    if (pEntry->hSession != CK_INVALID_HANDLE)
        (void)pCtx->pFunctionList->C_CloseSession(pEntry->hSession);

    pEntry->hSession  = CK_INVALID_HANDLE;
    pEntry->bLoggedIn = FALSE;
}

/* Acquire a session from the pool */
SECURITY_STATUS P11_AcquireSession(int nScope, CK_SESSION_HANDLE *phSession)
{
    DWORD  dwWait;
    int    i, p;
    SECURITY_STATUS ss;

    if (!phSession)
        return NTE_INVALID_PARAMETER;

    /* Bind the slot if nothing has yet. This is the point at which token
     * selection closes — a session belongs to a token, so there is no
     * later moment at which the choice could still be honoured. It also
     * has to happen before PoolFor(), which asks whether the deployment
     * has per-scope tokens, and that is not known until the slots resolve. */
    ss = P11_EnsureSlotSelected();
    if (ss != ERROR_SUCCESS)
        return ss;

    p = PoolFor(nScope);

    /* Wait for a session to become available (5 s timeout) */
    dwWait = WaitForSingleObject(g_ahSemaphore[p], 5000);
    if (dwWait != WAIT_OBJECT_0) {
        LOG_ERROR("P11_AcquireSession - timeout", NTE_NO_MEMORY);
        return NTE_NO_MEMORY;
    }

    EnterCriticalSection(&g_csPool);

    /* Find a free entry */
    for (i = 0; i < P11_SESSION_POOL_SIZE; i++) {
        if (!g_aPool[p][i].bInUse) {
            g_aPool[p][i].bInUse = TRUE;
            LeaveCriticalSection(&g_csPool);

            /* Open the session if it does not exist yet, or reopen it if
             * the one we cached has since been closed or logged out. */
            EnterCriticalSection(&g_aPool[p][i].cs);
            if (g_aPool[p][i].hSession != CK_INVALID_HANDLE &&
                !SessionIsUsable(&g_aPool[p][i])) {
                DiscardSession(&g_aPool[p][i]);
            }
            if (g_aPool[p][i].hSession == CK_INVALID_HANDLE) {
                ss = OpenAndLoginSession(&g_aPool[p][i], nScope);
                if (ss != ERROR_SUCCESS) {
                    g_aPool[p][i].bInUse = FALSE;
                    LeaveCriticalSection(&g_aPool[p][i].cs);
                    ReleaseSemaphore(g_ahSemaphore[p], 1, NULL);
                    return ss;
                }
            }
            LeaveCriticalSection(&g_aPool[p][i].cs);

            *phSession = g_aPool[p][i].hSession;
            return ERROR_SUCCESS;
        }
    }

    LeaveCriticalSection(&g_csPool);
    /* Should not happen thanks to the semaphore */
    ReleaseSemaphore(g_ahSemaphore[p], 1, NULL);
    return NTE_NO_MEMORY;
}

/* Return the session to the pool */
/* Return a session to the pool.
 *
 * The scope is not a parameter, and deliberately so: a caller that released
 * under the wrong scope would return the semaphore to the wrong pool, and
 * the pool it took from would leak a slot while the other over-counted. A
 * PKCS#11 session handle identifies its session uniquely across the module,
 * so searching is both correct and cheap at thirty-two entries. */
void P11_ReleaseSession(CK_SESSION_HANDLE hSession)
{
    int i, p;

    EnterCriticalSection(&g_csPool);
    for (p = 0; p < P11_SCOPE_COUNT; p++) {
        for (i = 0; i < P11_SESSION_POOL_SIZE; i++) {
            if (g_aPool[p][i].hSession == hSession && g_aPool[p][i].bInUse) {
                g_aPool[p][i].bInUse = FALSE;
                ReleaseSemaphore(g_ahSemaphore[p], 1, NULL);
                LeaveCriticalSection(&g_csPool);
                return;
            }
        }
    }
    LeaveCriticalSection(&g_csPool);
}
