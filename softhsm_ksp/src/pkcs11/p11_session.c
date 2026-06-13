/* p11_session.c — Implémentation du pool de sessions PKCS#11 */
#include "p11_session.h"
#include "p11_context.h"
#include "p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <string.h>
#include <stdlib.h>

/* Pool de sessions statique */
static P11_SESSION_ENTRY g_aPool[P11_SESSION_POOL_SIZE];
static HANDLE            g_hSemaphore = NULL;
static CRITICAL_SECTION  g_csPool;
static BOOL              g_bPoolInit  = FALSE;

/* Initialise le pool de sessions */
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

/* Détruit le pool de sessions */
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
    g_bPoolInit = FALSE;
}

/* Ouvre une nouvelle session PKCS#11 et effectue le login */
static SECURITY_STATUS OpenAndLoginSession(P11_SESSION_ENTRY *pEntry)
{
    P11_CONTEXT *pCtx = P11_GetContext();
    CK_RV        rv;
    char         szPin[128] = {0};
    DWORD        dwPinLen;

    rv = pCtx->pFunctionList->C_OpenSession(
        pCtx->slotId,
        CKF_SERIAL_SESSION | CKF_RW_SESSION,
        NULL, NULL,
        &pEntry->hSession);

    if (rv != CKR_OK) {
        LOG_ERROR("C_OpenSession", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    /* Lit le PIN depuis la variable d'environnement */
    dwPinLen = GetEnvironmentVariableA(SOFTHSM2_PIN_ENV, szPin, sizeof(szPin));
    if (dwPinLen == 0 || dwPinLen >= sizeof(szPin))
        strcpy_s(szPin, sizeof(szPin), SOFTHSM2_PIN_DEFAULT);

    rv = pCtx->pFunctionList->C_Login(
        pEntry->hSession,
        CKU_USER,
        (CK_UTF8CHAR_PTR)szPin,
        (CK_ULONG)strlen(szPin));

    SecureZeroMemory(szPin, sizeof(szPin));

    /* Ignorer si déjà connecté (peut arriver avec sessions partagées) */
    if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
        LOG_ERROR("C_Login", P11RvToSecStatus(rv));
        pCtx->pFunctionList->C_CloseSession(pEntry->hSession);
        pEntry->hSession = CK_INVALID_HANDLE;
        return P11RvToSecStatus(rv);
    }

    pEntry->bLoggedIn = TRUE;
    LOG_INFO("Session ouverte : handle=0x%lX", (unsigned long)pEntry->hSession);
    return ERROR_SUCCESS;
}

/* Acquiert une session du pool */
SECURITY_STATUS P11_AcquireSession(CK_SESSION_HANDLE *phSession)
{
    DWORD  dwWait;
    int    i;
    SECURITY_STATUS ss;

    if (!phSession)
        return NTE_INVALID_PARAMETER;

    /* Attend qu'une session soit disponible (timeout 5 s) */
    dwWait = WaitForSingleObject(g_hSemaphore, 5000);
    if (dwWait != WAIT_OBJECT_0) {
        LOG_ERROR("P11_AcquireSession - timeout", NTE_NO_MEMORY);
        return NTE_NO_MEMORY;
    }

    EnterCriticalSection(&g_csPool);

    /* Trouve une entrée libre */
    for (i = 0; i < P11_SESSION_POOL_SIZE; i++) {
        if (!g_aPool[i].bInUse) {
            g_aPool[i].bInUse = TRUE;
            LeaveCriticalSection(&g_csPool);

            /* Ouvre la session si elle n'existe pas encore */
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
    /* Ne devrait pas arriver grâce au sémaphore */
    ReleaseSemaphore(g_hSemaphore, 1, NULL);
    return NTE_NO_MEMORY;
}

/* Remet la session dans le pool */
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
