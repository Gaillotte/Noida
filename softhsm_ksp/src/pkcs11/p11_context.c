/* p11_context.c — PKCS#11 context singleton implementation */
#include "p11_context.h"
#include "p11_caps.h"
#include "p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <stdlib.h>
#include <string.h>

/* Singleton, guarded so that a FAILED initialisation can be retried.
 *
 * This used to be a bare InitOnceExecuteOnce, which runs its callback
 * exactly once per process whether it succeeded or not. One bad module path
 * therefore poisoned the provider for the lifetime of the host: correcting
 * KSP_PKCS11_LIB changed nothing, because the callback would never run
 * again, and the only cure was restarting the application. For a service
 * that loads this DLL that meant a restart of the service.
 *
 * A critical section replaces it. A successful initialisation is still
 * one-shot — C_Initialize must not be called twice — but a failed one
 * leaves the context in its not-initialised state and the next caller tries
 * again. The retry costs a LoadLibrary on the failure path only.
 *
 * INIT_ONCE is still used, for the one thing that genuinely cannot fail:
 * creating the critical section itself, which Windows gives no static
 * initialiser for. */
static P11_CONTEXT  g_ctx;
static CRITICAL_SECTION g_initLock;
static INIT_ONCE    g_lockOnce = INIT_ONCE_STATIC_INIT;
static SECURITY_STATUS g_initStatus = NTE_PROVIDER_DLL_FAIL;

static BOOL CALLBACK CreateInitLock(PINIT_ONCE p1, PVOID p2, PVOID *p3)
{
    (void)p1; (void)p2; (void)p3;
    InitializeCriticalSection(&g_initLock);
    return TRUE;
}

/* Load the PKCS#11 module and retrieve its function list.
 *
 * KSP_PKCS11_LIB names the module; SOFTHSM2_LIB is the older name for the
 * same thing and is honoured when the new one is unset. With neither, the
 * SoftHSM2 path baked in at build time is used. */
static BOOL LoadP11Module(P11_CONTEXT *pCtx)
{
    WCHAR   wszLibPath[MAX_PATH];
    char    szLibPath[MAX_PATH];
    DWORD   dwLen;
    CK_C_GetFunctionList pfnGetFunctionList;

    dwLen = GetEnvironmentVariableA(KSP_PKCS11_LIB_ENV, szLibPath, MAX_PATH);
    if (dwLen == 0 || dwLen >= MAX_PATH)
        dwLen = GetEnvironmentVariableA(SOFTHSM2_LIB_ENV, szLibPath, MAX_PATH);

    if (dwLen == 0 || dwLen >= MAX_PATH) {
        /* Use the default path */
        wcscpy_s(wszLibPath, MAX_PATH, SOFTHSM2_LIB_DEFAULT);
    } else {
        MultiByteToWideChar(CP_ACP, 0, szLibPath, -1, wszLibPath, MAX_PATH);
    }

    LOG_INFO("Loading PKCS#11 module: %ls", wszLibPath);

    pCtx->hModule = LoadLibraryW(wszLibPath);
    if (!pCtx->hModule) {
        LOG_ERROR("P11_Initialize", NTE_PROVIDER_DLL_FAIL);
        return FALSE;
    }

    pfnGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(
        pCtx->hModule, "C_GetFunctionList");
    if (!pfnGetFunctionList) {
        FreeLibrary(pCtx->hModule);
        pCtx->hModule = NULL;
        return FALSE;
    }

    if (pfnGetFunctionList(&pCtx->pFunctionList) != CKR_OK) {
        FreeLibrary(pCtx->hModule);
        pCtx->hModule = NULL;
        return FALSE;
    }

    return TRUE;
}

/* Choose the token this process will use.
 *
 * Order of preference:
 *   1. SOFTHSM2_TOKEN_LABEL — matched against each slot's token label
 *   2. SOFTHSM2_SLOT        — an explicit slot ID
 *   3. the first slot reporting a token present (the historical default)
 *
 * An explicit selection that cannot be satisfied is an error rather than a
 * silent fallback: falling back to slot 0 would sign with the wrong key and
 * look like it worked. */
static BOOL SelectSlot(P11_CONTEXT *pCtx)
{
    CK_SLOT_ID  aSlots[P11_MAX_SLOTS];
    CK_ULONG    ulCount = P11_MAX_SLOTS;
    CK_RV       rv;
    char        szLabel[P11_TOKEN_LABEL_LEN + 1] = {0};
    char        szSlot[32] = {0};
    DWORD       dwLen;
    CK_ULONG    i;

    rv = pCtx->pFunctionList->C_GetSlotList(CK_TRUE, aSlots, &ulCount);
    if (rv != CKR_OK || ulCount == 0) {
        LOG_ERROR("SelectSlot - C_GetSlotList", P11RvToSecStatus(rv));
        return FALSE;
    }

    /* 1. By token label. */
    dwLen = GetEnvironmentVariableA(SOFTHSM2_TOKEN_LABEL_ENV,
                                    szLabel, sizeof(szLabel));
    if (dwLen > 0 && dwLen < sizeof(szLabel)) {
        for (i = 0; i < ulCount; i++) {
            CK_TOKEN_INFO info;
            memset(&info, 0, sizeof(info));
            if (pCtx->pFunctionList->C_GetTokenInfo(aSlots[i], &info) != CKR_OK)
                continue;
            if (P11_TokenLabelMatches(info.label, szLabel)) {
                pCtx->slotId = aSlots[i];
                LOG_INFO("Selected slot %lu by token label '%s'",
                         (unsigned long)pCtx->slotId, szLabel);
                return TRUE;
            }
        }
        LOG_ERROR("SelectSlot - no token matches " SOFTHSM2_TOKEN_LABEL_ENV,
                  NTE_NO_KEY);
        return FALSE;
    }

    /* 2. By explicit slot ID. */
    dwLen = GetEnvironmentVariableA(SOFTHSM2_SLOT_ENV, szSlot, sizeof(szSlot));
    if (dwLen > 0 && dwLen < sizeof(szSlot)) {
        char     *pszEnd = NULL;
        unsigned long ulWanted = strtoul(szSlot, &pszEnd, 10);

        if (pszEnd == szSlot || (pszEnd && *pszEnd != '\0')) {
            LOG_ERROR("SelectSlot - " SOFTHSM2_SLOT_ENV " is not a number",
                      NTE_INVALID_PARAMETER);
            return FALSE;
        }

        for (i = 0; i < ulCount; i++) {
            if (aSlots[i] == (CK_SLOT_ID)ulWanted) {
                pCtx->slotId = aSlots[i];
                LOG_INFO("Selected slot %lu (explicit)",
                         (unsigned long)pCtx->slotId);
                return TRUE;
            }
        }
        LOG_ERROR("SelectSlot - " SOFTHSM2_SLOT_ENV " names no present token",
                  NTE_NO_KEY);
        return FALSE;
    }

    /* 3. Default: first token present. */
    pCtx->slotId = aSlots[0];
    LOG_INFO("Selected slot %lu (first token present, of %lu)",
             (unsigned long)pCtx->slotId, (unsigned long)ulCount);
    return TRUE;
}

/* One initialisation attempt. Caller holds g_initLock. */
static void TryInitialize(void)
{
    CK_C_INITIALIZE_ARGS initArgs;
    CK_RV rv;

    memset(&g_ctx, 0, sizeof(g_ctx));

    if (!LoadP11Module(&g_ctx)) {
        g_initStatus = NTE_PROVIDER_DLL_FAIL;
        return;
    }

    /* Initialise Cryptoki with OS locking */
    memset(&initArgs, 0, sizeof(initArgs));
    initArgs.flags = CKF_OS_LOCKING_OK;

    rv = g_ctx.pFunctionList->C_Initialize(&initArgs);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        LOG_ERROR("C_Initialize", P11RvToSecStatus(rv));
        FreeLibrary(g_ctx.hModule);
        g_ctx.hModule = NULL;
        g_initStatus  = P11RvToSecStatus(rv);
        return;
    }

    if (!SelectSlot(&g_ctx)) {
        g_ctx.pFunctionList->C_Finalize(NULL);
        FreeLibrary(g_ctx.hModule);
        g_ctx.hModule = NULL;
        g_initStatus  = NTE_NO_KEY;
        return;
    }

    g_ctx.bInitialized = TRUE;

    /* Ask the token what it implements, so the provider advertises the
     * intersection rather than a list describing one particular backend.
     * A refusal is not fatal — see P11_ProbeCapabilities — so the return
     * value is deliberately not propagated into g_initStatus. */
    (void)P11_ProbeCapabilities();

    g_initStatus = ERROR_SUCCESS;
    LOG_INFO("P11_Initialize: success, slot=%lu", (unsigned long)g_ctx.slotId);
}

/* Initialise the PKCS#11 context (thread-safe, idempotent on success).
 *
 * Idempotent once it has succeeded; retried while it has not. See the note
 * on the guard above for why that distinction exists. */
SECURITY_STATUS P11_Initialize(void)
{
    SECURITY_STATUS ss;

    InitOnceExecuteOnce(&g_lockOnce, CreateInitLock, NULL, NULL);

    EnterCriticalSection(&g_initLock);
    if (g_initStatus != ERROR_SUCCESS)
        TryInitialize();
    ss = g_initStatus;
    LeaveCriticalSection(&g_initLock);

    return ss;
}

/* Free the PKCS#11 context */
void P11_Finalize(void)
{
    P11_ReleaseCapabilities();

    /* Return to the not-initialised state so a later P11_Initialize starts
     * over. Finalising while another thread holds a session is unsafe and
     * always has been — this is called from DllMain on process detach. */
    g_initStatus = NTE_PROVIDER_DLL_FAIL;

    if (g_ctx.bInitialized && g_ctx.pFunctionList) {
        g_ctx.pFunctionList->C_Finalize(NULL);
        g_ctx.bInitialized = FALSE;
    }
    if (g_ctx.hModule) {
        FreeLibrary(g_ctx.hModule);
        g_ctx.hModule = NULL;
    }
}

/* Return a pointer to the global context */
P11_CONTEXT *P11_GetContext(void)
{
    return &g_ctx;
}
