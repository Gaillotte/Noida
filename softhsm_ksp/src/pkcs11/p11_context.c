/* p11_context.c — PKCS#11 context singleton implementation */
#include "p11_context.h"
#include "p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <stdlib.h>
#include <string.h>

/* Singleton protected by InitOnceExecuteOnce */
static P11_CONTEXT  g_ctx;
static INIT_ONCE    g_initOnce = INIT_ONCE_STATIC_INIT;
static SECURITY_STATUS g_initStatus = NTE_PROVIDER_DLL_FAIL;

/* Load softhsm2.dll and retrieve the function list */
static BOOL LoadSoftHSM2(P11_CONTEXT *pCtx)
{
    WCHAR   wszLibPath[MAX_PATH];
    char    szLibPath[MAX_PATH];
    DWORD   dwLen;
    CK_C_GetFunctionList pfnGetFunctionList;

    /* Read the path from the environment variable */
    dwLen = GetEnvironmentVariableA(SOFTHSM2_LIB_ENV, szLibPath, MAX_PATH);
    if (dwLen == 0 || dwLen >= MAX_PATH) {
        /* Use the default path */
        wcscpy_s(wszLibPath, MAX_PATH, SOFTHSM2_LIB_DEFAULT);
    } else {
        MultiByteToWideChar(CP_ACP, 0, szLibPath, -1, wszLibPath, MAX_PATH);
    }

    LOG_INFO("Loading SoftHSM2: %ls", wszLibPath);

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

/* Select the first slot with a token present */
static BOOL SelectSlot(P11_CONTEXT *pCtx)
{
    CK_SLOT_ID  aSlots[64];
    CK_ULONG    ulCount = 64;
    CK_RV       rv;

    rv = pCtx->pFunctionList->C_GetSlotList(CK_TRUE, aSlots, &ulCount);
    if (rv != CKR_OK || ulCount == 0) {
        LOG_ERROR("SelectSlot - C_GetSlotList", P11RvToSecStatus(rv));
        return FALSE;
    }

    pCtx->slotId = aSlots[0];
    LOG_INFO("Selected slot: %lu", (unsigned long)pCtx->slotId);
    return TRUE;
}

/* Callback for InitOnceExecuteOnce */
static BOOL CALLBACK InitOnceCallback(
    PINIT_ONCE  pInitOnce,
    PVOID       pParameter,
    PVOID      *ppContext)
{
    CK_C_INITIALIZE_ARGS initArgs;
    CK_RV rv;

    (void)pInitOnce;
    (void)pParameter;
    (void)ppContext;

    memset(&g_ctx, 0, sizeof(g_ctx));

    if (!LoadSoftHSM2(&g_ctx)) {
        g_initStatus = NTE_PROVIDER_DLL_FAIL;
        return TRUE;
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
        return TRUE;
    }

    if (!SelectSlot(&g_ctx)) {
        g_ctx.pFunctionList->C_Finalize(NULL);
        FreeLibrary(g_ctx.hModule);
        g_ctx.hModule = NULL;
        g_initStatus  = NTE_NO_KEY;
        return TRUE;
    }

    g_ctx.bInitialized = TRUE;
    g_initStatus       = ERROR_SUCCESS;
    LOG_INFO("P11_Initialize: success, slot=%lu", (unsigned long)g_ctx.slotId);
    return TRUE;
}

/* Initialise the PKCS#11 context (thread-safe, idempotent) */
SECURITY_STATUS P11_Initialize(void)
{
    InitOnceExecuteOnce(&g_initOnce, InitOnceCallback, NULL, NULL);
    return g_initStatus;
}

/* Free the PKCS#11 context */
void P11_Finalize(void)
{
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
