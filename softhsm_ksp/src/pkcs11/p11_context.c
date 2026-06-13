/* p11_context.c — Implémentation du singleton de contexte PKCS#11 */
#include "p11_context.h"
#include "p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <stdlib.h>
#include <string.h>

/* Singleton protégé par InitOnceExecuteOnce */
static P11_CONTEXT  g_ctx;
static INIT_ONCE    g_initOnce = INIT_ONCE_STATIC_INIT;
static SECURITY_STATUS g_initStatus = NTE_PROVIDER_DLL_FAIL;

/* Charge softhsm2.dll et récupère la liste des fonctions */
static BOOL LoadSoftHSM2(P11_CONTEXT *pCtx)
{
    WCHAR   wszLibPath[MAX_PATH];
    char    szLibPath[MAX_PATH];
    DWORD   dwLen;
    CK_C_GetFunctionList pfnGetFunctionList;

    /* Lit le chemin depuis la variable d'environnement */
    dwLen = GetEnvironmentVariableA(SOFTHSM2_LIB_ENV, szLibPath, MAX_PATH);
    if (dwLen == 0 || dwLen >= MAX_PATH) {
        /* Utilise le chemin par défaut */
        wcscpy_s(wszLibPath, MAX_PATH, SOFTHSM2_LIB_DEFAULT);
    } else {
        MultiByteToWideChar(CP_ACP, 0, szLibPath, -1, wszLibPath, MAX_PATH);
    }

    LOG_INFO("Chargement SoftHSM2 : %ls", wszLibPath);

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

/* Sélectionne le premier slot avec un token présent */
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
    LOG_INFO("Slot selectionne : %lu", (unsigned long)pCtx->slotId);
    return TRUE;
}

/* Callback pour InitOnceExecuteOnce */
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

    /* Initialise Cryptoki avec verrouillage OS */
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
    LOG_INFO("P11_Initialize : succes, slot=%lu", (unsigned long)g_ctx.slotId);
    return TRUE;
}

/* Initialise le contexte PKCS#11 (thread-safe, idempotent) */
SECURITY_STATUS P11_Initialize(void)
{
    InitOnceExecuteOnce(&g_initOnce, InitOnceCallback, NULL, NULL);
    return g_initStatus;
}

/* Libère le contexte PKCS#11 */
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

/* Retourne le pointeur vers le contexte global */
P11_CONTEXT *P11_GetContext(void)
{
    return &g_ctx;
}
