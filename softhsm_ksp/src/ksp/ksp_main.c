/* ksp_main.c — DllMain and CNG function table initialisation */
#include "ksp_main.h"
#include "ksp_provider.h"
#include "ksp_key.h"
#include "ksp_crypto.h"
#include "ksp_properties.h"
#include "../pkcs11/p11_context.h"
#include "../pkcs11/p11_session.h"
#include "../common/config.h"
#include "../common/logging.h"

/* Global KSP function table */
NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_KspFunctionTable = {
    NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
    KSP_OpenProvider,
    KSP_OpenKey,
    KSP_CreatePersistedKey,
    KSP_GetProviderProperty,
    KSP_GetKeyProperty,
    KSP_SetProviderProperty,
    KSP_SetKeyProperty,
    KSP_FinalizeKey,
    KSP_DeleteKey,
    KSP_FreeProvider,
    KSP_FreeKey,
    KSP_FreeBuffer,
    KSP_EnumKeys,
    KSP_ImportKey,
    KSP_ExportKey,
    KSP_SignHash,
    KSP_Decrypt,
    KSP_NotifyChangeKey,
    KSP_GetOperationProperty,
    KSP_FreeObject,
    KSP_PromptUser
};

/* Exported entry point: returns the function table */
SECURITY_STATUS WINAPI GetKeyStorageInterface(
    LPCWSTR                             pszProviderName,
    NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    DWORD                               dwFlags)
{
    UNREFERENCED_PARAMETER(dwFlags);

    LOG_ENTER("GetKeyStorageInterface");

    if (!ppFunctionTable) {
        LOG_LEAVE("GetKeyStorageInterface", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    if (pszProviderName &&
        _wcsicmp(pszProviderName, KSP_PROVIDER_NAME) != 0) {
        LOG_LEAVE("GetKeyStorageInterface", NTE_PROV_TYPE_NOT_DEF);
        return NTE_PROV_TYPE_NOT_DEF;
    }

    *ppFunctionTable = &g_KspFunctionTable;

    LOG_LEAVE("GetKeyStorageInterface", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* DLL entry point */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        Log_Initialize();
        LOG_INFO("DllMain : PROCESS_ATTACH");
        break;

    case DLL_PROCESS_DETACH:
        LOG_INFO("DllMain : PROCESS_DETACH");
        P11_SessionPool_Finalize();
        P11_Finalize();
        break;

    default:
        break;
    }

    return TRUE;
}
