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

/* Global KSP function table.
 *
 * Written with designated initialisers on purpose. The slot order in
 * NCRYPT_KEY_STORAGE_FUNCTION_TABLE is defined by the Windows SDK's
 * <ncrypt_provider.h>, and this project does not ship that header — it
 * comes with the WDK. Initialising by position means guessing that order,
 * and a wrong guess does not fail loudly: Windows simply calls the wrong
 * function pointer. Initialising by name makes the compiler do the
 * assignment from the real header, and turns any mistake into a build
 * error instead of memory corruption at runtime.
 *
 * The previous version of this table was ordered to the hand-written mock
 * in tests/mock/windows_compat.h and displaced every slot from the
 * thirteenth onward.
 */
NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_KspFunctionTable = {
    .Version             = NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
    .OpenProvider        = KSP_OpenProvider,
    .OpenKey             = KSP_OpenKey,
    .CreatePersistedKey  = KSP_CreatePersistedKey,
    .GetProviderProperty = KSP_GetProviderProperty,
    .GetKeyProperty      = KSP_GetKeyProperty,
    .SetProviderProperty = KSP_SetProviderProperty,
    .SetKeyProperty      = KSP_SetKeyProperty,
    .FinalizeKey         = KSP_FinalizeKey,
    .DeleteKey           = KSP_DeleteKey,
    .FreeProvider        = KSP_FreeProvider,
    .FreeKey             = KSP_FreeKey,
    .FreeBuffer          = KSP_FreeBuffer,
    .Encrypt             = KSP_Encrypt,
    .Decrypt             = KSP_Decrypt,
    .IsAlgSupported      = KSP_IsAlgSupported,
    .EnumAlgorithms      = KSP_EnumAlgorithms,
    .EnumKeys            = KSP_EnumKeys,
    .ImportKey           = KSP_ImportKey,
    .ExportKey           = KSP_ExportKey,
    .SignHash            = KSP_SignHash,
    .VerifySignature     = KSP_VerifySignature,
    .PromptUser          = KSP_PromptUser,
    .NotifyChangeKey     = KSP_NotifyChangeKey,
    .SecretAgreement     = KSP_SecretAgreement,
    .DeriveKey           = KSP_DeriveKey,
    .FreeSecret          = KSP_FreeSecret
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
