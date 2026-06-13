/* ksp_provider.c — Implémentation des fonctions de gestion du fournisseur */
#include "ksp_provider.h"
#include "../pkcs11/p11_context.h"
#include "../pkcs11/p11_session.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/memory.h"
#include <string.h>
#include <wchar.h>

/* Valide un handle de fournisseur */
BOOL KSP_IsValidProvider(NCRYPT_PROV_HANDLE hProvider)
{
    KSP_PROVIDER *pProv = (KSP_PROVIDER *)(ULONG_PTR)hProvider;
    return (pProv && pProv->dwMagic == KSP_PROVIDER_MAGIC);
}

/* Ouvre le fournisseur et initialise la couche PKCS#11 */
SECURITY_STATUS WINAPI KSP_OpenProvider(
    NCRYPT_PROV_HANDLE *phProvider,
    LPCWSTR             pszProviderName,
    DWORD               dwFlags)
{
    KSP_PROVIDER   *pProv;
    SECURITY_STATUS ss;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_OpenProvider");

    if (!phProvider) {
        LOG_LEAVE("KSP_OpenProvider", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    /* Initialise la couche PKCS#11 (idempotent) */
    ss = P11_Initialize();
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_OpenProvider", ss);
        return ss;
    }

    /* Initialise le pool de sessions */
    ss = P11_SessionPool_Initialize();
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_OpenProvider", ss);
        return ss;
    }

    pProv = (KSP_PROVIDER *)KSP_AllocZero(sizeof(KSP_PROVIDER));
    if (!pProv) {
        LOG_LEAVE("KSP_OpenProvider", NTE_NO_MEMORY);
        return NTE_NO_MEMORY;
    }

    pProv->dwMagic = KSP_PROVIDER_MAGIC;
    wcscpy_s(pProv->szName, 256,
             pszProviderName ? pszProviderName : KSP_PROVIDER_NAME);

    *phProvider = (NCRYPT_PROV_HANDLE)(ULONG_PTR)pProv;

    LOG_LEAVE("KSP_OpenProvider", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Libère le fournisseur */
SECURITY_STATUS WINAPI KSP_FreeProvider(NCRYPT_PROV_HANDLE hProvider)
{
    KSP_PROVIDER *pProv;

    LOG_ENTER("KSP_FreeProvider");

    if (!KSP_IsValidProvider(hProvider)) {
        LOG_LEAVE("KSP_FreeProvider", NTE_INVALID_HANDLE);
        return NTE_INVALID_HANDLE;
    }

    pProv = (KSP_PROVIDER *)(ULONG_PTR)hProvider;
    pProv->dwMagic = 0;
    KSP_Free(pProv);

    LOG_LEAVE("KSP_FreeProvider", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Retourne une propriété du fournisseur */
SECURITY_STATUS WINAPI KSP_GetProviderProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszProperty,
    PBYTE               pbOutput,
    DWORD               cbOutput,
    DWORD              *pcbResult,
    DWORD               dwFlags)
{
    SECURITY_STATUS ss = ERROR_SUCCESS;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_GetProviderProperty");

    if (!KSP_IsValidProvider(hProvider) || !pszProperty || !pcbResult) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_GetProviderProperty", ss);
        return ss;
    }

    if (_wcsicmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        DWORD cbNeeded = (DWORD)((wcslen(KSP_PROVIDER_NAME) + 1) * sizeof(WCHAR));
        *pcbResult = cbNeeded;
        if (pbOutput) {
            if (cbOutput < cbNeeded) {
                ss = NTE_BUFFER_TOO_SMALL;
            } else {
                memcpy(pbOutput, KSP_PROVIDER_NAME, cbNeeded);
            }
        }
    } else if (_wcsicmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0) {
        DWORD dwVersion = KSP_VERSION;
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                ss = NTE_BUFFER_TOO_SMALL;
            } else {
                memcpy(pbOutput, &dwVersion, sizeof(DWORD));
            }
        }
    } else if (_wcsicmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0) {
        DWORD dwImpl = NCRYPT_IMPL_HARDWARE_FLAG;
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                ss = NTE_BUFFER_TOO_SMALL;
            } else {
                memcpy(pbOutput, &dwImpl, sizeof(DWORD));
            }
        }
    } else {
        ss = NTE_NOT_SUPPORTED;
    }

    LOG_LEAVE("KSP_GetProviderProperty", ss);
    return ss;
}

/* Définit une propriété du fournisseur */
SECURITY_STATUS WINAPI KSP_SetProviderProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszProperty,
    PBYTE               pbInput,
    DWORD               cbInput,
    DWORD               dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(pszProperty);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(dwFlags);

    return NTE_NOT_SUPPORTED;
}

/* Libère un buffer alloué par le KSP */
SECURITY_STATUS WINAPI KSP_FreeBuffer(PVOID pvInput)
{
    KSP_Free(pvInput);
    return ERROR_SUCCESS;
}

/* Libère un objet opaque */
SECURITY_STATUS WINAPI KSP_FreeObject(PVOID pvInput)
{
    KSP_Free(pvInput);
    return ERROR_SUCCESS;
}

/* Notifie un changement de clé (stub) */
SECURITY_STATUS WINAPI KSP_NotifyChangeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(dwFlags);

    return ERROR_SUCCESS;
}

/* Invite l'utilisateur (non supporté) */
SECURITY_STATUS WINAPI KSP_PromptUser(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    LPCWSTR            pszOperation,
    DWORD              dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszOperation);
    UNREFERENCED_PARAMETER(dwFlags);

    return NTE_NOT_SUPPORTED;
}

/* Retourne une propriété d'opération (non supporté) */
SECURITY_STATUS WINAPI KSP_GetOperationProperty(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    LPCWSTR            pszProperty,
    PBYTE              pbOutput,
    DWORD              cbOutput,
    DWORD             *pcbResult,
    DWORD              dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszProperty);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);

    return NTE_NOT_SUPPORTED;
}
