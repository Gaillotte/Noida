/* ksp_properties.c — Implémentation des propriétés de clé CNG */
#include "ksp_properties.h"
#include "ksp_key.h"
#include "ksp_provider.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <string.h>
#include <wchar.h>

/* Retourne une propriété de la clé */
SECURITY_STATUS WINAPI KSP_GetKeyProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hKey,
    LPCWSTR             pszProperty,
    PBYTE               pbOutput,
    DWORD               cbOutput,
    DWORD              *pcbResult,
    DWORD               dwFlags)
{
    KSP_KEY        *pKey;
    SECURITY_STATUS ss = ERROR_SUCCESS;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_GetKeyProperty");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pszProperty || !pcbResult) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_GetKeyProperty", ss);
        return ss;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    if (_wcsicmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0) {
        DWORD cbNeeded = (DWORD)((wcslen(pKey->szAlgId) + 1) * sizeof(WCHAR));
        *pcbResult = cbNeeded;
        if (pbOutput) {
            if (cbOutput < cbNeeded)
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, pKey->szAlgId, cbNeeded);
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD))
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, &pKey->dwKeyBitLen, sizeof(DWORD));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD))
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, &pKey->dwKeySpec, sizeof(DWORD));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0 ||
               _wcsicmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0) {
        DWORD cbNeeded = (DWORD)((wcslen(pKey->szKeyName) + 1) * sizeof(WCHAR));
        *pcbResult = cbNeeded;
        if (pbOutput) {
            if (cbOutput < cbNeeded)
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, pKey->szKeyName, cbNeeded);
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0) {
        /* Non exportable depuis le HSM */
        DWORD dwPolicy = 0;
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD))
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, &dwPolicy, sizeof(DWORD));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0) {
        DWORD dwUsage = (pKey->dwKeySpec == AT_SIGNATURE)
                        ? NCRYPT_ALLOW_SIGNING_FLAG
                        : NCRYPT_ALLOW_DECRYPT_FLAG;
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD))
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, &dwUsage, sizeof(DWORD));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0) {
        LPCWSTR pszGroup = (_wcsicmp(pKey->szAlgId, ALG_RSA) == 0)
                           ? NCRYPT_RSA_ALGORITHM_GROUP
                           : NCRYPT_ECDSA_ALGORITHM_GROUP;
        DWORD cbNeeded = (DWORD)((wcslen(pszGroup) + 1) * sizeof(WCHAR));
        *pcbResult = cbNeeded;
        if (pbOutput) {
            if (cbOutput < cbNeeded)
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, pszGroup, cbNeeded);
        }

    } else {
        ss = NTE_NOT_SUPPORTED;
    }

    LOG_LEAVE("KSP_GetKeyProperty", ss);
    return ss;
}

/* Définit une propriété de la clé */
SECURITY_STATUS WINAPI KSP_SetKeyProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hKey,
    LPCWSTR             pszProperty,
    PBYTE               pbInput,
    DWORD               cbInput,
    DWORD               dwFlags)
{
    KSP_KEY        *pKey;
    SECURITY_STATUS ss = NTE_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_SetKeyProperty");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pszProperty) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_SetKeyProperty", ss);
        return ss;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    /* Seule NCRYPT_LENGTH_PROPERTY est modifiable (avant FinalizeKey) */
    if (_wcsicmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
        if (!pbInput || cbInput < sizeof(DWORD)) {
            ss = NTE_INVALID_PARAMETER;
        } else if (pKey->bFinalized) {
            ss = NTE_INVALID_HANDLE;
        } else {
            DWORD dwBits;
            memcpy(&dwBits, pbInput, sizeof(DWORD));
            /* Valide la taille (RSA uniquement) */
            if (_wcsicmp(pKey->szAlgId, ALG_RSA) == 0 &&
                (dwBits == 2048 || dwBits == 3072 || dwBits == 4096)) {
                pKey->dwKeyBitLen = dwBits;
                ss = ERROR_SUCCESS;
            } else {
                ss = NTE_BAD_LEN;
            }
        }
    }

    LOG_LEAVE("KSP_SetKeyProperty", ss);
    return ss;
}
