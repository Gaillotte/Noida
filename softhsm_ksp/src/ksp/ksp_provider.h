/* ksp_provider.h — CNG provider management (provider handle) */
#ifndef KSP_PROVIDER_H
#define KSP_PROVIDER_H

#include <windows.h>
#include <ncrypt.h>
#include "../common/config.h"

/* Internal provider structure */
typedef struct _KSP_PROVIDER {
    DWORD  dwMagic;           /* KSP_PROVIDER_MAGIC */
    WCHAR  szName[256];       /* Provider name */
} KSP_PROVIDER;

/* Open the provider and initialise the PKCS#11 layer */
SECURITY_STATUS WINAPI KSP_OpenProvider(
    NCRYPT_PROV_HANDLE *phProvider,
    LPCWSTR             pszProviderName,
    DWORD               dwFlags);

/* Free the provider */
SECURITY_STATUS WINAPI KSP_FreeProvider(
    NCRYPT_PROV_HANDLE hProvider);

/* Return a provider property */
SECURITY_STATUS WINAPI KSP_GetProviderProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszProperty,
    PBYTE               pbOutput,
    DWORD               cbOutput,
    DWORD              *pcbResult,
    DWORD               dwFlags);

/* Set a provider property */
SECURITY_STATUS WINAPI KSP_SetProviderProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszProperty,
    PBYTE               pbInput,
    DWORD               cbInput,
    DWORD               dwFlags);

/* Free a buffer allocated by the KSP */
SECURITY_STATUS WINAPI KSP_FreeBuffer(PVOID pvInput);

/* Free an opaque object */
SECURITY_STATUS WINAPI KSP_FreeObject(PVOID pvInput);

/* Required stubs */
SECURITY_STATUS WINAPI KSP_NotifyChangeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags);

SECURITY_STATUS WINAPI KSP_PromptUser(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    LPCWSTR            pszOperation,
    DWORD              dwFlags);

SECURITY_STATUS WINAPI KSP_GetOperationProperty(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    LPCWSTR            pszProperty,
    PBYTE              pbOutput,
    DWORD              cbOutput,
    DWORD             *pcbResult,
    DWORD              dwFlags);

/* Validate a provider handle */
BOOL KSP_IsValidProvider(NCRYPT_PROV_HANDLE hProvider);

#endif /* KSP_PROVIDER_H */
