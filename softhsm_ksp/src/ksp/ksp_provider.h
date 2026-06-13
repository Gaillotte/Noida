/* ksp_provider.h — Gestion du fournisseur CNG (provider handle) */
#ifndef KSP_PROVIDER_H
#define KSP_PROVIDER_H

#include <windows.h>
#include <ncrypt.h>
#include "../common/config.h"

/* Structure interne du fournisseur */
typedef struct _KSP_PROVIDER {
    DWORD  dwMagic;           /* KSP_PROVIDER_MAGIC */
    WCHAR  szName[256];       /* Nom du fournisseur */
} KSP_PROVIDER;

/* Ouvre le fournisseur et initialise la couche PKCS#11 */
SECURITY_STATUS WINAPI KSP_OpenProvider(
    NCRYPT_PROV_HANDLE *phProvider,
    LPCWSTR             pszProviderName,
    DWORD               dwFlags);

/* Libère le fournisseur */
SECURITY_STATUS WINAPI KSP_FreeProvider(
    NCRYPT_PROV_HANDLE hProvider);

/* Retourne une propriété du fournisseur */
SECURITY_STATUS WINAPI KSP_GetProviderProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszProperty,
    PBYTE               pbOutput,
    DWORD               cbOutput,
    DWORD              *pcbResult,
    DWORD               dwFlags);

/* Définit une propriété du fournisseur */
SECURITY_STATUS WINAPI KSP_SetProviderProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszProperty,
    PBYTE               pbInput,
    DWORD               cbInput,
    DWORD               dwFlags);

/* Libère un buffer alloué par le KSP */
SECURITY_STATUS WINAPI KSP_FreeBuffer(PVOID pvInput);

/* Libère un objet opaque */
SECURITY_STATUS WINAPI KSP_FreeObject(PVOID pvInput);

/* Stubs obligatoires */
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

/* Valide un handle de fournisseur */
BOOL KSP_IsValidProvider(NCRYPT_PROV_HANDLE hProvider);

#endif /* KSP_PROVIDER_H */
