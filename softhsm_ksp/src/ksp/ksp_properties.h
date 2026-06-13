/* ksp_properties.h — Propriétés des clés CNG */
#ifndef KSP_PROPERTIES_H
#define KSP_PROPERTIES_H

#include <windows.h>
#include <ncrypt.h>

/* Retourne une propriété de la clé */
SECURITY_STATUS WINAPI KSP_GetKeyProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hKey,
    LPCWSTR             pszProperty,
    PBYTE               pbOutput,
    DWORD               cbOutput,
    DWORD              *pcbResult,
    DWORD               dwFlags);

/* Définit une propriété de la clé */
SECURITY_STATUS WINAPI KSP_SetKeyProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hKey,
    LPCWSTR             pszProperty,
    PBYTE               pbInput,
    DWORD               cbInput,
    DWORD               dwFlags);

#endif /* KSP_PROPERTIES_H */
