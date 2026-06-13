/* ksp_properties.h — CNG key properties */
#ifndef KSP_PROPERTIES_H
#define KSP_PROPERTIES_H

#include <windows.h>
#include <ncrypt.h>

/* Return a key property */
SECURITY_STATUS WINAPI KSP_GetKeyProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hKey,
    LPCWSTR             pszProperty,
    PBYTE               pbOutput,
    DWORD               cbOutput,
    DWORD              *pcbResult,
    DWORD               dwFlags);

/* Set a key property */
SECURITY_STATUS WINAPI KSP_SetKeyProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hKey,
    LPCWSTR             pszProperty,
    PBYTE               pbInput,
    DWORD               cbInput,
    DWORD               dwFlags);

#endif /* KSP_PROPERTIES_H */
