/* ksp_crypto.h — Opérations cryptographiques : signature, déchiffrement, export/import */
#ifndef KSP_CRYPTO_H
#define KSP_CRYPTO_H

#include <windows.h>
#include <ncrypt.h>

/* Signe un hash avec la clé privée */
SECURITY_STATUS WINAPI KSP_SignHash(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    VOID              *pPaddingInfo,
    PBYTE              pbHashValue,
    DWORD              cbHashValue,
    PBYTE              pbSignature,
    DWORD              cbSignature,
    DWORD             *pcbResult,
    DWORD              dwFlags);

/* Déchiffre des données avec la clé privée */
SECURITY_STATUS WINAPI KSP_Decrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    PBYTE              pbInput,
    DWORD              cbInput,
    VOID              *pPaddingInfo,
    PBYTE              pbOutput,
    DWORD              cbOutput,
    DWORD             *pcbResult,
    DWORD              dwFlags);

/* Exporte une clé au format BCRYPT */
SECURITY_STATUS WINAPI KSP_ExportKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    NCRYPT_KEY_HANDLE  hExportKey,
    LPCWSTR            pszBlobType,
    NCryptBufferDesc  *pParameterList,
    PBYTE              pbOutput,
    DWORD              cbOutput,
    DWORD             *pcbResult,
    DWORD              dwFlags);

/* Importe une clé depuis un format BCRYPT */
SECURITY_STATUS WINAPI KSP_ImportKey(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hImportKey,
    LPCWSTR             pszBlobType,
    NCryptBufferDesc   *pParameterList,
    NCRYPT_KEY_HANDLE  *phKey,
    PBYTE               pbData,
    DWORD               cbData,
    DWORD               dwFlags);

#endif /* KSP_CRYPTO_H */
