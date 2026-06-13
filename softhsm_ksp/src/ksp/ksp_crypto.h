/* ksp_crypto.h — Cryptographic operations: signing, decryption, export/import */
#ifndef KSP_CRYPTO_H
#define KSP_CRYPTO_H

#include <windows.h>
#include <ncrypt.h>

/* Sign a hash with the private key */
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

/* Decrypt data with the private key */
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

/* Export a key in BCRYPT format */
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

/* Import a key from a BCRYPT format */
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
