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

/* Encrypt data with a symmetric key (AES ECB / CBC / CTR / GCM) */
SECURITY_STATUS WINAPI KSP_Encrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    PBYTE              pbInput,
    DWORD              cbInput,
    VOID              *pPaddingInfo,
    PBYTE              pbOutput,
    DWORD              cbOutput,
    DWORD             *pcbResult,
    DWORD              dwFlags);

/* ECDH key agreement: derive a shared secret from a private key and a
 * peer public key. Produces an NCRYPT_SECRET_HANDLE consumed by
 * KSP_DeriveKey and released by KSP_FreeSecret. */
SECURITY_STATUS WINAPI KSP_SecretAgreement(
    NCRYPT_PROV_HANDLE    hProvider,
    NCRYPT_KEY_HANDLE     hPrivKey,
    NCRYPT_KEY_HANDLE     hPubKey,
    NCRYPT_SECRET_HANDLE *phAgreedSecret,
    DWORD                 dwFlags);

/* Derive key material from an agreed secret produced by KSP_SecretAgreement */
SECURITY_STATUS WINAPI KSP_DeriveKey(
    NCRYPT_PROV_HANDLE   hProvider,
    NCRYPT_SECRET_HANDLE hSharedSecret,
    LPCWSTR              pwszKDF,
    NCryptBufferDesc    *pParameterList,
    PBYTE                pbDerivedKey,
    DWORD                cbDerivedKey,
    DWORD               *pcbResult,
    DWORD                dwFlags);

/* Release an agreed secret handle */
SECURITY_STATUS WINAPI KSP_FreeSecret(
    NCRYPT_PROV_HANDLE   hProvider,
    NCRYPT_SECRET_HANDLE hSharedSecret);

/* Validate an agreed-secret handle */
BOOL KSP_IsValidSecret(NCRYPT_SECRET_HANDLE hSecret);

#endif /* KSP_CRYPTO_H */
