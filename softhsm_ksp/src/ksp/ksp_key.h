/* ksp_key.h — Key management: creation, opening, deletion, enumeration */
#ifndef KSP_KEY_H
#define KSP_KEY_H

#include <windows.h>
#include <ncrypt.h>
#include "../pkcs11/pkcs11.h"
#include "../common/config.h"

/* Internal key structure */
typedef struct _KSP_KEY {
    DWORD            dwMagic;                   /* KSP_KEY_MAGIC */
    WCHAR            szKeyName[MAX_KEY_LABEL_LEN]; /* CKA_LABEL */
    WCHAR            szAlgId[MAX_ALG_ID_LEN];    /* L"RSA", L"ECDSA_P256"... */
    DWORD            dwKeyBitLen;               /* Key length in bits (RSA) */
    DWORD            dwPublicExponent;          /* RSA public exponent (default 65537) */
    DWORD            dwKeySpec;                 /* AT_SIGNATURE or AT_KEYEXCHANGE */
    CK_OBJECT_HANDLE hPrivKey;                  /* PKCS#11 private key handle */
    CK_OBJECT_HANDLE hPubKey;                   /* PKCS#11 public key handle */
    CK_SLOT_ID       slotId;                    /* PKCS#11 slot */
    BOOL             bFinalized;                /* FinalizeKey called? */
    BOOL             bPersistOnly;              /* Deferred generation? */
    DWORD            dwKeyClass;                /* KSP_KEY_CLASS_ASYMMETRIC / _SYMMETRIC */
    CK_OBJECT_HANDLE hSecretKey;                /* Symmetric key object (AES/HMAC) */
    BOOL             bSessionObject;            /* TRUE = session object, destroy on FreeKey */

    /* Symmetric cipher state (AES) — set via NCryptSetProperty */
    WCHAR            szChainingMode[MAX_ALG_ID_LEN]; /* NCRYPT_CHAINING_MODE_PROPERTY */
    BYTE             pbIV[AES_BLOCK_SIZE];      /* NCRYPT_INITIALIZATION_VECTOR */
    DWORD            cbIV;                      /* IV length actually set */
    BYTE             pbAuthData[MAX_AUTH_DATA_LEN]; /* GCM additional authenticated data */
    DWORD            cbAuthData;                /* AAD length actually set */
} KSP_KEY;

/* Agreed-secret handle produced by KSP_SecretAgreement (ECDH).
 * Consumed by KSP_DeriveKey and released by KSP_FreeSecret. */
typedef struct _KSP_SECRET {
    DWORD            dwMagic;      /* KSP_SECRET_MAGIC */
    CK_OBJECT_HANDLE hSecretObj;   /* CKO_SECRET_KEY produced by C_DeriveKey */
    DWORD            dwSecretLen;  /* Raw secret length in bytes */
} KSP_SECRET;

/* Open an existing key from SoftHSM2 */
SECURITY_STATUS WINAPI KSP_OpenKey(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE  *phKey,
    LPCWSTR             pszKeyName,
    DWORD               dwLegacyKeySpec,
    DWORD               dwFlags);

/* Create a new persistent key */
SECURITY_STATUS WINAPI KSP_CreatePersistedKey(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE  *phKey,
    LPCWSTR             pszAlgId,
    LPCWSTR             pszKeyName,
    DWORD               dwLegacyKeySpec,
    DWORD               dwFlags);

/* Finalise the key (generate the pair if deferred) */
SECURITY_STATUS WINAPI KSP_FinalizeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags);

/* Delete a key from the token */
SECURITY_STATUS WINAPI KSP_DeleteKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags);

/* Free the key structure */
SECURITY_STATUS WINAPI KSP_FreeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey);

/* Enumerate keys in the token */
SECURITY_STATUS WINAPI KSP_EnumKeys(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszScope,
    NCryptKeyName      **ppKeyName,
    PVOID              *ppEnumState,
    DWORD               dwFlags);

/* Validate a key handle */
BOOL KSP_IsValidKey(NCRYPT_KEY_HANDLE hKey);

/* Generate an RSA key pair in SoftHSM2 */
SECURITY_STATUS KSP_GenerateRsaKeyPair(KSP_KEY *pKey);

/* Generate an EC key pair in SoftHSM2 (NIST P-256 / P-384 / P-521) */
SECURITY_STATUS KSP_GenerateEcKeyPair(KSP_KEY *pKey);

/* Generate an Edwards-curve key pair in SoftHSM2 (Ed25519 / Ed448) */
SECURITY_STATUS KSP_GenerateEddsaKeyPair(KSP_KEY *pKey);

/* Generate a symmetric key in SoftHSM2 (AES / HMAC generic secret) */
SECURITY_STATUS KSP_GenerateSymmetricKey(KSP_KEY *pKey);

/* Encode an RSA public exponent as minimal-length big-endian bytes.
 * pbOut must have room for 4 bytes; returns the count written. */
CK_ULONG KSP_EncodePublicExponent(DWORD dwExp, CK_BYTE *pbOut);

/* Return TRUE when pszAlgId names a NIST ECDSA curve */
BOOL KSP_IsEcdsaAlg(LPCWSTR pszAlgId);

/* Return TRUE when pszAlgId names a NIST ECDH curve */
BOOL KSP_IsEcdhAlg(LPCWSTR pszAlgId);

/* Return TRUE when pszAlgId names an Edwards curve */
BOOL KSP_IsEddsaAlg(LPCWSTR pszAlgId);

/* Return TRUE when pszAlgId names a symmetric algorithm (AES or HMAC) */
BOOL KSP_IsSymmetricAlg(LPCWSTR pszAlgId);

/* Internal enumeration state */
typedef struct _KSP_ENUM_STATE {
    CK_OBJECT_HANDLE *phObjects;   /* Array of found handles */
    DWORD             dwCount;     /* Total count */
    DWORD             dwIndex;     /* Current index */
} KSP_ENUM_STATE;

#endif /* KSP_KEY_H */
