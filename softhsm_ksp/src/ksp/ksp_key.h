/* ksp_key.h — Gestion des clés : création, ouverture, suppression, énumération */
#ifndef KSP_KEY_H
#define KSP_KEY_H

#include <windows.h>
#include <ncrypt.h>
#include "../pkcs11/pkcs11.h"
#include "../common/config.h"

/* Structure interne d'une clé */
typedef struct _KSP_KEY {
    DWORD            dwMagic;                   /* KSP_KEY_MAGIC */
    WCHAR            szKeyName[MAX_KEY_LABEL_LEN]; /* CKA_LABEL */
    WCHAR            szAlgId[MAX_ALG_ID_LEN];    /* L"RSA", L"ECDSA_P256"... */
    DWORD            dwKeyBitLen;               /* Longueur en bits (RSA) */
    DWORD            dwKeySpec;                 /* AT_SIGNATURE ou AT_KEYEXCHANGE */
    CK_OBJECT_HANDLE hPrivKey;                  /* Handle clé privée PKCS#11 */
    CK_OBJECT_HANDLE hPubKey;                   /* Handle clé publique PKCS#11 */
    CK_SLOT_ID       slotId;                    /* Slot PKCS#11 */
    BOOL             bFinalized;                /* FinalizeKey appelé ? */
    BOOL             bPersistOnly;              /* Génération différée ? */
} KSP_KEY;

/* Ouvre une clé existante depuis SoftHSM2 */
SECURITY_STATUS WINAPI KSP_OpenKey(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE  *phKey,
    LPCWSTR             pszKeyName,
    DWORD               dwLegacyKeySpec,
    DWORD               dwFlags);

/* Crée une nouvelle clé persistante */
SECURITY_STATUS WINAPI KSP_CreatePersistedKey(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE  *phKey,
    LPCWSTR             pszAlgId,
    LPCWSTR             pszKeyName,
    DWORD               dwLegacyKeySpec,
    DWORD               dwFlags);

/* Finalise la clé (génère la paire si différée) */
SECURITY_STATUS WINAPI KSP_FinalizeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags);

/* Supprime une clé du token */
SECURITY_STATUS WINAPI KSP_DeleteKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags);

/* Libère la structure de clé */
SECURITY_STATUS WINAPI KSP_FreeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey);

/* Énumère les clés du token */
SECURITY_STATUS WINAPI KSP_EnumKeys(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszScope,
    NCryptKeyName      **ppKeyName,
    PVOID              *ppEnumState,
    DWORD               dwFlags);

/* Valide un handle de clé */
BOOL KSP_IsValidKey(NCRYPT_KEY_HANDLE hKey);

/* Génère une paire de clés RSA dans SoftHSM2 */
SECURITY_STATUS KSP_GenerateRsaKeyPair(KSP_KEY *pKey);

/* Génère une paire de clés EC dans SoftHSM2 */
SECURITY_STATUS KSP_GenerateEcKeyPair(KSP_KEY *pKey);

/* État d'énumération interne */
typedef struct _KSP_ENUM_STATE {
    CK_OBJECT_HANDLE *phObjects;   /* Tableau des handles trouvés */
    DWORD             dwCount;     /* Nombre total */
    DWORD             dwIndex;     /* Index courant */
} KSP_ENUM_STATE;

#endif /* KSP_KEY_H */
