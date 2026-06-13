/* ksp_key.c — Implémentation des opérations sur les clés */
#include "ksp_key.h"
#include "ksp_provider.h"
#include "../pkcs11/p11_context.h"
#include "../pkcs11/p11_session.h"
#include "../pkcs11/p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/memory.h"
#include <string.h>
#include <wchar.h>
#include <stdlib.h>

/* Valide un handle de clé */
BOOL KSP_IsValidKey(NCRYPT_KEY_HANDLE hKey)
{
    KSP_KEY *pKey = (KSP_KEY *)(ULONG_PTR)hKey;
    return (pKey && pKey->dwMagic == KSP_KEY_MAGIC);
}

/* Convertit un label wchar en UTF-8 pour PKCS#11 */
static int WideToUtf8Label(LPCWSTR pwsz, char *pszBuf, int cbBuf)
{
    return WideCharToMultiByte(CP_UTF8, 0, pwsz, -1, pszBuf, cbBuf, NULL, NULL);
}

/* Génère une paire de clés RSA dans SoftHSM2 */
SECURITY_STATUS KSP_GenerateRsaKeyPair(KSP_KEY *pKey)
{
    P11_CONTEXT     *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;
    CK_RV             rv;
    CK_MECHANISM      mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    char              szLabel[MAX_KEY_LABEL_LEN];
    int               nLabelLen;
    CK_ULONG          ulModBits = pKey->dwKeyBitLen;
    CK_BYTE           pubExp[]  = { 0x01, 0x00, 0x01 }; /* 65537 */
    CK_BBOOL          bTrue     = CK_TRUE;
    CK_BBOOL          bFalse    = CK_FALSE;
    CK_BBOOL          bSign, bDecrypt;
    CK_OBJECT_CLASS   classPriv = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   classPub  = CKO_PUBLIC_KEY;

    nLabelLen = WideToUtf8Label(pKey->szKeyName, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;
    nLabelLen--; /* Sans le null terminateur */

    bSign    = (pKey->dwKeySpec == AT_SIGNATURE)    ? CK_TRUE : CK_FALSE;
    bDecrypt = (pKey->dwKeySpec == AT_KEYEXCHANGE)  ? CK_TRUE : CK_FALSE;

    CK_ATTRIBUTE aPubTemplate[] = {
        { CKA_CLASS,          &classPub,   sizeof(classPub)   },
        { CKA_TOKEN,          &bTrue,      sizeof(bTrue)      },
        { CKA_LABEL,          szLabel,     (CK_ULONG)nLabelLen },
        { CKA_MODULUS_BITS,   &ulModBits,  sizeof(ulModBits)  },
        { CKA_PUBLIC_EXPONENT, pubExp,     sizeof(pubExp)     },
        { CKA_VERIFY,         &bSign,      sizeof(bSign)      },
        { CKA_ENCRYPT,        &bDecrypt,   sizeof(bDecrypt)   },
    };

    CK_ATTRIBUTE aPrivTemplate[] = {
        { CKA_CLASS,       &classPriv,  sizeof(classPriv)  },
        { CKA_TOKEN,       &bTrue,      sizeof(bTrue)      },
        { CKA_LABEL,       szLabel,     (CK_ULONG)nLabelLen },
        { CKA_SENSITIVE,   &bTrue,      sizeof(bTrue)      },
        { CKA_EXTRACTABLE, &bFalse,     sizeof(bFalse)     },
        { CKA_SIGN,        &bSign,      sizeof(bSign)      },
        { CKA_DECRYPT,     &bDecrypt,   sizeof(bDecrypt)   },
    };

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS)
        return ss;

    rv = pCtx->pFunctionList->C_GenerateKeyPair(
        hSession, &mech,
        aPubTemplate,  (CK_ULONG)(sizeof(aPubTemplate)  / sizeof(CK_ATTRIBUTE)),
        aPrivTemplate, (CK_ULONG)(sizeof(aPrivTemplate) / sizeof(CK_ATTRIBUTE)),
        &pKey->hPubKey, &pKey->hPrivKey);

    P11_ReleaseSession(hSession);

    if (rv != CKR_OK) {
        LOG_ERROR("C_GenerateKeyPair RSA", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    LOG_INFO("RSA %lu bits generee : priv=0x%lX pub=0x%lX",
             (unsigned long)ulModBits,
             (unsigned long)pKey->hPrivKey,
             (unsigned long)pKey->hPubKey);
    return ERROR_SUCCESS;
}

/* Génère une paire de clés EC dans SoftHSM2 */
SECURITY_STATUS KSP_GenerateEcKeyPair(KSP_KEY *pKey)
{
    P11_CONTEXT     *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;
    CK_RV             rv;
    CK_MECHANISM      mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    char              szLabel[MAX_KEY_LABEL_LEN];
    int               nLabelLen;
    CK_BBOOL          bTrue  = CK_TRUE;
    CK_BBOOL          bFalse = CK_FALSE;
    CK_OBJECT_CLASS   classPriv = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   classPub  = CKO_PUBLIC_KEY;
    const char       *pbOid;
    CK_ULONG          cbOid;

    nLabelLen = WideToUtf8Label(pKey->szKeyName, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;
    nLabelLen--;

    /* Sélectionne l'OID DER selon la courbe */
    if (_wcsicmp(pKey->szAlgId, ALG_ECDSA_P256) == 0) {
        pbOid = EC_OID_P256;
        cbOid = EC_OID_P256_LEN;
    } else if (_wcsicmp(pKey->szAlgId, ALG_ECDSA_P384) == 0) {
        pbOid = EC_OID_P384;
        cbOid = EC_OID_P384_LEN;
    } else {
        return NTE_BAD_ALGID;
    }

    CK_ATTRIBUTE aPubTemplate[] = {
        { CKA_CLASS,     &classPub,           sizeof(classPub)        },
        { CKA_TOKEN,     &bTrue,              sizeof(bTrue)           },
        { CKA_LABEL,     szLabel,             (CK_ULONG)nLabelLen     },
        { CKA_EC_PARAMS, (CK_VOID_PTR)pbOid, cbOid                   },
        { CKA_VERIFY,    &bTrue,              sizeof(bTrue)           },
    };

    CK_ATTRIBUTE aPrivTemplate[] = {
        { CKA_CLASS,       &classPriv, sizeof(classPriv) },
        { CKA_TOKEN,       &bTrue,     sizeof(bTrue)     },
        { CKA_LABEL,       szLabel,    (CK_ULONG)nLabelLen },
        { CKA_SENSITIVE,   &bTrue,     sizeof(bTrue)     },
        { CKA_EXTRACTABLE, &bFalse,    sizeof(bFalse)    },
        { CKA_SIGN,        &bTrue,     sizeof(bTrue)     },
    };

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS)
        return ss;

    rv = pCtx->pFunctionList->C_GenerateKeyPair(
        hSession, &mech,
        aPubTemplate,  (CK_ULONG)(sizeof(aPubTemplate)  / sizeof(CK_ATTRIBUTE)),
        aPrivTemplate, (CK_ULONG)(sizeof(aPrivTemplate) / sizeof(CK_ATTRIBUTE)),
        &pKey->hPubKey, &pKey->hPrivKey);

    P11_ReleaseSession(hSession);

    if (rv != CKR_OK) {
        LOG_ERROR("C_GenerateKeyPair EC", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    LOG_INFO("EC generee : alg=%ls priv=0x%lX pub=0x%lX",
             pKey->szAlgId,
             (unsigned long)pKey->hPrivKey,
             (unsigned long)pKey->hPubKey);
    return ERROR_SUCCESS;
}

/* Ouvre une clé existante depuis SoftHSM2 */
SECURITY_STATUS WINAPI KSP_OpenKey(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE  *phKey,
    LPCWSTR             pszKeyName,
    DWORD               dwLegacyKeySpec,
    DWORD               dwFlags)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    KSP_KEY          *pKey = NULL;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hPriv, hPub;
    CK_ULONG          ulKeyType = 0;
    CK_ULONG          ulModBits = 0;
    SECURITY_STATUS   ss;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_OpenKey");

    if (!KSP_IsValidProvider(hProvider) || !phKey || !pszKeyName) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_OpenKey", ss);
        return ss;
    }

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_OpenKey", ss);
        return ss;
    }

    hPriv = P11_FindObjectByLabel(hSession, CKO_PRIVATE_KEY, pszKeyName);
    if (hPriv == CK_INVALID_HANDLE) {
        P11_ReleaseSession(hSession);
        LOG_LEAVE("KSP_OpenKey", NTE_BAD_KEYSET);
        return NTE_BAD_KEYSET;
    }

    hPub = P11_FindObjectByLabel(hSession, CKO_PUBLIC_KEY, pszKeyName);

    /* Détermine le type de clé */
    P11_GetUlongAttr(hSession, hPriv, CKA_KEY_TYPE, &ulKeyType);

    pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
    if (!pKey) {
        P11_ReleaseSession(hSession);
        return NTE_NO_MEMORY;
    }

    pKey->dwMagic   = KSP_KEY_MAGIC;
    pKey->hPrivKey  = hPriv;
    pKey->hPubKey   = hPub;
    pKey->slotId    = pCtx->slotId;
    pKey->bFinalized = TRUE;
    pKey->dwKeySpec  = (dwLegacyKeySpec == AT_KEYEXCHANGE)
                       ? AT_KEYEXCHANGE : AT_SIGNATURE;

    wcscpy_s(pKey->szKeyName, MAX_KEY_LABEL_LEN, pszKeyName);

    if (ulKeyType == CKK_RSA) {
        wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_RSA);
        P11_GetUlongAttr(hSession, hPriv, CKA_MODULUS_BITS, &ulModBits);
        pKey->dwKeyBitLen = (DWORD)ulModBits;
    } else if (ulKeyType == CKK_EC) {
        /* Détermine P-256 ou P-384 via CKA_EC_PARAMS */
        BYTE  *pbParams = NULL;
        DWORD  cbParams = 0;
        if (P11_GetBinaryAttr(hSession, hPriv, CKA_EC_PARAMS,
                              &pbParams, &cbParams) == CKR_OK) {
            if (cbParams == EC_OID_P256_LEN &&
                memcmp(pbParams, EC_OID_P256, EC_OID_P256_LEN) == 0) {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_ECDSA_P256);
                pKey->dwKeyBitLen = 256;
            } else {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_ECDSA_P384);
                pKey->dwKeyBitLen = 384;
            }
            KSP_Free(pbParams);
        }
    }

    P11_ReleaseSession(hSession);

    *phKey = (NCRYPT_KEY_HANDLE)(ULONG_PTR)pKey;

    LOG_INFO("KSP_OpenKey : '%ls' ouvert, alg=%ls bits=%lu",
             pszKeyName, pKey->szAlgId, (unsigned long)pKey->dwKeyBitLen);
    LOG_LEAVE("KSP_OpenKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Crée une nouvelle clé persistante */
SECURITY_STATUS WINAPI KSP_CreatePersistedKey(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE  *phKey,
    LPCWSTR             pszAlgId,
    LPCWSTR             pszKeyName,
    DWORD               dwLegacyKeySpec,
    DWORD               dwFlags)
{
    KSP_KEY         *pKey = NULL;
    P11_CONTEXT     *pCtx = P11_GetContext();
    SECURITY_STATUS  ss;
    BOOL             bPersistOnly;

    LOG_ENTER("KSP_CreatePersistedKey");

    if (!KSP_IsValidProvider(hProvider) || !phKey || !pszAlgId) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_CreatePersistedKey", ss);
        return ss;
    }

    /* Valide l'algorithme */
    if (_wcsicmp(pszAlgId, ALG_RSA)        != 0 &&
        _wcsicmp(pszAlgId, ALG_ECDSA_P256) != 0 &&
        _wcsicmp(pszAlgId, ALG_ECDSA_P384) != 0) {
        LOG_LEAVE("KSP_CreatePersistedKey", NTE_BAD_ALGID);
        return NTE_BAD_ALGID;
    }

    pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
    if (!pKey) {
        LOG_LEAVE("KSP_CreatePersistedKey", NTE_NO_MEMORY);
        return NTE_NO_MEMORY;
    }

    pKey->dwMagic    = KSP_KEY_MAGIC;
    pKey->hPrivKey   = CK_INVALID_HANDLE;
    pKey->hPubKey    = CK_INVALID_HANDLE;
    pKey->slotId     = pCtx->slotId;
    pKey->bFinalized = FALSE;
    pKey->dwKeySpec  = (dwLegacyKeySpec == AT_KEYEXCHANGE)
                       ? AT_KEYEXCHANGE : AT_SIGNATURE;

    wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, pszAlgId);

    if (pszKeyName)
        wcscpy_s(pKey->szKeyName, MAX_KEY_LABEL_LEN, pszKeyName);

    /* Taille par défaut */
    if (_wcsicmp(pszAlgId, ALG_RSA) == 0)
        pKey->dwKeyBitLen = RSA_DEFAULT_KEY_BITS;
    else if (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0)
        pKey->dwKeyBitLen = 256;
    else
        pKey->dwKeyBitLen = 384;

    bPersistOnly = (dwFlags & NCRYPT_PERSIST_ONLY_FLAG) != 0;

    if (!bPersistOnly) {
        /* Génère immédiatement */
        if (_wcsicmp(pszAlgId, ALG_RSA) == 0)
            ss = KSP_GenerateRsaKeyPair(pKey);
        else
            ss = KSP_GenerateEcKeyPair(pKey);

        if (ss != ERROR_SUCCESS) {
            KSP_Free(pKey);
            LOG_LEAVE("KSP_CreatePersistedKey", ss);
            return ss;
        }
        pKey->bFinalized = TRUE;
    } else {
        pKey->bPersistOnly = TRUE;
    }

    *phKey = (NCRYPT_KEY_HANDLE)(ULONG_PTR)pKey;

    LOG_INFO("KSP_CreatePersistedKey : '%ls' cree", pKey->szKeyName);
    LOG_LEAVE("KSP_CreatePersistedKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Finalise la clé (génère la paire si différée) */
SECURITY_STATUS WINAPI KSP_FinalizeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags)
{
    KSP_KEY        *pKey;
    SECURITY_STATUS ss = ERROR_SUCCESS;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_FinalizeKey");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey)) {
        LOG_LEAVE("KSP_FinalizeKey", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    if (!pKey->bFinalized) {
        if (_wcsicmp(pKey->szAlgId, ALG_RSA) == 0)
            ss = KSP_GenerateRsaKeyPair(pKey);
        else
            ss = KSP_GenerateEcKeyPair(pKey);

        if (ss == ERROR_SUCCESS)
            pKey->bFinalized = TRUE;
    }

    LOG_LEAVE("KSP_FinalizeKey", ss);
    return ss;
}

/* Supprime une clé du token */
SECURITY_STATUS WINAPI KSP_DeleteKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    KSP_KEY          *pKey;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;
    CK_RV             rv;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_DeleteKey");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey)) {
        LOG_LEAVE("KSP_DeleteKey", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_DeleteKey", ss);
        return ss;
    }

    if (pKey->hPrivKey != CK_INVALID_HANDLE) {
        rv = pCtx->pFunctionList->C_DestroyObject(hSession, pKey->hPrivKey);
        if (rv != CKR_OK)
            LOG_ERROR("C_DestroyObject priv", P11RvToSecStatus(rv));
    }

    if (pKey->hPubKey != CK_INVALID_HANDLE) {
        rv = pCtx->pFunctionList->C_DestroyObject(hSession, pKey->hPubKey);
        if (rv != CKR_OK)
            LOG_ERROR("C_DestroyObject pub", P11RvToSecStatus(rv));
    }

    P11_ReleaseSession(hSession);

    pKey->dwMagic = 0;
    KSP_Free(pKey);

    LOG_LEAVE("KSP_DeleteKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Libère la structure de clé */
SECURITY_STATUS WINAPI KSP_FreeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey)
{
    KSP_KEY *pKey;

    UNREFERENCED_PARAMETER(hProvider);
    LOG_ENTER("KSP_FreeKey");

    if (!KSP_IsValidKey(hKey)) {
        LOG_LEAVE("KSP_FreeKey", NTE_INVALID_HANDLE);
        return NTE_INVALID_HANDLE;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;
    pKey->dwMagic = 0;
    KSP_Free(pKey);

    LOG_LEAVE("KSP_FreeKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Énumère les clés du token */
SECURITY_STATUS WINAPI KSP_EnumKeys(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszScope,
    NCryptKeyName      **ppKeyName,
    PVOID              *ppEnumState,
    DWORD               dwFlags)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    KSP_ENUM_STATE   *pState;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;

    UNREFERENCED_PARAMETER(pszScope);
    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_EnumKeys");

    if (!KSP_IsValidProvider(hProvider) || !ppKeyName || !ppEnumState) {
        LOG_LEAVE("KSP_EnumKeys", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    /* Première itération : charge tous les handles */
    if (*ppEnumState == NULL) {
        CK_OBJECT_CLASS   classPriv = CKO_PRIVATE_KEY;
        CK_BBOOL          bToken    = CK_TRUE;
        CK_ATTRIBUTE      aTemplate[2] = {
            { CKA_CLASS, &classPriv, sizeof(classPriv) },
            { CKA_TOKEN, &bToken,    sizeof(bToken)    },
        };
        CK_OBJECT_HANDLE  aBuf[256];
        CK_ULONG          ulFound = 0;
        CK_RV             rv;

        pState = (KSP_ENUM_STATE *)KSP_AllocZero(sizeof(KSP_ENUM_STATE));
        if (!pState) {
            LOG_LEAVE("KSP_EnumKeys", NTE_NO_MEMORY);
            return NTE_NO_MEMORY;
        }

        ss = P11_AcquireSession(&hSession);
        if (ss != ERROR_SUCCESS) {
            KSP_Free(pState);
            LOG_LEAVE("KSP_EnumKeys", ss);
            return ss;
        }

        rv = pCtx->pFunctionList->C_FindObjectsInit(hSession, aTemplate, 2);
        if (rv == CKR_OK) {
            rv = pCtx->pFunctionList->C_FindObjects(hSession, aBuf, 256, &ulFound);
            pCtx->pFunctionList->C_FindObjectsFinal(hSession);
        }

        P11_ReleaseSession(hSession);

        if (rv != CKR_OK || ulFound == 0) {
            KSP_Free(pState);
            LOG_LEAVE("KSP_EnumKeys", NTE_NO_MORE_ITEMS);
            return NTE_NO_MORE_ITEMS;
        }

        pState->phObjects = (CK_OBJECT_HANDLE *)KSP_Alloc(
            ulFound * sizeof(CK_OBJECT_HANDLE));
        if (!pState->phObjects) {
            KSP_Free(pState);
            return NTE_NO_MEMORY;
        }
        memcpy(pState->phObjects, aBuf, ulFound * sizeof(CK_OBJECT_HANDLE));
        pState->dwCount = (DWORD)ulFound;
        pState->dwIndex = 0;
        *ppEnumState    = pState;
    } else {
        pState = (KSP_ENUM_STATE *)*ppEnumState;
    }

    /* Fin de l'énumération */
    if (pState->dwIndex >= pState->dwCount) {
        KSP_Free(pState->phObjects);
        KSP_Free(pState);
        *ppEnumState = NULL;
        LOG_LEAVE("KSP_EnumKeys", NTE_NO_MORE_ITEMS);
        return NTE_NO_MORE_ITEMS;
    }

    /* Lit le label de la clé courante */
    {
        CK_OBJECT_HANDLE hObj = pState->phObjects[pState->dwIndex++];
        char             szLabel[MAX_KEY_LABEL_LEN] = {0};
        WCHAR            wszLabel[MAX_KEY_LABEL_LEN] = {0};
        CK_ATTRIBUTE     attr = { CKA_LABEL, szLabel, sizeof(szLabel) - 1 };
        NCryptKeyName   *pName;
        SIZE_T           cbName;
        CK_RV            rv;

        ss = P11_AcquireSession(&hSession);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_EnumKeys", ss);
            return ss;
        }

        rv = pCtx->pFunctionList->C_GetAttributeValue(hSession, hObj, &attr, 1);
        P11_ReleaseSession(hSession);

        if (rv != CKR_OK) {
            LOG_LEAVE("KSP_EnumKeys", P11RvToSecStatus(rv));
            return P11RvToSecStatus(rv);
        }

        szLabel[attr.ulValueLen] = '\0';
        MultiByteToWideChar(CP_UTF8, 0, szLabel, -1,
                            wszLabel, MAX_KEY_LABEL_LEN);

        cbName = sizeof(NCryptKeyName) +
                 (wcslen(wszLabel) + 1) * sizeof(WCHAR);
        pName  = (NCryptKeyName *)KSP_AllocZero(cbName);
        if (!pName) {
            LOG_LEAVE("KSP_EnumKeys", NTE_NO_MEMORY);
            return NTE_NO_MEMORY;
        }

        pName->pszName    = (LPWSTR)((BYTE *)pName + sizeof(NCryptKeyName));
        pName->pszAlgid   = NULL;
        pName->dwLegacyKeySpec = 0;
        pName->dwFlags    = 0;
        wcscpy_s(pName->pszName,
                 wcslen(wszLabel) + 1,
                 wszLabel);

        *ppKeyName = pName;
    }

    LOG_LEAVE("KSP_EnumKeys", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}
