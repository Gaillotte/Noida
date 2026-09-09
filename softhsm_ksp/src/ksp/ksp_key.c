/* ksp_key.c — Key operation implementation */
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

/* Validate a key handle */
BOOL KSP_IsValidKey(NCRYPT_KEY_HANDLE hKey)
{
    KSP_KEY *pKey = (KSP_KEY *)(ULONG_PTR)hKey;
    return (pKey && pKey->dwMagic == KSP_KEY_MAGIC);
}

/* Convert a wchar label to UTF-8 for PKCS#11 */
static int WideToUtf8Label(LPCWSTR pwsz, char *pszBuf, int cbBuf)
{
    return WideCharToMultiByte(CP_UTF8, 0, pwsz, -1, pszBuf, cbBuf, NULL, NULL);
}

/* Encode an exponent as a minimal-length big-endian byte string, the form
 * CKA_PUBLIC_EXPONENT expects. 65537 becomes {01 00 01}; 3 becomes {03}.
 * Returns the number of bytes written into pbOut (at most 4). */
CK_ULONG KSP_EncodePublicExponent(DWORD dwExp, CK_BYTE *pbOut)
{
    CK_BYTE  tmp[4];
    int      i;
    int      first = 4;

    tmp[0] = (CK_BYTE)((dwExp >> 24) & 0xFF);
    tmp[1] = (CK_BYTE)((dwExp >> 16) & 0xFF);
    tmp[2] = (CK_BYTE)((dwExp >>  8) & 0xFF);
    tmp[3] = (CK_BYTE)( dwExp        & 0xFF);

    for (i = 0; i < 4; i++) {
        if (tmp[i] != 0x00) { first = i; break; }
    }
    if (first == 4) {          /* exponent 0 — encode a single zero byte */
        pbOut[0] = 0x00;
        return 1;
    }

    for (i = first; i < 4; i++)
        pbOut[i - first] = tmp[i];
    return (CK_ULONG)(4 - first);
}

/* ── Algorithm classifiers ──────────────────────────────────────────────── */

BOOL KSP_IsEcdsaAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDSA_P521) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDSA_SECP256K1) == 0);
}

BOOL KSP_IsEcdhAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_ECDH_P256) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDH_P384) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDH_P521) == 0);
}

BOOL KSP_IsEddsaAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_EDDSA_ED25519) == 0 ||
            _wcsicmp(pszAlgId, ALG_EDDSA_ED448)   == 0);
}

BOOL KSP_IsSymmetricAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_AES)         == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA1)   == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA224) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA256) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA384) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA512) == 0);
}

/* Default key length in bits for a given algorithm */
static DWORD DefaultKeyBits(LPCWSTR pszAlgId)
{
    if (_wcsicmp(pszAlgId, ALG_RSA) == 0)            return RSA_DEFAULT_KEY_BITS;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P256)  == 0)     return 256;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P384)  == 0)     return 384;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P521) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P521)  == 0)     return 521;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_SECP256K1) == 0) return 256;
    if (_wcsicmp(pszAlgId, ALG_EDDSA_ED25519) == 0)  return 255;
    if (_wcsicmp(pszAlgId, ALG_EDDSA_ED448)   == 0)  return 448;
    if (_wcsicmp(pszAlgId, ALG_AES) == 0)            return 256;
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA1)   == 0)    return 160;
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA224) == 0)    return 224;
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA256) == 0)    return 256;
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA384) == 0)    return 384;
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA512) == 0)    return 512;
    return 0;
}

/* Dispatch key generation to the right generator for pKey->szAlgId */
static SECURITY_STATUS GenerateForAlg(KSP_KEY *pKey)
{
    if (_wcsicmp(pKey->szAlgId, ALG_RSA) == 0)
        return KSP_GenerateRsaKeyPair(pKey);
    if (KSP_IsEddsaAlg(pKey->szAlgId))
        return KSP_GenerateEddsaKeyPair(pKey);
    if (KSP_IsSymmetricAlg(pKey->szAlgId))
        return KSP_GenerateSymmetricKey(pKey);
    if (KSP_IsEcdsaAlg(pKey->szAlgId) || KSP_IsEcdhAlg(pKey->szAlgId))
        return KSP_GenerateEcKeyPair(pKey);
    return NTE_BAD_ALGID;
}

/* Generate an RSA key pair in SoftHSM2 */
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
    CK_BYTE           pubExp[4];                 /* big-endian, minimal length */
    CK_ULONG          cbPubExp;
    CK_BBOOL          bTrue     = CK_TRUE;
    CK_BBOOL          bFalse    = CK_FALSE;
    CK_BBOOL          bSign, bDecrypt;
    CK_OBJECT_CLASS   classPriv = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   classPub  = CKO_PUBLIC_KEY;

    nLabelLen = WideToUtf8Label(pKey->szKeyName, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;
    nLabelLen--; /* Exclude the null terminator */

    cbPubExp = KSP_EncodePublicExponent(pKey->dwPublicExponent
                                            ? pKey->dwPublicExponent
                                            : RSA_DEFAULT_PUBEXP,
                                        pubExp);

    bSign    = (pKey->dwKeySpec == AT_SIGNATURE)    ? CK_TRUE : CK_FALSE;
    bDecrypt = (pKey->dwKeySpec == AT_KEYEXCHANGE)  ? CK_TRUE : CK_FALSE;

    CK_ATTRIBUTE aPubTemplate[] = {
        { CKA_CLASS,          &classPub,   sizeof(classPub)   },
        { CKA_TOKEN,          &bTrue,      sizeof(bTrue)      },
        { CKA_LABEL,          szLabel,     (CK_ULONG)nLabelLen },
        { CKA_MODULUS_BITS,   &ulModBits,  sizeof(ulModBits)  },
        { CKA_PUBLIC_EXPONENT, pubExp,     cbPubExp           },
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

    LOG_INFO("RSA %lu bits generated: priv=0x%lX pub=0x%lX",
             (unsigned long)ulModBits,
             (unsigned long)pKey->hPrivKey,
             (unsigned long)pKey->hPubKey);
    return ERROR_SUCCESS;
}

/* Generate an EC key pair in SoftHSM2 */
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

    /* ECDH keys derive; ECDSA keys sign */
    CK_BBOOL bDerive = KSP_IsEcdhAlg(pKey->szAlgId) ? CK_TRUE : CK_FALSE;
    CK_BBOOL bSign   = bDerive ? CK_FALSE : CK_TRUE;

    nLabelLen = WideToUtf8Label(pKey->szKeyName, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;
    nLabelLen--;

    /* Select the DER OID based on the curve (P-256 / P-384 / P-521) */
    pbOid = P11_GetCurveOid(pKey->szAlgId, &cbOid);
    if (!pbOid)
        return NTE_BAD_ALGID;

    CK_ATTRIBUTE aPubTemplate[] = {
        { CKA_CLASS,     &classPub,           sizeof(classPub)        },
        { CKA_TOKEN,     &bTrue,              sizeof(bTrue)           },
        { CKA_LABEL,     szLabel,             (CK_ULONG)nLabelLen     },
        { CKA_EC_PARAMS, (CK_VOID_PTR)pbOid,  cbOid                   },
        { CKA_VERIFY,    &bSign,              sizeof(bSign)           },
        { CKA_DERIVE,    &bDerive,            sizeof(bDerive)         },
    };

    CK_ATTRIBUTE aPrivTemplate[] = {
        { CKA_CLASS,       &classPriv, sizeof(classPriv) },
        { CKA_TOKEN,       &bTrue,     sizeof(bTrue)     },
        { CKA_LABEL,       szLabel,    (CK_ULONG)nLabelLen },
        { CKA_SENSITIVE,   &bTrue,     sizeof(bTrue)     },
        { CKA_EXTRACTABLE, &bFalse,    sizeof(bFalse)    },
        { CKA_SIGN,        &bSign,     sizeof(bSign)     },
        { CKA_DERIVE,      &bDerive,   sizeof(bDerive)   },
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

    LOG_INFO("EC generated: alg=%ls priv=0x%lX pub=0x%lX",
             pKey->szAlgId,
             (unsigned long)pKey->hPrivKey,
             (unsigned long)pKey->hPubKey);
    return ERROR_SUCCESS;
}

/* Generate an Edwards-curve key pair (Ed25519 / Ed448) in SoftHSM2.
 * Uses CKM_EC_EDWARDS_KEY_PAIR_GEN with the Edwards curve OID in
 * CKA_EC_PARAMS. EdDSA keys are signature-only (no key agreement). */
SECURITY_STATUS KSP_GenerateEddsaKeyPair(KSP_KEY *pKey)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;
    CK_RV             rv;
    CK_MECHANISM      mech = { CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL, 0 };
    char              szLabel[MAX_KEY_LABEL_LEN];
    int               nLabelLen;
    CK_BBOOL          bTrue  = CK_TRUE;
    CK_BBOOL          bFalse = CK_FALSE;
    CK_OBJECT_CLASS   classPriv = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   classPub  = CKO_PUBLIC_KEY;
    CK_KEY_TYPE       keyType   = CKK_EC_EDWARDS;
    const char       *pbOid;
    CK_ULONG          cbOid;

    nLabelLen = WideToUtf8Label(pKey->szKeyName, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;
    nLabelLen--;

    pbOid = P11_GetCurveOid(pKey->szAlgId, &cbOid);
    if (!pbOid)
        return NTE_BAD_ALGID;

    CK_ATTRIBUTE aPubTemplate[] = {
        { CKA_CLASS,     &classPub,          sizeof(classPub)    },
        { CKA_KEY_TYPE,  &keyType,           sizeof(keyType)     },
        { CKA_TOKEN,     &bTrue,             sizeof(bTrue)       },
        { CKA_LABEL,     szLabel,            (CK_ULONG)nLabelLen },
        { CKA_EC_PARAMS, (CK_VOID_PTR)pbOid, cbOid               },
        { CKA_VERIFY,    &bTrue,             sizeof(bTrue)       },
    };

    CK_ATTRIBUTE aPrivTemplate[] = {
        { CKA_CLASS,       &classPriv, sizeof(classPriv)   },
        { CKA_KEY_TYPE,    &keyType,   sizeof(keyType)     },
        { CKA_TOKEN,       &bTrue,     sizeof(bTrue)       },
        { CKA_LABEL,       szLabel,    (CK_ULONG)nLabelLen },
        { CKA_SENSITIVE,   &bTrue,     sizeof(bTrue)       },
        { CKA_EXTRACTABLE, &bFalse,    sizeof(bFalse)      },
        { CKA_SIGN,        &bTrue,     sizeof(bTrue)       },
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
        LOG_ERROR("C_GenerateKeyPair EdDSA", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    LOG_INFO("EdDSA generated: alg=%ls priv=0x%lX pub=0x%lX",
             pKey->szAlgId,
             (unsigned long)pKey->hPrivKey,
             (unsigned long)pKey->hPubKey);
    return ERROR_SUCCESS;
}

/* Generate a symmetric key (AES or HMAC generic secret) in SoftHSM2.
 * AES keys use CKM_AES_KEY_GEN; HMAC keys use CKM_GENERIC_SECRET_KEY_GEN.
 * The resulting object handle is stored in pKey->hSecretKey. */
SECURITY_STATUS KSP_GenerateSymmetricKey(KSP_KEY *pKey)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;
    CK_RV             rv;
    CK_MECHANISM      mech;
    char              szLabel[MAX_KEY_LABEL_LEN];
    int               nLabelLen;
    CK_BBOOL          bTrue  = CK_TRUE;
    CK_BBOOL          bFalse = CK_FALSE;
    CK_OBJECT_CLASS   classSecret = CKO_SECRET_KEY;
    CK_KEY_TYPE       keyType;
    CK_ULONG          ulValueLen;
    BOOL              bAes = (_wcsicmp(pKey->szAlgId, ALG_AES) == 0);

    nLabelLen = WideToUtf8Label(pKey->szKeyName, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;
    nLabelLen--;

    memset(&mech, 0, sizeof(mech));

    if (bAes) {
        /* AES supports exactly 128, 192 and 256 bits */
        if (pKey->dwKeyBitLen != 128 &&
            pKey->dwKeyBitLen != 192 &&
            pKey->dwKeyBitLen != 256)
            return NTE_BAD_LEN;

        mech.mechanism = CKM_AES_KEY_GEN;
        keyType        = CKK_AES;
        ulValueLen     = pKey->dwKeyBitLen / 8;
    } else {
        /* HMAC key: generic secret sized to the hash output */
        mech.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
        keyType        = CKK_GENERIC_SECRET;
        ulValueLen     = pKey->dwKeyBitLen / 8;
        if (ulValueLen == 0)
            return NTE_BAD_LEN;
    }

    {
        /* AES keys encrypt/decrypt; HMAC keys sign/verify */
        CK_BBOOL bCipher = bAes ? CK_TRUE : CK_FALSE;
        CK_BBOOL bMac    = bAes ? CK_FALSE : CK_TRUE;

        CK_ATTRIBUTE aTemplate[] = {
            { CKA_CLASS,       &classSecret, sizeof(classSecret) },
            { CKA_KEY_TYPE,    &keyType,     sizeof(keyType)     },
            { CKA_TOKEN,       &bTrue,       sizeof(bTrue)       },
            { CKA_LABEL,       szLabel,      (CK_ULONG)nLabelLen },
            { CKA_VALUE_LEN,   &ulValueLen,  sizeof(ulValueLen)  },
            { CKA_SENSITIVE,   &bTrue,       sizeof(bTrue)       },
            { CKA_EXTRACTABLE, &bFalse,      sizeof(bFalse)      },
            { CKA_ENCRYPT,     &bCipher,     sizeof(bCipher)     },
            { CKA_DECRYPT,     &bCipher,     sizeof(bCipher)     },
            { CKA_SIGN,        &bMac,        sizeof(bMac)        },
            { CKA_VERIFY,      &bMac,        sizeof(bMac)        },
        };

        ss = P11_AcquireSession(&hSession);
        if (ss != ERROR_SUCCESS)
            return ss;

        rv = pCtx->pFunctionList->C_GenerateKey(
            hSession, &mech, aTemplate,
            (CK_ULONG)(sizeof(aTemplate) / sizeof(CK_ATTRIBUTE)),
            &pKey->hSecretKey);

        P11_ReleaseSession(hSession);
    }

    if (rv != CKR_OK) {
        LOG_ERROR("C_GenerateKey symmetric", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    pKey->dwKeyClass = KSP_KEY_CLASS_SYMMETRIC;

    LOG_INFO("Symmetric key generated: alg=%ls bits=%lu obj=0x%lX",
             pKey->szAlgId,
             (unsigned long)pKey->dwKeyBitLen,
             (unsigned long)pKey->hSecretKey);
    return ERROR_SUCCESS;
}

/* Open an existing key from SoftHSM2 */
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
        /* No private key — this may be a symmetric (secret) key */
        CK_OBJECT_HANDLE hSecret =
            P11_FindObjectByLabel(hSession, CKO_SECRET_KEY, pszKeyName);

        if (hSecret == CK_INVALID_HANDLE) {
            P11_ReleaseSession(hSession);
            LOG_LEAVE("KSP_OpenKey", NTE_BAD_KEYSET);
            return NTE_BAD_KEYSET;
        }

        pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
        if (!pKey) {
            P11_ReleaseSession(hSession);
            return NTE_NO_MEMORY;
        }

        pKey->dwMagic    = KSP_KEY_MAGIC;
        pKey->hPrivKey   = CK_INVALID_HANDLE;
        pKey->hPubKey    = CK_INVALID_HANDLE;
        pKey->hSecretKey = hSecret;
        pKey->slotId     = pCtx->slotId;
        pKey->bFinalized = TRUE;
        pKey->dwKeyClass = KSP_KEY_CLASS_SYMMETRIC;
        pKey->dwKeySpec  = AT_KEYEXCHANGE;
        wcscpy_s(pKey->szKeyName, MAX_KEY_LABEL_LEN, pszKeyName);

        P11_GetUlongAttr(hSession, hSecret, CKA_KEY_TYPE, &ulKeyType);
        if (ulKeyType == CKK_AES) {
            CK_ULONG ulValueLen = 0;
            wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_AES);
            if (P11_GetUlongAttr(hSession, hSecret,
                                 CKA_VALUE_LEN, &ulValueLen) == CKR_OK)
                pKey->dwKeyBitLen = (DWORD)(ulValueLen * 8);
        } else {
            CK_ULONG ulValueLen = 0;
            wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_HMAC_SHA256);
            if (P11_GetUlongAttr(hSession, hSecret,
                                 CKA_VALUE_LEN, &ulValueLen) == CKR_OK)
                pKey->dwKeyBitLen = (DWORD)(ulValueLen * 8);
        }

        P11_ReleaseSession(hSession);
        *phKey = (NCRYPT_KEY_HANDLE)(ULONG_PTR)pKey;
        LOG_INFO("KSP_OpenKey: '%ls' opened (symmetric), alg=%ls bits=%lu",
                 pszKeyName, pKey->szAlgId, (unsigned long)pKey->dwKeyBitLen);
        LOG_LEAVE("KSP_OpenKey", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    hPub = P11_FindObjectByLabel(hSession, CKO_PUBLIC_KEY, pszKeyName);

    /* Determine the key type */
    P11_GetUlongAttr(hSession, hPriv, CKA_KEY_TYPE, &ulKeyType);

    pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
    if (!pKey) {
        P11_ReleaseSession(hSession);
        return NTE_NO_MEMORY;
    }

    pKey->dwMagic   = KSP_KEY_MAGIC;
    pKey->hPrivKey  = hPriv;
    pKey->hPubKey   = hPub;
    pKey->hSecretKey = CK_INVALID_HANDLE;
    pKey->slotId    = pCtx->slotId;
    pKey->bFinalized = TRUE;
    pKey->dwKeyClass = KSP_KEY_CLASS_ASYMMETRIC;
    pKey->dwKeySpec  = (dwLegacyKeySpec == AT_KEYEXCHANGE)
                       ? AT_KEYEXCHANGE : AT_SIGNATURE;

    wcscpy_s(pKey->szKeyName, MAX_KEY_LABEL_LEN, pszKeyName);

    if (ulKeyType == CKK_RSA) {
        wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_RSA);
        P11_GetUlongAttr(hSession, hPriv, CKA_MODULUS_BITS, &ulModBits);
        pKey->dwKeyBitLen = (DWORD)ulModBits;
    } else if (ulKeyType == CKK_EC || ulKeyType == CKK_EC_EDWARDS) {
        /* Identify the exact curve via CKA_EC_PARAMS */
        BYTE  *pbParams = NULL;
        DWORD  cbParams = 0;
        BOOL   bDerive  = FALSE;
        CK_ULONG ulDerive = 0;

        /* CKA_DERIVE distinguishes ECDH keys from ECDSA keys */
        if (P11_GetUlongAttr(hSession, hPriv, CKA_DERIVE, &ulDerive) == CKR_OK)
            bDerive = (ulDerive != 0);

        if (P11_GetBinaryAttr(hSession, hPriv, CKA_EC_PARAMS,
                              &pbParams, &cbParams) == CKR_OK) {
            if (cbParams == EC_OID_ED25519_LEN &&
                memcmp(pbParams, EC_OID_ED25519, EC_OID_ED25519_LEN) == 0) {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_EDDSA_ED25519);
                pKey->dwKeyBitLen = 255;
            } else if (cbParams == EC_OID_ED448_LEN &&
                       memcmp(pbParams, EC_OID_ED448, EC_OID_ED448_LEN) == 0) {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_EDDSA_ED448);
                pKey->dwKeyBitLen = 448;
            } else if (cbParams == EC_OID_P256_LEN &&
                       memcmp(pbParams, EC_OID_P256, EC_OID_P256_LEN) == 0) {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN,
                         bDerive ? ALG_ECDH_P256 : ALG_ECDSA_P256);
                pKey->dwKeyBitLen = 256;
            } else if (cbParams == EC_OID_P521_LEN &&
                       memcmp(pbParams, EC_OID_P521, EC_OID_P521_LEN) == 0) {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN,
                         bDerive ? ALG_ECDH_P521 : ALG_ECDSA_P521);
                pKey->dwKeyBitLen = 521;
            } else {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN,
                         bDerive ? ALG_ECDH_P384 : ALG_ECDSA_P384);
                pKey->dwKeyBitLen = 384;
            }
            KSP_Free(pbParams);
        }
    }

    P11_ReleaseSession(hSession);

    *phKey = (NCRYPT_KEY_HANDLE)(ULONG_PTR)pKey;

    LOG_INFO("KSP_OpenKey: '%ls' opened, alg=%ls bits=%lu",
             pszKeyName, pKey->szAlgId, (unsigned long)pKey->dwKeyBitLen);
    LOG_LEAVE("KSP_OpenKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Create a new persistent key */
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

    /* Validate the algorithm */
    if (_wcsicmp(pszAlgId, ALG_RSA) != 0 &&
        !KSP_IsEcdsaAlg(pszAlgId)   &&
        !KSP_IsEcdhAlg(pszAlgId)    &&
        !KSP_IsEddsaAlg(pszAlgId)   &&
        !KSP_IsSymmetricAlg(pszAlgId)) {
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
    pKey->hSecretKey = CK_INVALID_HANDLE;
    pKey->slotId     = pCtx->slotId;
    pKey->bFinalized = FALSE;
    pKey->dwKeyClass = KSP_IsSymmetricAlg(pszAlgId)
                       ? KSP_KEY_CLASS_SYMMETRIC : KSP_KEY_CLASS_ASYMMETRIC;

    /* ECDH keys are key-agreement keys regardless of the requested spec */
    if (KSP_IsEcdhAlg(pszAlgId))
        pKey->dwKeySpec = AT_KEYEXCHANGE;
    else
        pKey->dwKeySpec = (dwLegacyKeySpec == AT_KEYEXCHANGE)
                          ? AT_KEYEXCHANGE : AT_SIGNATURE;

    wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, pszAlgId);

    if (pszKeyName)
        wcscpy_s(pKey->szKeyName, MAX_KEY_LABEL_LEN, pszKeyName);

    pKey->dwKeyBitLen      = DefaultKeyBits(pszAlgId);
    pKey->dwPublicExponent = RSA_DEFAULT_PUBEXP;

    bPersistOnly = (dwFlags & NCRYPT_PERSIST_ONLY_FLAG) != 0;

    if (!bPersistOnly) {
        /* Generate immediately */
        ss = GenerateForAlg(pKey);

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

    LOG_INFO("KSP_CreatePersistedKey: '%ls' created", pKey->szKeyName);
    LOG_LEAVE("KSP_CreatePersistedKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Finalise the key (generate the pair if deferred) */
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
        ss = GenerateForAlg(pKey);

        if (ss == ERROR_SUCCESS)
            pKey->bFinalized = TRUE;
    }

    LOG_LEAVE("KSP_FinalizeKey", ss);
    return ss;
}

/* Delete a key from the token */
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

    /* Symmetric keys live in hSecretKey */
    if (pKey->hSecretKey != CK_INVALID_HANDLE) {
        rv = pCtx->pFunctionList->C_DestroyObject(hSession, pKey->hSecretKey);
        if (rv != CKR_OK)
            LOG_ERROR("C_DestroyObject secret", P11RvToSecStatus(rv));
    }

    P11_ReleaseSession(hSession);

    pKey->dwMagic = 0;
    KSP_Free(pKey);

    LOG_LEAVE("KSP_DeleteKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Free the key structure.
 * Session objects (imported public keys) are destroyed on the token first —
 * token-resident keys are left in place, only the handle wrapper is freed. */
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

    /* Imported public keys are session objects — clean them up */
    if (pKey->bSessionObject && pKey->hPubKey != CK_INVALID_HANDLE) {
        P11_CONTEXT      *pCtx = P11_GetContext();
        CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

        if (pCtx && pCtx->pFunctionList &&
            P11_AcquireSession(&hSession) == ERROR_SUCCESS) {
            pCtx->pFunctionList->C_DestroyObject(hSession, pKey->hPubKey);
            P11_ReleaseSession(hSession);
        }
    }

    pKey->dwMagic = 0;
    KSP_Free(pKey);

    LOG_LEAVE("KSP_FreeKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Enumerate keys in the token */
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

    /* First iteration: load all handles */
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

    /* End of enumeration */
    if (pState->dwIndex >= pState->dwCount) {
        KSP_Free(pState->phObjects);
        KSP_Free(pState);
        *ppEnumState = NULL;
        LOG_LEAVE("KSP_EnumKeys", NTE_NO_MORE_ITEMS);
        return NTE_NO_MORE_ITEMS;
    }

    /* Read the current key label */
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
