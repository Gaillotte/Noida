/* ksp_key.c — Key operation implementation */
#include "ksp_key.h"
#include "ksp_provider.h"
#include "../pkcs11/p11_context.h"
#include "../pkcs11/p11_caps.h"
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

/* Wide-string form of the scoped label, for lookups by name.
 * Produces L"m/name" or L"u/name". */
static void BuildScopedNameW(LPCWSTR pszName, BOOL bMachine,
                             LPWSTR pszOut, size_t cchOut)
{
    pszOut[0] = bMachine ? L'm' : L'u';
    pszOut[1] = L'/';
    pszOut[2] = L'\0';
    wcscat_s(pszOut, cchOut, pszName);
}

/* Find a key object by name within a scope.
 *
 * Keys created before scoping existed carry an unprefixed label. Looking
 * only for the scoped name would orphan every one of them, so an
 * unprefixed lookup is tried as a fallback. New keys are always written
 * with a prefix, so this path only ever finds legacy objects. */
static CK_OBJECT_HANDLE FindScopedObject(CK_SESSION_HANDLE hSession,
                                         CK_OBJECT_CLASS   ulClass,
                                         LPCWSTR           pszName,
                                         BOOL              bMachine)
{
    WCHAR            wszScoped[MAX_KEY_LABEL_LEN + KSP_SCOPE_PREFIX_LEN + 1];
    CK_OBJECT_HANDLE hObj;

    BuildScopedNameW(pszName, bMachine, wszScoped,
                     sizeof(wszScoped) / sizeof(wszScoped[0]));

    hObj = P11_FindObjectByLabel(hSession, ulClass, wszScoped);
    if (hObj != CK_INVALID_HANDLE)
        return hObj;

    return P11_FindObjectByLabel(hSession, ulClass, pszName);
}

/* Build the CKA_LABEL for a key, prefixed with its scope.
 *
 * CNG keeps machine keys and user keys in separate stores. PKCS#11 has no
 * user concept inside a token, so the scope lives in the label: "m/name"
 * or "u/name". Before this, both scopes shared one namespace and a machine
 * key silently aliased a user key of the same name.
 *
 * Returns the label length excluding the terminator, or -1. */
static int BuildScopedLabel(const KSP_KEY *pKey, char *pszBuf, int cbBuf)
{
    const char *pszPrefix = pKey->bMachineKey ? KSP_SCOPE_PREFIX_MACHINE
                                              : KSP_SCOPE_PREFIX_USER;
    int n;

    if (cbBuf <= KSP_SCOPE_PREFIX_LEN)
        return -1;

    memcpy(pszBuf, pszPrefix, KSP_SCOPE_PREFIX_LEN);

    n = WideToUtf8Label(pKey->szKeyName,
                        pszBuf + KSP_SCOPE_PREFIX_LEN,
                        cbBuf - KSP_SCOPE_PREFIX_LEN);
    if (n <= 0)
        return -1;

    return KSP_SCOPE_PREFIX_LEN + n - 1;   /* drop the terminator */
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
            _wcsicmp(pszAlgId, ALG_ECDSA_SECP256K1) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDSA_BP256) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDSA_BP384) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDSA_BP512) == 0);
}

BOOL KSP_IsEcdhAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_ECDH_P256)  == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDH_P384)  == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDH_P521)  == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDH_X25519) == 0);
}

/* The generic CNG ECC identifiers. A key created with one of these has no
 * curve yet: the caller supplies it through BCRYPT_ECC_CURVE_NAME before
 * FinalizeKey. This is how a portable application reaches secp256k1,
 * Brainpool or X25519 without naming anything provider-specific. */
BOOL KSP_IsGenericEccAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, BCRYPT_ECDSA_ALGORITHM) == 0 ||
            _wcsicmp(pszAlgId, BCRYPT_ECDH_ALGORITHM)  == 0);
}

/* X25519 is a Montgomery curve, and PKCS#11 3.0 gives Montgomery curves
 * their own generator and key type — CKM_EC_MONTGOMERY_KEY_PAIR_GEN and
 * CKK_EC_MONTGOMERY — not the Edwards pair with a different curve OID.
 * This file asserted the opposite until session 10 ran X25519 against
 * Kryoptic, which implements the Montgomery generator and not the Edwards
 * one and refused every X25519 key. The key is also for agreement rather
 * than signing, so it needs CKA_DERIVE where Ed25519 needs CKA_SIGN. */
BOOL KSP_IsMontgomeryAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_ECDH_X25519) == 0);
}

BOOL KSP_IsEddsaAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_EDDSA_ED25519) == 0 ||
            _wcsicmp(pszAlgId, ALG_EDDSA_ED448)   == 0);
}

/* ML-DSA, by name only. Whether the token can act on it is a separate
 * question, asked of the capability probe at the point of use. */
BOOL KSP_IsMlDsaAlg(LPCWSTR pszAlgId)
{
    return (P11_MlDsaParameterSet(pszAlgId) != 0);
}

BOOL KSP_IsSymmetricAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_AES)         == 0 ||
            _wcsicmp(pszAlgId, BCRYPT_AES_CMAC_ALGORITHM) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA1)   == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA224) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA256) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA384) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA512) == 0);
}

/* Default key length in bits for a given algorithm */
DWORD KSP_DefaultKeyBits(LPCWSTR pszAlgId)
{
    if (_wcsicmp(pszAlgId, ALG_RSA) == 0)            return RSA_DEFAULT_KEY_BITS;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P256)  == 0)     return 256;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P384)  == 0)     return 384;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P521) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P521)  == 0)     return 521;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_SECP256K1) == 0) return 256;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_BP256) == 0)     return 256;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_BP384) == 0)     return 384;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_BP512) == 0)     return 512;
    /* X25519 keys are 255-bit scalars in a 32-byte field, reported as 255
     * for consistency with Ed25519. */
    if (_wcsicmp(pszAlgId, ALG_ECDH_X25519) == 0)     return 255;
    if (_wcsicmp(pszAlgId, ALG_EDDSA_ED25519) == 0)  return 255;
    if (_wcsicmp(pszAlgId, ALG_EDDSA_ED448)   == 0)  return 448;
    /* ML-DSA has no key size in the sense RSA and EC do — the parameter set
     * fixes everything. The public key length in bits is reported so callers
     * asking NCRYPT_LENGTH_PROPERTY get something meaningful rather than
     * zero, which they would read as an error. */
    if (P11_MlDsaPublicKeySize(pszAlgId) != 0)
        return P11_MlDsaPublicKeySize(pszAlgId) * 8;
    if (_wcsicmp(pszAlgId, ALG_AES) == 0)            return 256;
    /* CMAC keys are AES keys; 256 matches the AES default. */
    if (_wcsicmp(pszAlgId, BCRYPT_AES_CMAC_ALGORITHM) == 0) return 256;
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
    /* A generic ECDSA/ECDH key that never received BCRYPT_ECC_CURVE_NAME
     * has no curve to generate on. Refusing here is far clearer than
     * whatever the token would say about an empty CKA_EC_PARAMS. */
    if (pKey->bCurvePending) {
        LOG_ERROR("FinalizeKey - generic ECC key has no curve; set "
                  "BCRYPT_ECC_CURVE_NAME before finalising", NTE_BAD_ALGID);
        return NTE_BAD_ALGID;
    }

    if (KSP_IsMlDsaAlg(pKey->szAlgId))
        return KSP_GenerateMlDsaKeyPair(pKey);
    if (KSP_IsEddsaAlg(pKey->szAlgId) || KSP_IsMontgomeryAlg(pKey->szAlgId))
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

    nLabelLen = BuildScopedLabel(pKey, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;

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

    nLabelLen = BuildScopedLabel(pKey, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;

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

/* Generate an Edwards or Montgomery curve key pair.
 *
 * The two are NOT the same mechanism with a different curve OID, which is
 * what this comment claimed before a real token contradicted it. PKCS#11
 * 3.0 defines CKM_EC_MONTGOMERY_KEY_PAIR_GEN / CKK_EC_MONTGOMERY for
 * X25519 and X448, separately from the Edwards pair, and a token may
 * implement either alone. The usage attribute differs too: Ed25519 and
 * Ed448 are signature-only, X25519 is agreement-only, and setting the wrong
 * one makes the token refuse the operation later with an error that does
 * not point back here. */
SECURITY_STATUS KSP_GenerateEddsaKeyPair(KSP_KEY *pKey)
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
    CK_OBJECT_CLASS   classPriv = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   classPub  = CKO_PUBLIC_KEY;
    CK_KEY_TYPE       keyType;
    const char       *pbOid;
    CK_ULONG          cbOid;
    BOOL              bAgreement;

    nLabelLen = BuildScopedLabel(pKey, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;

    pbOid = P11_GetCurveOid(pKey->szAlgId, &cbOid);
    if (!pbOid)
        return NTE_BAD_ALGID;

    /* X25519 derives; Ed25519 and Ed448 sign. The generator and key type
     * follow the same split. */
    bAgreement = KSP_IsMontgomeryAlg(pKey->szAlgId);

    mech.mechanism      = bAgreement ? CKM_EC_MONTGOMERY_KEY_PAIR_GEN
                                     : CKM_EC_EDWARDS_KEY_PAIR_GEN;
    mech.pParameter     = NULL;
    mech.ulParameterLen = 0;
    keyType             = bAgreement ? CKK_EC_MONTGOMERY : CKK_EC_EDWARDS;

    CK_ATTRIBUTE aPubTemplate[] = {
        { CKA_CLASS,     &classPub,          sizeof(classPub)    },
        { CKA_KEY_TYPE,  &keyType,           sizeof(keyType)     },
        { CKA_TOKEN,     &bTrue,             sizeof(bTrue)       },
        { CKA_LABEL,     szLabel,            (CK_ULONG)nLabelLen },
        { CKA_EC_PARAMS, (CK_VOID_PTR)pbOid, cbOid               },
        { CKA_VERIFY,    bAgreement ? &bFalse : &bTrue, sizeof(bTrue) },
    };

    CK_ATTRIBUTE aPrivTemplate[] = {
        { CKA_CLASS,       &classPriv, sizeof(classPriv)   },
        { CKA_KEY_TYPE,    &keyType,   sizeof(keyType)     },
        { CKA_TOKEN,       &bTrue,     sizeof(bTrue)       },
        { CKA_LABEL,       szLabel,    (CK_ULONG)nLabelLen },
        { CKA_SENSITIVE,   &bTrue,     sizeof(bTrue)       },
        { CKA_EXTRACTABLE, &bFalse,    sizeof(bFalse)      },
        { CKA_SIGN,        bAgreement ? &bFalse : &bTrue, sizeof(bTrue) },
        { CKA_DERIVE,      bAgreement ? &bTrue : &bFalse, sizeof(bTrue) },
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

/* Generate an ML-DSA key pair (FIPS 204).
 *
 * The shape is EdDSA's: one generation mechanism, a signature-only key, and
 * no padding anywhere. What differs is that the variant is not a curve in
 * CKA_EC_PARAMS but a parameter set in CKA_PARAMETER_SET, a PKCS#11 v3.2
 * attribute — so an older token will not merely refuse the mechanism, it
 * will not recognise the attribute either.
 *
 * Reachable only on a token that advertises both mechanisms. SoftHSM2 2.7.0
 * never does: it defines them in its header and implements neither. The
 * check is here rather than only in the advertisement path because
 * NCryptCreatePersistedKey takes an algorithm name from the caller, who is
 * free not to have asked what was supported. */
SECURITY_STATUS KSP_GenerateMlDsaKeyPair(KSP_KEY *pKey)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;
    CK_RV             rv;
    CK_MECHANISM      mech = { CKM_ML_DSA_KEY_PAIR_GEN, NULL, 0 };
    char              szLabel[MAX_KEY_LABEL_LEN];
    int               nLabelLen;
    CK_BBOOL          bTrue  = CK_TRUE;
    CK_BBOOL          bFalse = CK_FALSE;
    CK_OBJECT_CLASS   classPriv = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS   classPub  = CKO_PUBLIC_KEY;
    CK_KEY_TYPE       keyType   = CKK_ML_DSA;
    CK_ULONG          ulParamSet;

    ulParamSet = P11_MlDsaParameterSet(pKey->szAlgId);
    if (ulParamSet == 0)
        return NTE_BAD_ALGID;

    if (!P11_HasMechanism(CKM_ML_DSA_KEY_PAIR_GEN) ||
        !P11_HasMechanism(CKM_ML_DSA)) {
        LOG_ERROR("FinalizeKey - the token does not implement ML-DSA",
                  NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    nLabelLen = BuildScopedLabel(pKey, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;

    {
        CK_ATTRIBUTE aPubTemplate[] = {
            { CKA_CLASS,         &classPub,   sizeof(classPub)    },
            { CKA_KEY_TYPE,      &keyType,    sizeof(keyType)     },
            { CKA_TOKEN,         &bTrue,      sizeof(bTrue)       },
            { CKA_LABEL,         szLabel,     (CK_ULONG)nLabelLen },
            { CKA_PARAMETER_SET, &ulParamSet, sizeof(ulParamSet)  },
            { CKA_VERIFY,        &bTrue,      sizeof(bTrue)       },
        };

        CK_ATTRIBUTE aPrivTemplate[] = {
            { CKA_CLASS,         &classPriv,  sizeof(classPriv)   },
            { CKA_KEY_TYPE,      &keyType,    sizeof(keyType)     },
            { CKA_TOKEN,         &bTrue,      sizeof(bTrue)       },
            { CKA_LABEL,         szLabel,     (CK_ULONG)nLabelLen },
            { CKA_PARAMETER_SET, &ulParamSet, sizeof(ulParamSet)  },
            { CKA_SENSITIVE,     &bTrue,      sizeof(bTrue)       },
            { CKA_EXTRACTABLE,   &bFalse,     sizeof(bFalse)      },
            { CKA_SIGN,          &bTrue,      sizeof(bTrue)       },
        };

        ss = P11_AcquireSession(&hSession);
        if (ss != ERROR_SUCCESS)
            return ss;

        rv = pCtx->pFunctionList->C_GenerateKeyPair(
            hSession, &mech,
            aPubTemplate,
            (CK_ULONG)(sizeof(aPubTemplate)  / sizeof(CK_ATTRIBUTE)),
            aPrivTemplate,
            (CK_ULONG)(sizeof(aPrivTemplate) / sizeof(CK_ATTRIBUTE)),
            &pKey->hPubKey, &pKey->hPrivKey);

        P11_ReleaseSession(hSession);
    }

    if (rv != CKR_OK) {
        LOG_ERROR("C_GenerateKeyPair ML-DSA", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    LOG_INFO("ML-DSA generated: alg=%ls paramset=%lu priv=0x%lX pub=0x%lX",
             pKey->szAlgId, (unsigned long)ulParamSet,
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
    BOOL              bAes  = (_wcsicmp(pKey->szAlgId, ALG_AES) == 0);
    /* AES-CMAC needs an AES key like bAes, but signs like an HMAC key.
     * The two questions are separate, so they are separate flags. */
    BOOL              bCmac = (_wcsicmp(pKey->szAlgId,
                                        BCRYPT_AES_CMAC_ALGORITHM) == 0);

    nLabelLen = BuildScopedLabel(pKey, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;

    memset(&mech, 0, sizeof(mech));

    if (bAes || bCmac) {
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
        /* AES keys encrypt/decrypt; HMAC and CMAC keys sign/verify. A CMAC
         * key marked for encryption would let the same key be used as a
         * cipher key, which is exactly the key reuse CMAC assumes away.
         *
         * AES keys are also marked for wrapping, because CNG has no
         * separate notion of a key-encryption key: whatever the caller
         * passes as hExportKey is used as one. Without CKA_WRAP a
         * conformant token refuses with CKR_KEY_FUNCTION_NOT_PERMITTED —
         * Kryoptic does, SoftHSM2 does not — which made the whole of
         * AES-09 non-functional on any token that enforces usage flags.
         *
         * The capability is narrower than it looks: a wrapping key can only
         * extract a key the token marks CKA_EXTRACTABLE, and this provider
         * never creates one. It reaches only keys that arrived from
         * elsewhere already extractable, which is exactly the migration
         * case key wrap exists for. MAC keys get no wrapping rights. */
        CK_BBOOL bCipher = bAes ? CK_TRUE : CK_FALSE;
        CK_BBOOL bMac    = bAes ? CK_FALSE : CK_TRUE;
        CK_BBOOL bWrap   = bAes ? CK_TRUE : CK_FALSE;

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
            { CKA_WRAP,        &bWrap,       sizeof(bWrap)       },
            { CKA_UNWRAP,      &bWrap,       sizeof(bWrap)       },
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

    BOOL bMachine = (dwFlags & NCRYPT_MACHINE_KEY_FLAG) != 0;

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

    hPriv = FindScopedObject(hSession, CKO_PRIVATE_KEY, pszKeyName, bMachine);
    if (hPriv == CK_INVALID_HANDLE) {
        /* No private key — this may be a symmetric (secret) key */
        CK_OBJECT_HANDLE hSecret =
            FindScopedObject(hSession, CKO_SECRET_KEY, pszKeyName, bMachine);

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
        pKey->bMachineKey = bMachine;
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

    hPub = FindScopedObject(hSession, CKO_PUBLIC_KEY, pszKeyName, bMachine);

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
    pKey->bMachineKey = bMachine;
    pKey->dwKeyClass = KSP_KEY_CLASS_ASYMMETRIC;
    pKey->dwKeySpec  = (dwLegacyKeySpec == AT_KEYEXCHANGE)
                       ? AT_KEYEXCHANGE : AT_SIGNATURE;

    wcscpy_s(pKey->szKeyName, MAX_KEY_LABEL_LEN, pszKeyName);

    if (ulKeyType == CKK_RSA) {
        wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_RSA);
        P11_GetUlongAttr(hSession, hPriv, CKA_MODULUS_BITS, &ulModBits);
        pKey->dwKeyBitLen = (DWORD)ulModBits;
    } else if (ulKeyType == CKK_EC || ulKeyType == CKK_EC_EDWARDS ||
               ulKeyType == CKK_EC_MONTGOMERY) {
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
        !KSP_IsSymmetricAlg(pszAlgId) &&
        !KSP_IsMlDsaAlg(pszAlgId)   &&
        !KSP_IsGenericEccAlg(pszAlgId)) {
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
    /* CNG keeps machine and user keys in separate stores; here the scope
     * becomes a CKA_LABEL prefix. See BuildScopedLabel. */
    pKey->bMachineKey = (dwFlags & NCRYPT_MACHINE_KEY_FLAG) != 0;
    /* A generic ECDSA/ECDH key has no curve until the caller sets one. */
    pKey->bCurvePending = KSP_IsGenericEccAlg(pszAlgId);
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

    pKey->dwKeyBitLen      = KSP_DefaultKeyBits(pszAlgId);
    pKey->dwPublicExponent = RSA_DEFAULT_PUBEXP;

    bPersistOnly = (dwFlags & NCRYPT_PERSIST_ONLY_FLAG) != 0;

    if (!bPersistOnly) {
        /* Generate immediately */
        ss = GenerateForAlg(pKey);

        if (ss != ERROR_SUCCESS) {
            /* The per-key PIN is the only secret this structure holds. */
    SecureZeroMemory(pKey->szKeyPin, sizeof(pKey->szKeyPin));
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

/* ── Certificate stored beside the key (NCRYPT_CERTIFICATE_PROPERTY) ──────
 *
 * Certificate enrolment is the flow this provider exists to serve, and it
 * has two halves: the CA signs a request with a key the KSP holds, then
 * hands back the issued certificate for the KSP to keep with that key. A
 * provider that cannot do the second half leaves the caller to store the
 * certificate somewhere else and re-associate it by hand.
 *
 * PKCS#11 already has the object type. The certificate is a CKO_CERTIFICATE
 * carrying the same scoped CKA_LABEL as the key, so the two travel together
 * through the same naming and the same machine/user scoping.
 *
 * CKA_SUBJECT is set, and the history of that is worth keeping. PKCS#11
 * marks it required for X.509 certificates. SoftHSM2 does not enforce it —
 * see the CKO_CERTIFICATE branch of SoftHSM.cpp's template check — so this
 * originally omitted it, with a comment saying a stricter token would
 * refuse and that writing a workaround blind was how this project had
 * accumulated code that only worked against its own assumptions.
 *
 * Kryoptic is that stricter token, and it answers CKR_TEMPLATE_INCONSISTENT.
 * The subject is now parsed out of the certificate by
 * P11_ExtractCertSubject. When that fails — a malformed certificate, or one
 * shaped in a way the walk does not expect — an empty Name is sent instead,
 * so a token that does not require the attribute still stores the object
 * and one that does still accepts it.
 */

/* Replace any certificate already stored under this key's label, then
 * create the new one. Without the destroy, a re-enrolment leaves two
 * certificate objects with the same label and lookups become a coin toss. */
SECURITY_STATUS KSP_StoreCertificate(KSP_KEY *pKey,
                                     const BYTE *pbCert, DWORD cbCert)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hExisting;
    CK_OBJECT_HANDLE  hCert = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;
    CK_RV             rv;
    char              szLabel[MAX_KEY_LABEL_LEN];
    int               nLabelLen;
    CK_BBOOL          bTrue  = CK_TRUE;
    CK_BBOOL          bFalse = CK_FALSE;
    CK_OBJECT_CLASS   classCert = CKO_CERTIFICATE;
    CK_ULONG          certType  = CKC_X_509;
    const BYTE       *pbSubject = NULL;
    DWORD             cbSubject = 0;
    /* An empty RDNSequence: SEQUENCE, length 0. Valid DER, and what is sent
     * when the certificate's own subject cannot be located. */
    static const BYTE abEmptyName[] = { 0x30, 0x00 };

    if (!pbCert || cbCert == 0)
        return NTE_INVALID_PARAMETER;

    if (!P11_ExtractCertSubject(pbCert, cbCert, &pbSubject, &cbSubject)) {
        LOG_INFO("KSP_StoreCertificate: could not locate the subject in a "
                 "%lu-byte certificate; storing an empty Name",
                 (unsigned long)cbCert);
        pbSubject = abEmptyName;
        cbSubject = (DWORD)sizeof(abEmptyName);
    }

    nLabelLen = BuildScopedLabel(pKey, szLabel, sizeof(szLabel));
    if (nLabelLen <= 0)
        return NTE_INVALID_PARAMETER;

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS)
        return ss;

    hExisting = FindScopedObject(hSession, CKO_CERTIFICATE,
                                 pKey->szKeyName, pKey->bMachineKey);
    if (hExisting != CK_INVALID_HANDLE)
        pCtx->pFunctionList->C_DestroyObject(hSession, hExisting);

    {
        CK_ATTRIBUTE aTemplate[] = {
            { CKA_CLASS,            &classCert,         sizeof(classCert)   },
            { CKA_CERTIFICATE_TYPE, &certType,          sizeof(certType)    },
            { CKA_TOKEN,            &bTrue,             sizeof(bTrue)       },
            { CKA_PRIVATE,          &bFalse,            sizeof(bFalse)      },
            { CKA_LABEL,            szLabel,            (CK_ULONG)nLabelLen },
            { CKA_SUBJECT,          (CK_VOID_PTR)pbSubject, (CK_ULONG)cbSubject },
            { CKA_VALUE,            (CK_VOID_PTR)pbCert, (CK_ULONG)cbCert   },
        };

        rv = pCtx->pFunctionList->C_CreateObject(
            hSession, aTemplate,
            (CK_ULONG)(sizeof(aTemplate) / sizeof(CK_ATTRIBUTE)), &hCert);
    }

    P11_ReleaseSession(hSession);

    if (rv != CKR_OK) {
        LOG_ERROR("KSP_StoreCertificate - C_CreateObject", P11RvToSecStatus(rv));
        return P11RvToSecStatus(rv);
    }

    LOG_INFO("Certificate stored for '%ls' (%lu bytes, obj=0x%lX)",
             pKey->szKeyName, (unsigned long)cbCert, (unsigned long)hCert);
    return ERROR_SUCCESS;
}

/* Read the certificate back. Follows the CNG two-call convention: a NULL
 * output buffer reports the size and returns success. */
SECURITY_STATUS KSP_LoadCertificate(KSP_KEY *pKey, PBYTE pbOutput,
                                    DWORD cbOutput, DWORD *pcbResult)
{
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hCert;
    SECURITY_STATUS   ss;
    CK_RV             rv;
    BYTE             *pbValue = NULL;
    DWORD             cbValue = 0;

    if (!pcbResult)
        return NTE_INVALID_PARAMETER;

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS)
        return ss;

    hCert = FindScopedObject(hSession, CKO_CERTIFICATE,
                             pKey->szKeyName, pKey->bMachineKey);
    if (hCert == CK_INVALID_HANDLE) {
        P11_ReleaseSession(hSession);
        /* No certificate is a normal state for a key that has been
         * generated but not yet enrolled, so it is NTE_NOT_FOUND rather
         * than an error about the property itself. */
        return NTE_NOT_FOUND;
    }

    rv = P11_GetBinaryAttr(hSession, hCert, CKA_VALUE, &pbValue, &cbValue);
    P11_ReleaseSession(hSession);

    if (rv != CKR_OK || !pbValue)
        return P11RvToSecStatus(rv);

    *pcbResult = cbValue;

    if (pbOutput) {
        if (cbOutput < cbValue) {
            KSP_Free(pbValue);
            return NTE_BUFFER_TOO_SMALL;
        }
        memcpy(pbOutput, pbValue, cbValue);
    }

    KSP_Free(pbValue);
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

    /* The certificate stored beside the key goes with it.
     *
     * Leaving it behind is not merely a storage leak. The certificate is
     * found by the key's scoped label, so the next key created with the
     * same name inherits a certificate belonging to a key that no longer
     * exists — and a caller reading NCRYPT_CERTIFICATE_PROPERTY would get
     * a certificate whose public key does not match the one it now holds.
     *
     * Found by the live-token suite: a second run of it read back a
     * certificate the previous run had left on the token. */
    {
        CK_OBJECT_HANDLE hCert = FindScopedObject(hSession, CKO_CERTIFICATE,
                                                  pKey->szKeyName,
                                                  pKey->bMachineKey);
        if (hCert != CK_INVALID_HANDLE) {
            rv = pCtx->pFunctionList->C_DestroyObject(hSession, hCert);
            if (rv != CKR_OK)
                LOG_ERROR("C_DestroyObject certificate",
                          P11RvToSecStatus(rv));
            else
                LOG_INFO("Certificate for '%ls' removed with the key",
                         pKey->szKeyName);
        }
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

        /* Report only keys in the scope the caller asked for, and report
         * them under the name the caller knows — without the prefix.
         *
         * A label with no prefix predates scoping. Those are shown in the
         * user scope, which is where an unflagged NCryptOpenKey will find
         * them, so enumeration and opening agree. */
        {
            const char *pszWanted = (dwFlags & NCRYPT_MACHINE_KEY_FLAG)
                                    ? KSP_SCOPE_PREFIX_MACHINE
                                    : KSP_SCOPE_PREFIX_USER;
            BOOL bHasPrefix =
                (strncmp(szLabel, KSP_SCOPE_PREFIX_MACHINE,
                         KSP_SCOPE_PREFIX_LEN) == 0) ||
                (strncmp(szLabel, KSP_SCOPE_PREFIX_USER,
                         KSP_SCOPE_PREFIX_LEN) == 0);

            if (bHasPrefix) {
                if (strncmp(szLabel, pszWanted, KSP_SCOPE_PREFIX_LEN) != 0) {
                    /* Another scope's key: skip it and let the caller ask
                     * again rather than returning it under a name that
                     * would not open. */
                    LOG_LEAVE("KSP_EnumKeys", ERROR_SUCCESS);
                    return KSP_EnumKeys(hProvider, pszScope, ppKeyName,
                                        ppEnumState, dwFlags);
                }
                memmove(szLabel, szLabel + KSP_SCOPE_PREFIX_LEN,
                        strlen(szLabel + KSP_SCOPE_PREFIX_LEN) + 1);
            } else if (dwFlags & NCRYPT_MACHINE_KEY_FLAG) {
                /* Legacy unprefixed key, and the caller wants machine
                 * scope: not a match. */
                LOG_LEAVE("KSP_EnumKeys", ERROR_SUCCESS);
                return KSP_EnumKeys(hProvider, pszScope, ppKeyName,
                                    ppEnumState, dwFlags);
            }
        }

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
