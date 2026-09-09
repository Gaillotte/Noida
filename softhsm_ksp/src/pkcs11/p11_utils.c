/* p11_utils.c — PKCS#11 utility implementation */
#include "p11_utils.h"
#include "p11_context.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/memory.h"
#include <string.h>
#include <wchar.h>

/* Convert CK_RV to SECURITY_STATUS */
SECURITY_STATUS P11RvToSecStatus(CK_RV rv)
{
    switch (rv) {
    case CKR_OK:                        return ERROR_SUCCESS;
    case CKR_HOST_MEMORY:               return NTE_NO_MEMORY;
    case CKR_ARGUMENTS_BAD:             return NTE_INVALID_PARAMETER;
    case CKR_BUFFER_TOO_SMALL:          return NTE_BUFFER_TOO_SMALL;
    case CKR_FUNCTION_NOT_SUPPORTED:    return NTE_NOT_SUPPORTED;
    case CKR_KEY_HANDLE_INVALID:        return NTE_BAD_KEY;
    case CKR_KEY_SIZE_RANGE:            return NTE_BAD_LEN;
    case CKR_KEY_TYPE_INCONSISTENT:     return NTE_BAD_ALGID;
    case CKR_MECHANISM_INVALID:         return NTE_BAD_ALGID;
    case CKR_MECHANISM_PARAM_INVALID:   return NTE_BAD_ALGID;
    case CKR_OBJECT_HANDLE_INVALID:     return NTE_BAD_KEY;
    case CKR_PIN_INCORRECT:             return NTE_BAD_KEYSET_PARAM;
    case CKR_PIN_LOCKED:                return NTE_BAD_KEYSET_PARAM;
    case CKR_SESSION_HANDLE_INVALID:    return NTE_FAIL;
    case CKR_SIGNATURE_INVALID:         return NTE_BAD_SIGNATURE;
    case CKR_SIGNATURE_LEN_RANGE:       return NTE_BAD_LEN;
    case CKR_TOKEN_NOT_PRESENT:         return NTE_NO_KEY;
    case CKR_USER_NOT_LOGGED_IN:        return NTE_BAD_KEYSET_PARAM;
    case CKR_KEY_UNEXTRACTABLE:         return NTE_NOT_SUPPORTED;
    case CKR_CRYPTOKI_NOT_INITIALIZED:  return NTE_FAIL;
    default:                            return NTE_FAIL;
    }
}

/* Resolve the PKCS#11 mechanism from algorithm identifier and CNG flags */
SECURITY_STATUS P11_ResolveMechanism(
    LPCWSTR          pszAlgId,
    DWORD            dwFlags,
    CK_MECHANISM    *pMechanism,
    CK_RSA_PKCS_PSS_PARAMS *pPssParams)
{
    if (!pszAlgId || !pMechanism)
        return NTE_INVALID_PARAMETER;

    memset(pMechanism, 0, sizeof(*pMechanism));

    if (_wcsicmp(pszAlgId, ALG_RSA) == 0) {
        if (dwFlags & NCRYPT_PAD_PSS_FLAG) {
            pMechanism->mechanism    = CKM_RSA_PKCS_PSS;
            if (pPssParams) {
                /* Default PSS parameters (SHA-256, MGF1-SHA256, salt=32) */
                pPssParams->hashAlg = CKM_SHA256;
                pPssParams->mgf     = CKG_MGF1_SHA256;
                pPssParams->sLen    = 32;
                pMechanism->pParameter    = pPssParams;
                pMechanism->ulParameterLen = sizeof(*pPssParams);
            }
        } else {
            /* PKCS1 v1.5 by default */
            pMechanism->mechanism = CKM_RSA_PKCS;
        }
        return ERROR_SUCCESS;
    }

    if (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDSA_P521) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDSA_SECP256K1) == 0) {
        pMechanism->mechanism = CKM_ECDSA;
        return ERROR_SUCCESS;
    }

    /* EdDSA: deterministic, no padding, no external parameters */
    if (_wcsicmp(pszAlgId, ALG_EDDSA_ED25519) == 0 ||
        _wcsicmp(pszAlgId, ALG_EDDSA_ED448)   == 0) {
        pMechanism->mechanism = CKM_EDDSA;
        return ERROR_SUCCESS;
    }

    /* HMAC secret keys sign through C_Sign with the matching HMAC mechanism */
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA1) == 0) {
        pMechanism->mechanism = CKM_SHA_1_HMAC;
        return ERROR_SUCCESS;
    }
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA224) == 0) {
        pMechanism->mechanism = CKM_SHA224_HMAC;
        return ERROR_SUCCESS;
    }
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA256) == 0) {
        pMechanism->mechanism = CKM_SHA256_HMAC;
        return ERROR_SUCCESS;
    }
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA384) == 0) {
        pMechanism->mechanism = CKM_SHA384_HMAC;
        return ERROR_SUCCESS;
    }
    if (_wcsicmp(pszAlgId, ALG_HMAC_SHA512) == 0) {
        pMechanism->mechanism = CKM_SHA512_HMAC;
        return ERROR_SUCCESS;
    }

    return NTE_BAD_ALGID;
}

/* Map a CNG hash name to PKCS#11 digest mechanism + MGF1 identifier */
SECURITY_STATUS P11_MapHashAlg(
    LPCWSTR            pszHashAlg,
    CK_MECHANISM_TYPE *pHashMech,
    CK_ULONG          *pMgf)
{
    if (!pszHashAlg || !pHashMech || !pMgf)
        return NTE_INVALID_PARAMETER;

    if (_wcsicmp(pszHashAlg, BCRYPT_SHA1_ALGORITHM) == 0) {
        *pHashMech = CKM_SHA_1;   *pMgf = CKG_MGF1_SHA1;   return ERROR_SUCCESS;
    }
    if (_wcsicmp(pszHashAlg, BCRYPT_SHA224_ALGORITHM) == 0) {
        *pHashMech = CKM_SHA224;  *pMgf = CKG_MGF1_SHA224; return ERROR_SUCCESS;
    }
    if (_wcsicmp(pszHashAlg, BCRYPT_SHA256_ALGORITHM) == 0) {
        *pHashMech = CKM_SHA256;  *pMgf = CKG_MGF1_SHA256; return ERROR_SUCCESS;
    }
    if (_wcsicmp(pszHashAlg, BCRYPT_SHA384_ALGORITHM) == 0) {
        *pHashMech = CKM_SHA384;  *pMgf = CKG_MGF1_SHA384; return ERROR_SUCCESS;
    }
    if (_wcsicmp(pszHashAlg, BCRYPT_SHA512_ALGORITHM) == 0) {
        *pHashMech = CKM_SHA512;  *pMgf = CKG_MGF1_SHA512; return ERROR_SUCCESS;
    }

    return NTE_NOT_SUPPORTED;
}

/* Populate CK_RSA_PKCS_OAEP_PARAMS from a BCRYPT_OAEP_PADDING_INFO.
 * Defaults to SHA-1 when no padding info is supplied (CNG legacy behaviour). */
SECURITY_STATUS P11_BuildOaepParams(
    BCRYPT_OAEP_PADDING_INFO *pOaepInfo,
    CK_RSA_PKCS_OAEP_PARAMS  *pParams)
{
    SECURITY_STATUS ss;

    if (!pParams)
        return NTE_INVALID_PARAMETER;

    memset(pParams, 0, sizeof(*pParams));

    if (!pOaepInfo || !pOaepInfo->pszAlgId) {
        /* No padding info → SHA-1, the CNG default for OAEP */
        pParams->hashAlg = CKM_SHA_1;
        pParams->mgf     = CKG_MGF1_SHA1;
    } else {
        ss = P11_MapHashAlg(pOaepInfo->pszAlgId,
                            &pParams->hashAlg, &pParams->mgf);
        if (ss != ERROR_SUCCESS)
            return ss;
    }

    pParams->source = CKZ_DATA_SPECIFIED;

    /* An OAEP label is optional; pass it through when present */
    if (pOaepInfo && pOaepInfo->pbLabel && pOaepInfo->cbLabel > 0) {
        pParams->pSourceData     = pOaepInfo->pbLabel;
        pParams->ulSourceDataLen = pOaepInfo->cbLabel;
    } else {
        pParams->pSourceData     = NULL;
        pParams->ulSourceDataLen = 0;
    }

    return ERROR_SUCCESS;
}

/* Search for an object by label and class */
CK_OBJECT_HANDLE P11_FindObjectByLabel(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_CLASS   ulClass,
    LPCWSTR           pszLabel)
{
    P11_CONTEXT *pCtx = P11_GetContext();
    CK_RV        rv;
    CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
    CK_ULONG     ulCount = 0;

    /* Convert the wide label to UTF-8 */
    char szLabel[MAX_KEY_LABEL_LEN];
    int  nLabelLen;
    CK_ATTRIBUTE aTemplate[2];

    if (!pszLabel)
        return CK_INVALID_HANDLE;

    nLabelLen = WideCharToMultiByte(CP_UTF8, 0, pszLabel, -1,
                                    szLabel, sizeof(szLabel), NULL, NULL);
    if (nLabelLen <= 0)
        return CK_INVALID_HANDLE;
    nLabelLen--; /* Remove null terminator from the count */

    aTemplate[0].type       = CKA_CLASS;
    aTemplate[0].pValue     = &ulClass;
    aTemplate[0].ulValueLen = sizeof(ulClass);
    aTemplate[1].type       = CKA_LABEL;
    aTemplate[1].pValue     = szLabel;
    aTemplate[1].ulValueLen = (CK_ULONG)nLabelLen;

    rv = pCtx->pFunctionList->C_FindObjectsInit(hSession, aTemplate, 2);
    if (rv != CKR_OK) {
        LOG_ERROR("C_FindObjectsInit", P11RvToSecStatus(rv));
        return CK_INVALID_HANDLE;
    }

    rv = pCtx->pFunctionList->C_FindObjects(hSession, &hObject, 1, &ulCount);
    pCtx->pFunctionList->C_FindObjectsFinal(hSession);

    if (rv != CKR_OK || ulCount == 0)
        return CK_INVALID_HANDLE;

    return hObject;
}

/* Read a CK_ULONG attribute */
CK_RV P11_GetUlongAttr(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE  hObject,
    CK_ATTRIBUTE_TYPE attrType,
    CK_ULONG         *pulValue)
{
    P11_CONTEXT *pCtx = P11_GetContext();
    CK_ATTRIBUTE attr;
    CK_RV rv;

    attr.type       = attrType;
    attr.pValue     = pulValue;
    attr.ulValueLen = sizeof(CK_ULONG);

    rv = pCtx->pFunctionList->C_GetAttributeValue(hSession, hObject, &attr, 1);
    return rv;
}

/* Read a binary attribute and allocate the buffer */
CK_RV P11_GetBinaryAttr(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hObject,
    CK_ATTRIBUTE_TYPE  attrType,
    BYTE             **ppData,
    DWORD             *pcbData)
{
    P11_CONTEXT *pCtx = P11_GetContext();
    CK_ATTRIBUTE attr;
    CK_RV rv;

    /* First call to obtain the size */
    attr.type       = attrType;
    attr.pValue     = NULL;
    attr.ulValueLen = 0;

    rv = pCtx->pFunctionList->C_GetAttributeValue(hSession, hObject, &attr, 1);
    if (rv != CKR_OK)
        return rv;

    *ppData  = (BYTE *)KSP_Alloc(attr.ulValueLen);
    *pcbData = (DWORD)attr.ulValueLen;

    if (!*ppData)
        return CKR_HOST_MEMORY;

    attr.pValue = *ppData;
    rv = pCtx->pFunctionList->C_GetAttributeValue(hSession, hObject, &attr, 1);
    if (rv != CKR_OK) {
        KSP_Free(*ppData);
        *ppData  = NULL;
        *pcbData = 0;
    }

    return rv;
}

/* Export an RSA public key as a BCRYPT_RSAKEY_BLOB */
SECURITY_STATUS P11_ExportRsaPublicKey(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hPubKey,
    BYTE             **ppBlob,
    DWORD             *pcbBlob)
{
    BYTE  *pbModulus   = NULL;
    DWORD  cbModulus   = 0;
    BYTE  *pbExponent  = NULL;
    DWORD  cbExponent  = 0;
    DWORD  cbBlob;
    BCRYPT_RSAKEY_BLOB *pRsaBlob;
    BYTE  *pbCur;

    if (P11_GetBinaryAttr(hSession, hPubKey, CKA_MODULUS,
                          &pbModulus, &cbModulus) != CKR_OK)
        return NTE_BAD_KEY;

    if (P11_GetBinaryAttr(hSession, hPubKey, CKA_PUBLIC_EXPONENT,
                          &pbExponent, &cbExponent) != CKR_OK) {
        KSP_Free(pbModulus);
        return NTE_BAD_KEY;
    }

    cbBlob  = sizeof(BCRYPT_RSAKEY_BLOB) + cbExponent + cbModulus;
    *ppBlob = (BYTE *)KSP_AllocZero(cbBlob);
    if (!*ppBlob) {
        KSP_Free(pbModulus);
        KSP_Free(pbExponent);
        return NTE_NO_MEMORY;
    }

    pRsaBlob = (BCRYPT_RSAKEY_BLOB *)*ppBlob;
    pRsaBlob->Magic       = BCRYPT_RSAPUBLIC_MAGIC;
    pRsaBlob->BitLength   = cbModulus * 8;
    pRsaBlob->cbPublicExp = cbExponent;
    pRsaBlob->cbModulus   = cbModulus;
    pRsaBlob->cbPrime1    = 0;
    pRsaBlob->cbPrime2    = 0;

    pbCur = *ppBlob + sizeof(BCRYPT_RSAKEY_BLOB);
    memcpy(pbCur, pbExponent, cbExponent); pbCur += cbExponent;
    memcpy(pbCur, pbModulus,  cbModulus);

    *pcbBlob = cbBlob;

    KSP_Free(pbModulus);
    KSP_Free(pbExponent);
    return ERROR_SUCCESS;
}

/* Export an EC public key as a BCRYPT_ECCKEY_BLOB */
SECURITY_STATUS P11_ExportEcPublicKey(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hPubKey,
    BYTE             **ppBlob,
    DWORD             *pcbBlob)
{
    BYTE  *pbEcPoint  = NULL;
    DWORD  cbEcPoint  = 0;
    DWORD  cbCoord;
    DWORD  cbBlob;
    BCRYPT_ECCKEY_BLOB *pEccBlob;

    /* Read CKA_EC_POINT (ANSI X9.62 format: 0x04 || Qx || Qy) */
    if (P11_GetBinaryAttr(hSession, hPubKey, CKA_EC_POINT,
                          &pbEcPoint, &cbEcPoint) != CKR_OK)
        return NTE_BAD_KEY;

    /* The point is DER OCTET STRING encoded: skip the first 2 bytes */
    /* Expected format: TAG(04) LEN 04 Qx Qy */
    if (cbEcPoint < 3 || pbEcPoint[0] != 0x04) {
        KSP_Free(pbEcPoint);
        return NTE_BAD_KEY;
    }

    /* Find the 0x04 uncompressed point marker */
    {
        BYTE *pbPoint = pbEcPoint;
        DWORD cbRemain = cbEcPoint;

        /* Skip the DER OCTET STRING wrapper. P-256/P-384 points use a
         * short-form length; a P-521 point is 133 bytes and uses the
         * long form (0x81 LEN), so the header is one byte longer. */
        if (pbPoint[0] == 0x04 && cbRemain > 2) {
            if (pbPoint[1] == 0x81 && cbRemain > 3) {
                pbPoint  += 3;
                cbRemain -= 3;
            } else if (pbPoint[1] < 128) {
                pbPoint  += 2;
                cbRemain -= 2;
            }
        }

        if (cbRemain < 1 || pbPoint[0] != 0x04) {
            KSP_Free(pbEcPoint);
            return NTE_BAD_KEY;
        }

        cbCoord = (cbRemain - 1) / 2;
        cbBlob  = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cbCoord;

        *ppBlob = (BYTE *)KSP_AllocZero(cbBlob);
        if (!*ppBlob) {
            KSP_Free(pbEcPoint);
            return NTE_NO_MEMORY;
        }

        pEccBlob = (BCRYPT_ECCKEY_BLOB *)*ppBlob;
        if (cbCoord == EC_P256_COORD_SIZE)
            pEccBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        else if (cbCoord == EC_P521_COORD_SIZE)
            pEccBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
        else
            pEccBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
        pEccBlob->cbKey   = cbCoord;

        memcpy(*ppBlob + sizeof(BCRYPT_ECCKEY_BLOB), pbPoint + 1, 2 * cbCoord);
    }

    *pcbBlob = cbBlob;
    KSP_Free(pbEcPoint);
    return ERROR_SUCCESS;
}

/* Return the EC coordinate size in bytes (ECDSA and ECDH curves) */
DWORD P11_EcCoordSize(LPCWSTR pszAlgId)
{
    if (!pszAlgId)
        return 0;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P256)  == 0)
        return EC_P256_COORD_SIZE;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P384)  == 0)
        return EC_P384_COORD_SIZE;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P521) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P521)  == 0)
        return EC_P521_COORD_SIZE;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_SECP256K1) == 0)
        return EC_SECP256K1_COORD_SIZE;
    return 0;
}

/* Map an EC / EdDSA algorithm name to its DER-encoded curve OID */
const char *P11_GetCurveOid(LPCWSTR pszAlgId, CK_ULONG *pcbOid)
{
    if (!pszAlgId || !pcbOid)
        return NULL;

    if (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P256)  == 0) {
        *pcbOid = EC_OID_P256_LEN;  return EC_OID_P256;
    }
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P384)  == 0) {
        *pcbOid = EC_OID_P384_LEN;  return EC_OID_P384;
    }
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P521) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P521)  == 0) {
        *pcbOid = EC_OID_P521_LEN;  return EC_OID_P521;
    }
    if (_wcsicmp(pszAlgId, ALG_ECDSA_SECP256K1) == 0) {
        *pcbOid = EC_OID_SECP256K1_LEN; return EC_OID_SECP256K1;
    }
    if (_wcsicmp(pszAlgId, ALG_EDDSA_ED25519) == 0) {
        *pcbOid = EC_OID_ED25519_LEN; return EC_OID_ED25519;
    }
    if (_wcsicmp(pszAlgId, ALG_EDDSA_ED448) == 0) {
        *pcbOid = EC_OID_ED448_LEN;   return EC_OID_ED448;
    }
    return NULL;
}

/* Build CKA_EC_POINT (DER OCTET STRING wrapping 0x04 || X || Y).
 * Uses short-form DER length for points below 128 bytes and long-form
 * (0x81 LEN) above — a P-521 point is 133 bytes and needs long form. */
SECURITY_STATUS P11_BuildEcPointDer(
    const BYTE *pbX,
    const BYTE *pbY,
    DWORD       cbCoord,
    BYTE      **ppDer,
    DWORD      *pcbDer)
{
    DWORD cbPoint;   /* 0x04 || X || Y */
    DWORD cbHeader;
    BYTE *pb;

    if (!pbX || !pbY || !ppDer || !pcbDer || cbCoord == 0)
        return NTE_INVALID_PARAMETER;

    cbPoint  = 1 + 2 * cbCoord;
    cbHeader = (cbPoint < 128) ? 2 : 3;

    *ppDer = (BYTE *)KSP_Alloc(cbHeader + cbPoint);
    if (!*ppDer)
        return NTE_NO_MEMORY;

    pb = *ppDer;
    *pb++ = 0x04;                       /* OCTET STRING tag */
    if (cbPoint < 128) {
        *pb++ = (BYTE)cbPoint;          /* short-form length */
    } else {
        *pb++ = 0x81;                   /* long form, 1 length byte */
        *pb++ = (BYTE)cbPoint;
    }
    *pb++ = 0x04;                       /* uncompressed point marker */
    memcpy(pb, pbX, cbCoord); pb += cbCoord;
    memcpy(pb, pbY, cbCoord);

    *pcbDer = cbHeader + cbPoint;
    return ERROR_SUCCESS;
}

/* Export an Edwards-curve public key as a BCRYPT_ECCKEY_BLOB.
 * EdDSA public keys are a single compressed point, so the blob carries
 * the raw key bytes directly after the header. */
SECURITY_STATUS P11_ExportEddsaPublicKey(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hPubKey,
    LPCWSTR            pszAlgId,
    BYTE             **ppBlob,
    DWORD             *pcbBlob)
{
    BYTE  *pbEcPoint = NULL;
    DWORD  cbEcPoint = 0;
    BYTE  *pbRaw;
    DWORD  cbRaw;
    DWORD  cbExpected;
    DWORD  cbBlob;
    BCRYPT_ECCKEY_BLOB *pEccBlob;

    if (!pszAlgId || !ppBlob || !pcbBlob)
        return NTE_INVALID_PARAMETER;

    cbExpected = (_wcsicmp(pszAlgId, ALG_EDDSA_ED25519) == 0)
                 ? ED25519_PUBKEY_SIZE : ED448_PUBKEY_SIZE;

    if (P11_GetBinaryAttr(hSession, hPubKey, CKA_EC_POINT,
                          &pbEcPoint, &cbEcPoint) != CKR_OK)
        return NTE_BAD_KEY;

    /* CKA_EC_POINT is DER OCTET STRING wrapped; unwrap to the raw point */
    pbRaw = pbEcPoint;
    cbRaw = cbEcPoint;

    if (cbRaw >= 2 && pbRaw[0] == 0x04) {
        if (pbRaw[1] == 0x81 && cbRaw >= 3) {
            pbRaw += 3; cbRaw -= 3;     /* long-form length */
        } else if (pbRaw[1] < 128) {
            pbRaw += 2; cbRaw -= 2;     /* short-form length */
        }
    }

    if (cbRaw != cbExpected) {
        KSP_Free(pbEcPoint);
        return NTE_BAD_KEY;
    }

    cbBlob  = sizeof(BCRYPT_ECCKEY_BLOB) + cbRaw;
    *ppBlob = (BYTE *)KSP_AllocZero(cbBlob);
    if (!*ppBlob) {
        KSP_Free(pbEcPoint);
        return NTE_NO_MEMORY;
    }

    pEccBlob = (BCRYPT_ECCKEY_BLOB *)*ppBlob;
    pEccBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC;
    pEccBlob->cbKey   = cbRaw;

    memcpy(*ppBlob + sizeof(BCRYPT_ECCKEY_BLOB), pbRaw, cbRaw);

    *pcbBlob = cbBlob;
    KSP_Free(pbEcPoint);
    return ERROR_SUCCESS;
}

/* Decode a DER ECDSA signature into Windows r||s format */
SECURITY_STATUS P11_DecodeDerEcdsaSignature(
    LPCWSTR  pszAlgId,
    BYTE    *pbDer,
    DWORD    cbDer,
    BYTE    *pbOut,
    DWORD   *pcbOut)
{
    DWORD  cbCoord = P11_EcCoordSize(pszAlgId);
    DWORD  cbSig   = cbCoord * 2;
    BYTE  *p       = pbDer;
    BYTE  *pEnd    = pbDer + cbDer;
    DWORD  cbInt;
    BYTE  *pbInt;

    if (cbCoord == 0)
        return NTE_BAD_ALGID;

    /* Size-only query */
    if (!pbOut) {
        *pcbOut = cbSig;
        return ERROR_SUCCESS;
    }

    if (*pcbOut < cbSig)
        return NTE_BUFFER_TOO_SMALL;

    memset(pbOut, 0, cbSig);

    /* Decode SEQUENCE */
    if (p >= pEnd || *p != 0x30) return NTE_INVALID_PARAMETER; p++;
    if (p >= pEnd) return NTE_INVALID_PARAMETER;
    /* Skip the sequence length */
    if (*p & 0x80) {
        DWORD nLenBytes = *p & 0x7F; p++;
        if (nLenBytes > (DWORD)(pEnd - p)) return NTE_INVALID_PARAMETER;
        p += nLenBytes;
    } else {
        p++;
    }

    /* Decode INTEGER r */
    if (p >= pEnd || *p != 0x02) return NTE_INVALID_PARAMETER; p++;
    if (p >= pEnd) return NTE_INVALID_PARAMETER;
    cbInt = *p++;
    if (cbInt > (DWORD)(pEnd - p)) return NTE_INVALID_PARAMETER;
    pbInt = p; p += cbInt;

    /* Strip the 0x00 sign byte if present */
    if (cbInt > 0 && *pbInt == 0x00) { pbInt++; cbInt--; }
    if (cbInt > cbCoord) return NTE_INVALID_PARAMETER;
    memcpy(pbOut + cbCoord - cbInt, pbInt, cbInt);

    /* Decode INTEGER s */
    if (p >= pEnd || *p != 0x02) return NTE_INVALID_PARAMETER; p++;
    if (p >= pEnd) return NTE_INVALID_PARAMETER;
    cbInt = *p++;
    if (cbInt > (DWORD)(pEnd - p)) return NTE_INVALID_PARAMETER;
    pbInt = p;

    if (cbInt > 0 && *pbInt == 0x00) { pbInt++; cbInt--; }
    if (cbInt > cbCoord) return NTE_INVALID_PARAMETER;
    memcpy(pbOut + cbCoord + cbCoord - cbInt, pbInt, cbInt);

    *pcbOut = cbSig;
    return ERROR_SUCCESS;
}
