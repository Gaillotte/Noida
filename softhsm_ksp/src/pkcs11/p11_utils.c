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
        _wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0) {
        pMechanism->mechanism = CKM_ECDSA;
        return ERROR_SUCCESS;
    }

    return NTE_BAD_ALGID;
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
    P11_CONTEXT *pCtx = P11_GetContext();

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

        /* Skip DER OCTET STRING wrapper (PKCS#11 CKA_EC_POINT is always DER-encoded) */
        if (pbPoint[0] == 0x04 && cbRemain > 2) {
            pbPoint  += 2;
            cbRemain -= 2;
        }

        if (pbPoint[0] != 0x04) {
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
        pEccBlob->dwMagic = (cbCoord == EC_P256_COORD_SIZE)
                          ? BCRYPT_ECDSA_PUBLIC_P256_MAGIC
                          : BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
        pEccBlob->cbKey   = cbCoord;

        memcpy(*ppBlob + sizeof(BCRYPT_ECCKEY_BLOB), pbPoint + 1, 2 * cbCoord);
    }

    *pcbBlob = cbBlob;
    KSP_Free(pbEcPoint);
    return ERROR_SUCCESS;
}

/* Return the EC coordinate size in bytes */
DWORD P11_EcCoordSize(LPCWSTR pszAlgId)
{
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0)
        return EC_P256_COORD_SIZE;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0)
        return EC_P384_COORD_SIZE;
    return 0;
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
        p += nLenBytes;
    } else {
        p++;
    }

    /* Decode INTEGER r */
    if (p >= pEnd || *p != 0x02) return NTE_INVALID_PARAMETER; p++;
    if (p >= pEnd) return NTE_INVALID_PARAMETER;
    cbInt = *p++; pbInt = p; p += cbInt;

    /* Strip the 0x00 sign byte if present */
    if (cbInt > 0 && *pbInt == 0x00) { pbInt++; cbInt--; }
    if (cbInt > cbCoord) return NTE_INVALID_PARAMETER;
    memcpy(pbOut + cbCoord - cbInt, pbInt, cbInt);

    /* Decode INTEGER s */
    if (p >= pEnd || *p != 0x02) return NTE_INVALID_PARAMETER; p++;
    if (p >= pEnd) return NTE_INVALID_PARAMETER;
    cbInt = *p++; pbInt = p;

    if (cbInt > 0 && *pbInt == 0x00) { pbInt++; cbInt--; }
    if (cbInt > cbCoord) return NTE_INVALID_PARAMETER;
    memcpy(pbOut + cbCoord + cbCoord - cbInt, pbInt, cbInt);

    *pcbOut = cbSig;
    return ERROR_SUCCESS;
}
