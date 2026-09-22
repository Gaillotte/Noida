/* ksp_crypto.c — Cryptographic operation implementation */
#include "ksp_crypto.h"
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

/* Fill PSS parameters from BCRYPT_PSS_PADDING_INFO */
static void FillPssParams(
    BCRYPT_PSS_PADDING_INFO *pPssInfo,
    CK_RSA_PKCS_PSS_PARAMS  *pPssParams)
{
    if (!pPssInfo || !pPssParams) {
        pPssParams->hashAlg = CKM_SHA256;
        pPssParams->mgf     = CKG_MGF1_SHA256;
        pPssParams->sLen    = 32;
        return;
    }

    pPssParams->sLen = pPssInfo->cbSalt;

    if (_wcsicmp(pPssInfo->pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0) {
        pPssParams->hashAlg = CKM_SHA_1;
        pPssParams->mgf     = CKG_MGF1_SHA1;
    } else if (_wcsicmp(pPssInfo->pszAlgId, KSP_SHA224_ALGORITHM) == 0) {
        pPssParams->hashAlg = CKM_SHA224;
        pPssParams->mgf     = CKG_MGF1_SHA224;
    } else if (_wcsicmp(pPssInfo->pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0) {
        pPssParams->hashAlg = CKM_SHA384;
        pPssParams->mgf     = CKG_MGF1_SHA384;
    } else if (_wcsicmp(pPssInfo->pszAlgId, BCRYPT_SHA512_ALGORITHM) == 0) {
        pPssParams->hashAlg = CKM_SHA512;
        pPssParams->mgf     = CKG_MGF1_SHA512;
    } else {
        /* SHA-256 by default */
        pPssParams->hashAlg = CKM_SHA256;
        pPssParams->mgf     = CKG_MGF1_SHA256;
        if (pPssParams->sLen == 0)
            pPssParams->sLen = 32;
    }
}

/* Build the PKCS#11 mechanism for an AES operation.
 *
 * Follows the CNG symmetric contract: the chaining mode is a key property
 * (NCRYPT_CHAINING_MODE_PROPERTY) and the IV / nonce is supplied through
 * NCRYPT_INITIALIZATION_VECTOR, both set before the operation. Mapping:
 *   ChainingModeECB → CKM_AES_ECB      (no IV)
 *   ChainingModeCBC → CKM_AES_CBC      (16-byte IV), CBC_PAD when padding asked
 *   ChainingModeGCM → CKM_AES_GCM      (12-byte nonce, 128-bit tag)
 *   ChainingModeCTR → CKM_AES_CTR      (16-byte counter block, KSP extension)
 */
static SECURITY_STATUS KspBuildAesMechanism(
    KSP_KEY           *pKey,
    DWORD              dwFlags,
    CK_MECHANISM      *pMech,
    CK_GCM_PARAMS     *pGcm,
    CK_AES_CTR_PARAMS *pCtr)
{
    if (!pKey || !pMech || !pGcm || !pCtr)
        return NTE_INVALID_PARAMETER;

    /* Only AES is a block cipher here; HMAC keys never reach this path */
    if (_wcsicmp(pKey->szAlgId, ALG_AES) != 0)
        return NTE_BAD_ALGID;

    memset(pMech, 0, sizeof(*pMech));

    /* ECB — no IV required */
    if (_wcsicmp(pKey->szChainingMode, BCRYPT_CHAIN_MODE_ECB) == 0) {
        pMech->mechanism = CKM_AES_ECB;
        return ERROR_SUCCESS;
    }

    /* GCM — authenticated mode, nonce is typically 12 bytes */
    if (_wcsicmp(pKey->szChainingMode, BCRYPT_CHAIN_MODE_GCM) == 0) {
        if (pKey->cbIV == 0)
            return NTE_INVALID_PARAMETER;

        memset(pGcm, 0, sizeof(*pGcm));
        pGcm->pIv       = pKey->pbIV;
        pGcm->ulIvLen   = pKey->cbIV;
        pGcm->ulIvBits  = pKey->cbIV * 8;
        pGcm->pAAD      = pKey->cbAuthData ? pKey->pbAuthData : NULL;
        pGcm->ulAADLen  = pKey->cbAuthData;
        pGcm->ulTagBits = AES_GCM_TAG_BITS;

        pMech->mechanism      = CKM_AES_GCM;
        pMech->pParameter     = pGcm;
        pMech->ulParameterLen = sizeof(*pGcm);
        return ERROR_SUCCESS;
    }

    /* CTR — counter block is a full AES block */
    if (_wcsicmp(pKey->szChainingMode, KSP_CHAIN_MODE_CTR) == 0) {
        if (pKey->cbIV != AES_BLOCK_SIZE)
            return NTE_INVALID_PARAMETER;

        memset(pCtr, 0, sizeof(*pCtr));
        pCtr->ulCounterBits = 32;   /* Low 32 bits form the counter */
        memcpy(pCtr->cb, pKey->pbIV, AES_BLOCK_SIZE);

        pMech->mechanism      = CKM_AES_CTR;
        pMech->pParameter     = pCtr;
        pMech->ulParameterLen = sizeof(*pCtr);
        return ERROR_SUCCESS;
    }

    /* CBC (the default when no chaining mode was set) */
    if (pKey->cbIV != AES_BLOCK_SIZE)
        return NTE_INVALID_PARAMETER;

    pMech->mechanism      = (dwFlags & NCRYPT_PAD_CIPHER_FLAG)
                            ? CKM_AES_CBC_PAD : CKM_AES_CBC;
    pMech->pParameter     = pKey->pbIV;
    pMech->ulParameterLen = pKey->cbIV;
    return ERROR_SUCCESS;
}

/* Sign a hash — implements the CNG double-call pattern */
SECURITY_STATUS WINAPI KSP_SignHash(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    VOID              *pPaddingInfo,
    PBYTE              pbHashValue,
    DWORD              cbHashValue,
    PBYTE              pbSignature,
    DWORD              cbSignature,
    DWORD             *pcbResult,
    DWORD              dwFlags)
{
    P11_CONTEXT          *pCtx = P11_GetContext();
    KSP_KEY              *pKey;
    CK_SESSION_HANDLE     hSession = CK_INVALID_HANDLE;
    CK_MECHANISM          mech;
    CK_RSA_PKCS_PSS_PARAMS pssParams;
    CK_RV                 rv;
    SECURITY_STATUS       ss;
    BYTE                 *pbRawSig  = NULL;
    CK_ULONG              cbRawSig  = 0;
    BOOL                  bEcdsa;

    LOG_ENTER("KSP_SignHash");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pbHashValue || !pcbResult) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    if (!pKey->bFinalized || pKey->hPrivKey == CK_INVALID_HANDLE) {
        LOG_LEAVE("KSP_SignHash", NTE_INVALID_HANDLE);
        return NTE_INVALID_HANDLE;
    }

    memset(&pssParams, 0, sizeof(pssParams));
    ss = P11_ResolveMechanism(pKey->szAlgId, dwFlags, &mech, &pssParams);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    /* For PSS, update parameters from BCRYPT_PSS_PADDING_INFO */
    if (mech.mechanism == CKM_RSA_PKCS_PSS && pPaddingInfo) {
        FillPssParams((BCRYPT_PSS_PADDING_INFO *)pPaddingInfo, &pssParams);
        mech.pParameter     = &pssParams;
        mech.ulParameterLen = sizeof(pssParams);
    }

    bEcdsa = (mech.mechanism == CKM_ECDSA);

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    rv = pCtx->pFunctionList->C_SignInit(hSession, &mech, pKey->hPrivKey);
    if (rv != CKR_OK) {
        P11_ReleaseSession(hSession);
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    /* First call: obtain the size */
    rv = pCtx->pFunctionList->C_Sign(
        hSession,
        pbHashValue, (CK_ULONG)cbHashValue,
        NULL, &cbRawSig);

    if (rv != CKR_OK) {
        P11_ReleaseSession(hSession);
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    if (pbSignature == NULL) {
        /* Size-only mode */
        P11_ReleaseSession(hSession);
        if (bEcdsa) {
            /* For ECDSA the final size is r||s (Windows format) */
            *pcbResult = P11_EcCoordSize(pKey->szAlgId) * 2;
        } else {
            *pcbResult = (DWORD)cbRawSig;
        }
        LOG_LEAVE("KSP_SignHash", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    pbRawSig = (BYTE *)KSP_Alloc(cbRawSig);
    if (!pbRawSig) {
        P11_ReleaseSession(hSession);
        LOG_LEAVE("KSP_SignHash", NTE_NO_MEMORY);
        return NTE_NO_MEMORY;
    }

    /* Second call: actual signature */
    rv = pCtx->pFunctionList->C_Sign(
        hSession,
        pbHashValue, (CK_ULONG)cbHashValue,
        pbRawSig, &cbRawSig);

    P11_ReleaseSession(hSession);

    if (rv != CKR_OK) {
        KSP_Free(pbRawSig);
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    if (bEcdsa) {
        /* Convert DER → r||s Windows format */
        DWORD cbDecoded = cbSignature;
        ss = P11_DecodeDerEcdsaSignature(
            pKey->szAlgId, pbRawSig, (DWORD)cbRawSig,
            pbSignature, &cbDecoded);
        KSP_Free(pbRawSig);
        if (ss == ERROR_SUCCESS)
            *pcbResult = cbDecoded;
    } else {
        if (cbSignature < (DWORD)cbRawSig) {
            KSP_Free(pbRawSig);
            LOG_LEAVE("KSP_SignHash", NTE_BUFFER_TOO_SMALL);
            return NTE_BUFFER_TOO_SMALL;
        }
        memcpy(pbSignature, pbRawSig, cbRawSig);
        *pcbResult = (DWORD)cbRawSig;
        KSP_Free(pbRawSig);
        ss = ERROR_SUCCESS;
    }

    LOG_LEAVE("KSP_SignHash", ss);
    return ss;
}

/* Decrypt RSA data */
SECURITY_STATUS WINAPI KSP_Decrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    PBYTE              pbInput,
    DWORD              cbInput,
    VOID              *pPaddingInfo,
    PBYTE              pbOutput,
    DWORD              cbOutput,
    DWORD             *pcbResult,
    DWORD              dwFlags)
{
    P11_CONTEXT         *pCtx = P11_GetContext();
    KSP_KEY             *pKey;
    CK_SESSION_HANDLE    hSession = CK_INVALID_HANDLE;
    CK_MECHANISM         mech;
    CK_RSA_PKCS_OAEP_PARAMS oaepParams;
    CK_GCM_PARAMS        gcmParams;
    CK_AES_CTR_PARAMS    ctrParams;
    CK_OBJECT_HANDLE     hDecryptKey = CK_INVALID_HANDLE;
    CK_RV                rv;
    SECURITY_STATUS      ss;
    CK_ULONG             cbDecrypted = 0;

    LOG_ENTER("KSP_Decrypt");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pbInput || !pcbResult) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_Decrypt", ss);
        return ss;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    /* Asymmetric decryption needs a private key; symmetric needs a secret */
    if (!pKey->bFinalized ||
        (pKey->dwKeyClass == KSP_KEY_CLASS_SYMMETRIC
            ? pKey->hSecretKey == CK_INVALID_HANDLE
            : pKey->hPrivKey   == CK_INVALID_HANDLE)) {
        LOG_LEAVE("KSP_Decrypt", NTE_INVALID_HANDLE);
        return NTE_INVALID_HANDLE;
    }

    memset(&mech, 0, sizeof(mech));

    if (pKey->dwKeyClass == KSP_KEY_CLASS_SYMMETRIC) {
        /* Symmetric decryption (AES) — mode selected by dwFlags */
        ss = KspBuildAesMechanism(pKey, dwFlags,
                                  &mech, &gcmParams, &ctrParams);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_Decrypt", ss);
            return ss;
        }
        hDecryptKey = pKey->hSecretKey;
    } else if (dwFlags & NCRYPT_PAD_OAEP_FLAG) {
        /* RSA OAEP — SHA-1/224/256/384/512 all supported */
        ss = P11_BuildOaepParams((BCRYPT_OAEP_PADDING_INFO *)pPaddingInfo,
                                 &oaepParams);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_Decrypt", ss);
            return ss;
        }

        mech.mechanism      = CKM_RSA_PKCS_OAEP;
        mech.pParameter     = &oaepParams;
        mech.ulParameterLen = sizeof(oaepParams);
        hDecryptKey = pKey->hPrivKey;
    } else {
        mech.mechanism = CKM_RSA_PKCS;
        hDecryptKey = pKey->hPrivKey;
    }

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_Decrypt", ss);
        return ss;
    }

    rv = pCtx->pFunctionList->C_DecryptInit(hSession, &mech, hDecryptKey);
    if (rv != CKR_OK) {
        P11_ReleaseSession(hSession);
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_Decrypt", ss);
        return ss;
    }

    /* First call: size */
    cbDecrypted = cbOutput;
    rv = pCtx->pFunctionList->C_Decrypt(
        hSession, pbInput, (CK_ULONG)cbInput,
        pbOutput, &cbDecrypted);

    P11_ReleaseSession(hSession);

    if (rv == CKR_BUFFER_TOO_SMALL || (rv == CKR_OK && pbOutput == NULL)) {
        *pcbResult = (DWORD)cbDecrypted;
        LOG_LEAVE("KSP_Decrypt", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    if (rv != CKR_OK) {
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_Decrypt", ss);
        return ss;
    }

    *pcbResult = (DWORD)cbDecrypted;
    LOG_LEAVE("KSP_Decrypt", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

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
    DWORD              dwFlags)
{
    KSP_KEY          *pKey;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    BYTE             *pbBlob   = NULL;
    DWORD             cbBlob   = 0;
    SECURITY_STATUS   ss;

    UNREFERENCED_PARAMETER(hExportKey);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_ExportKey");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pszBlobType || !pcbResult) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_ExportKey", ss);
        return ss;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    /* Private keys are not exportable from the HSM */
    if (_wcsicmp(pszBlobType, BCRYPT_RSAFULLPRIVATE_BLOB) == 0 ||
        _wcsicmp(pszBlobType, BCRYPT_RSAPRIVATE_BLOB)     == 0 ||
        _wcsicmp(pszBlobType, BCRYPT_ECCPRIVATE_BLOB)     == 0) {
        LOG_LEAVE("KSP_ExportKey", NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    /* Nor is raw symmetric key material. Every key this provider creates
     * or imports is CKA_EXTRACTABLE=FALSE, so C_GetAttributeValue would
     * refuse CKA_VALUE and the failure would surface as a generic PKCS#11
     * error several layers down. Say so here instead.
     *
     * BCRYPT_KEY_DATA_BLOB is supported for IMPORT — see KSP_ImportKey. */
    if (_wcsicmp(pszBlobType, BCRYPT_KEY_DATA_BLOB) == 0) {
        LOG_ERROR("KSP_ExportKey - symmetric key material is not extractable "
                  "(CKA_EXTRACTABLE=FALSE); import is supported, export is not",
                  NTE_NOT_SUPPORTED);
        LOG_LEAVE("KSP_ExportKey", NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    if (pKey->hPubKey == CK_INVALID_HANDLE) {
        LOG_LEAVE("KSP_ExportKey", NTE_BAD_KEY);
        return NTE_BAD_KEY;
    }

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_ExportKey", ss);
        return ss;
    }

    if (_wcsicmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) == 0) {
        ss = P11_ExportRsaPublicKey(hSession, pKey->hPubKey, &pbBlob, &cbBlob);
    } else if (_wcsicmp(pszBlobType, BCRYPT_ECCPUBLIC_BLOB) == 0) {
        ss = P11_ExportEcPublicKey(hSession, pKey->hPubKey, &pbBlob, &cbBlob);
    } else {
        P11_ReleaseSession(hSession);
        LOG_LEAVE("KSP_ExportKey", NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    P11_ReleaseSession(hSession);

    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_ExportKey", ss);
        return ss;
    }

    *pcbResult = cbBlob;

    if (pbOutput) {
        if (cbOutput < cbBlob) {
            KSP_Free(pbBlob);
            LOG_LEAVE("KSP_ExportKey", NTE_BUFFER_TOO_SMALL);
            return NTE_BUFFER_TOO_SMALL;
        }
        memcpy(pbOutput, pbBlob, cbBlob);
    }

    KSP_Free(pbBlob);
    LOG_LEAVE("KSP_ExportKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Import a public key from a BCRYPT blob */
SECURITY_STATUS WINAPI KSP_ImportKey(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hImportKey,
    LPCWSTR             pszBlobType,
    NCryptBufferDesc   *pParameterList,
    NCRYPT_KEY_HANDLE  *phKey,
    PBYTE               pbData,
    DWORD               cbData,
    DWORD               dwFlags)
{
    P11_CONTEXT         *pCtx = P11_GetContext();
    KSP_KEY             *pKey = NULL;
    CK_SESSION_HANDLE    hSession = CK_INVALID_HANDLE;
    CK_RV                rv;
    SECURITY_STATUS      ss;
    CK_BBOOL             bTrue  = CK_TRUE;
    CK_BBOOL             bFalse = CK_FALSE;
    CK_OBJECT_CLASS      classPub = CKO_PUBLIC_KEY;
    CK_OBJECT_HANDLE     hPubObj  = CK_INVALID_HANDLE;

    UNREFERENCED_PARAMETER(hImportKey);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_ImportKey");

    if (!KSP_IsValidProvider(hProvider) || !phKey || !pbData) {
        LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    /* Only public keys are importable */
    if (_wcsicmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) == 0) {
        BCRYPT_RSAKEY_BLOB *pRsa = (BCRYPT_RSAKEY_BLOB *)pbData;
        BYTE  *pbExp = pbData + sizeof(BCRYPT_RSAKEY_BLOB);
        BYTE  *pbMod = pbExp + pRsa->cbPublicExp;
        CK_ULONG ulModBits = pRsa->BitLength;
        CK_KEY_TYPE keyType = CKK_RSA;

        CK_ATTRIBUTE aTemplate[] = {
            { CKA_CLASS,           &classPub,    sizeof(classPub)    },
            { CKA_KEY_TYPE,        &keyType,      sizeof(keyType)     },
            { CKA_TOKEN,           &bFalse,       sizeof(bFalse)      },
            { CKA_MODULUS,         pbMod,         pRsa->cbModulus     },
            { CKA_PUBLIC_EXPONENT, pbExp,         pRsa->cbPublicExp   },
            { CKA_MODULUS_BITS,    &ulModBits,    sizeof(ulModBits)   },
            { CKA_VERIFY,          &bTrue,        sizeof(bTrue)       },
        };

        ss = P11_AcquireSession(&hSession);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_ImportKey", ss);
            return ss;
        }

        rv = pCtx->pFunctionList->C_CreateObject(
            hSession, aTemplate,
            (CK_ULONG)(sizeof(aTemplate) / sizeof(CK_ATTRIBUTE)),
            &hPubObj);

        P11_ReleaseSession(hSession);

        if (rv != CKR_OK) {
            ss = P11RvToSecStatus(rv);
            LOG_LEAVE("KSP_ImportKey", ss);
            return ss;
        }

        pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
        if (!pKey) {
            LOG_LEAVE("KSP_ImportKey", NTE_NO_MEMORY);
            return NTE_NO_MEMORY;
        }

        pKey->dwMagic     = KSP_KEY_MAGIC;
        pKey->hPubKey     = hPubObj;
        pKey->hPrivKey    = CK_INVALID_HANDLE;
        pKey->hSecretKey  = CK_INVALID_HANDLE;
        pKey->bFinalized  = TRUE;
        pKey->bSessionObject = TRUE;   /* Destroyed on KSP_FreeKey */
        pKey->dwKeyBitLen = pRsa->BitLength;
        wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_RSA);

    } else if (_wcsicmp(pszBlobType, BCRYPT_ECCPUBLIC_BLOB) == 0) {
        /* Import an EC public key as a real PKCS#11 session object so it
         * can be used for verification and as an ECDH peer key. */
        BCRYPT_ECCKEY_BLOB *pEcc = (BCRYPT_ECCKEY_BLOB *)pbData;
        CK_KEY_TYPE  keyType = CKK_EC;
        const char  *pbOid   = NULL;
        CK_ULONG     cbOid   = 0;
        BYTE        *pbDer   = NULL;
        DWORD        cbDer   = 0;
        DWORD        cbCoord;
        WCHAR        szAlg[MAX_ALG_ID_LEN];
        DWORD        dwBits;

        if (cbData < sizeof(BCRYPT_ECCKEY_BLOB)) {
            LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        cbCoord = pEcc->cbKey;

        /* The blob must carry both coordinates after the header */
        if (cbData < sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cbCoord) {
            LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        /* Identify the curve from the coordinate size */
        if (cbCoord == EC_P256_COORD_SIZE) {
            wcscpy_s(szAlg, MAX_ALG_ID_LEN, ALG_ECDSA_P256); dwBits = 256;
        } else if (cbCoord == EC_P384_COORD_SIZE) {
            wcscpy_s(szAlg, MAX_ALG_ID_LEN, ALG_ECDSA_P384); dwBits = 384;
        } else if (cbCoord == EC_P521_COORD_SIZE) {
            wcscpy_s(szAlg, MAX_ALG_ID_LEN, ALG_ECDSA_P521); dwBits = 521;
        } else {
            LOG_LEAVE("KSP_ImportKey", NTE_BAD_ALGID);
            return NTE_BAD_ALGID;
        }

        pbOid = P11_GetCurveOid(szAlg, &cbOid);
        if (!pbOid) {
            LOG_LEAVE("KSP_ImportKey", NTE_BAD_ALGID);
            return NTE_BAD_ALGID;
        }

        /* Build CKA_EC_POINT = DER OCTET STRING { 04 || X || Y } */
        ss = P11_BuildEcPointDer(
                pbData + sizeof(BCRYPT_ECCKEY_BLOB),
                pbData + sizeof(BCRYPT_ECCKEY_BLOB) + cbCoord,
                cbCoord, &pbDer, &cbDer);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_ImportKey", ss);
            return ss;
        }

        {
            CK_ATTRIBUTE aTemplate[] = {
                { CKA_CLASS,     &classPub,          sizeof(classPub) },
                { CKA_KEY_TYPE,  &keyType,           sizeof(keyType)  },
                { CKA_TOKEN,     &bFalse,            sizeof(bFalse)   },
                { CKA_EC_PARAMS, (CK_VOID_PTR)pbOid, cbOid            },
                { CKA_EC_POINT,  pbDer,              cbDer            },
                { CKA_VERIFY,    &bTrue,             sizeof(bTrue)    },
                { CKA_DERIVE,    &bTrue,             sizeof(bTrue)    },
            };

            ss = P11_AcquireSession(&hSession);
            if (ss != ERROR_SUCCESS) {
                KSP_Free(pbDer);
                LOG_LEAVE("KSP_ImportKey", ss);
                return ss;
            }

            rv = pCtx->pFunctionList->C_CreateObject(
                hSession, aTemplate,
                (CK_ULONG)(sizeof(aTemplate) / sizeof(CK_ATTRIBUTE)),
                &hPubObj);

            P11_ReleaseSession(hSession);
        }

        KSP_Free(pbDer);

        if (rv != CKR_OK) {
            ss = P11RvToSecStatus(rv);
            LOG_ERROR("C_CreateObject EC public", ss);
            LOG_LEAVE("KSP_ImportKey", ss);
            return ss;
        }

        pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
        if (!pKey) {
            LOG_LEAVE("KSP_ImportKey", NTE_NO_MEMORY);
            return NTE_NO_MEMORY;
        }

        pKey->dwMagic        = KSP_KEY_MAGIC;
        pKey->hPrivKey       = CK_INVALID_HANDLE;
        pKey->hPubKey        = hPubObj;
        pKey->hSecretKey     = CK_INVALID_HANDLE;
        pKey->bFinalized     = TRUE;
        pKey->bSessionObject = TRUE;   /* Destroyed on KSP_FreeKey */
        pKey->dwKeyBitLen    = dwBits;
        wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, szAlg);

    } else if (_wcsicmp(pszBlobType, BCRYPT_KEY_DATA_BLOB) == 0) {
        /* Raw symmetric key material — an AES or HMAC key the caller
         * already holds. The layout is BCRYPT_KEY_DATA_BLOB_HEADER
         * followed by cbKeyData bytes of key.
         *
         * The imported object is created CKA_EXTRACTABLE=FALSE like every
         * other key this provider makes, so it cannot be read back out.
         * That is the point of the HSM model: material goes in, and from
         * then on only the token can use it. Callers wanting the bytes
         * back should keep their own copy — see KSP_ExportKey, which says
         * so rather than failing obscurely. */
        BCRYPT_KEY_DATA_BLOB_HEADER *pHdr =
            (BCRYPT_KEY_DATA_BLOB_HEADER *)pbData;
        CK_OBJECT_CLASS  classSecret = CKO_SECRET_KEY;
        CK_KEY_TYPE      keyType;
        CK_OBJECT_HANDLE hSecret = CK_INVALID_HANDLE;
        BYTE            *pbKeyData;
        DWORD            cbKeyData;
        WCHAR            szAlg[MAX_ALG_ID_LEN];

        if (cbData < sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)) {
            LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        if (pHdr->dwMagic   != BCRYPT_KEY_DATA_BLOB_MAGIC ||
            pHdr->dwVersion != BCRYPT_KEY_DATA_BLOB_VERSION1) {
            LOG_LEAVE("KSP_ImportKey", NTE_BAD_DATA);
            return NTE_BAD_DATA;
        }

        cbKeyData = pHdr->cbKeyData;
        pbKeyData = pbData + sizeof(BCRYPT_KEY_DATA_BLOB_HEADER);

        /* cbKeyData comes from the caller: check it against what is
         * actually present before reading that many bytes. */
        if (cbKeyData == 0 ||
            cbKeyData > cbData - sizeof(BCRYPT_KEY_DATA_BLOB_HEADER)) {
            LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        /* The blob carries no algorithm name, so the length decides.
         * 16/24/32 bytes is AES; anything else is treated as an HMAC
         * generic secret, which is what SoftHSM2 stores those as. */
        if (cbKeyData == 16 || cbKeyData == 24 || cbKeyData == 32) {
            keyType = CKK_AES;
            wcscpy_s(szAlg, MAX_ALG_ID_LEN, ALG_AES);
        } else {
            keyType = CKK_GENERIC_SECRET;
            wcscpy_s(szAlg, MAX_ALG_ID_LEN, ALG_HMAC_SHA256);
        }

        {
            CK_ATTRIBUTE aTemplate[] = {
                { CKA_CLASS,       &classSecret, sizeof(classSecret) },
                { CKA_KEY_TYPE,    &keyType,     sizeof(keyType)     },
                { CKA_TOKEN,       &bFalse,      sizeof(bFalse)      },
                { CKA_SENSITIVE,   &bTrue,       sizeof(bTrue)       },
                { CKA_EXTRACTABLE, &bFalse,      sizeof(bFalse)      },
                { CKA_ENCRYPT,     &bTrue,       sizeof(bTrue)       },
                { CKA_DECRYPT,     &bTrue,       sizeof(bTrue)       },
                { CKA_SIGN,        &bTrue,       sizeof(bTrue)       },
                { CKA_VERIFY,      &bTrue,       sizeof(bTrue)       },
                { CKA_VALUE,       pbKeyData,    cbKeyData           },
            };

            ss = P11_AcquireSession(&hSession);
            if (ss != ERROR_SUCCESS) {
                LOG_LEAVE("KSP_ImportKey", ss);
                return ss;
            }

            rv = pCtx->pFunctionList->C_CreateObject(
                hSession, aTemplate,
                (CK_ULONG)(sizeof(aTemplate) / sizeof(CK_ATTRIBUTE)),
                &hSecret);

            P11_ReleaseSession(hSession);

            if (rv != CKR_OK) {
                ss = P11RvToSecStatus(rv);
                LOG_LEAVE("KSP_ImportKey", ss);
                return ss;
            }
        }

        pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
        if (!pKey) {
            LOG_LEAVE("KSP_ImportKey", NTE_NO_MEMORY);
            return NTE_NO_MEMORY;
        }

        pKey->dwMagic        = KSP_KEY_MAGIC;
        pKey->hSecretKey     = hSecret;
        pKey->hPubKey        = CK_INVALID_HANDLE;
        pKey->hPrivKey       = CK_INVALID_HANDLE;
        pKey->bFinalized     = TRUE;
        pKey->bSessionObject = TRUE;   /* Destroyed on KSP_FreeKey */
        pKey->dwKeyBitLen    = cbKeyData * 8;
        wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, szAlg);

    } else {
        /* Private key → not supported */
        LOG_LEAVE("KSP_ImportKey", NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    *phKey = (NCRYPT_KEY_HANDLE)(ULONG_PTR)pKey;
    LOG_LEAVE("KSP_ImportKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* ── Symmetric encryption (AES) ─────────────────────────────────────────── */

/* Encrypt data with a symmetric key. Asymmetric keys are rejected: RSA
 * encryption is a public-key operation performed by BCrypt, not the KSP. */
SECURITY_STATUS WINAPI KSP_Encrypt(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    PBYTE              pbInput,
    DWORD              cbInput,
    VOID              *pPaddingInfo,
    PBYTE              pbOutput,
    DWORD              cbOutput,
    DWORD             *pcbResult,
    DWORD              dwFlags)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    KSP_KEY          *pKey;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_GCM_PARAMS     gcmParams;
    CK_AES_CTR_PARAMS ctrParams;
    CK_RV             rv;
    SECURITY_STATUS   ss;
    CK_ULONG          cbEncrypted = 0;

    UNREFERENCED_PARAMETER(pPaddingInfo);
    LOG_ENTER("KSP_Encrypt");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pbInput || !pcbResult) {
        LOG_LEAVE("KSP_Encrypt", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    if (pKey->dwKeyClass != KSP_KEY_CLASS_SYMMETRIC) {
        /* RSA/EC public-key encryption is performed by BCrypt on the
         * exported public key, not through the storage provider. */
        LOG_LEAVE("KSP_Encrypt", NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    if (!pKey->bFinalized || pKey->hSecretKey == CK_INVALID_HANDLE) {
        LOG_LEAVE("KSP_Encrypt", NTE_INVALID_HANDLE);
        return NTE_INVALID_HANDLE;
    }

    ss = KspBuildAesMechanism(pKey, dwFlags, &mech, &gcmParams, &ctrParams);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_Encrypt", ss);
        return ss;
    }

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_Encrypt", ss);
        return ss;
    }

    rv = pCtx->pFunctionList->C_EncryptInit(hSession, &mech, pKey->hSecretKey);
    if (rv != CKR_OK) {
        P11_ReleaseSession(hSession);
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_Encrypt", ss);
        return ss;
    }

    cbEncrypted = cbOutput;
    rv = pCtx->pFunctionList->C_Encrypt(
        hSession, pbInput, (CK_ULONG)cbInput, pbOutput, &cbEncrypted);

    P11_ReleaseSession(hSession);

    /* Size query: pbOutput NULL, or the buffer was too small */
    if (rv == CKR_BUFFER_TOO_SMALL || (rv == CKR_OK && pbOutput == NULL)) {
        *pcbResult = (DWORD)cbEncrypted;
        LOG_LEAVE("KSP_Encrypt", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    if (rv != CKR_OK) {
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_Encrypt", ss);
        return ss;
    }

    *pcbResult = (DWORD)cbEncrypted;
    LOG_LEAVE("KSP_Encrypt", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* ── ECDH key agreement ─────────────────────────────────────────────────── */

/* Validate an agreed-secret handle */
BOOL KSP_IsValidSecret(NCRYPT_SECRET_HANDLE hSecret)
{
    KSP_SECRET *pSecret = (KSP_SECRET *)(ULONG_PTR)hSecret;
    return (pSecret && pSecret->dwMagic == KSP_SECRET_MAGIC);
}

/* Derive a shared secret from a local private key and a peer public key.
 *
 * Reads the peer's CKA_EC_POINT from the imported public key object, feeds
 * it to CKM_ECDH1_DERIVE with CKD_NULL (raw shared secret — any KDF is
 * applied afterwards by KSP_DeriveKey), and returns the resulting
 * CKO_SECRET_KEY object wrapped in a KSP_SECRET handle. */
SECURITY_STATUS WINAPI KSP_SecretAgreement(
    NCRYPT_PROV_HANDLE    hProvider,
    NCRYPT_KEY_HANDLE     hPrivKey,
    NCRYPT_KEY_HANDLE     hPubKey,
    NCRYPT_SECRET_HANDLE *phAgreedSecret,
    DWORD                 dwFlags)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    KSP_KEY          *pPriv, *pPub;
    KSP_SECRET       *pSecret = NULL;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_MECHANISM      mech;
    CK_ECDH1_DERIVE_PARAMS ecdhParams;
    CK_OBJECT_CLASS   classSecret = CKO_SECRET_KEY;
    CK_KEY_TYPE       keyType     = CKK_GENERIC_SECRET;
    CK_BBOOL          bTrue  = CK_TRUE;
    CK_BBOOL          bFalse = CK_FALSE;
    CK_OBJECT_HANDLE  hDerived = CK_INVALID_HANDLE;
    BYTE             *pbPeerPoint = NULL;
    DWORD             cbPeerPoint = 0;
    BYTE             *pbRaw;
    DWORD             cbRaw;
    CK_ULONG          ulSecretLen;
    CK_RV             rv;
    SECURITY_STATUS   ss;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_SecretAgreement");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hPrivKey) ||
        !KSP_IsValidKey(hPubKey) || !phAgreedSecret) {
        LOG_LEAVE("KSP_SecretAgreement", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    pPriv = (KSP_KEY *)(ULONG_PTR)hPrivKey;
    pPub  = (KSP_KEY *)(ULONG_PTR)hPubKey;

    if (pPriv->hPrivKey == CK_INVALID_HANDLE ||
        pPub->hPubKey   == CK_INVALID_HANDLE) {
        LOG_LEAVE("KSP_SecretAgreement", NTE_BAD_KEY);
        return NTE_BAD_KEY;
    }

    /* Both keys must sit on the same curve */
    ulSecretLen = P11_EcCoordSize(pPriv->szAlgId);
    if (ulSecretLen == 0 ||
        ulSecretLen != P11_EcCoordSize(pPub->szAlgId)) {
        LOG_LEAVE("KSP_SecretAgreement", NTE_BAD_ALGID);
        return NTE_BAD_ALGID;
    }

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_SecretAgreement", ss);
        return ss;
    }

    /* Read the peer's public point */
    if (P11_GetBinaryAttr(hSession, pPub->hPubKey, CKA_EC_POINT,
                          &pbPeerPoint, &cbPeerPoint) != CKR_OK) {
        P11_ReleaseSession(hSession);
        LOG_LEAVE("KSP_SecretAgreement", NTE_BAD_KEY);
        return NTE_BAD_KEY;
    }

    /* CKM_ECDH1_DERIVE takes the raw point, not the DER OCTET STRING.
     *
     * Stripping on a leading 0x04 alone is not safe. For a Montgomery
     * curve the public key is 32 raw bytes with no wrapper at all, and
     * those bytes are effectively random — roughly one X25519 key in 256
     * begins with 0x04, and two of its own key bytes would then be eaten
     * as a tag and length. So the declared DER length has to agree with
     * what is actually there before anything is removed. */
    pbRaw = pbPeerPoint;
    cbRaw = cbPeerPoint;
    if (cbRaw >= 2 && pbRaw[0] == 0x04) {
        if (pbRaw[1] == 0x81 && cbRaw >= 3 &&
            (DWORD)pbRaw[2] == cbRaw - 3) {
            /* Long form: 0x04 0x81 <len>, used by P-521. */
            pbRaw += 3; cbRaw -= 3;
        } else if (pbRaw[1] < 128 && (DWORD)pbRaw[1] == cbRaw - 2) {
            /* Short form: 0x04 <len>. */
            pbRaw += 2; cbRaw -= 2;
        }
        /* Otherwise the leading 0x04 is key material, not a tag. */
    }

    memset(&ecdhParams, 0, sizeof(ecdhParams));
    ecdhParams.kdf             = CKD_NULL;   /* Raw Z; KDF applied later */
    ecdhParams.ulSharedDataLen = 0;
    ecdhParams.pSharedData     = NULL;
    ecdhParams.ulPublicDataLen = cbRaw;
    ecdhParams.pPublicData     = pbRaw;

    memset(&mech, 0, sizeof(mech));
    mech.mechanism      = CKM_ECDH1_DERIVE;
    mech.pParameter     = &ecdhParams;
    mech.ulParameterLen = sizeof(ecdhParams);

    {
        CK_ATTRIBUTE aTemplate[] = {
            { CKA_CLASS,       &classSecret, sizeof(classSecret) },
            { CKA_KEY_TYPE,    &keyType,     sizeof(keyType)     },
            { CKA_TOKEN,       &bFalse,      sizeof(bFalse)      },
            { CKA_SENSITIVE,   &bFalse,      sizeof(bFalse)      },
            { CKA_EXTRACTABLE, &bTrue,       sizeof(bTrue)       },
            { CKA_VALUE_LEN,   &ulSecretLen, sizeof(ulSecretLen) },
        };

        rv = pCtx->pFunctionList->C_DeriveKey(
            hSession, &mech, pPriv->hPrivKey,
            aTemplate, (CK_ULONG)(sizeof(aTemplate) / sizeof(CK_ATTRIBUTE)),
            &hDerived);
    }

    P11_ReleaseSession(hSession);
    KSP_Free(pbPeerPoint);

    if (rv != CKR_OK) {
        ss = P11RvToSecStatus(rv);
        LOG_ERROR("C_DeriveKey ECDH", ss);
        LOG_LEAVE("KSP_SecretAgreement", ss);
        return ss;
    }

    pSecret = (KSP_SECRET *)KSP_AllocZero(sizeof(KSP_SECRET));
    if (!pSecret) {
        LOG_LEAVE("KSP_SecretAgreement", NTE_NO_MEMORY);
        return NTE_NO_MEMORY;
    }

    pSecret->dwMagic     = KSP_SECRET_MAGIC;
    pSecret->hSecretObj  = hDerived;
    pSecret->dwSecretLen = (DWORD)ulSecretLen;

    *phAgreedSecret = (NCRYPT_SECRET_HANDLE)(ULONG_PTR)pSecret;

    LOG_INFO("ECDH secret agreed: %lu bytes, obj=0x%lX",
             (unsigned long)ulSecretLen, (unsigned long)hDerived);
    LOG_LEAVE("KSP_SecretAgreement", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Derive key material from an agreed secret.
 *
 * Supports BCRYPT_KDF_RAW_SECRET, which returns the raw Z value. Hash-based
 * KDFs (SP 800-56A concatenation, HKDF) are not implemented — callers should
 * request the raw secret and run the KDF with BCrypt. */
/* ── BCRYPT_KDF_HASH ─────────────────────────────────────────────────────
 *
 * CNG's hash KDF is Hash(prepend || Z || append). The hash algorithm comes
 * from a KDF_HASH_ALGORITHM buffer and defaults to SHA-1 when absent, which
 * is the documented CNG default rather than a choice made here. A caller
 * may supply several KDF_SECRET_PREPEND or KDF_SECRET_APPEND buffers; they
 * concatenate in the order given.
 *
 * The digest runs on the token through C_Digest*, not in the KSP. That is
 * not a security boundary — CKD_NULL already handed us the raw Z — but it
 * keeps the KSP free of its own crypto and reuses mechanisms SoftHSM2
 * certainly has. */
static SECURITY_STATUS KdfFindHashMech(NCryptBufferDesc *pParams,
                                       CK_MECHANISM_TYPE *pMech,
                                       DWORD *pcbDigest)
{
    LPCWSTR pszAlg = BCRYPT_SHA1_ALGORITHM;   /* CNG default */
    ULONG   i;

    if (pParams && pParams->pBuffers) {
        for (i = 0; i < pParams->cBuffers; i++) {
            if (pParams->pBuffers[i].BufferType == KDF_HASH_ALGORITHM &&
                pParams->pBuffers[i].pvBuffer != NULL) {
                pszAlg = (LPCWSTR)pParams->pBuffers[i].pvBuffer;
                break;
            }
        }
    }

    if (_wcsicmp(pszAlg, BCRYPT_SHA1_ALGORITHM) == 0) {
        *pMech = CKM_SHA_1;  *pcbDigest = 20;
    } else if (_wcsicmp(pszAlg, KSP_SHA224_ALGORITHM) == 0) {
        *pMech = CKM_SHA224; *pcbDigest = 28;
    } else if (_wcsicmp(pszAlg, BCRYPT_SHA256_ALGORITHM) == 0) {
        *pMech = CKM_SHA256; *pcbDigest = 32;
    } else if (_wcsicmp(pszAlg, BCRYPT_SHA384_ALGORITHM) == 0) {
        *pMech = CKM_SHA384; *pcbDigest = 48;
    } else if (_wcsicmp(pszAlg, BCRYPT_SHA512_ALGORITHM) == 0) {
        *pMech = CKM_SHA512; *pcbDigest = 64;
    } else {
        return NTE_BAD_ALGID;
    }
    return ERROR_SUCCESS;
}

/* Feed every buffer of one type into the running digest, in order. */
static CK_RV KdfDigestBuffers(P11_CONTEXT *pCtx, CK_SESSION_HANDLE hSession,
                              NCryptBufferDesc *pParams, ULONG ulType)
{
    ULONG i;
    CK_RV rv;

    if (!pParams || !pParams->pBuffers)
        return CKR_OK;

    for (i = 0; i < pParams->cBuffers; i++) {
        if (pParams->pBuffers[i].BufferType != ulType)
            continue;
        if (!pParams->pBuffers[i].pvBuffer || pParams->pBuffers[i].cbBuffer == 0)
            continue;
        rv = pCtx->pFunctionList->C_DigestUpdate(
                hSession,
                (CK_BYTE_PTR)pParams->pBuffers[i].pvBuffer,
                (CK_ULONG)pParams->pBuffers[i].cbBuffer);
        if (rv != CKR_OK)
            return rv;
    }
    return CKR_OK;
}

SECURITY_STATUS WINAPI KSP_DeriveKey(
    NCRYPT_PROV_HANDLE   hProvider,
    NCRYPT_SECRET_HANDLE hSharedSecret,
    LPCWSTR              pwszKDF,
    NCryptBufferDesc    *pParameterList,
    PBYTE                pbDerivedKey,
    DWORD                cbDerivedKey,
    DWORD               *pcbResult,
    DWORD                dwFlags)
{
    KSP_SECRET       *pSecret;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    BYTE             *pbValue = NULL;
    DWORD             cbValue = 0;
    SECURITY_STATUS   ss;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_DeriveKey");

    if (!KSP_IsValidProvider(hProvider) ||
        !KSP_IsValidSecret(hSharedSecret) || !pcbResult) {
        LOG_LEAVE("KSP_DeriveKey", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    pSecret = (KSP_SECRET *)(ULONG_PTR)hSharedSecret;

    /* BCRYPT_KDF_HASH — Hash(prepend || Z || append). */
    if (pwszKDF && _wcsicmp(pwszKDF, BCRYPT_KDF_HASH) == 0) {
        P11_CONTEXT      *pCtx = P11_GetContext();
        CK_MECHANISM      mech;
        CK_MECHANISM_TYPE mechType;
        DWORD             cbDigest = 0;
        BYTE              abDigest[64];
        CK_ULONG          ulDigest = sizeof(abDigest);
        CK_RV             rv;

        ss = KdfFindHashMech(pParameterList, &mechType, &cbDigest);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }

        /* Size-only query: the output is exactly one digest. */
        if (pbDerivedKey == NULL) {
            *pcbResult = cbDigest;
            LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }
        if (cbDerivedKey < cbDigest) {
            *pcbResult = cbDigest;
            LOG_LEAVE("KSP_DeriveKey", NTE_BUFFER_TOO_SMALL);
            return NTE_BUFFER_TOO_SMALL;
        }

        ss = P11_AcquireSession(&hSession);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }

        if (P11_GetBinaryAttr(hSession, pSecret->hSecretObj, CKA_VALUE,
                              &pbValue, &cbValue) != CKR_OK) {
            P11_ReleaseSession(hSession);
            LOG_LEAVE("KSP_DeriveKey", NTE_BAD_KEY);
            return NTE_BAD_KEY;
        }

        memset(&mech, 0, sizeof(mech));
        mech.mechanism = mechType;

        rv = pCtx->pFunctionList->C_DigestInit(hSession, &mech);
        if (rv == CKR_OK)
            rv = KdfDigestBuffers(pCtx, hSession, pParameterList,
                                  KDF_SECRET_PREPEND);
        if (rv == CKR_OK)
            rv = pCtx->pFunctionList->C_DigestUpdate(hSession, pbValue,
                                                     (CK_ULONG)cbValue);
        if (rv == CKR_OK)
            rv = KdfDigestBuffers(pCtx, hSession, pParameterList,
                                  KDF_SECRET_APPEND);
        if (rv == CKR_OK)
            rv = pCtx->pFunctionList->C_DigestFinal(hSession, abDigest,
                                                    &ulDigest);

        P11_ReleaseSession(hSession);
        SecureZeroMemory(pbValue, cbValue);
        KSP_Free(pbValue);

        if (rv != CKR_OK) {
            SecureZeroMemory(abDigest, sizeof(abDigest));
            ss = P11RvToSecStatus(rv);
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }

        if (ulDigest > cbDigest)
            ulDigest = cbDigest;

        memcpy(pbDerivedKey, abDigest, ulDigest);
        *pcbResult = (DWORD)ulDigest;
        SecureZeroMemory(abDigest, sizeof(abDigest));

        LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    /* Anything else: only the raw secret is available. HMAC, TLS_PRF and
     * HKDF need a keyed primitive over the Z value, which is more than a
     * digest chain — see ECDH-05 in the feature matrix. */
    if (pwszKDF && _wcsicmp(pwszKDF, BCRYPT_KDF_RAW_SECRET) != 0) {
        LOG_LEAVE("KSP_DeriveKey", NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    /* Size-only query */
    if (pbDerivedKey == NULL) {
        *pcbResult = pSecret->dwSecretLen;
        LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_DeriveKey", ss);
        return ss;
    }

    if (P11_GetBinaryAttr(hSession, pSecret->hSecretObj, CKA_VALUE,
                          &pbValue, &cbValue) != CKR_OK) {
        P11_ReleaseSession(hSession);
        LOG_LEAVE("KSP_DeriveKey", NTE_BAD_KEY);
        return NTE_BAD_KEY;
    }

    P11_ReleaseSession(hSession);

    if (cbDerivedKey < cbValue) {
        SecureZeroMemory(pbValue, cbValue);
        KSP_Free(pbValue);
        *pcbResult = cbValue;
        LOG_LEAVE("KSP_DeriveKey", NTE_BUFFER_TOO_SMALL);
        return NTE_BUFFER_TOO_SMALL;
    }

    memcpy(pbDerivedKey, pbValue, cbValue);
    *pcbResult = cbValue;

    SecureZeroMemory(pbValue, cbValue);
    KSP_Free(pbValue);

    LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Release an agreed secret and destroy its PKCS#11 object */
SECURITY_STATUS WINAPI KSP_FreeSecret(
    NCRYPT_PROV_HANDLE   hProvider,
    NCRYPT_SECRET_HANDLE hSharedSecret)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    KSP_SECRET       *pSecret;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;

    UNREFERENCED_PARAMETER(hProvider);
    LOG_ENTER("KSP_FreeSecret");

    if (!KSP_IsValidSecret(hSharedSecret)) {
        LOG_LEAVE("KSP_FreeSecret", NTE_INVALID_HANDLE);
        return NTE_INVALID_HANDLE;
    }

    pSecret = (KSP_SECRET *)(ULONG_PTR)hSharedSecret;

    if (pSecret->hSecretObj != CK_INVALID_HANDLE &&
        pCtx && pCtx->pFunctionList &&
        P11_AcquireSession(&hSession) == ERROR_SUCCESS) {
        pCtx->pFunctionList->C_DestroyObject(hSession, pSecret->hSecretObj);
        P11_ReleaseSession(hSession);
    }

    pSecret->dwMagic = 0;
    KSP_Free(pSecret);

    LOG_LEAVE("KSP_FreeSecret", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}
