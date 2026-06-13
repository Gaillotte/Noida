/* ksp_crypto.c — Implémentation des opérations cryptographiques */
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

/* Renseigne les paramètres PSS depuis BCRYPT_PSS_PADDING_INFO */
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
    } else if (_wcsicmp(pPssInfo->pszAlgId, BCRYPT_SHA384_ALGORITHM) == 0) {
        pPssParams->hashAlg = CKM_SHA384;
        pPssParams->mgf     = CKG_MGF1_SHA384;
    } else if (_wcsicmp(pPssInfo->pszAlgId, BCRYPT_SHA512_ALGORITHM) == 0) {
        pPssParams->hashAlg = CKM_SHA512;
        pPssParams->mgf     = CKG_MGF1_SHA512;
    } else {
        /* SHA-256 par défaut */
        pPssParams->hashAlg = CKM_SHA256;
        pPssParams->mgf     = CKG_MGF1_SHA256;
        if (pPssParams->sLen == 0)
            pPssParams->sLen = 32;
    }
}

/* Signe un hash — implémente le pattern double-appel CNG */
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
        LOG_LEAVE("KSP_SignHash", NTE_KEY_DOES_NOT_EXIST);
        return NTE_KEY_DOES_NOT_EXIST;
    }

    memset(&pssParams, 0, sizeof(pssParams));
    ss = P11_ResolveMechanism(pKey->szAlgId, dwFlags, &mech, &pssParams);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    /* Pour PSS, actualise les paramètres depuis BCRYPT_PSS_PADDING_INFO */
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

    /* Premier appel : obtient la taille */
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
        /* Mode taille seule */
        P11_ReleaseSession(hSession);
        if (bEcdsa) {
            /* Pour ECDSA la taille finale est r||s (format Windows) */
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

    /* Deuxième appel : signature réelle */
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
        /* Convertit DER → r||s format Windows */
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

/* Déchiffre des données RSA */
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

    if (!pKey->bFinalized || pKey->hPrivKey == CK_INVALID_HANDLE) {
        LOG_LEAVE("KSP_Decrypt", NTE_KEY_DOES_NOT_EXIST);
        return NTE_KEY_DOES_NOT_EXIST;
    }

    memset(&mech, 0, sizeof(mech));

    if (dwFlags & NCRYPT_PAD_OAEP_FLAG) {
        BCRYPT_OAEP_PADDING_INFO *pOaep = (BCRYPT_OAEP_PADDING_INFO *)pPaddingInfo;
        memset(&oaepParams, 0, sizeof(oaepParams));

        if (pOaep && pOaep->pszAlgId &&
            _wcsicmp(pOaep->pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0) {
            oaepParams.hashAlg = CKM_SHA256;
            oaepParams.mgf     = CKG_MGF1_SHA256;
        } else {
            oaepParams.hashAlg = CKM_SHA_1;
            oaepParams.mgf     = CKG_MGF1_SHA1;
        }
        oaepParams.source      = CKZ_DATA_SPECIFIED;
        oaepParams.pSourceData = NULL;
        oaepParams.ulSourceDataLen = 0;

        mech.mechanism     = CKM_RSA_PKCS_OAEP;
        mech.pParameter    = &oaepParams;
        mech.ulParameterLen = sizeof(oaepParams);
    } else {
        mech.mechanism = CKM_RSA_PKCS;
    }

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_Decrypt", ss);
        return ss;
    }

    rv = pCtx->pFunctionList->C_DecryptInit(hSession, &mech, pKey->hPrivKey);
    if (rv != CKR_OK) {
        P11_ReleaseSession(hSession);
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_Decrypt", ss);
        return ss;
    }

    /* Premier appel : taille */
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

/* Exporte une clé au format BCRYPT */
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

    /* Les clés privées ne sont pas exportables depuis le HSM */
    if (_wcsicmp(pszBlobType, BCRYPT_RSAFULLPRIVATE_BLOB) == 0 ||
        _wcsicmp(pszBlobType, BCRYPT_RSAPRIVATE_BLOB)     == 0 ||
        _wcsicmp(pszBlobType, BCRYPT_ECCPRIVATE_BLOB)     == 0) {
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

/* Importe une clé publique depuis un blob BCRYPT */
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

    /* Seules les clés publiques sont importables */
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
        pKey->bFinalized  = TRUE;
        pKey->dwKeyBitLen = pRsa->BitLength;
        wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_RSA);

    } else if (_wcsicmp(pszBlobType, BCRYPT_ECCPUBLIC_BLOB) == 0) {
        /* Import clé publique EC — stocké en session uniquement */
        pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
        if (!pKey) {
            LOG_LEAVE("KSP_ImportKey", NTE_NO_MEMORY);
            return NTE_NO_MEMORY;
        }
        pKey->dwMagic    = KSP_KEY_MAGIC;
        pKey->hPrivKey   = CK_INVALID_HANDLE;
        pKey->hPubKey    = CK_INVALID_HANDLE;
        pKey->bFinalized = TRUE;

        if (cbData >= sizeof(BCRYPT_ECCKEY_BLOB)) {
            BCRYPT_ECCKEY_BLOB *pEcc = (BCRYPT_ECCKEY_BLOB *)pbData;
            if (pEcc->cbKey == EC_P256_COORD_SIZE) {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_ECDSA_P256);
                pKey->dwKeyBitLen = 256;
            } else {
                wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_ECDSA_P384);
                pKey->dwKeyBitLen = 384;
            }
        }
    } else {
        /* Clé privée → non supporté */
        LOG_LEAVE("KSP_ImportKey", NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    *phKey = (NCRYPT_KEY_HANDLE)(ULONG_PTR)pKey;
    LOG_LEAVE("KSP_ImportKey", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}
