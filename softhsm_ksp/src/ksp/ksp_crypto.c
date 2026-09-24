/* ksp_crypto.c — Cryptographic operation implementation */
#include "ksp_crypto.h"
#include "ksp_key.h"
#include "ksp_provider.h"
#include "../pkcs11/p11_context.h"
#include "../pkcs11/p11_session.h"
#include "../pkcs11/p11_utils.h"
#include "../pkcs11/p11_caps.h"
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

/* Interpret pPaddingInfo as a BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO, but
 * only for a chaining mode where CNG would actually pass one.
 *
 * pPaddingInfo is a void pointer whose meaning depends on the flags, so
 * reading it as the wrong structure is how a provider dereferences a
 * BCRYPT_OAEP_PADDING_INFO as something twice its size. GCM and CCM are
 * the only modes CNG documents as carrying this, and cbSize is checked
 * because a caller who passed the wrong thing is better refused than
 * trusted. */
static const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *KspAuthModeInfo(
    KSP_KEY *pKey, VOID *pPaddingInfo)
{
    const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *pInfo;

    if (!pKey || !pPaddingInfo)
        return NULL;
    if (_wcsicmp(pKey->szChainingMode, BCRYPT_CHAIN_MODE_GCM) != 0 &&
        _wcsicmp(pKey->szChainingMode, BCRYPT_CHAIN_MODE_CCM) != 0)
        return NULL;

    pInfo = (const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *)pPaddingInfo;
    if (pInfo->cbSize != sizeof(*pInfo))
        return NULL;

    return pInfo;
}

/* Build the PKCS#11 mechanism for an AES operation.
 *
 * Follows the CNG symmetric contract: the chaining mode is a key property
 * (NCRYPT_CHAINING_MODE_PROPERTY) and the IV / nonce is supplied through
 * NCRYPT_INITIALIZATION_VECTOR, both set before the operation. Mapping:
 *   ChainingModeECB → CKM_AES_ECB      (no IV)
 *   ChainingModeCBC → CKM_AES_CBC      (16-byte IV), CBC_PAD when padding asked
 *   ChainingModeGCM → CKM_AES_GCM      (12-byte nonce, 128-bit tag)
 *   ChainingModeCCM → CKM_AES_CCM      (7–13 byte nonce, plaintext length up front)
 *   ChainingModeCFB → CKM_AES_CFB8     by default, CKM_AES_CFB128 when
 *                                      MessageBlockLength is the block size
 *   ChainingModeCTR → CKM_AES_CTR      (16-byte counter block, KSP extension)
 *
 * For the authenticated modes, pAuthInfo is the BCRYPT_AUTHENTICATED_-
 * CIPHER_MODE_INFO that CNG passes as pPaddingInfo. That is the standard
 * route for the nonce, the additional authenticated data and the tag —
 * none of which are key properties. It may be NULL, in which case GCM
 * falls back to the IV key property, which is how this provider behaved
 * before the authenticated-mode route existed.
 *
 * cbData is the plaintext length. CCM needs it before the operation
 * starts, because unlike GCM it is not an online mode.
 */
static SECURITY_STATUS KspBuildAesMechanism(
    KSP_KEY           *pKey,
    DWORD              dwFlags,
    const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *pAuthInfo,
    DWORD              cbData,
    CK_MECHANISM      *pMech,
    CK_GCM_PARAMS     *pGcm,
    CK_AES_CTR_PARAMS *pCtr,
    CK_CCM_PARAMS     *pCcm)
{
    const BYTE *pbNonce = NULL;
    DWORD       cbNonce = 0;
    const BYTE *pbAAD   = NULL;
    DWORD       cbAAD   = 0;
    DWORD       cbTag   = AES_GCM_TAG_BITS / 8;

    if (!pKey || !pMech || !pGcm || !pCtr || !pCcm)
        return NTE_INVALID_PARAMETER;

    /* Only AES is a block cipher here; HMAC keys never reach this path */
    if (_wcsicmp(pKey->szAlgId, ALG_AES) != 0)
        return NTE_BAD_ALGID;

    memset(pMech, 0, sizeof(*pMech));

    /* The authenticated-mode info wins over the key properties when it is
     * present, because it is what a portable CNG application supplies. */
    if (pAuthInfo) {
        pbNonce = pAuthInfo->pbNonce;
        cbNonce = pAuthInfo->cbNonce;
        pbAAD   = pAuthInfo->pbAuthData;
        cbAAD   = pAuthInfo->cbAuthData;
        if (pAuthInfo->cbTag)
            cbTag = pAuthInfo->cbTag;
    }
    if (!pbNonce || cbNonce == 0) {
        pbNonce = pKey->pbIV;
        cbNonce = pKey->cbIV;
    }
    if (!pbAAD || cbAAD == 0) {
        pbAAD = pKey->cbAuthData ? pKey->pbAuthData : NULL;
        cbAAD = pKey->cbAuthData;
    }

    /* ECB — no IV required */
    if (_wcsicmp(pKey->szChainingMode, BCRYPT_CHAIN_MODE_ECB) == 0) {
        pMech->mechanism = CKM_AES_ECB;
        return ERROR_SUCCESS;
    }

    /* GCM — authenticated mode, nonce is typically 12 bytes */
    if (_wcsicmp(pKey->szChainingMode, BCRYPT_CHAIN_MODE_GCM) == 0) {
        if (cbNonce == 0)
            return NTE_INVALID_PARAMETER;

        memset(pGcm, 0, sizeof(*pGcm));
        pGcm->pIv       = (CK_BYTE_PTR)pbNonce;
        pGcm->ulIvLen   = cbNonce;
        pGcm->ulIvBits  = cbNonce * 8;
        pGcm->pAAD      = (CK_BYTE_PTR)pbAAD;
        pGcm->ulAADLen  = cbAAD;
        pGcm->ulTagBits = cbTag * 8;

        pMech->mechanism      = CKM_AES_GCM;
        pMech->pParameter     = pGcm;
        pMech->ulParameterLen = sizeof(*pGcm);
        return ERROR_SUCCESS;
    }

    /* CCM — authenticated, and NOT an online mode.
     *
     * CK_CCM_PARAMS.ulDataLen is the plaintext length and the token needs
     * it before any data arrives, which is the practical difference from
     * GCM. The nonce is 7 to 13 bytes (NIST SP 800-38C); anything else is
     * refused here rather than passed down to be rejected with an error
     * that does not point back. */
    if (_wcsicmp(pKey->szChainingMode, BCRYPT_CHAIN_MODE_CCM) == 0) {
        if (!P11_HasMechanism(CKM_AES_CCM)) {
            LOG_ERROR("AES-CCM: the token does not implement CKM_AES_CCM",
                      NTE_NOT_SUPPORTED);
            return NTE_NOT_SUPPORTED;
        }
        if (cbNonce < AES_CCM_MIN_NONCE || cbNonce > AES_CCM_MAX_NONCE)
            return NTE_INVALID_PARAMETER;

        memset(pCcm, 0, sizeof(*pCcm));
        pCcm->ulDataLen  = cbData;
        pCcm->pNonce     = (CK_BYTE_PTR)pbNonce;
        pCcm->ulNonceLen = cbNonce;
        pCcm->pAAD       = (CK_BYTE_PTR)pbAAD;
        pCcm->ulAADLen   = cbAAD;
        pCcm->ulMACLen   = cbTag;

        pMech->mechanism      = CKM_AES_CCM;
        pMech->pParameter     = pCcm;
        pMech->ulParameterLen = sizeof(*pCcm);
        return ERROR_SUCCESS;
    }

    /* CFB — the feedback size decides the mechanism, and the default is
     * NOT the full block.
     *
     * Microsoft's property documentation for MessageBlockLength: "By
     * default, this property is set to 1 for 8-bit CFB. Setting it to the
     * block size in bytes causes full-block CFB to be used." So a caller
     * who sets ChainingModeCFB and nothing else means CFB8, and mapping
     * that to CKM_AES_CFB128 would produce ciphertext no other CNG
     * implementation could decrypt. The feature matrix said this gap
     * "would need CKM_AES_CFB128", naming the mechanism a caller gets
     * only by asking for it explicitly. */
    if (_wcsicmp(pKey->szChainingMode, BCRYPT_CHAIN_MODE_CFB) == 0) {
        CK_MECHANISM_TYPE mechCfb;

        if (pKey->cbMessageBlockLen == 0 ||
            pKey->cbMessageBlockLen == 1) {
            mechCfb = CKM_AES_CFB8;
        } else if (pKey->cbMessageBlockLen == AES_BLOCK_SIZE) {
            mechCfb = CKM_AES_CFB128;
        } else {
            /* CNG allows any size up to the block; PKCS#11 defines
             * mechanisms only for 1, 8, 64 and 128 bits, and this provider
             * wires the two CNG actually reaches. Refusing beats silently
             * rounding to a different cipher. */
            return NTE_NOT_SUPPORTED;
        }

        if (!P11_HasMechanism(mechCfb)) {
            LOG_ERROR("AES-CFB: the token does not implement this feedback "
                      "size", NTE_NOT_SUPPORTED);
            return NTE_NOT_SUPPORTED;
        }
        if (pKey->cbIV != AES_BLOCK_SIZE)
            return NTE_INVALID_PARAMETER;

        pMech->mechanism      = mechCfb;
        pMech->pParameter     = pKey->pbIV;
        pMech->ulParameterLen = pKey->cbIV;
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
/* Re-authenticate for a key that carries a per-key PIN (PROP-13).
 *
 * PKCS#11's own mechanism: a key marked CKA_ALWAYS_AUTHENTICATE requires
 * C_Login(CKU_CONTEXT_SPECIFIC) between the operation's Init call and the
 * operation itself. Called with the operation already initialised, which is
 * what makes the login context-specific.
 *
 * A token that did not need it answers CKR_OPERATION_NOT_INITIALIZED, and
 * that is tolerated: a caller may set a PIN on a key the token does not
 * actually mark as always-authenticate, and failing the operation for that
 * would be worse than ignoring a credential the token did not want. */
static SECURITY_STATUS KeyContextLogin(KSP_KEY *pKey, CK_SESSION_HANDLE hSession)
{
    P11_CONTEXT *pCtx = P11_GetContext();
    CK_RV        rv;

    if (pKey->szKeyPin[0] == '\0')
        return ERROR_SUCCESS;

    rv = pCtx->pFunctionList->C_Login(
        hSession, CKU_CONTEXT_SPECIFIC,
        (CK_UTF8CHAR_PTR)pKey->szKeyPin,
        (CK_ULONG)strlen(pKey->szKeyPin));

    if (rv == CKR_OK ||
        rv == CKR_OPERATION_NOT_INITIALIZED ||
        rv == CKR_USER_ALREADY_LOGGED_IN)
        return ERROR_SUCCESS;

    LOG_ERROR("Per-key re-authentication failed", P11RvToSecStatus(rv));
    return P11RvToSecStatus(rv);
}

/* How long a signature this key and mechanism produce.
 *
 * Answered without asking the token, and that is the point rather than an
 * optimisation. CNG callers ask for the size first and sign second. Getting
 * the size by starting a signing operation and abandoning it leaves that
 * operation active on the session, and because sessions are POOLED the next
 * caller to draw that session gets CKR_OPERATION_ACTIVE from its own
 * C_SignInit — for a key it does not own, on a thread that did nothing
 * wrong.
 *
 * That is what this provider did until a run against Kryoptic exposed it.
 * SoftHSM2 permits re-initialising over an active operation, so against the
 * only backend ever tested the bug was invisible. PKCS#11 v2.40 §5.2 is
 * explicit that C_SignInit returns CKR_OPERATION_ACTIVE, and it offers no
 * way to cancel an operation, so the only portable fix is not to start one.
 *
 * Every size here is fixed by the algorithm, so nothing is lost. */
static SECURITY_STATUS KspSignatureLength(const KSP_KEY *pKey,
                                          CK_MECHANISM_TYPE mech,
                                          DWORD *pcbSig)
{
    switch (mech) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_RSA_X_509:
        /* Always the modulus length — raw RSA included, since the output
         * of the exponentiation is exactly one modulus wide. */
        if (pKey->dwKeyBitLen == 0)
            return NTE_BAD_KEY;
        *pcbSig = pKey->dwKeyBitLen / 8;
        return ERROR_SUCCESS;

    case CKM_ECDSA:
        /* The token returns DER; the caller gets raw r||s. */
        *pcbSig = P11_EcCoordSize(pKey->szAlgId) * 2;
        return (*pcbSig > 0) ? ERROR_SUCCESS : NTE_BAD_ALGID;

    case CKM_EDDSA:
        if (_wcsicmp(pKey->szAlgId, ALG_EDDSA_ED25519) == 0)
            *pcbSig = ED25519_SIG_SIZE;
        else if (_wcsicmp(pKey->szAlgId, ALG_EDDSA_ED448) == 0)
            *pcbSig = ED448_SIG_SIZE;
        else
            return NTE_BAD_ALGID;
        return ERROR_SUCCESS;

    case CKM_ML_DSA:
        *pcbSig = P11_MlDsaSignatureSize(pKey->szAlgId);
        return (*pcbSig > 0) ? ERROR_SUCCESS : NTE_BAD_ALGID;

    case CKM_AES_CMAC:
        *pcbSig = AES_BLOCK_SIZE;
        return ERROR_SUCCESS;

    case CKM_SHA_1_HMAC:    *pcbSig = 20; return ERROR_SUCCESS;
    case CKM_SHA224_HMAC:   *pcbSig = 28; return ERROR_SUCCESS;
    case CKM_SHA256_HMAC:   *pcbSig = 32; return ERROR_SUCCESS;
    case CKM_SHA384_HMAC:   *pcbSig = 48; return ERROR_SUCCESS;
    case CKM_SHA512_HMAC:   *pcbSig = 64; return ERROR_SUCCESS;

    default:
        return NTE_NOT_SUPPORTED;
    }
}

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
    CK_EDDSA_PARAMS       eddsaParams;
    CK_RV                 rv;
    SECURITY_STATUS       ss;
    BYTE                 *pbRawSig  = NULL;
    CK_ULONG              cbRawSig  = 0;
    BOOL                  bEcdsa;
    CK_OBJECT_HANDLE      hSigningKey;

    LOG_ENTER("KSP_SignHash");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pbHashValue || !pcbResult) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    /* Which object signs depends on the key class, and this used to assume
     * asymmetric unconditionally.
     *
     * An HMAC or CMAC key lives in hSecretKey and has no hPrivKey at all,
     * so the guard below rejected it outright — meaning HMAC signing, which
     * this provider has advertised since the mechanism work in session 4,
     * had never worked, and AES-CMAC was born broken in phase 5. No test
     * caught it: the unit suites check that HMAC resolves to the right
     * mechanism and never call KSP_SignHash with an HMAC key, so the gap
     * was not merely hidden by the mock — it was never covered at all.
     * Running against a real token is what surfaced it. */
    hSigningKey = (pKey->dwKeyClass == KSP_KEY_CLASS_SYMMETRIC)
                  ? pKey->hSecretKey : pKey->hPrivKey;

    if (!pKey->bFinalized || hSigningKey == CK_INVALID_HANDLE) {
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

    /* Ed448 requires CK_EDDSA_PARAMS and Ed25519 must not be given it.
     *
     * RFC 8032 defines five algorithms, not two. Ed25519 has a pure form
     * taking no context, so an absent parameter selects it and a present
     * one with phFlag false selects Ed25519ctx — a different scheme that
     * would produce signatures no Ed25519 verifier accepts. Ed448 has no
     * context-free form at all: its context is merely empty by default,
     * and a token given no parameter answers CKR_MECHANISM_PARAM_INVALID.
     *
     * The provider sent NULL for both, so Ed448 signing had never worked.
     * SoftHSM2 accepts the bare mechanism for both curves, which is why
     * nine sessions and a full mock suite never saw it. */
    if (mech.mechanism == CKM_EDDSA &&
        _wcsicmp(pKey->szAlgId, ALG_EDDSA_ED448) == 0) {
        memset(&eddsaParams, 0, sizeof(eddsaParams));
        eddsaParams.phFlag           = CK_FALSE;  /* pure Ed448, not Ed448ph */
        eddsaParams.ulContextDataLen = 0;
        eddsaParams.pContextData     = NULL;
        mech.pParameter     = &eddsaParams;
        mech.ulParameterLen = sizeof(eddsaParams);
    }

    bEcdsa = (mech.mechanism == CKM_ECDSA);

    /* A size query never starts a token operation — see KspSignatureLength. */
    if (pbSignature == NULL) {
        DWORD cbNeeded = 0;
        ss = KspSignatureLength(pKey, mech.mechanism, &cbNeeded);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_SignHash", ss);
            return ss;
        }
        *pcbResult = cbNeeded;
        LOG_LEAVE("KSP_SignHash", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    ss = P11_AcquireSession(&hSession);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    rv = pCtx->pFunctionList->C_SignInit(hSession, &mech, hSigningKey);
    if (rv != CKR_OK) {
        P11_ReleaseSession(hSession);
        ss = P11RvToSecStatus(rv);
        LOG_LEAVE("KSP_SignHash", ss);
        return ss;
    }

    ss = KeyContextLogin(pKey, hSession);
    if (ss != ERROR_SUCCESS) {
        P11_ReleaseSession(hSession);
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
        /* PKCS#11 v2.40 §2.3.1 is explicit: CKM_ECDSA returns r||s, each
         * padded to the length of the curve order. That is already CNG's
         * format, so a conformant token needs no conversion at all.
         *
         * This provider used to DER-decode unconditionally, on the belief
         * that SoftHSM2 returns DER. It does not — OSSLECDSA.cpp writes
         * BN_bn2bin(r) then BN_bn2bin(s) into a 2*len buffer — so the
         * conversion was parsing a raw signature as if it were a structure
         * and rejecting it. Against Kryoptic that surfaced as
         * NTE_INVALID_PARAMETER on every ECDSA signature; against SoftHSM2
         * it would have done the same, and no test caught it because the
         * mock returns whatever DER the test itself supplied.
         *
         * The DER path is kept as a fallback rather than deleted. It costs
         * one length comparison, and a token that returns the OpenSSL EVP
         * form instead of the PKCS#11 form is a thing that exists. */
        DWORD cbCoord = P11_EcCoordSize(pKey->szAlgId);
        DWORD cbRaw   = cbCoord * 2;

        if (cbCoord == 0) {
            KSP_Free(pbRawSig);
            LOG_LEAVE("KSP_SignHash", NTE_BAD_ALGID);
            return NTE_BAD_ALGID;
        }

        if ((DWORD)cbRawSig == cbRaw) {
            /* Conformant: already r||s. */
            if (cbSignature < cbRaw) {
                KSP_Free(pbRawSig);
                LOG_LEAVE("KSP_SignHash", NTE_BUFFER_TOO_SMALL);
                return NTE_BUFFER_TOO_SMALL;
            }
            memcpy(pbSignature, pbRawSig, cbRaw);
            *pcbResult = cbRaw;
            KSP_Free(pbRawSig);
            ss = ERROR_SUCCESS;
        } else {
            DWORD cbDecoded = cbSignature;
            LOG_INFO("ECDSA signature is %lu bytes, not the %lu this curve "
                     "implies — trying the DER form",
                     (unsigned long)cbRawSig, (unsigned long)cbRaw);
            ss = P11_DecodeDerEcdsaSignature(
                pKey->szAlgId, pbRawSig, (DWORD)cbRawSig,
                pbSignature, &cbDecoded);
            KSP_Free(pbRawSig);
            if (ss == ERROR_SUCCESS)
                *pcbResult = cbDecoded;
        }
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
    CK_CCM_PARAMS        ccmParams;
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
        /* On decryption CCM's ulDataLen is the PLAINTEXT length, which is
         * the ciphertext minus the MAC. */
        {
            const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO *pAuth =
                KspAuthModeInfo(pKey, pPaddingInfo);
            DWORD cbTag = (pAuth && pAuth->cbTag) ? pAuth->cbTag
                                                  : AES_GCM_TAG_BITS / 8;
            DWORD cbPlain = (cbInput > cbTag) ? (cbInput - cbTag) : 0;

            ss = KspBuildAesMechanism(pKey, dwFlags, pAuth, cbPlain,
                                      &mech, &gcmParams, &ctrParams,
                                      &ccmParams);
        }
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
    } else if (dwFlags & NCRYPT_NO_PADDING_FLAG) {
        /* Raw RSA — the modular exponentiation and nothing else.
         *
         * Gated on the probe, like ML-DSA: SoftHSM2 2.7.0 does not
         * implement CKM_RSA_X_509, so it never advertises it and this
         * branch stays dark there. The matrix recorded that as a backend
         * blocker, which stopped being a reason not to wire it the moment
         * the capability probe existed.
         *
         * No padding means no structure to check, so a caller gets exactly
         * what the token computes. That is the point of the flag and also
         * why it is dangerous: raw RSA is a signature-forgery primitive in
         * the wrong hands. CNG exposes it deliberately for protocols that
         * carry their own padding, and this provider passes it through
         * rather than deciding for the caller. */
        if (!P11_HasMechanism(CKM_RSA_X_509)) {
            LOG_ERROR("Raw RSA: the token does not implement CKM_RSA_X_509",
                      NTE_NOT_SUPPORTED);
            LOG_LEAVE("KSP_Decrypt", NTE_NOT_SUPPORTED);
            return NTE_NOT_SUPPORTED;
        }
        mech.mechanism = CKM_RSA_X_509;
        hDecryptKey = pKey->hPrivKey;
    } else {
        mech.mechanism = CKM_RSA_PKCS;
        hDecryptKey = pKey->hPrivKey;
    }

    /* A size query never starts a token operation. Same reasoning as
     * KspSignatureLength: C_Decrypt leaves its operation active when the
     * output buffer is absent or too small, and the session then goes back
     * into a SHARED pool carrying it.
     *
     * The plaintext length is not known until the padding comes off, so an
     * upper bound is reported. That is what a size query is for — the caller
     * learns how large a buffer to provide, and the real call reports the
     * exact length. For RSA the bound is the modulus; for a block cipher the
     * plaintext is never longer than the ciphertext. */
    if (pbOutput == NULL) {
        if (pKey->dwKeyClass == KSP_KEY_CLASS_SYMMETRIC) {
            *pcbResult = cbInput;
        } else {
            if (pKey->dwKeyBitLen == 0) {
                LOG_LEAVE("KSP_Decrypt", NTE_BAD_KEY);
                return NTE_BAD_KEY;
            }
            *pcbResult = pKey->dwKeyBitLen / 8;
        }
        LOG_LEAVE("KSP_Decrypt", ERROR_SUCCESS);
        return ERROR_SUCCESS;
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

    ss = KeyContextLogin(pKey, hSession);
    if (ss != ERROR_SUCCESS) {
        P11_ReleaseSession(hSession);
        LOG_LEAVE("KSP_Decrypt", ss);
        return ss;
    }

    /* First call: size */
    cbDecrypted = cbOutput;
    rv = pCtx->pFunctionList->C_Decrypt(
        hSession, pbInput, (CK_ULONG)cbInput,
        pbOutput, &cbDecrypted);

    /* A caller that ignored the size query and passed a short buffer leaves
     * the operation active. PKCS#11 v2.40 offers no way to cancel one, so it
     * is completed into a scratch buffer and the plaintext discarded —
     * otherwise this session poisons the next caller to draw it from the
     * pool. The cost falls only on the caller who skipped the size query. */
    if (rv == CKR_BUFFER_TOO_SMALL) {
        BYTE *pbScratch = (BYTE *)KSP_Alloc(cbDecrypted);
        if (pbScratch) {
            CK_ULONG cbScratch = cbDecrypted;
            (void)pCtx->pFunctionList->C_Decrypt(
                hSession, pbInput, (CK_ULONG)cbInput, pbScratch, &cbScratch);
            SecureZeroMemory(pbScratch, cbDecrypted);
            KSP_Free(pbScratch);
        }
        P11_ReleaseSession(hSession);
        *pcbResult = (DWORD)cbDecrypted;
        LOG_LEAVE("KSP_Decrypt", NTE_BUFFER_TOO_SMALL);
        return NTE_BUFFER_TOO_SMALL;
    }

    P11_ReleaseSession(hSession);

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
    P11_CONTEXT      *pCtx = P11_GetContext();
    KSP_KEY          *pKey;
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    BYTE             *pbBlob   = NULL;
    DWORD             cbBlob   = 0;
    SECURITY_STATUS   ss;
    CK_RV             rv;

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

    /* ML-DSA public keys are not exported, deliberately.
     *
     * The key material is available — CKA_VALUE on the public object — and
     * the sizes are fixed and known (P11_MlDsaPublicKeySize). What is not
     * known here is the layout CNG expects: the PQC public key blob and its
     * magic are declared in a Windows SDK bcrypt.h that this workspace has
     * no copy of, and no other source carries them. Wine, ReactOS and the
     * Rust winapi crate have no post-quantum names at all.
     *
     * Emitting a blob with a guessed header would be worse than refusing.
     * It would be accepted by our own tests, which read the same guess, and
     * rejected by Windows — which is precisely the failure this project
     * already had once, with BCRYPT_SHA224_ALGORITHM. Signing works without
     * export; verification against a CNG-side public key does not, and says
     * so here rather than at the point of a confusing parse error. */
    if (P11_MlDsaParameterSet(pKey->szAlgId) != 0) {
        LOG_ERROR("KSP_ExportKey - ML-DSA public key export needs the CNG "
                  "PQC blob layout, which is not available in this build",
                  NTE_NOT_SUPPORTED);
        LOG_LEAVE("KSP_ExportKey", NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
    }

    /* ── AES key wrap (RFC 3394 / 5649) ──────────────────────────────────
     *
     * The standard CNG route for key material to leave a token: the caller
     * supplies a key-encryption key in hExportKey and gets the target key
     * back wrapped under it. Nothing is ever in the clear.
     *
     * This does NOT weaken the non-extractable posture, and cannot. The
     * token decides: every key this provider creates is
     * CKA_EXTRACTABLE=FALSE, and C_WrapKey on such a key returns
     * CKR_KEY_UNEXTRACTABLE, which surfaces here as NTE_NOT_SUPPORTED. The
     * path is useful for a key this provider opened rather than created —
     * a token provisioned with extractable keys for migration — and for
     * that case only. */
    if (_wcsicmp(pszBlobType, BCRYPT_AES_WRAP_KEY_BLOB) == 0) {
        KSP_KEY         *pKek;
        CK_OBJECT_HANDLE hTarget;
        CK_MECHANISM     mech = { CKM_AES_KEY_WRAP, NULL, 0 };
        CK_ULONG         cbWrapped = 0;

        if (!KSP_IsValidKey(hExportKey)) {
            LOG_ERROR("KSP_ExportKey - AES key wrap needs a wrapping key in "
                      "hExportKey", NTE_INVALID_PARAMETER);
            LOG_LEAVE("KSP_ExportKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        pKek = (KSP_KEY *)(ULONG_PTR)hExportKey;
        if (_wcsicmp(pKek->szAlgId, ALG_AES) != 0 ||
            pKek->hSecretKey == CK_INVALID_HANDLE) {
            LOG_ERROR("KSP_ExportKey - the wrapping key must be a finalised "
                      "AES key", NTE_BAD_KEY);
            LOG_LEAVE("KSP_ExportKey", NTE_BAD_KEY);
            return NTE_BAD_KEY;
        }

        if (!P11_HasMechanism(CKM_AES_KEY_WRAP)) {
            LOG_ERROR("KSP_ExportKey - the token does not implement "
                      "CKM_AES_KEY_WRAP", NTE_NOT_SUPPORTED);
            LOG_LEAVE("KSP_ExportKey", NTE_NOT_SUPPORTED);
            return NTE_NOT_SUPPORTED;
        }

        /* A symmetric key wraps its secret object; an asymmetric one wraps
         * its private key. The public half needs no protection. */
        hTarget = (pKey->dwKeyClass == KSP_KEY_CLASS_SYMMETRIC)
                  ? pKey->hSecretKey : pKey->hPrivKey;
        if (hTarget == CK_INVALID_HANDLE) {
            LOG_LEAVE("KSP_ExportKey", NTE_BAD_KEY);
            return NTE_BAD_KEY;
        }

        ss = P11_AcquireSession(&hSession);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_ExportKey", ss);
            return ss;
        }

        rv = pCtx->pFunctionList->C_WrapKey(hSession, &mech,
                                            pKek->hSecretKey, hTarget,
                                            NULL, &cbWrapped);
        if (rv != CKR_OK) {
            P11_ReleaseSession(hSession);
            ss = P11RvToSecStatus(rv);
            /* CKR_KEY_UNEXTRACTABLE is the expected answer for any key this
             * provider generated, and is not a defect. */
            LOG_ERROR("KSP_ExportKey - C_WrapKey (size)", ss);
            LOG_LEAVE("KSP_ExportKey", ss);
            return ss;
        }

        *pcbResult = (DWORD)cbWrapped;

        if (!pbOutput) {
            P11_ReleaseSession(hSession);
            LOG_LEAVE("KSP_ExportKey", ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }

        if (cbOutput < (DWORD)cbWrapped) {
            P11_ReleaseSession(hSession);
            LOG_LEAVE("KSP_ExportKey", NTE_BUFFER_TOO_SMALL);
            return NTE_BUFFER_TOO_SMALL;
        }

        rv = pCtx->pFunctionList->C_WrapKey(hSession, &mech,
                                            pKek->hSecretKey, hTarget,
                                            pbOutput, &cbWrapped);
        P11_ReleaseSession(hSession);

        if (rv != CKR_OK) {
            ss = P11RvToSecStatus(rv);
            LOG_LEAVE("KSP_ExportKey", ss);
            return ss;
        }

        *pcbResult = (DWORD)cbWrapped;
        LOG_LEAVE("KSP_ExportKey", ERROR_SUCCESS);
        return ERROR_SUCCESS;
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
        /* Edwards and Montgomery points are raw bytes, not X9.62. Sending
         * them to the Weierstrass parser is not merely a rejection: a raw
         * key whose first byte happens to be 0x04 parses as an
         * uncompressed point and yields a well-formed blob of nonsense,
         * roughly one key in 256. Dispatch on the curve family. */
        if (KSP_IsEddsaAlg(pKey->szAlgId) ||
            KSP_IsMontgomeryAlg(pKey->szAlgId)) {
            ss = P11_ExportEddsaPublicKey(hSession, pKey->hPubKey,
                                          pKey->szAlgId, &pbBlob, &cbBlob);
        } else {
            ss = P11_ExportEcPublicKey(hSession, pKey->hPubKey,
                                       &pbBlob, &cbBlob);
        }
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

    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_ImportKey");

    if (!KSP_IsValidProvider(hProvider) || !phKey || !pbData) {
        LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    /* ── AES key unwrap (RFC 3394 / 5649) ────────────────────────────────
     *
     * The useful half of key wrap, and the one that does not depend on the
     * token having been provisioned with extractable keys: an AES key
     * arrives wrapped under a key-encryption key already on the token, and
     * C_UnwrapKey decrypts it inside the token. The plaintext key never
     * exists outside it.
     *
     * The unwrapped key is created CKA_SENSITIVE / not extractable, so a
     * key that arrives this way cannot then be exported in the clear.
     * Wrapping is a way in, not a way back out. */
    if (_wcsicmp(pszBlobType, BCRYPT_AES_WRAP_KEY_BLOB) == 0) {
        KSP_KEY         *pKek;
        CK_MECHANISM     mech = { CKM_AES_KEY_WRAP, NULL, 0 };
        CK_OBJECT_CLASS  classSecret = CKO_SECRET_KEY;
        CK_KEY_TYPE      keyTypeAes  = CKK_AES;
        CK_OBJECT_HANDLE hNew = CK_INVALID_HANDLE;

        if (!KSP_IsValidKey(hImportKey)) {
            LOG_ERROR("KSP_ImportKey - AES key unwrap needs an unwrapping key "
                      "in hImportKey", NTE_INVALID_PARAMETER);
            LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        pKek = (KSP_KEY *)(ULONG_PTR)hImportKey;
        if (_wcsicmp(pKek->szAlgId, ALG_AES) != 0 ||
            pKek->hSecretKey == CK_INVALID_HANDLE) {
            LOG_ERROR("KSP_ImportKey - the unwrapping key must be a finalised "
                      "AES key", NTE_BAD_KEY);
            LOG_LEAVE("KSP_ImportKey", NTE_BAD_KEY);
            return NTE_BAD_KEY;
        }

        if (!P11_HasMechanism(CKM_AES_KEY_WRAP)) {
            LOG_ERROR("KSP_ImportKey - the token does not implement "
                      "CKM_AES_KEY_WRAP", NTE_NOT_SUPPORTED);
            LOG_LEAVE("KSP_ImportKey", NTE_NOT_SUPPORTED);
            return NTE_NOT_SUPPORTED;
        }

        {
            CK_ATTRIBUTE aTemplate[] = {
                { CKA_CLASS,       &classSecret, sizeof(classSecret) },
                { CKA_KEY_TYPE,    &keyTypeAes,  sizeof(keyTypeAes)  },
                { CKA_TOKEN,       &bFalse,      sizeof(bFalse)      },
                { CKA_SENSITIVE,   &bTrue,       sizeof(bTrue)       },
                { CKA_EXTRACTABLE, &bFalse,      sizeof(bFalse)      },
                { CKA_ENCRYPT,     &bTrue,       sizeof(bTrue)       },
                { CKA_DECRYPT,     &bTrue,       sizeof(bTrue)       },
            };

            ss = P11_AcquireSession(&hSession);
            if (ss != ERROR_SUCCESS) {
                LOG_LEAVE("KSP_ImportKey", ss);
                return ss;
            }

            rv = pCtx->pFunctionList->C_UnwrapKey(
                hSession, &mech, pKek->hSecretKey,
                pbData, (CK_ULONG)cbData,
                aTemplate,
                (CK_ULONG)(sizeof(aTemplate) / sizeof(CK_ATTRIBUTE)),
                &hNew);

            P11_ReleaseSession(hSession);
        }

        if (rv != CKR_OK) {
            ss = P11RvToSecStatus(rv);
            LOG_ERROR("KSP_ImportKey - C_UnwrapKey", ss);
            LOG_LEAVE("KSP_ImportKey", ss);
            return ss;
        }

        pKey = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
        if (!pKey) {
            LOG_LEAVE("KSP_ImportKey", NTE_NO_MEMORY);
            return NTE_NO_MEMORY;
        }

        pKey->dwMagic        = KSP_KEY_MAGIC;
        pKey->hSecretKey     = hNew;
        pKey->hPubKey        = CK_INVALID_HANDLE;
        pKey->hPrivKey       = CK_INVALID_HANDLE;
        pKey->bFinalized     = TRUE;
        pKey->bSessionObject = TRUE;
        pKey->dwKeyClass     = KSP_KEY_CLASS_SYMMETRIC;
        wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, ALG_AES);

        *phKey = (NCRYPT_KEY_HANDLE)(ULONG_PTR)pKey;
        LOG_LEAVE("KSP_ImportKey", ERROR_SUCCESS);
        return ERROR_SUCCESS;
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
        BOOL         bRawPoint;
        BOOL         bAgree = FALSE;

        if (cbData < sizeof(BCRYPT_ECCKEY_BLOB)) {
            LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        cbCoord = pEcc->cbKey;

        /* Edwards and Montgomery keys are a single raw string, not a pair
         * of coordinates, and the generic magics are what say so. The size
         * alone cannot: an X25519 key and a P-256 coordinate are both 32
         * bytes, so reading cbKey and nothing else identified every X25519
         * key as P-256 and then rejected it for being half a point.
         * X25519 and Ed25519 are 32 bytes each as well, so the ECDH and
         * ECDSA generic magics are the only thing separating those two. */
        bRawPoint = (pEcc->dwMagic == BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC ||
                     pEcc->dwMagic == BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC);

        if (bRawPoint) {
            if (cbData < sizeof(BCRYPT_ECCKEY_BLOB) + cbCoord) {
                LOG_LEAVE("KSP_ImportKey", NTE_INVALID_PARAMETER);
                return NTE_INVALID_PARAMETER;
            }

            if (pEcc->dwMagic == BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC &&
                cbCoord == EC_X25519_COORD_SIZE) {
                wcscpy_s(szAlg, MAX_ALG_ID_LEN, ALG_ECDH_X25519);
                dwBits = 255; keyType = CKK_EC_MONTGOMERY; bAgree = TRUE;
            } else if (pEcc->dwMagic == BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC &&
                       cbCoord == ED25519_PUBKEY_SIZE) {
                wcscpy_s(szAlg, MAX_ALG_ID_LEN, ALG_EDDSA_ED25519);
                dwBits = 255; keyType = CKK_EC_EDWARDS; bAgree = FALSE;
            } else if (pEcc->dwMagic == BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC &&
                       cbCoord == ED448_PUBKEY_SIZE) {
                wcscpy_s(szAlg, MAX_ALG_ID_LEN, ALG_EDDSA_ED448);
                dwBits = 448; keyType = CKK_EC_EDWARDS; bAgree = FALSE;
            } else {
                LOG_LEAVE("KSP_ImportKey", NTE_BAD_ALGID);
                return NTE_BAD_ALGID;
            }
        } else {
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
        }

        pbOid = P11_GetCurveOid(szAlg, &cbOid);
        if (!pbOid) {
            LOG_LEAVE("KSP_ImportKey", NTE_BAD_ALGID);
            return NTE_BAD_ALGID;
        }

        if (bRawPoint) {
            /* CKA_EC_POINT = DER OCTET STRING { raw key } — no 0x04 */
            ss = P11_BuildRawEcPointDer(pbData + sizeof(BCRYPT_ECCKEY_BLOB),
                                        cbCoord, &pbDer, &cbDer);
        } else {
            /* Build CKA_EC_POINT = DER OCTET STRING { 04 || X || Y } */
            ss = P11_BuildEcPointDer(
                    pbData + sizeof(BCRYPT_ECCKEY_BLOB),
                    pbData + sizeof(BCRYPT_ECCKEY_BLOB) + cbCoord,
                    cbCoord, &pbDer, &cbDer);
        }
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
                /* A Montgomery key may not verify and an Edwards key may
                 * not derive; a strict token refuses the template outright
                 * rather than ignoring the attribute it cannot honour. */
                { CKA_VERIFY,    bAgree ? &bFalse : &bTrue, sizeof(bTrue) },
                { CKA_DERIVE,    (bAgree || !bRawPoint) ? &bTrue : &bFalse,
                                 sizeof(bTrue) },
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
    CK_CCM_PARAMS     ccmParams;
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

    ss = KspBuildAesMechanism(pKey, dwFlags,
                              KspAuthModeInfo(pKey, pPaddingInfo), cbInput,
                              &mech, &gcmParams, &ctrParams, &ccmParams);
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_Encrypt", ss);
        return ss;
    }

    /* A size query never starts a token operation — same reasoning as
     * KspSignatureLength and KSP_Decrypt.
     *
     * One AES block of headroom covers every mode this provider offers:
     * CBC_PAD adds at most a full block of padding, GCM appends a 16-byte
     * tag, and ECB/CBC/CTR add nothing. */
    if (pbOutput == NULL) {
        *pcbResult = cbInput + AES_BLOCK_SIZE;
        LOG_LEAVE("KSP_Encrypt", ERROR_SUCCESS);
        return ERROR_SUCCESS;
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

    /* As in KSP_Decrypt: a short buffer leaves the operation active, and a
     * pooled session must not be returned carrying one. */
    if (rv == CKR_BUFFER_TOO_SMALL) {
        BYTE *pbScratch = (BYTE *)KSP_Alloc(cbEncrypted);
        if (pbScratch) {
            CK_ULONG cbScratch = cbEncrypted;
            (void)pCtx->pFunctionList->C_Encrypt(
                hSession, pbInput, (CK_ULONG)cbInput, pbScratch, &cbScratch);
            KSP_Free(pbScratch);
        }
        P11_ReleaseSession(hSession);
        *pcbResult = (DWORD)cbEncrypted;
        LOG_LEAVE("KSP_Encrypt", NTE_BUFFER_TOO_SMALL);
        return NTE_BUFFER_TOO_SMALL;
    }

    P11_ReleaseSession(hSession);

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

/* The HMAC mechanism matching a digest mechanism. */
static CK_MECHANISM_TYPE KdfHmacMech(CK_MECHANISM_TYPE digest)
{
    switch (digest) {
    case CKM_SHA_1:  return CKM_SHA_1_HMAC;
    case CKM_SHA224: return CKM_SHA224_HMAC;
    case CKM_SHA256: return CKM_SHA256_HMAC;
    case CKM_SHA384: return CKM_SHA384_HMAC;
    case CKM_SHA512: return CKM_SHA512_HMAC;
    default:         return 0;
    }
}

/* Find the first buffer of a type; returns FALSE when absent. */
static BOOL KdfFindBuffer(NCryptBufferDesc *pParams, ULONG ulType,
                          BYTE **ppb, DWORD *pcb)
{
    ULONG i;
    if (!pParams || !pParams->pBuffers)
        return FALSE;
    for (i = 0; i < pParams->cBuffers; i++) {
        if (pParams->pBuffers[i].BufferType == ulType) {
            *ppb = (BYTE *)pParams->pBuffers[i].pvBuffer;
            *pcb = (DWORD)pParams->pBuffers[i].cbBuffer;
            return TRUE;
        }
    }
    return FALSE;
}

/* Concatenate every buffer of one type into pbOut, in the order given.
 * Returns FALSE if they do not fit. */
static BOOL KdfConcatBuffers(NCryptBufferDesc *pParams, ULONG ulType,
                             BYTE *pbOut, DWORD cbOut, DWORD *pcbUsed)
{
    ULONG i;

    if (!pParams || !pParams->pBuffers)
        return TRUE;

    for (i = 0; i < pParams->cBuffers; i++) {
        DWORD cb;
        if (pParams->pBuffers[i].BufferType != ulType)
            continue;
        if (!pParams->pBuffers[i].pvBuffer)
            continue;
        cb = (DWORD)pParams->pBuffers[i].cbBuffer;
        if (cb == 0)
            continue;
        if (*pcbUsed + cb > cbOut)
            return FALSE;
        memcpy(pbOut + *pcbUsed, pParams->pBuffers[i].pvBuffer, cb);
        *pcbUsed += cb;
    }
    return TRUE;
}

/* One HMAC, with the key supplied as raw bytes.
 *
 * PKCS#11 has no "HMAC these bytes with that key" call: the key has to be
 * an object first. So each HMAC here is C_CreateObject, C_SignInit,
 * C_Sign, C_DestroyObject. The object is a session object and is destroyed
 * even when signing fails, or a long HKDF expansion would litter the token
 * with one generic secret per iteration. */
static CK_RV KdfHmac(P11_CONTEXT *pCtx, CK_SESSION_HANDLE hSession,
                     CK_MECHANISM_TYPE hmacMech,
                     const BYTE *pbKey, DWORD cbKey,
                     const BYTE *pbData, DWORD cbData,
                     BYTE *pbOut, CK_ULONG *pcbOut)
{
    CK_OBJECT_CLASS  cls     = CKO_SECRET_KEY;
    CK_KEY_TYPE      keyType = CKK_GENERIC_SECRET;
    CK_BBOOL         bTrue   = CK_TRUE;
    CK_BBOOL         bFalse  = CK_FALSE;
    CK_OBJECT_HANDLE hKey    = CK_INVALID_HANDLE;
    CK_MECHANISM     mech;
    CK_RV            rv;
    BYTE             abEmpty[1] = { 0 };

    CK_ATTRIBUTE aTemplate[] = {
        { CKA_CLASS,     &cls,     sizeof(cls)     },
        { CKA_KEY_TYPE,  &keyType, sizeof(keyType) },
        { CKA_TOKEN,     &bFalse,  sizeof(bFalse)  },
        { CKA_SIGN,      &bTrue,   sizeof(bTrue)   },
        { CKA_VALUE,     (CK_VOID_PTR)pbKey, cbKey },
    };

    /* A zero-length HMAC key is legal in RFC 5869 (an absent salt), but
     * PKCS#11 tokens differ on whether they accept CKA_VALUE of length 0.
     * One zero byte is the same key under HMAC's padding rules. */
    if (cbKey == 0) {
        aTemplate[4].pValue     = abEmpty;
        aTemplate[4].ulValueLen = 1;
    }

    rv = pCtx->pFunctionList->C_CreateObject(
            hSession, aTemplate,
            (CK_ULONG)(sizeof(aTemplate) / sizeof(CK_ATTRIBUTE)), &hKey);
    if (rv != CKR_OK)
        return rv;

    memset(&mech, 0, sizeof(mech));
    mech.mechanism = hmacMech;

    rv = pCtx->pFunctionList->C_SignInit(hSession, &mech, hKey);
    if (rv == CKR_OK)
        rv = pCtx->pFunctionList->C_Sign(hSession,
                (CK_BYTE_PTR)pbData, cbData, pbOut, pcbOut);

    (void)pCtx->pFunctionList->C_DestroyObject(hSession, hKey);
    return rv;
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

    /* BCRYPT_KDF_HMAC — HMAC(key, prepend || Z || append).
     *
     * The key comes from a KDF_HMAC_KEY buffer. CNG also defines
     * KDF_USE_SECRET_AS_HMAC_KEY_FLAG, which makes Z the key and removes it
     * from the message; that is honoured here because the alternative is
     * silently computing something different from what the caller asked
     * for. */
    if (pwszKDF && _wcsicmp(pwszKDF, BCRYPT_KDF_HMAC) == 0) {
        P11_CONTEXT      *pCtx = P11_GetContext();
        CK_MECHANISM_TYPE digestMech, hmacMech;
        DWORD             cbDigest = 0;
        BYTE             *pbHmacKey = NULL;
        DWORD             cbHmacKey = 0;
        BYTE              abMsg[1024];
        DWORD             cbMsg = 0;
        BYTE              abMac[64];
        CK_ULONG          ulMac = sizeof(abMac);
        BOOL              bSecretAsKey;
        CK_RV             rv;

        ss = KdfFindHashMech(pParameterList, &digestMech, &cbDigest);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }
        hmacMech = KdfHmacMech(digestMech);

        bSecretAsKey = (dwFlags & KDF_USE_SECRET_AS_HMAC_KEY_FLAG) != 0;
        (void)KdfFindBuffer(pParameterList, KDF_HMAC_KEY,
                            &pbHmacKey, &cbHmacKey);

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

        /* Message: prepend || Z || append, with Z omitted when it is
         * serving as the key instead. */
        if (!KdfConcatBuffers(pParameterList, KDF_SECRET_PREPEND,
                              abMsg, sizeof(abMsg), &cbMsg)) {
            goto hmac_too_long;
        }
        if (!bSecretAsKey) {
            if (cbMsg + cbValue > sizeof(abMsg))
                goto hmac_too_long;
            memcpy(abMsg + cbMsg, pbValue, cbValue);
            cbMsg += cbValue;
        }
        if (!KdfConcatBuffers(pParameterList, KDF_SECRET_APPEND,
                              abMsg, sizeof(abMsg), &cbMsg)) {
            goto hmac_too_long;
        }

        rv = KdfHmac(pCtx, hSession, hmacMech,
                     bSecretAsKey ? pbValue : pbHmacKey,
                     bSecretAsKey ? cbValue : cbHmacKey,
                     abMsg, cbMsg, abMac, &ulMac);

        P11_ReleaseSession(hSession);
        SecureZeroMemory(pbValue, cbValue);
        KSP_Free(pbValue);
        SecureZeroMemory(abMsg, sizeof(abMsg));

        if (rv != CKR_OK) {
            SecureZeroMemory(abMac, sizeof(abMac));
            ss = P11RvToSecStatus(rv);
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }

        if (ulMac > cbDigest)
            ulMac = cbDigest;
        memcpy(pbDerivedKey, abMac, ulMac);
        *pcbResult = (DWORD)ulMac;
        SecureZeroMemory(abMac, sizeof(abMac));

        LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
        return ERROR_SUCCESS;

    hmac_too_long:
        P11_ReleaseSession(hSession);
        SecureZeroMemory(pbValue, cbValue);
        KSP_Free(pbValue);
        SecureZeroMemory(abMsg, sizeof(abMsg));
        LOG_LEAVE("KSP_DeriveKey", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    /* BCRYPT_KDF_HKDF — RFC 5869.
     *
     *   PRK    = HMAC(salt, Z)                               extract
     *   T(i)   = HMAC(PRK, T(i-1) || info || byte(i))        expand
     *   OKM    = T(1) || T(2) || ... truncated to the request
     *
     * Unlike the hash KDF this is keyed, so every step goes through
     * KdfHmac and its create/sign/destroy cycle. */
    if (pwszKDF && _wcsicmp(pwszKDF, BCRYPT_KDF_HKDF) == 0) {
        P11_CONTEXT      *pCtx = P11_GetContext();
        CK_MECHANISM_TYPE digestMech, hmacMech;
        DWORD             cbDigest = 0;
        BYTE             *pbSalt = NULL, *pbInfo = NULL;
        DWORD             cbSalt = 0,    cbInfo = 0;
        BYTE              abPrk[64];
        BYTE              abT[64];
        BYTE              abBlock[64 + 256 + 1];
        CK_ULONG          ulOut;
        DWORD             cbDone = 0;
        BYTE              nCounter;
        CK_RV             rv;

        ss = KdfFindHashMech(pParameterList, &digestMech, &cbDigest);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }
        hmacMech = KdfHmacMech(digestMech);

        (void)KdfFindBuffer(pParameterList, KDF_HKDF_SALT, &pbSalt, &cbSalt);
        (void)KdfFindBuffer(pParameterList, KDF_HKDF_INFO, &pbInfo, &cbInfo);

        /* RFC 5869 allows any output length up to 255 * HashLen. */
        if (cbInfo > 256) {
            LOG_LEAVE("KSP_DeriveKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        /* Size query: HKDF produces whatever the caller asks for, so
         * without a buffer there is no length to report beyond one block. */
        if (pbDerivedKey == NULL) {
            *pcbResult = cbDigest;
            LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }
        if (cbDerivedKey > 255 * cbDigest) {
            LOG_LEAVE("KSP_DeriveKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
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

        /* Extract. An absent salt is HashLen zero bytes per RFC 5869; a
         * zero-length CKA_VALUE is handled inside KdfHmac. */
        ulOut = sizeof(abPrk);
        rv = KdfHmac(pCtx, hSession, hmacMech, pbSalt, cbSalt,
                     pbValue, cbValue, abPrk, &ulOut);

        SecureZeroMemory(pbValue, cbValue);
        KSP_Free(pbValue);
        pbValue = NULL;

        /* Expand. */
        nCounter = 1;
        while (rv == CKR_OK && cbDone < cbDerivedKey) {
            DWORD cbBlock = 0;
            DWORD cbCopy;

            /* T(i-1) is empty on the first round. */
            if (cbDone > 0) {
                memcpy(abBlock, abT, cbDigest);
                cbBlock = cbDigest;
            }
            if (cbInfo && pbInfo) {
                memcpy(abBlock + cbBlock, pbInfo, cbInfo);
                cbBlock += cbInfo;
            }
            abBlock[cbBlock++] = nCounter;

            ulOut = sizeof(abT);
            rv = KdfHmac(pCtx, hSession, hmacMech, abPrk, cbDigest,
                         abBlock, cbBlock, abT, &ulOut);
            if (rv != CKR_OK)
                break;

            cbCopy = cbDerivedKey - cbDone;
            if (cbCopy > cbDigest)
                cbCopy = cbDigest;
            memcpy(pbDerivedKey + cbDone, abT, cbCopy);
            cbDone += cbCopy;
            nCounter++;
        }

        P11_ReleaseSession(hSession);
        SecureZeroMemory(abPrk,   sizeof(abPrk));
        SecureZeroMemory(abT,     sizeof(abT));
        SecureZeroMemory(abBlock, sizeof(abBlock));

        if (rv != CKR_OK) {
            SecureZeroMemory(pbDerivedKey, cbDerivedKey);
            ss = P11RvToSecStatus(rv);
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }

        *pcbResult = cbDone;
        LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    /* BCRYPT_KDF_TLS_PRF — the TLS 1.2 PRF (RFC 5246 §5).
     *
     *   A(0)   = label || seed
     *   A(i)   = HMAC(secret, A(i-1))
     *   output = HMAC(secret, A(1) || label || seed) ||
     *            HMAC(secret, A(2) || label || seed) || ...
     *
     * TLS 1.0 and 1.1 used a different construction: the secret split in
     * half, P_MD5 of one half XORed with P_SHA1 of the other. That is NOT
     * implemented, and deliberately so — both protocol versions are
     * deprecated by RFC 8996, and the construction exists only to use MD5.
     * A caller asking for them gets NTE_NOT_SUPPORTED rather than a
     * silently different key. */
    if (pwszKDF && _wcsicmp(pwszKDF, BCRYPT_KDF_TLS_PRF) == 0) {
        P11_CONTEXT      *pCtx = P11_GetContext();
        CK_MECHANISM_TYPE digestMech, hmacMech;
        DWORD             cbDigest = 0;
        BYTE             *pbLabel = NULL, *pbSeed = NULL, *pbProto = NULL;
        DWORD             cbLabel = 0,    cbSeed = 0,     cbProto = 0;
        BYTE              abSeed[256];      /* label || seed */
        DWORD             cbFullSeed = 0;
        BYTE              abA[64];
        CK_ULONG          ulA;
        BYTE              abBlock[64 + 256];
        BYTE              abOut[64];
        CK_ULONG          ulOut;
        DWORD             cbDone = 0;
        CK_RV             rv;

        ss = KdfFindHashMech(pParameterList, &digestMech, &cbDigest);
        if (ss != ERROR_SUCCESS) {
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }
        hmacMech = KdfHmacMech(digestMech);

        /* Refuse the legacy versions explicitly. The protocol buffer is a
         * little-endian USHORT: 0x0303 is TLS 1.2, below that is older. */
        if (KdfFindBuffer(pParameterList, KDF_TLS_PRF_PROTOCOL,
                          &pbProto, &cbProto) &&
            pbProto && cbProto >= 2) {
            DWORD dwProto = (DWORD)pbProto[0] | ((DWORD)pbProto[1] << 8);
            if (dwProto < 0x0303) {
                LOG_ERROR("KSP_DeriveKey - TLS below 1.2 uses the MD5/SHA-1 "
                          "split PRF and is not implemented (RFC 8996)",
                          NTE_NOT_SUPPORTED);
                LOG_LEAVE("KSP_DeriveKey", NTE_NOT_SUPPORTED);
                return NTE_NOT_SUPPORTED;
            }
        }

        (void)KdfFindBuffer(pParameterList, KDF_TLS_PRF_LABEL,
                            &pbLabel, &cbLabel);
        (void)KdfFindBuffer(pParameterList, KDF_TLS_PRF_SEED,
                            &pbSeed, &cbSeed);

        if (cbLabel + cbSeed > sizeof(abSeed)) {
            LOG_LEAVE("KSP_DeriveKey", NTE_INVALID_PARAMETER);
            return NTE_INVALID_PARAMETER;
        }

        if (pbDerivedKey == NULL) {
            *pcbResult = cbDigest;
            LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
            return ERROR_SUCCESS;
        }

        if (pbLabel && cbLabel) {
            memcpy(abSeed, pbLabel, cbLabel);
            cbFullSeed = cbLabel;
        }
        if (pbSeed && cbSeed) {
            memcpy(abSeed + cbFullSeed, pbSeed, cbSeed);
            cbFullSeed += cbSeed;
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

        /* A(1) = HMAC(secret, A(0)) where A(0) is label || seed. */
        ulA = sizeof(abA);
        rv = KdfHmac(pCtx, hSession, hmacMech, pbValue, cbValue,
                     abSeed, cbFullSeed, abA, &ulA);

        while (rv == CKR_OK && cbDone < cbDerivedKey) {
            DWORD cbCopy;

            memcpy(abBlock, abA, cbDigest);
            memcpy(abBlock + cbDigest, abSeed, cbFullSeed);

            ulOut = sizeof(abOut);
            rv = KdfHmac(pCtx, hSession, hmacMech, pbValue, cbValue,
                         abBlock, cbDigest + cbFullSeed, abOut, &ulOut);
            if (rv != CKR_OK)
                break;

            cbCopy = cbDerivedKey - cbDone;
            if (cbCopy > cbDigest)
                cbCopy = cbDigest;
            memcpy(pbDerivedKey + cbDone, abOut, cbCopy);
            cbDone += cbCopy;

            if (cbDone < cbDerivedKey) {
                /* A(i+1) = HMAC(secret, A(i)) */
                ulA = sizeof(abA);
                rv = KdfHmac(pCtx, hSession, hmacMech, pbValue, cbValue,
                             abA, cbDigest, abA, &ulA);
            }
        }

        P11_ReleaseSession(hSession);
        SecureZeroMemory(pbValue, cbValue);
        KSP_Free(pbValue);
        SecureZeroMemory(abA,     sizeof(abA));
        SecureZeroMemory(abBlock, sizeof(abBlock));
        SecureZeroMemory(abOut,   sizeof(abOut));
        SecureZeroMemory(abSeed,  sizeof(abSeed));

        if (rv != CKR_OK) {
            SecureZeroMemory(pbDerivedKey, cbDerivedKey);
            ss = P11RvToSecStatus(rv);
            LOG_LEAVE("KSP_DeriveKey", ss);
            return ss;
        }

        *pcbResult = cbDone;
        LOG_LEAVE("KSP_DeriveKey", ERROR_SUCCESS);
        return ERROR_SUCCESS;
    }

    /* Anything else: only the raw secret is available. */
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
