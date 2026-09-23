/* ksp_key_stub.c — Minimal key-layer stubs
 * Used by test_ksp_key_props when ksp_key.c is not linked. Mirrors the
 * real handle validation and algorithm classifiers from ksp_key.c.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "../../src/ksp/ksp_key.h"
#include <string.h>
#include <wchar.h>

BOOL KSP_IsValidKey(NCRYPT_KEY_HANDLE hKey)
{
    KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
    return (k && k->dwMagic == KSP_KEY_MAGIC);
}

BOOL KSP_IsEcdsaAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
            _wcsicmp(pszAlgId, ALG_ECDSA_P521) == 0);
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

/* Certificate storage — recorded rather than performed, so the property
 * suite can assert that KSP_SetKeyProperty routed the blob correctly
 * without linking the whole key layer. test_certificate.c exercises the
 * real implementation. */
BYTE  g_stubCert[4096];
DWORD g_cbStubCert = 0;
SECURITY_STATUS g_ssStubStore = ERROR_SUCCESS;

SECURITY_STATUS KSP_StoreCertificate(KSP_KEY *pKey,
                                     const BYTE *pbCert, DWORD cbCert)
{
    (void)pKey;
    if (g_ssStubStore != ERROR_SUCCESS) return g_ssStubStore;
    if (!pbCert || cbCert == 0 || cbCert > sizeof(g_stubCert))
        return NTE_INVALID_PARAMETER;
    memcpy(g_stubCert, pbCert, cbCert);
    g_cbStubCert = cbCert;
    return ERROR_SUCCESS;
}

SECURITY_STATUS KSP_LoadCertificate(KSP_KEY *pKey, PBYTE pbOutput,
                                    DWORD cbOutput, DWORD *pcbResult)
{
    (void)pKey;
    if (!pcbResult) return NTE_INVALID_PARAMETER;
    if (g_cbStubCert == 0) return NTE_NOT_FOUND;
    *pcbResult = g_cbStubCert;
    if (pbOutput) {
        if (cbOutput < g_cbStubCert) return NTE_BUFFER_TOO_SMALL;
        memcpy(pbOutput, g_stubCert, g_cbStubCert);
    }
    return ERROR_SUCCESS;
}

BOOL KSP_IsMlDsaAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_MLDSA_44) == 0 ||
            _wcsicmp(pszAlgId, ALG_MLDSA_65) == 0 ||
            _wcsicmp(pszAlgId, ALG_MLDSA_87) == 0);
}

BOOL KSP_IsSymmetricAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_AES)         == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA1)   == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA256) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA384) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA512) == 0);
}

/* The curve-name property resolves a generic ECC key through these two.
 * Mirrors the real mapping for the curves this suite exercises. */
DWORD KSP_DefaultKeyBits(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return 0;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P256)  == 0) return 256;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P384)  == 0) return 384;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_P521) == 0 ||
        _wcsicmp(pszAlgId, ALG_ECDH_P521)  == 0) return 521;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_SECP256K1) == 0) return 256;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_BP256) == 0)     return 256;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_BP384) == 0)     return 384;
    if (_wcsicmp(pszAlgId, ALG_ECDSA_BP512) == 0)     return 512;
    if (_wcsicmp(pszAlgId, ALG_ECDH_X25519) == 0)     return 255;
    return 2048;
}

LPCWSTR P11_CurveNameToAlgId(LPCWSTR pszCurveName, BOOL bAgreement)
{
    if (!pszCurveName) return NULL;
    if (_wcsicmp(pszCurveName, BCRYPT_ECC_CURVE_NISTP256) == 0)
        return bAgreement ? ALG_ECDH_P256 : ALG_ECDSA_P256;
    if (_wcsicmp(pszCurveName, BCRYPT_ECC_CURVE_NISTP384) == 0)
        return bAgreement ? ALG_ECDH_P384 : ALG_ECDSA_P384;
    if (_wcsicmp(pszCurveName, BCRYPT_ECC_CURVE_NISTP521) == 0)
        return bAgreement ? ALG_ECDH_P521 : ALG_ECDSA_P521;
    if (_wcsicmp(pszCurveName, BCRYPT_ECC_CURVE_25519) == 0)
        return bAgreement ? ALG_ECDH_X25519 : NULL;
    if (_wcsicmp(pszCurveName, BCRYPT_ECC_CURVE_SECP256K1) == 0)
        return bAgreement ? NULL : ALG_ECDSA_SECP256K1;
    if (_wcsicmp(pszCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP256R1) == 0)
        return bAgreement ? NULL : ALG_ECDSA_BP256;
    if (_wcsicmp(pszCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP384R1) == 0)
        return bAgreement ? NULL : ALG_ECDSA_BP384;
    if (_wcsicmp(pszCurveName, BCRYPT_ECC_CURVE_BRAINPOOLP512R1) == 0)
        return bAgreement ? NULL : ALG_ECDSA_BP512;
    return NULL;
}
