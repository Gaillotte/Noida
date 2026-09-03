/* ksp_key_stub.c — Minimal key-layer stubs
 * Used by test_ksp_key_props when ksp_key.c is not linked. Mirrors the
 * real handle validation and algorithm classifiers from ksp_key.c.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "../../src/ksp/ksp_key.h"
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

BOOL KSP_IsSymmetricAlg(LPCWSTR pszAlgId)
{
    if (!pszAlgId) return FALSE;
    return (_wcsicmp(pszAlgId, ALG_AES)         == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA1)   == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA256) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA384) == 0 ||
            _wcsicmp(pszAlgId, ALG_HMAC_SHA512) == 0);
}
