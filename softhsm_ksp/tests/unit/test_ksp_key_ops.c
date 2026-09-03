/* test_ksp_key_ops.c — Coverage of ksp_key.c
 * Tests: OpenKey, CreatePersistedKey, FinalizeKey, DeleteKey, FreeKey, EnumKeys
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <wchar.h>
#include <string.h>

/* ── PKCS#11 context stubs ──────────────────────────────────────────────── */
typedef struct { void *hModule; CK_FUNCTION_LIST_PTR pFunctionList;
                 CK_SLOT_ID slotId; BOOL bInitialized; } P11_CONTEXT;
static P11_CONTEXT g_testCtx;
P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }

SECURITY_STATUS P11_Initialize(void)             { return ERROR_SUCCESS; }
SECURITY_STATUS P11_SessionPool_Initialize(void) { return ERROR_SUCCESS; }
void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }
void Log_Initialize(void) {}

void *KSP_Alloc(SIZE_T n);
void *KSP_AllocZero(SIZE_T n);
void  KSP_Free(void *p);
LPWSTR KSP_WStrDup(LPCWSTR p);

/* ── Session and PKCS#11 utility stubs ───────────────────────────────────── */

SECURITY_STATUS P11_AcquireSession(CK_SESSION_HANDLE *ph)
{
    *ph = (CK_SESSION_HANDLE)0xBEEF;
    return ERROR_SUCCESS;
}
void P11_ReleaseSession(CK_SESSION_HANDLE h) { (void)h; }

/* Which object class the stub should report as present.
 * CKO_PRIVATE_KEY (the default) exercises the asymmetric path;
 * CKO_SECRET_KEY exercises the symmetric path in KSP_OpenKey. */
static CK_OBJECT_CLASS g_findableClass = CKO_PRIVATE_KEY;

CK_OBJECT_HANDLE P11_FindObjectByLabel(
    CK_SESSION_HANDLE h, CK_OBJECT_CLASS cls, LPCWSTR pszLabel)
{
    (void)h; (void)pszLabel;
    if (P11Mock_GetConfig()->nKeyObjects <= 0)
        return CK_INVALID_HANDLE;

    /* Public keys are always reported alongside a findable private key */
    if (cls == CKO_PUBLIC_KEY && g_findableClass == CKO_PRIVATE_KEY)
        return (CK_OBJECT_HANDLE)0x11;

    if (cls != g_findableClass)
        return CK_INVALID_HANDLE;

    return (CK_OBJECT_HANDLE)0x10;
}

/* Curve OID lookup — mirrors the real P11_GetCurveOid mapping */
const char *P11_GetCurveOid(LPCWSTR pszAlgId, CK_ULONG *pcbOid)
{
    if (!pszAlgId || !pcbOid) return NULL;
    if (wcscmp(pszAlgId, ALG_ECDSA_P256) == 0 ||
        wcscmp(pszAlgId, ALG_ECDH_P256)  == 0) {
        *pcbOid = EC_OID_P256_LEN; return EC_OID_P256;
    }
    if (wcscmp(pszAlgId, ALG_ECDSA_P384) == 0 ||
        wcscmp(pszAlgId, ALG_ECDH_P384)  == 0) {
        *pcbOid = EC_OID_P384_LEN; return EC_OID_P384;
    }
    if (wcscmp(pszAlgId, ALG_ECDSA_P521) == 0 ||
        wcscmp(pszAlgId, ALG_ECDH_P521)  == 0) {
        *pcbOid = EC_OID_P521_LEN; return EC_OID_P521;
    }
    if (wcscmp(pszAlgId, ALG_EDDSA_ED25519) == 0) {
        *pcbOid = EC_OID_ED25519_LEN; return EC_OID_ED25519;
    }
    if (wcscmp(pszAlgId, ALG_EDDSA_ED448) == 0) {
        *pcbOid = EC_OID_ED448_LEN; return EC_OID_ED448;
    }
    return NULL;
}

CK_RV P11_GetUlongAttr(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_TYPE t, CK_ULONG *pv)
{
    (void)h; (void)o;
    switch (t) {
    case CKA_KEY_TYPE:     *pv = P11Mock_GetConfig()->ulKeyType;   return CKR_OK;
    case CKA_MODULUS_BITS: *pv = P11Mock_GetConfig()->ulModBits;   return CKR_OK;
    case CKA_VALUE_LEN:    *pv = P11Mock_GetConfig()->ulValueLen;  return CKR_OK;
    case CKA_DERIVE:       *pv = P11Mock_GetConfig()->ulDerive;    return CKR_OK;
    default: return CKR_ATTRIBUTE_TYPE_INVALID;
    }
}

CK_RV P11_GetBinaryAttr(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_TYPE t, BYTE **ppData, DWORD *pcbData)
{
    (void)h; (void)o;
    P11_MOCK_CONFIG *cfg = P11Mock_GetConfig();
    if (t == CKA_EC_PARAMS && cfg->pbEcParams) {
        *ppData = (BYTE *)KSP_Alloc(cfg->cbEcParams);
        if (!*ppData) return CKR_HOST_MEMORY;
        memcpy(*ppData, cfg->pbEcParams, cfg->cbEcParams);
        *pcbData = (DWORD)cfg->cbEcParams;
        return CKR_OK;
    }
    return CKR_ATTRIBUTE_TYPE_INVALID;
}

SECURITY_STATUS P11RvToSecStatus(CK_RV rv)
{
    if (rv == CKR_OK)         return ERROR_SUCCESS;
    if (rv == CKR_HOST_MEMORY) return NTE_NO_MEMORY;
    return NTE_FAIL;
}

#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_provider.h"

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS    ss;

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);

    /* ── Suite 1 : KSP_OpenKey ────────────────────────────────────────────── */
    TEST_SUITE("KSP_OpenKey");

    /* RSA 2048 key */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_RSA;
    P11Mock_GetConfig()->ulModBits   = 2048;

    NCRYPT_KEY_HANDLE hKey = 0;
    ss = KSP_OpenKey(hProv, &hKey, L"TestKey", AT_SIGNATURE, 0);
    ASSERT_OK("OpenKey RSA 2048 → OK", ss);
    ASSERT_NOTNULL("hKey non-null (RSA)", (void *)(ULONG_PTR)hKey);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_EQ("dwKeyBitLen = 2048", k->dwKeyBitLen, 2048U);
        ASSERT("szAlgId = RSA", _wcsicmp(k->szAlgId, ALG_RSA) == 0);
        ASSERT("bFinalized = TRUE", k->bFinalized == TRUE);
        ASSERT("dwKeySpec = AT_SIGNATURE", k->dwKeySpec == AT_SIGNATURE);
        ASSERT_EQ("hPrivKey = 0x10", k->hPrivKey, (CK_OBJECT_HANDLE)0x10);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* RSA AT_KEYEXCHANGE key */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_RSA;
    P11Mock_GetConfig()->ulModBits   = 4096;

    ss = KSP_OpenKey(hProv, &hKey, L"BigKey", AT_KEYEXCHANGE, 0);
    ASSERT_OK("OpenKey RSA 4096 AT_KEYEXCHANGE → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_EQ("dwKeyBitLen = 4096", k->dwKeyBitLen, 4096U);
        ASSERT_EQ("dwKeySpec = AT_KEYEXCHANGE", k->dwKeySpec, (DWORD)AT_KEYEXCHANGE);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* EC P256 key */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_EC;
    /* pbEcParams = default OID P256 (already set by P11Mock_Reset) */

    ss = KSP_OpenKey(hProv, &hKey, L"TestEC", AT_KEYEXCHANGE, 0);
    ASSERT_OK("OpenKey EC P256 → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("szAlgId = ECDSA_P256",
               _wcsicmp(k->szAlgId, ALG_ECDSA_P256) == 0);
        ASSERT_EQ("dwKeyBitLen = 256", k->dwKeyBitLen, 256U);
        ASSERT_EQ("dwKeySpec = AT_KEYEXCHANGE", k->dwKeySpec, (DWORD)AT_KEYEXCHANGE);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* EC P384 key */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_EC;
    static const char g_oidP384[] = "\x06\x05\x2b\x81\x04\x00\x22";
    P11Mock_GetConfig()->pbEcParams = g_oidP384;
    P11Mock_GetConfig()->cbEcParams = 7;

    ss = KSP_OpenKey(hProv, &hKey, L"TestP384", 0, 0);
    ASSERT_OK("OpenKey EC P384 → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("szAlgId = ECDSA_P384",
               _wcsicmp(k->szAlgId, ALG_ECDSA_P384) == 0);
        ASSERT_EQ("dwKeyBitLen = 384", k->dwKeyBitLen, 384U);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* Missing key → NTE_BAD_KEYSET */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 0;

    ss = KSP_OpenKey(hProv, &hKey, L"Missing", 0, 0);
    ASSERT_EQ("Missing key → NTE_BAD_KEYSET",
        ss, (SECURITY_STATUS)NTE_BAD_KEYSET);

    /* Invalid parameters */
    ss = KSP_OpenKey(hProv, NULL, L"TestKey", 0, 0);
    ASSERT_EQ("phKey=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_OpenKey(hProv, &hKey, NULL, 0, 0);
    ASSERT_EQ("pszKeyName=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_OpenKey(0, &hKey, L"TestKey", 0, 0);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 2 : KSP_CreatePersistedKey ────────────────────────────────── */
    TEST_SUITE("KSP_CreatePersistedKey");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    /* Immediate RSA */
    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, L"RsaKey",
        AT_SIGNATURE, 0);
    ASSERT_OK("CreatePersistedKey RSA → OK", ss);
    ASSERT_NOTNULL("hKey RSA non-null", (void *)(ULONG_PTR)hKey);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("bFinalized = TRUE", k->bFinalized == TRUE);
        ASSERT_EQ("dwKeyBitLen = 2048 (default)", k->dwKeyBitLen, 2048U);
        ASSERT("dwKeySpec = AT_SIGNATURE", k->dwKeySpec == AT_SIGNATURE);
        ASSERT("szKeyName = RsaKey",
               _wcsicmp(k->szKeyName, L"RsaKey") == 0);
        ASSERT_EQ("GenerateKeyPair called 1×",
            P11Mock_GetCalls()->nGenerateKeyPair, 1);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* RSA PERSIST_ONLY (deferred generation) */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, L"Deferred",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("CreatePersistedKey RSA PERSIST_ONLY → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("bFinalized = FALSE", k->bFinalized == FALSE);
        ASSERT("bPersistOnly = TRUE", k->bPersistOnly == TRUE);
        ASSERT_EQ("GenerateKeyPair NOT called",
            P11Mock_GetCalls()->nGenerateKeyPair, 0);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* EC P256 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_ECDSA_P256, L"EcKey",
        AT_KEYEXCHANGE, 0);
    ASSERT_OK("CreatePersistedKey ECDSA_P256 → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("szAlgId = ECDSA_P256",
               _wcsicmp(k->szAlgId, ALG_ECDSA_P256) == 0);
        ASSERT_EQ("dwKeyBitLen = 256", k->dwKeyBitLen, 256U);
        ASSERT("dwKeySpec = AT_KEYEXCHANGE",
               k->dwKeySpec == AT_KEYEXCHANGE);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* EC P384 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_ECDSA_P384, L"P384Key",
        0, 0);
    ASSERT_OK("CreatePersistedKey ECDSA_P384 → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_EQ("dwKeyBitLen = 384", k->dwKeyBitLen, 384U);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* Key without name (NULL pszKeyName) with PERSIST_ONLY → OK */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, NULL,
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("CreatePersistedKey without name PERSIST_ONLY → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("szKeyName empty", k->szKeyName[0] == L'\0');
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* Unknown algorithm */
    ss = KSP_CreatePersistedKey(hProv, &hKey, L"DES", L"k", 0, 0);
    ASSERT_EQ("Unknown alg → NTE_BAD_ALGID",
        ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    /* Invalid parameters */
    ss = KSP_CreatePersistedKey(hProv, NULL, ALG_RSA, L"k", 0, 0);
    ASSERT_EQ("phKey=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_CreatePersistedKey(hProv, &hKey, NULL, L"k", 0, 0);
    ASSERT_EQ("pszAlgId=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_CreatePersistedKey(0, &hKey, ALG_RSA, L"k", 0, 0);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* GenerateKeyPair fails → error propagated */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_GenerateKeyPair = CKR_FUNCTION_FAILED;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, L"BadKey",
        AT_SIGNATURE, 0);
    ASSERT_ERR("GenerateKeyPair fails → error", ss);
    ASSERT_EQ("hKey remains 0 after error", hKey, (NCRYPT_KEY_HANDLE)0);

    /* GenerateKeyPair also fails on EC */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_GenerateKeyPair = CKR_FUNCTION_FAILED;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_ECDSA_P256, L"BadEC",
        0, 0);
    ASSERT_ERR("GenerateKeyPair EC fails → error", ss);

    /* ── Suite 3 : KSP_FinalizeKey ───────────────────────────────────────── */
    TEST_SUITE("KSP_FinalizeKey");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    /* Deferred RSA key → finalized on first call */
    NCRYPT_KEY_HANDLE hPre = 0;
    ss = KSP_CreatePersistedKey(hProv, &hPre, ALG_RSA, L"PreKey",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Create deferred RSA key", ss);
    ASSERT("Not yet finalized",
           !((KSP_KEY *)(ULONG_PTR)hPre)->bFinalized);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_FinalizeKey(hProv, hPre, 0);
    ASSERT_OK("FinalizeKey RSA → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hPre;
        ASSERT("bFinalized = TRUE after Finalize", k->bFinalized == TRUE);
        ASSERT_EQ("GenerateKeyPair called",
            P11Mock_GetCalls()->nGenerateKeyPair, 1);
    }

    /* Second FinalizeKey → no-op */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_FinalizeKey(hProv, hPre, 0);
    ASSERT_OK("FinalizeKey already finalized → OK (no-op)", ss);
    ASSERT_EQ("GenerateKeyPair NOT called again",
        P11Mock_GetCalls()->nGenerateKeyPair, 0);

    KSP_Free((void *)(ULONG_PTR)hPre);

    /* Deferred EC P256 key → finalized */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hEcPre = 0;
    ss = KSP_CreatePersistedKey(hProv, &hEcPre, ALG_ECDSA_P256, L"ECPre",
        0, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Create deferred EC key", ss);
    ss = KSP_FinalizeKey(hProv, hEcPre, 0);
    ASSERT_OK("FinalizeKey EC → OK", ss);
    ASSERT("EC bFinalized = TRUE",
           ((KSP_KEY *)(ULONG_PTR)hEcPre)->bFinalized == TRUE);
    KSP_Free((void *)(ULONG_PTR)hEcPre);

    /* Deferred EC P384 key → finalized */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hP384Pre = 0;
    ss = KSP_CreatePersistedKey(hProv, &hP384Pre, ALG_ECDSA_P384, L"P384Pre",
        0, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Create deferred P384 key", ss);
    ss = KSP_FinalizeKey(hProv, hP384Pre, 0);
    ASSERT_OK("FinalizeKey P384 → OK", ss);
    KSP_Free((void *)(ULONG_PTR)hP384Pre);

    /* FinalizeKey but GenerateKeyPair fails */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hFailPre = 0;
    KSP_CreatePersistedKey(hProv, &hFailPre, ALG_RSA, L"FailKey",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    P11Mock_GetConfig()->rv_GenerateKeyPair = CKR_FUNCTION_FAILED;
    ss = KSP_FinalizeKey(hProv, hFailPre, 0);
    ASSERT_ERR("FinalizeKey generation fails → error", ss);
    ASSERT("bFinalized remains FALSE",
           !((KSP_KEY *)(ULONG_PTR)hFailPre)->bFinalized);
    KSP_Free((void *)(ULONG_PTR)hFailPre);

    /* Invalid handle */
    ss = KSP_FinalizeKey(hProv, 0, 0);
    ASSERT_EQ("FinalizeKey hKey=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_FinalizeKey(0, (NCRYPT_KEY_HANDLE)1, 0);
    ASSERT_EQ("FinalizeKey hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 4 : KSP_DeleteKey ─────────────────────────────────────────── */
    TEST_SUITE("KSP_DeleteKey");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    /* Key with priv + pub handles (immediately generated) */
    NCRYPT_KEY_HANDLE hDel = 0;
    ss = KSP_CreatePersistedKey(hProv, &hDel, ALG_RSA, L"DelKey",
        AT_SIGNATURE, 0);
    ASSERT_OK("Create key for deletion", ss);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_DeleteKey(hProv, hDel, 0);
    ASSERT_OK("DeleteKey → OK", ss);
    ASSERT_EQ("DestroyObject called 2× (priv + pub)",
        P11Mock_GetCalls()->nDestroyObject, 2);

    /* Key with only hPrivKey */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hPrivOnly = 0;
    KSP_CreatePersistedKey(hProv, &hPrivOnly, ALG_RSA, L"PrivOnly",
        AT_SIGNATURE, 0);
    ((KSP_KEY *)(ULONG_PTR)hPrivOnly)->hPubKey = CK_INVALID_HANDLE;

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_DeleteKey(hProv, hPrivOnly, 0);
    ASSERT_OK("DeleteKey priv-only → OK", ss);
    ASSERT_EQ("DestroyObject called 1× (priv only)",
        P11Mock_GetCalls()->nDestroyObject, 1);

    /* Key with no handles */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hNoHandle = 0;
    KSP_CreatePersistedKey(hProv, &hNoHandle, ALG_RSA, L"NoHandle",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_DeleteKey(hProv, hNoHandle, 0);
    ASSERT_OK("DeleteKey sans handles → OK", ss);
    ASSERT_EQ("DestroyObject NOT called",
        P11Mock_GetCalls()->nDestroyObject, 0);

    /* Invalid handle */
    ss = KSP_DeleteKey(hProv, 0, 0);
    ASSERT_EQ("DeleteKey hKey=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_DeleteKey(0, (NCRYPT_KEY_HANDLE)1, 0);
    ASSERT_EQ("DeleteKey hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 5 : KSP_FreeKey ───────────────────────────────────────────── */
    TEST_SUITE("KSP_FreeKey");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    NCRYPT_KEY_HANDLE hFree = 0;
    ss = KSP_CreatePersistedKey(hProv, &hFree, ALG_RSA, L"FreeKey",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Create key for FreeKey", ss);

    ss = KSP_FreeKey(hProv, hFree);
    ASSERT_OK("FreeKey → OK", ss);
    /* Note: hFree is freed — do not dereference memory after free */

    /* Invalid handle */
    ss = KSP_FreeKey(hProv, 0);
    ASSERT_EQ("FreeKey(0) → NTE_INVALID_HANDLE",
        ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);

    /* Wrong magic → NTE_INVALID_HANDLE (without dereferencing a wild pointer) */
    KSP_KEY badKey;
    memset(&badKey, 0, sizeof(badKey));
    badKey.dwMagic = 0xDEADBEEFUL;
    ss = KSP_FreeKey(hProv, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&badKey);
    ASSERT_EQ("FreeKey(wrong magic) → NTE_INVALID_HANDLE",
        ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);

    /* ── Suite 6 : KSP_EnumKeys ──────────────────────────────────────────── */
    TEST_SUITE("KSP_EnumKeys");

    /* Empty token → NTE_NO_MORE_ITEMS immediately */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 0;

    NCryptKeyName *pName = NULL;
    PVOID pState = NULL;
    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_EQ("Empty token → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);
    ASSERT_NULL("pState=NULL after end on empty token", pState);

    /* One key → success then NTE_NO_MORE_ITEMS */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    strcpy(P11Mock_GetConfig()->szKeyLabel, "MyKey");

    pName = NULL; pState = NULL;
    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_OK("EnumKeys 1 key → OK", ss);
    ASSERT_NOTNULL("pName non-null", pName);
    ASSERT_NOTNULL("pName->pszName non-null", pName->pszName);
    KSP_Free(pName); pName = NULL;

    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_EQ("Second call → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);
    ASSERT_NULL("pState=NULL after complete enumeration", pState);

    /* Three keys */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 3;
    strcpy(P11Mock_GetConfig()->szKeyLabel, "Key");

    pName = NULL; pState = NULL;
    int nKeys = 0;
    while ((ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0)) == ERROR_SUCCESS) {
        nKeys++;
        KSP_Free(pName); pName = NULL;
    }
    ASSERT_EQ("3 keys enumerated", nKeys, 3);
    ASSERT_EQ("End of 3 keys → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);

    /* FindObjectsInit fails → NTE_NO_MORE_ITEMS */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects   = 1;
    P11Mock_GetConfig()->rv_FindObjectsInit = CKR_SESSION_HANDLE_INVALID;

    pName = NULL; pState = NULL;
    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_EQ("FindObjectsInit fails → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);

    /* FindObjects fails → NTE_NO_MORE_ITEMS */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->rv_FindObjects = CKR_SESSION_HANDLE_INVALID;

    pName = NULL; pState = NULL;
    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_EQ("FindObjects fails → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);

    /* Invalid parameters */
    ss = KSP_EnumKeys(hProv, NULL, NULL, &pState, 0);
    ASSERT_EQ("ppKeyName=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_EnumKeys(hProv, NULL, &pName, NULL, 0);
    ASSERT_EQ("ppEnumState=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_EnumKeys(0, NULL, &pName, &pState, 0);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite: OpenKey — curve identification (P-521, EdDSA, ECDH) ─────── */
    TEST_SUITE("KSP_OpenKey — curve identification");

    /* P-521 is recognised from its DER OID */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_findableClass = CKO_PRIVATE_KEY;
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_EC;
    P11Mock_GetConfig()->pbEcParams  = EC_OID_P521;
    P11Mock_GetConfig()->cbEcParams  = EC_OID_P521_LEN;
    P11Mock_GetConfig()->ulDerive    = 0;
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_OpenKey(hProv, &h, L"P521Key", AT_SIGNATURE, 0);
        ASSERT_OK("P-521 key opened", ss);
        {
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            ASSERT_WSTR("Algorithm is ECDSA_P521", k->szAlgId, ALG_ECDSA_P521);
            ASSERT_EQ("Length is 521 bits", k->dwKeyBitLen, 521U);
        }
        KSP_FreeKey(hProv, h);
    }

    /* CKA_DERIVE set on a P-256 key means ECDH, not ECDSA */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_findableClass = CKO_PRIVATE_KEY;
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_EC;
    P11Mock_GetConfig()->pbEcParams  = EC_OID_P256;
    P11Mock_GetConfig()->cbEcParams  = EC_OID_P256_LEN;
    P11Mock_GetConfig()->ulDerive    = 1;
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_OpenKey(hProv, &h, L"EcdhKey", AT_KEYEXCHANGE, 0);
        ASSERT_OK("ECDH P-256 key opened", ss);
        {
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            ASSERT_WSTR("CKA_DERIVE → ECDH_P256", k->szAlgId, ALG_ECDH_P256);
            ASSERT_EQ("Length is 256 bits", k->dwKeyBitLen, 256U);
        }
        KSP_FreeKey(hProv, h);
    }

    /* Ed25519 is recognised from its OID and reported as an Edwards curve */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_findableClass = CKO_PRIVATE_KEY;
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_EC_EDWARDS;
    P11Mock_GetConfig()->pbEcParams  = EC_OID_ED25519;
    P11Mock_GetConfig()->cbEcParams  = EC_OID_ED25519_LEN;
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_OpenKey(hProv, &h, L"Ed25519Key", AT_SIGNATURE, 0);
        ASSERT_OK("Ed25519 key opened", ss);
        {
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            ASSERT_WSTR("Algorithm is EDDSA_ED25519", k->szAlgId,
                        ALG_EDDSA_ED25519);
            ASSERT_EQ("Length is 255 bits", k->dwKeyBitLen, 255U);
        }
        KSP_FreeKey(hProv, h);
    }

    /* Ed448 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_findableClass = CKO_PRIVATE_KEY;
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_EC_EDWARDS;
    P11Mock_GetConfig()->pbEcParams  = EC_OID_ED448;
    P11Mock_GetConfig()->cbEcParams  = EC_OID_ED448_LEN;
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_OpenKey(hProv, &h, L"Ed448Key", AT_SIGNATURE, 0);
        ASSERT_OK("Ed448 key opened", ss);
        {
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            ASSERT_WSTR("Algorithm is EDDSA_ED448", k->szAlgId,
                        ALG_EDDSA_ED448);
            ASSERT_EQ("Length is 448 bits", k->dwKeyBitLen, 448U);
        }
        KSP_FreeKey(hProv, h);
    }

    /* ── Suite: OpenKey — symmetric keys ────────────────────────────────── */
    TEST_SUITE("KSP_OpenKey — symmetric keys");

    /* An AES key has no private object, only a secret object */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_findableClass = CKO_SECRET_KEY;
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_AES;
    P11Mock_GetConfig()->ulValueLen  = 32;      /* 256-bit AES key */
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_OpenKey(hProv, &h, L"AesKey", 0, 0);
        ASSERT_OK("AES key opened", ss);
        {
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            ASSERT_WSTR("Algorithm is AES", k->szAlgId, ALG_AES);
            ASSERT_EQ("Key class is symmetric", k->dwKeyClass,
                      (DWORD)KSP_KEY_CLASS_SYMMETRIC);
            ASSERT_EQ("Length derived from CKA_VALUE_LEN", k->dwKeyBitLen, 256U);
            ASSERT_NEQ("Secret handle set", k->hSecretKey,
                       (CK_OBJECT_HANDLE)CK_INVALID_HANDLE);
            ASSERT_EQ("No private key handle", k->hPrivKey,
                      (CK_OBJECT_HANDLE)CK_INVALID_HANDLE);
        }
        KSP_FreeKey(hProv, h);
    }

    /* A generic-secret object is reported as an HMAC key */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_findableClass = CKO_SECRET_KEY;
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_GENERIC_SECRET;
    P11Mock_GetConfig()->ulValueLen  = 48;      /* 384-bit HMAC key */
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_OpenKey(hProv, &h, L"HmacKey", 0, 0);
        ASSERT_OK("HMAC key opened", ss);
        {
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            ASSERT_WSTR("Algorithm is HMAC_SHA256", k->szAlgId,
                        ALG_HMAC_SHA256);
            ASSERT_EQ("Key class is symmetric", k->dwKeyClass,
                      (DWORD)KSP_KEY_CLASS_SYMMETRIC);
            ASSERT_EQ("Length is 384 bits", k->dwKeyBitLen, 384U);
        }
        KSP_FreeKey(hProv, h);
    }

    /* Neither a private nor a secret object exists */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_findableClass = CKO_DATA;      /* nothing the KSP looks for */
    P11Mock_GetConfig()->nKeyObjects = 1;
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_OpenKey(hProv, &h, L"Missing", 0, 0);
        ASSERT_EQ("No key object → NTE_BAD_KEYSET", ss,
                  (SECURITY_STATUS)NTE_BAD_KEYSET);
    }

    /* ── Suite: symmetric key creation and deletion ─────────────────────── */
    TEST_SUITE("Symmetric key creation and deletion");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_CreatePersistedKey(hProv, &h, ALG_AES, L"AesDel",
                                    AT_KEYEXCHANGE, 0);
        ASSERT_OK("AES key created", ss);
        ASSERT_EQ("C_GenerateKey used, not C_GenerateKeyPair",
                  P11Mock_GetCalls()->nGenerateKeyPair, 0);
        ASSERT_EQ("C_GenerateKey called once",
                  P11Mock_GetCalls()->nGenerateKey, 1);

        /* Deleting a symmetric key destroys its secret object */
        ss = KSP_DeleteKey(hProv, h, 0);
        ASSERT_OK("AES key deleted", ss);
        ASSERT_EQ("Secret object destroyed",
                  P11Mock_GetCalls()->nDestroyObject, 1);
    }

    /* Symmetric generation failure propagates */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_GenerateKey = CKR_DEVICE_ERROR;
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_CreatePersistedKey(hProv, &h, ALG_AES, L"AesFail",
                                    AT_KEYEXCHANGE, 0);
        ASSERT_ERR("C_GenerateKey failure propagates", ss);
    }

    /* An unknown algorithm is rejected before any PKCS#11 call */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_CreatePersistedKey(hProv, &h, L"DSA", L"DsaKey",
                                    AT_SIGNATURE, 0);
        ASSERT_EQ("DSA → NTE_BAD_ALGID", ss, (SECURITY_STATUS)NTE_BAD_ALGID);
        ASSERT_EQ("No key generated", P11Mock_GetCalls()->nGenerateKeyPair, 0);
    }

    /* ── Suite: P-521 and ECDH key generation ───────────────────────────── */
    TEST_SUITE("P-521 and ECDH key generation");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        NCRYPT_KEY_HANDLE h = 0;
        ss = KSP_CreatePersistedKey(hProv, &h, ALG_ECDSA_P521, L"P521Gen",
                                    AT_SIGNATURE, 0);
        ASSERT_OK("ECDSA P-521 key created", ss);
        {
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            ASSERT_EQ("Default length is 521 bits", k->dwKeyBitLen, 521U);
            ASSERT_EQ("Key spec is AT_SIGNATURE", k->dwKeySpec,
                      (DWORD)AT_SIGNATURE);
        }
        KSP_FreeKey(hProv, h);
    }

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        NCRYPT_KEY_HANDLE h = 0;
        /* ECDH keys are key-agreement keys even when AT_SIGNATURE is asked */
        ss = KSP_CreatePersistedKey(hProv, &h, ALG_ECDH_P384, L"EcdhGen",
                                    AT_SIGNATURE, 0);
        ASSERT_OK("ECDH P-384 key created", ss);
        {
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            ASSERT_EQ("ECDH forces AT_KEYEXCHANGE", k->dwKeySpec,
                      (DWORD)AT_KEYEXCHANGE);
            ASSERT_EQ("Default length is 384 bits", k->dwKeyBitLen, 384U);
        }
        KSP_FreeKey(hProv, h);
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
