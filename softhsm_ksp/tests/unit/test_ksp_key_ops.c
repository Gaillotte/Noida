/* test_ksp_key_ops.c — Couverture de ksp_key.c
 * Tests : OpenKey, CreatePersistedKey, FinalizeKey, DeleteKey, FreeKey, EnumKeys
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <wchar.h>
#include <string.h>

/* ── Stubs du contexte PKCS#11 ──────────────────────────────────────────── */
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

/* ── Stubs session et utilitaires PKCS#11 ───────────────────────────────── */

SECURITY_STATUS P11_AcquireSession(CK_SESSION_HANDLE *ph)
{
    *ph = (CK_SESSION_HANDLE)0xBEEF;
    return ERROR_SUCCESS;
}
void P11_ReleaseSession(CK_SESSION_HANDLE h) { (void)h; }

CK_OBJECT_HANDLE P11_FindObjectByLabel(
    CK_SESSION_HANDLE h, CK_OBJECT_CLASS cls, LPCWSTR pszLabel)
{
    (void)h; (void)cls; (void)pszLabel;
    if (P11Mock_GetConfig()->nKeyObjects > 0)
        return (CK_OBJECT_HANDLE)0x10;
    return CK_INVALID_HANDLE;
}

CK_RV P11_GetUlongAttr(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_TYPE t, CK_ULONG *pv)
{
    (void)h; (void)o;
    switch (t) {
    case CKA_KEY_TYPE:     *pv = P11Mock_GetConfig()->ulKeyType;  return CKR_OK;
    case CKA_MODULUS_BITS: *pv = P11Mock_GetConfig()->ulModBits;  return CKR_OK;
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

    /* Clé RSA 2048 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_RSA;
    P11Mock_GetConfig()->ulModBits   = 2048;

    NCRYPT_KEY_HANDLE hKey = 0;
    ss = KSP_OpenKey(hProv, &hKey, L"TestKey", AT_SIGNATURE, 0);
    ASSERT_OK("OpenKey RSA 2048 → OK", ss);
    ASSERT_NOTNULL("hKey non nul (RSA)", (void *)(ULONG_PTR)hKey);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_EQ("dwKeyBitLen = 2048", k->dwKeyBitLen, 2048U);
        ASSERT("szAlgId = RSA", _wcsicmp(k->szAlgId, ALG_RSA) == 0);
        ASSERT("bFinalized = TRUE", k->bFinalized == TRUE);
        ASSERT("dwKeySpec = AT_SIGNATURE", k->dwKeySpec == AT_SIGNATURE);
        ASSERT_EQ("hPrivKey = 0x10", k->hPrivKey, (CK_OBJECT_HANDLE)0x10);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* Clé RSA AT_KEYEXCHANGE */
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

    /* Clé EC P256 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->ulKeyType   = CKK_EC;
    /* pbEcParams = OID P256 par défaut (déjà dans P11Mock_Reset) */

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

    /* Clé EC P384 */
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

    /* Clé absente → NTE_BAD_KEYSET */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 0;

    ss = KSP_OpenKey(hProv, &hKey, L"Inexistante", 0, 0);
    ASSERT_EQ("Clé absente → NTE_BAD_KEYSET",
        ss, (SECURITY_STATUS)NTE_BAD_KEYSET);

    /* Paramètres invalides */
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

    /* RSA immédiat */
    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, L"CleRSA",
        AT_SIGNATURE, 0);
    ASSERT_OK("CreatePersistedKey RSA → OK", ss);
    ASSERT_NOTNULL("hKey RSA non nul", (void *)(ULONG_PTR)hKey);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("bFinalized = TRUE", k->bFinalized == TRUE);
        ASSERT_EQ("dwKeyBitLen = 2048 (défaut)", k->dwKeyBitLen, 2048U);
        ASSERT("dwKeySpec = AT_SIGNATURE", k->dwKeySpec == AT_SIGNATURE);
        ASSERT("szKeyName = CleRSA",
               _wcsicmp(k->szKeyName, L"CleRSA") == 0);
        ASSERT_EQ("GenerateKeyPair appelé 1×",
            P11Mock_GetCalls()->nGenerateKeyPair, 1);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* RSA PERSIST_ONLY (génération différée) */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, L"Deferred",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("CreatePersistedKey RSA PERSIST_ONLY → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("bFinalized = FALSE", k->bFinalized == FALSE);
        ASSERT("bPersistOnly = TRUE", k->bPersistOnly == TRUE);
        ASSERT_EQ("GenerateKeyPair NON appelé",
            P11Mock_GetCalls()->nGenerateKeyPair, 0);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* EC P256 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_ECDSA_P256, L"CleEC",
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
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_ECDSA_P384, L"CleP384",
        0, 0);
    ASSERT_OK("CreatePersistedKey ECDSA_P384 → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_EQ("dwKeyBitLen = 384", k->dwKeyBitLen, 384U);
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* Clé sans nom (NULL pszKeyName) avec PERSIST_ONLY → OK */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, NULL,
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("CreatePersistedKey sans nom PERSIST_ONLY → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT("szKeyName vide", k->szKeyName[0] == L'\0');
    }
    KSP_Free((void *)(ULONG_PTR)hKey); hKey = 0;

    /* Algorithme inconnu */
    ss = KSP_CreatePersistedKey(hProv, &hKey, L"DES", L"k", 0, 0);
    ASSERT_EQ("Alg inconnu → NTE_BAD_ALGID",
        ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    /* Paramètres invalides */
    ss = KSP_CreatePersistedKey(hProv, NULL, ALG_RSA, L"k", 0, 0);
    ASSERT_EQ("phKey=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_CreatePersistedKey(hProv, &hKey, NULL, L"k", 0, 0);
    ASSERT_EQ("pszAlgId=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_CreatePersistedKey(0, &hKey, ALG_RSA, L"k", 0, 0);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* GenerateKeyPair échoue → erreur retransmise */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_GenerateKeyPair = CKR_FUNCTION_FAILED;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, L"BadKey",
        AT_SIGNATURE, 0);
    ASSERT_ERR("GenerateKeyPair échoue → erreur", ss);
    ASSERT_EQ("hKey reste 0 après erreur", hKey, (NCRYPT_KEY_HANDLE)0);

    /* GenerateKeyPair échoue sur EC aussi */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_GenerateKeyPair = CKR_FUNCTION_FAILED;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_ECDSA_P256, L"BadEC",
        0, 0);
    ASSERT_ERR("GenerateKeyPair EC échoue → erreur", ss);

    /* ── Suite 3 : KSP_FinalizeKey ───────────────────────────────────────── */
    TEST_SUITE("KSP_FinalizeKey");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    /* Clé RSA différée → finalisée au premier appel */
    NCRYPT_KEY_HANDLE hPre = 0;
    ss = KSP_CreatePersistedKey(hProv, &hPre, ALG_RSA, L"PreKey",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Crée clé RSA différée", ss);
    ASSERT("Pas encore finalisée",
           !((KSP_KEY *)(ULONG_PTR)hPre)->bFinalized);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_FinalizeKey(hProv, hPre, 0);
    ASSERT_OK("FinalizeKey RSA → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hPre;
        ASSERT("bFinalized = TRUE après Finalize", k->bFinalized == TRUE);
        ASSERT_EQ("GenerateKeyPair appelé",
            P11Mock_GetCalls()->nGenerateKeyPair, 1);
    }

    /* Deuxième FinalizeKey → no-op */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_FinalizeKey(hProv, hPre, 0);
    ASSERT_OK("FinalizeKey déjà finalisée → OK (no-op)", ss);
    ASSERT_EQ("GenerateKeyPair NON rappelé",
        P11Mock_GetCalls()->nGenerateKeyPair, 0);

    KSP_Free((void *)(ULONG_PTR)hPre);

    /* Clé EC P256 différée → finalisée */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hEcPre = 0;
    ss = KSP_CreatePersistedKey(hProv, &hEcPre, ALG_ECDSA_P256, L"ECPre",
        0, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Crée clé EC différée", ss);
    ss = KSP_FinalizeKey(hProv, hEcPre, 0);
    ASSERT_OK("FinalizeKey EC → OK", ss);
    ASSERT("EC bFinalized = TRUE",
           ((KSP_KEY *)(ULONG_PTR)hEcPre)->bFinalized == TRUE);
    KSP_Free((void *)(ULONG_PTR)hEcPre);

    /* Clé EC P384 différée → finalisée */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hP384Pre = 0;
    ss = KSP_CreatePersistedKey(hProv, &hP384Pre, ALG_ECDSA_P384, L"P384Pre",
        0, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Crée clé P384 différée", ss);
    ss = KSP_FinalizeKey(hProv, hP384Pre, 0);
    ASSERT_OK("FinalizeKey P384 → OK", ss);
    KSP_Free((void *)(ULONG_PTR)hP384Pre);

    /* FinalizeKey mais GenerateKeyPair échoue */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hFailPre = 0;
    KSP_CreatePersistedKey(hProv, &hFailPre, ALG_RSA, L"FailKey",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    P11Mock_GetConfig()->rv_GenerateKeyPair = CKR_FUNCTION_FAILED;
    ss = KSP_FinalizeKey(hProv, hFailPre, 0);
    ASSERT_ERR("FinalizeKey génération échoue → erreur", ss);
    ASSERT("bFinalized reste FALSE",
           !((KSP_KEY *)(ULONG_PTR)hFailPre)->bFinalized);
    KSP_Free((void *)(ULONG_PTR)hFailPre);

    /* Handle invalide */
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

    /* Clé avec handles priv + pub (générée immédiatement) */
    NCRYPT_KEY_HANDLE hDel = 0;
    ss = KSP_CreatePersistedKey(hProv, &hDel, ALG_RSA, L"DelKey",
        AT_SIGNATURE, 0);
    ASSERT_OK("Crée clé pour suppression", ss);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_DeleteKey(hProv, hDel, 0);
    ASSERT_OK("DeleteKey → OK", ss);
    ASSERT_EQ("DestroyObject appelé 2× (priv + pub)",
        P11Mock_GetCalls()->nDestroyObject, 2);

    /* Clé avec seulement hPrivKey */
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
    ASSERT_EQ("DestroyObject appelé 1× (priv seulement)",
        P11Mock_GetCalls()->nDestroyObject, 1);

    /* Clé sans aucun handle */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hNoHandle = 0;
    KSP_CreatePersistedKey(hProv, &hNoHandle, ALG_RSA, L"NoHandle",
        AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    ss = KSP_DeleteKey(hProv, hNoHandle, 0);
    ASSERT_OK("DeleteKey sans handles → OK", ss);
    ASSERT_EQ("DestroyObject NON appelé",
        P11Mock_GetCalls()->nDestroyObject, 0);

    /* Handle invalide */
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
    ASSERT_OK("Crée clé pour FreeKey", ss);

    ss = KSP_FreeKey(hProv, hFree);
    ASSERT_OK("FreeKey → OK", ss);
    /* Note: hFree est libéré — on ne déréférence pas la mémoire après free */

    /* Handle invalide */
    ss = KSP_FreeKey(hProv, 0);
    ASSERT_EQ("FreeKey(0) → NTE_INVALID_HANDLE",
        ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);

    /* Magic incorrecte → NTE_INVALID_HANDLE (sans déréférencer un pointeur sauvage) */
    KSP_KEY badKey;
    memset(&badKey, 0, sizeof(badKey));
    badKey.dwMagic = 0xDEADBEEFUL;
    ss = KSP_FreeKey(hProv, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&badKey);
    ASSERT_EQ("FreeKey(magic incorrecte) → NTE_INVALID_HANDLE",
        ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);

    /* ── Suite 6 : KSP_EnumKeys ──────────────────────────────────────────── */
    TEST_SUITE("KSP_EnumKeys");

    /* Token vide → NTE_NO_MORE_ITEMS immédiatement */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 0;

    NCryptKeyName *pName = NULL;
    PVOID pState = NULL;
    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_EQ("Token vide → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);
    ASSERT_NULL("pState=NULL après fin sur token vide", pState);

    /* Une clé → succès puis NTE_NO_MORE_ITEMS */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    strcpy(P11Mock_GetConfig()->szKeyLabel, "MaCle");

    pName = NULL; pState = NULL;
    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_OK("EnumKeys 1 clé → OK", ss);
    ASSERT_NOTNULL("pName non nul", pName);
    ASSERT_NOTNULL("pName->pszName non nul", pName->pszName);
    KSP_Free(pName); pName = NULL;

    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_EQ("Deuxième appel → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);
    ASSERT_NULL("pState=NULL après énumération complète", pState);

    /* Trois clés */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 3;
    strcpy(P11Mock_GetConfig()->szKeyLabel, "Cle");

    pName = NULL; pState = NULL;
    int nKeys = 0;
    while ((ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0)) == ERROR_SUCCESS) {
        nKeys++;
        KSP_Free(pName); pName = NULL;
    }
    ASSERT_EQ("3 clés énumérées", nKeys, 3);
    ASSERT_EQ("Fin de 3 clés → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);

    /* FindObjectsInit échoue → NTE_NO_MORE_ITEMS */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects   = 1;
    P11Mock_GetConfig()->rv_FindObjectsInit = CKR_SESSION_HANDLE_INVALID;

    pName = NULL; pState = NULL;
    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_EQ("FindObjectsInit échoue → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);

    /* FindObjects échoue → NTE_NO_MORE_ITEMS */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->rv_FindObjects = CKR_SESSION_HANDLE_INVALID;

    pName = NULL; pState = NULL;
    ss = KSP_EnumKeys(hProv, NULL, &pName, &pState, 0);
    ASSERT_EQ("FindObjects échoue → NTE_NO_MORE_ITEMS",
        ss, (SECURITY_STATUS)NTE_NO_MORE_ITEMS);

    /* Paramètres invalides */
    ss = KSP_EnumKeys(hProv, NULL, NULL, &pState, 0);
    ASSERT_EQ("ppKeyName=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_EnumKeys(hProv, NULL, &pName, NULL, 0);
    ASSERT_EQ("ppEnumState=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_EnumKeys(0, NULL, &pName, &pState, 0);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
