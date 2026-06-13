/* test_ksp_key_props.c — Full coverage of ksp_properties.c
 * All read/write properties, all error paths.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <wchar.h>
#include <string.h>

typedef struct { void *hModule; CK_FUNCTION_LIST_PTR pFunctionList;
                 CK_SLOT_ID slotId; BOOL bInitialized; } P11_CONTEXT;
static P11_CONTEXT g_testCtx;
P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }
SECURITY_STATUS P11_Initialize(void)            { return ERROR_SUCCESS; }
SECURITY_STATUS P11_SessionPool_Initialize(void){ return ERROR_SUCCESS; }
void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }
void Log_Initialize(void) {}

void *KSP_Alloc(SIZE_T n);
void *KSP_AllocZero(SIZE_T n);
void  KSP_Free(void *p);

#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_properties.h"
#include "../../src/ksp/ksp_provider.h"

/* Creates a test KSP_KEY without going through PKCS#11 */
static NCRYPT_KEY_HANDLE make_test_key(
    LPCWSTR szAlg, DWORD bits, DWORD spec, BOOL finalized)
{
    KSP_KEY *k = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
    k->dwMagic     = KSP_KEY_MAGIC;
    k->dwKeyBitLen = bits;
    k->dwKeySpec   = spec;
    k->hPrivKey    = finalized ? (CK_OBJECT_HANDLE)0x10 : CK_INVALID_HANDLE;
    k->hPubKey     = finalized ? (CK_OBJECT_HANDLE)0x11 : CK_INVALID_HANDLE;
    k->bFinalized  = finalized;
    k->slotId      = 0;
    wcscpy_s(k->szAlgId,   MAX_ALG_ID_LEN,      szAlg);
    wcscpy_s(k->szKeyName, MAX_KEY_LABEL_LEN,    L"MyTestKey");
    return (NCRYPT_KEY_HANDLE)(ULONG_PTR)k;
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv;
    SECURITY_STATUS    ss;
    DWORD cbResult, dwVal;
    WCHAR wszBuf[256];

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);

    /* ── Suite 1 : GetKeyProperty — RSA key ────────────────────────────── */
    TEST_SUITE("KSP_GetKeyProperty — RSA 2048");

    NCRYPT_KEY_HANDLE hRsa = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);

    /* NCRYPT_ALGORITHM_PROPERTY */
    cbResult = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_ALGORITHM_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("ALG → size OK", ss);
    ASSERT("cbResult > 0", cbResult > 0);

    memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_ALGORITHM_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("ALG → content OK", ss);
    ASSERT("szAlgId = RSA", _wcsicmp(wszBuf, ALG_RSA) == 0);

    /* NCRYPT_LENGTH_PROPERTY */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("LENGTH → OK", ss);
    ASSERT_EQ("dwKeyBitLen = 2048", dwVal, 2048U);

    /* NCRYPT_KEY_TYPE_PROPERTY */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_KEY_TYPE_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("KEY_TYPE → OK", ss);
    ASSERT_EQ("dwKeySpec = AT_SIGNATURE", dwVal, (DWORD)AT_SIGNATURE);

    /* NCRYPT_NAME_PROPERTY */
    cbResult = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_NAME_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("NAME size → OK", ss);

    memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_NAME_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("NAME content → OK", ss);
    ASSERT("szKeyName = MyTestKey",
           _wcsicmp(wszBuf, L"MyTestKey") == 0);

    /* NCRYPT_UNIQUE_NAME_PROPERTY */
    cbResult = 0; memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_UNIQUE_NAME_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("UNIQUE_NAME size → OK", ss);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_UNIQUE_NAME_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("UNIQUE_NAME content → OK", ss);
    ASSERT("Unique name = szKeyName", _wcsicmp(wszBuf, L"MyTestKey") == 0);

    /* NCRYPT_EXPORT_POLICY_PROPERTY */
    dwVal = 0xFF;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_EXPORT_POLICY_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("EXPORT_POLICY → OK", ss);
    ASSERT_EQ("EXPORT_POLICY = 0 (non exportable)", dwVal, 0U);

    /* NCRYPT_KEY_USAGE_PROPERTY — AT_SIGNATURE */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_KEY_USAGE_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("KEY_USAGE AT_SIGNATURE → OK", ss);
    ASSERT("ALLOW_SIGNING_FLAG set",
           (dwVal & NCRYPT_ALLOW_SIGNING_FLAG) != 0);

    /* NCRYPT_ALGORITHM_GROUP_PROPERTY — RSA */
    cbResult = 0; memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("ALGORITHM_GROUP RSA size → OK", ss);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("ALGORITHM_GROUP RSA content → OK", ss);
    ASSERT("Group = RSA", _wcsicmp(wszBuf, NCRYPT_RSA_ALGORITHM_GROUP) == 0);

    KSP_Free((void *)(ULONG_PTR)hRsa);

    /* ── Suite 2 : GetKeyProperty — ECDSA key ───────────────────────────── */
    TEST_SUITE("KSP_GetKeyProperty — ECDSA P-256");

    NCRYPT_KEY_HANDLE hEc = make_test_key(ALG_ECDSA_P256, 256, AT_KEYEXCHANGE, TRUE);

    /* KEY_USAGE AT_KEYEXCHANGE */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hEc, NCRYPT_KEY_USAGE_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("KEY_USAGE AT_KEYEXCHANGE → OK", ss);
    ASSERT("ALLOW_DECRYPT_FLAG set",
           (dwVal & NCRYPT_ALLOW_DECRYPT_FLAG) != 0);

    /* ALGORITHM_GROUP → ECDSA */
    cbResult = 0; memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hEc, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        NULL, 0, &cbResult, 0);
    ss = KSP_GetKeyProperty(hProv, hEc, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("ALGORITHM_GROUP ECDSA → OK", ss);
    ASSERT("Group = ECDSA", _wcsicmp(wszBuf, NCRYPT_ECDSA_ALGORITHM_GROUP) == 0);

    KSP_Free((void *)(ULONG_PTR)hEc);

    /* ── Suite 3 : GetKeyProperty erreurs ───────────────────────────────── */
    TEST_SUITE("KSP_GetKeyProperty — error cases");

    NCRYPT_KEY_HANDLE hK = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);

    /* Unknown property */
    ss = KSP_GetKeyProperty(hProv, hK, L"PourquoiPas",
        NULL, 0, &cbResult, 0);
    ASSERT_EQ("Unknown prop → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Invalid key handle */
    ss = KSP_GetKeyProperty(hProv, 0,
        NCRYPT_ALGORITHM_PROPERTY, NULL, 0, &cbResult, 0);
    ASSERT_EQ("hKey=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* Buffer too small for LENGTH */
    ss = KSP_GetKeyProperty(hProv, hK, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwVal, 1, &cbResult, 0);
    ASSERT_EQ("Buffer too small (LENGTH) → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

    /* pcbResult NULL */
    ss = KSP_GetKeyProperty(hProv, hK, NCRYPT_ALGORITHM_PROPERTY,
        NULL, 0, NULL, 0);
    ASSERT_EQ("pcbResult=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_Free((void *)(ULONG_PTR)hK);

    /* ── Suite 4 : SetKeyProperty ───────────────────────────────────────── */
    TEST_SUITE("KSP_SetKeyProperty");

    /* Modify length before FinalizeKey */
    NCRYPT_KEY_HANDLE hPre = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, FALSE);
    DWORD newBits = 4096;
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_OK("SetKeyProperty LENGTH=4096 before FinalizeKey → OK", ss);

    /* Verify the modification */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("GetKeyProperty after Set → OK", ss);
    ASSERT_EQ("Length = 4096 after Set", dwVal, 4096U);

    /* Length 3072 */
    newBits = 3072;
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_OK("SetKeyProperty LENGTH=3072 → OK", ss);

    /* Invalid length */
    newBits = 1024;
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_EQ("LENGTH=1024 (invalid) → NTE_BAD_LEN",
        ss, (SECURITY_STATUS)NTE_BAD_LEN);

    newBits = 512;
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_EQ("LENGTH=512 → NTE_BAD_LEN", ss, (SECURITY_STATUS)NTE_BAD_LEN);

    /* Buffer too short */
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, 1, 0);
    ASSERT_EQ("Short buffer → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* pbInput NULL */
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        NULL, sizeof newBits, 0);
    ASSERT_EQ("pbInput=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_Free((void *)(ULONG_PTR)hPre);

    /* Modify after FinalizeKey → forbidden */
    NCRYPT_KEY_HANDLE hPost = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);
    newBits = 4096;
    ss = KSP_SetKeyProperty(hProv, hPost, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_EQ("SetKeyProperty after Finalize → NTE_INVALID_HANDLE",
        ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);
    KSP_Free((void *)(ULONG_PTR)hPost);

    /* Non-modifiable property */
    NCRYPT_KEY_HANDLE hAny = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, FALSE);
    ss = KSP_SetKeyProperty(hProv, hAny, NCRYPT_ALGORITHM_PROPERTY,
        (PBYTE)L"EC", 6, 0);
    ASSERT_EQ("Set ALGORITHM → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Invalid handle */
    ss = KSP_SetKeyProperty(hProv, 0, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_EQ("Invalid hKey → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_Free((void *)(ULONG_PTR)hAny);
    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
