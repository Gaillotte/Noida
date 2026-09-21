/* test_ksp_provider.c — Coverage of ksp_provider.c and ksp_properties.c
 * Uses stubs for P11_Initialize and P11_SessionPool_Initialize.
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

static SECURITY_STATUS g_p11InitStatus = ERROR_SUCCESS;
SECURITY_STATUS P11_Initialize(void)       { return g_p11InitStatus; }
SECURITY_STATUS P11_SessionPool_Initialize(void) { return ERROR_SUCCESS; }
void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }
void Log_Initialize(void) {}

void *KSP_Alloc(SIZE_T n);
void *KSP_AllocZero(SIZE_T n);
void  KSP_Free(void *p);
LPWSTR KSP_WStrDup(LPCWSTR p);

/* Inclure les modules sous test */
#include "../../src/ksp/ksp_provider.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_properties.h"

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS    ss;
    DWORD              cbResult;
    WCHAR              wszBuf[256];
    DWORD              dwVal;

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    g_testCtx.slotId        = 0;

    /* ── Suite 1 : OpenProvider ─────────────────────────────────────────── */
    TEST_SUITE("KSP_OpenProvider");

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_OK("OpenProvider OK", ss);
    ASSERT("hProv non-null", hProv != 0);
    ASSERT("IsValidProvider", KSP_IsValidProvider(hProv));

    /* Double call → two independent handles */
    NCRYPT_PROV_HANDLE hProv2 = 0;
    ss = KSP_OpenProvider(&hProv2, KSP_PROVIDER_NAME, 0);
    ASSERT_OK("Second OpenProvider OK", ss);
    ASSERT("Distinct handles", hProv != hProv2);
    KSP_FreeProvider(hProv2);

    /* ppProvider = NULL */
    ss = KSP_OpenProvider(NULL, KSP_PROVIDER_NAME, 0);
    ASSERT_EQ("ppProvider=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* P11_Initialize fails */
    g_p11InitStatus = NTE_PROVIDER_DLL_FAIL;
    NCRYPT_PROV_HANDLE hBad = 0;
    ss = KSP_OpenProvider(&hBad, KSP_PROVIDER_NAME, 0);
    ASSERT_EQ("P11 init fails → NTE_PROVIDER_DLL_FAIL",
        ss, (SECURITY_STATUS)NTE_PROVIDER_DLL_FAIL);
    ASSERT_EQ("hBad remains 0", hBad, (NCRYPT_PROV_HANDLE)0);
    g_p11InitStatus = ERROR_SUCCESS;

    /* ── Suite 2 : FreeProvider ─────────────────────────────────────────── */
    TEST_SUITE("KSP_FreeProvider");

    ss = KSP_FreeProvider(hProv);
    ASSERT_OK("FreeProvider OK", ss);
    /* Note: hProv is freed — no dereference after free */

    /* Invalid handle */
    ss = KSP_FreeProvider(0);
    ASSERT_EQ("FreeProvider(0) → NTE_INVALID_HANDLE",
        ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);

    /* Wrong magic → NTE_INVALID_HANDLE (without dereferencing a wild pointer) */
    KSP_PROVIDER badProv;
    memset(&badProv, 0, sizeof(badProv));
    badProv.dwMagic = 0xDEADBEEFUL;
    ss = KSP_FreeProvider((NCRYPT_PROV_HANDLE)(ULONG_PTR)&badProv);
    ASSERT_EQ("FreeProvider(wrong magic) → NTE_INVALID_HANDLE",
        ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);

    /* Reopen for subsequent test suites */
    KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);

    /* ── Suite 3 : GetProviderProperty ──────────────────────────────────── */
    TEST_SUITE("KSP_GetProviderProperty");

    /* NCRYPT_NAME_PROPERTY */
    cbResult = 0;
    ss = KSP_GetProviderProperty(hProv, NCRYPT_NAME_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("NAME → size OK", ss);
    ASSERT("cbResult > 0", cbResult > 0);

    memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetProviderProperty(hProv, NCRYPT_NAME_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("NAME → content OK", ss);
    ASSERT("Name = KSP_PROVIDER_NAME",
           _wcsicmp(wszBuf, KSP_PROVIDER_NAME) == 0);

    /* NCRYPT_VERSION_PROPERTY */
    dwVal = 0;
    ss = KSP_GetProviderProperty(hProv, NCRYPT_VERSION_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("VERSION → OK", ss);
    ASSERT_EQ("Version = 1", dwVal, 1U);

    /* NCRYPT_IMPL_TYPE_PROPERTY */
    dwVal = 0;
    ss = KSP_GetProviderProperty(hProv, NCRYPT_IMPL_TYPE_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("IMPL_TYPE → OK", ss);
    /* SoftHSM2 is a software token, so the provider reports SOFTWARE.
     * The emitted value is unchanged from before — NCRYPT_IMPL_HARDWARE_FLAG
     * used to be mis-defined as 0x2, which is the SOFTWARE flag's value. */
    ASSERT("IMPL_SOFTWARE_FLAG set",
           (dwVal & NCRYPT_IMPL_SOFTWARE_FLAG) != 0);
    ASSERT("IMPL_HARDWARE_FLAG not set",
           (dwVal & NCRYPT_IMPL_HARDWARE_FLAG) == 0);

    /* Buffer too small for NAME */
    ss = KSP_GetProviderProperty(hProv, NCRYPT_NAME_PROPERTY,
        (PBYTE)wszBuf, 2, &cbResult, 0);
    ASSERT_EQ("Buffer too small → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

    /* Unknown property */
    ss = KSP_GetProviderProperty(hProv, L"UnknownProp",
        (PBYTE)wszBuf, sizeof wszBuf, &cbResult, 0);
    ASSERT_EQ("Unknown prop → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Invalid handle */
    ss = KSP_GetProviderProperty(0, NCRYPT_NAME_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_EQ("Invalid handle → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* pcbResult NULL */
    ss = KSP_GetProviderProperty(hProv, NCRYPT_NAME_PROPERTY,
        NULL, 0, NULL, 0);
    ASSERT_EQ("pcbResult=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 4 : SetProviderProperty ──────────────────────────────────── */
    TEST_SUITE("KSP_SetProviderProperty");

    ss = KSP_SetProviderProperty(hProv, NCRYPT_NAME_PROPERTY,
        (PBYTE)L"Test", 10, 0);
    ASSERT_EQ("SetProviderProperty → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* ── Suite 5 : FreeBuffer / FreeObject ──────────────────────────────── */
    TEST_SUITE("KSP_FreeBuffer / KSP_FreeObject");

    void *pBuf = KSP_Alloc(64);
    ASSERT_NOTNULL("Alloc before FreeBuffer", pBuf);
    ss = KSP_FreeBuffer(pBuf);
    ASSERT_OK("FreeBuffer → OK", ss);

    ss = KSP_FreeBuffer(NULL);
    ASSERT_OK("FreeBuffer(NULL) → OK", ss);

    pBuf = KSP_Alloc(32);
    ss = KSP_FreeObject(pBuf);
    ASSERT_OK("FreeObject → OK", ss);

    /* ── Suite 6 : Stubs obligatoires ───────────────────────────────────── */
    TEST_SUITE("Stubs obligatoires (NotifyChangeKey, PromptUser, GetOperationProperty)");

    NCRYPT_KEY_HANDLE dummy = 0;
    ss = KSP_NotifyChangeKey(hProv, dummy, 0);
    ASSERT_OK("NotifyChangeKey → ERROR_SUCCESS", ss);

    ss = KSP_PromptUser(hProv, dummy, L"Sign", 0);
    ASSERT_EQ("PromptUser → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    DWORD cbOp = 0;
    ss = KSP_GetOperationProperty(hProv, dummy, L"Prop",
        NULL, 0, &cbOp, 0);
    ASSERT_EQ("GetOperationProperty → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* ── Suite : algorithm discovery ──────────────────────────────────── */
    TEST_SUITE("KSP_IsAlgSupported / KSP_EnumAlgorithms");

    /* Only algorithms with a real CNG identifier are published. */
    ASSERT_OK("RSA supported",
        KSP_IsAlgSupported(hProv, ALG_RSA, 0));
    ASSERT_OK("ECDSA_P256 supported",
        KSP_IsAlgSupported(hProv, ALG_ECDSA_P256, 0));
    ASSERT_OK("ECDSA_P521 supported",
        KSP_IsAlgSupported(hProv, ALG_ECDSA_P521, 0));
    ASSERT_OK("ECDH_P384 supported",
        KSP_IsAlgSupported(hProv, ALG_ECDH_P384, 0));
    ASSERT_OK("AES supported",
        KSP_IsAlgSupported(hProv, ALG_AES, 0));
    ASSERT_OK("Algorithm match is case-insensitive",
        KSP_IsAlgSupported(hProv, L"rsa", 0));

    /* These work through the provider, but CNG has no identifier for them,
     * so they are deliberately not advertised. */
    ASSERT_EQ("EDDSA_ED25519 not advertised",
        KSP_IsAlgSupported(hProv, ALG_EDDSA_ED25519, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    ASSERT_EQ("HMAC_SHA256 not advertised",
        KSP_IsAlgSupported(hProv, ALG_HMAC_SHA256, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    ASSERT_EQ("ECDSA_SECP256K1 not advertised",
        KSP_IsAlgSupported(hProv, ALG_ECDSA_SECP256K1, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    ASSERT_EQ("Unknown algorithm → NTE_NOT_SUPPORTED",
        KSP_IsAlgSupported(hProv, L"NOT_AN_ALGORITHM", 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    ASSERT_EQ("pszAlgId=NULL → NTE_INVALID_PARAMETER",
        KSP_IsAlgSupported(hProv, NULL, 0),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    ASSERT_EQ("Invalid provider → NTE_INVALID_HANDLE",
        KSP_IsAlgSupported(0, ALG_RSA, 0),
        (SECURITY_STATUS)NTE_INVALID_HANDLE);

    {
        NCryptAlgorithmName *pAlgs = NULL;
        DWORD  cAlgs = 0;
        DWORD  i;
        BOOL   bFoundRsa = FALSE;
        BOOL   bFoundAes = FALSE;

        /* 0 means every operation class. */
        ss = KSP_EnumAlgorithms(hProv, 0, &cAlgs, &pAlgs, 0);
        ASSERT_OK("EnumAlgorithms(all) → OK", ss);
        ASSERT("At least RSA, three ECDSA, three ECDH and AES", cAlgs >= 8);
        ASSERT_NOTNULL("Algorithm list returned", pAlgs);

        for (i = 0; i < cAlgs; i++) {
            ASSERT_NOTNULL("  name is non-NULL", pAlgs[i].pszName);
            ASSERT_EQ("  class is key storage",
                pAlgs[i].dwClass, (DWORD)NCRYPT_KEY_STORAGE_INTERFACE);
            ASSERT("  at least one operation set",
                pAlgs[i].dwAlgOperations != 0);
            if (wcscmp(pAlgs[i].pszName, ALG_RSA) == 0) bFoundRsa = TRUE;
            if (wcscmp(pAlgs[i].pszName, ALG_AES) == 0) bFoundAes = TRUE;
        }
        ASSERT("RSA present in the list", bFoundRsa);
        ASSERT("AES present in the list", bFoundAes);
        KSP_FreeBuffer(pAlgs);
    }
    {
        /* Filtering by operation class. */
        NCryptAlgorithmName *pAlgs = NULL;
        DWORD cAlgs = 0, i;

        ss = KSP_EnumAlgorithms(hProv, NCRYPT_SECRET_AGREEMENT_OPERATION,
                                &cAlgs, &pAlgs, 0);
        ASSERT_OK("EnumAlgorithms(secret agreement) → OK", ss);
        ASSERT_EQ("Exactly the three ECDH curves", cAlgs, 3U);
        for (i = 0; i < cAlgs; i++)
            ASSERT("  each carries the secret-agreement operation",
                (pAlgs[i].dwAlgOperations &
                 NCRYPT_SECRET_AGREEMENT_OPERATION) != 0);
        KSP_FreeBuffer(pAlgs);

        ss = KSP_EnumAlgorithms(hProv, NCRYPT_CIPHER_OPERATION,
                                &cAlgs, &pAlgs, 0);
        ASSERT_OK("EnumAlgorithms(cipher) → OK", ss);
        ASSERT_EQ("Only AES is a cipher", cAlgs, 1U);
        ASSERT_WSTR("  and it is AES", pAlgs[0].pszName, ALG_AES);
        KSP_FreeBuffer(pAlgs);

        /* RSA signs and decrypts, so it appears under both classes. */
        ss = KSP_EnumAlgorithms(hProv,
                NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION, &cAlgs, &pAlgs, 0);
        ASSERT_OK("EnumAlgorithms(asymmetric encryption) → OK", ss);
        ASSERT_EQ("Only RSA decrypts", cAlgs, 1U);
        ASSERT_WSTR("  and it is RSA", pAlgs[0].pszName, ALG_RSA);
        KSP_FreeBuffer(pAlgs);

        /* An operation class this provider implements for no algorithm. */
        ss = KSP_EnumAlgorithms(hProv, NCRYPT_RNG_OPERATION,
                                &cAlgs, &pAlgs, 0);
        ASSERT_OK("EnumAlgorithms(RNG) → OK", ss);
        ASSERT_EQ("No RNG algorithms", cAlgs, 0U);
        ASSERT_NULL("List is NULL when empty", pAlgs);
    }
    {
        NCryptAlgorithmName *pAlgs = NULL;
        DWORD cAlgs = 0;

        ASSERT_EQ("pdwAlgCount=NULL → NTE_INVALID_PARAMETER",
            KSP_EnumAlgorithms(hProv, 0, NULL, &pAlgs, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);
        ASSERT_EQ("ppAlgList=NULL → NTE_INVALID_PARAMETER",
            KSP_EnumAlgorithms(hProv, 0, &cAlgs, NULL, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);
        ASSERT_EQ("Invalid provider → NTE_INVALID_HANDLE",
            KSP_EnumAlgorithms(0, 0, &cAlgs, &pAlgs, 0),
            (SECURITY_STATUS)NTE_INVALID_HANDLE);
    }

    /* ── Suite : KSP_VerifySignature ───────────────────────────────────── */
    TEST_SUITE("KSP_VerifySignature");

    /* Deliberately unimplemented: callers verify far more cheaply with
     * BCryptVerifySignature against the exported public key. The slot is
     * wired to this stub rather than left NULL, which ncrypt.dll would
     * call regardless. */
    ASSERT_EQ("VerifySignature → NTE_NOT_SUPPORTED",
        KSP_VerifySignature(hProv, 0, NULL, (PBYTE)"h", 1, (PBYTE)"s", 1, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
