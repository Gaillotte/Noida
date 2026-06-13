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
    ASSERT_EQ("hBad reste 0", hBad, (NCRYPT_PROV_HANDLE)0);
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
    ASSERT("IMPL_HARDWARE_FLAG set",
           (dwVal & NCRYPT_IMPL_HARDWARE_FLAG) != 0);

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

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
