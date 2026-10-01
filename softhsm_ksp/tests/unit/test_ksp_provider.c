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

/* Deferred slot binding (proposal B). The real pair lives in p11_context.c,
 * which this suite does not link; these record what the provider asked for
 * so the tests can assert the translation from CNG property to PKCS#11
 * selection, which is the part that lives in ksp_provider.c. */
static BOOL       g_bStubBound;
static char       g_szStubLabel[64];
static CK_SLOT_ID g_stubSlot;
static BOOL       g_bStubLabelSet, g_bStubSlotSet;
static int        g_nStubEnsure;

SECURITY_STATUS P11_EnsureSlotSelected(void)
{
    g_nStubEnsure++;
    g_bStubBound = TRUE;
    return ERROR_SUCCESS;
}

SECURITY_STATUS P11_SetTokenSelection(const char *szLabel,
                                      const CK_SLOT_ID *pSlot)
{
    if ((szLabel == NULL) == (pSlot == NULL))
        return NTE_INVALID_PARAMETER;
    if (g_bStubBound)
        return NTE_INVALID_HANDLE;
    if (szLabel) {
        size_t cb = strlen(szLabel);
        if (cb == 0 || cb > 32)
            return NTE_INVALID_PARAMETER;
        memcpy(g_szStubLabel, szLabel, cb + 1);
        g_bStubLabelSet = TRUE; g_bStubSlotSet = FALSE;
    } else {
        g_stubSlot = *pSlot;
        g_bStubSlotSet = TRUE; g_bStubLabelSet = FALSE;
    }
    return ERROR_SUCCESS;
}

BOOL P11_IsSlotBound(void) { return g_bStubBound; }
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

/* Records what KSP_SetProviderProperty hands to the session layer. */
static char g_szLastPin[256];
static int  g_nSetPinCalls = 0;
static SECURITY_STATUS g_ssSetPinResult = ERROR_SUCCESS;

SECURITY_STATUS P11_SetPin(const char *szPin)
{
    g_nSetPinCalls++;
    if (szPin)
        strncpy(g_szLastPin, szPin, sizeof(g_szLastPin) - 1);
    else
        g_szLastPin[0] = '\0';
    return g_ssSetPinResult;
}
void P11_ClearPin(void) { g_szLastPin[0] = '\0'; }

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

    /* ── Suite 6 : the slots that must exist ───────────────────────────── */
    TEST_SUITE("Required slots (PromptUser, GetOperationProperty)");

    /* KSP_NotifyChangeKey has its own suite below. It used to be asserted
     * here as "NotifyChangeKey → ERROR_SUCCESS", which was the defect
     * written down as a test: it returned success without writing the
     * caller's HANDLE. */
    NCRYPT_KEY_HANDLE dummy = 0;

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

    /* ── Suite : KSP_NotifyChangeKey ───────────────────────────────────── */
    TEST_SUITE("KSP_NotifyChangeKey");

    /* This returned ERROR_SUCCESS and never wrote *phEvent, so a caller
     * registering for notification was told it had succeeded and then
     * waited on an uninitialised HANDLE. The refusal below is the honest
     * answer: a PKCS#11 token has no key-change channel to register on. */
    {
        HANDLE hEvent = (HANDLE)(ULONG_PTR)0xDEADBEEF;

        ASSERT_EQ("Registering is refused, not falsely granted",
            KSP_NotifyChangeKey(hProv, &hEvent, NCRYPT_REGISTER_NOTIFY_FLAG),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        ASSERT("and *phEvent is cleared, so a caller that ignores the "
               "return value waits on nothing rather than on a stale value",
               hEvent == NULL);

        /* Tearing down something that was never registered is not an
         * error worth raising. */
        ASSERT_OK("Unregistering succeeds",
            KSP_NotifyChangeKey(hProv, NULL,
                                NCRYPT_UNREGISTER_NOTIFY_FLAG));

        ASSERT_EQ("An unknown flag is refused",
            KSP_NotifyChangeKey(hProv, &hEvent, 0x80000000),
            (SECURITY_STATUS)NTE_BAD_FLAGS);
        ASSERT_EQ("An invalid provider is refused",
            KSP_NotifyChangeKey(0, &hEvent, NCRYPT_REGISTER_NOTIFY_FLAG),
            (SECURITY_STATUS)NTE_INVALID_HANDLE);
    }

    /* ── Suite : KSP_SetProviderProperty — PIN (IFACE-04) ─────────────── */
    TEST_SUITE("KSP_SetProviderProperty — NCRYPT_PIN_PROPERTY");
    {
        WCHAR wszPin[] = L"1234";

        g_nSetPinCalls = 0;
        g_szLastPin[0] = '\0';

        /* cbInput excluding the terminator — what CNG usually passes. */
        ss = KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY,
                (PBYTE)wszPin, (DWORD)(wcslen(wszPin) * sizeof(WCHAR)), 0);
        ASSERT_OK("Set PIN → OK", ss);
        ASSERT_EQ("Session layer called once", g_nSetPinCalls, 1);
        ASSERT_STR("PIN narrowed to UTF-8 correctly", g_szLastPin, "1234");

        /* cbInput including the terminator — also legal, and the wide
         * string must not acquire a trailing NUL in the narrow copy. */
        g_nSetPinCalls = 0;
        ss = KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY,
                (PBYTE)wszPin, (DWORD)sizeof(wszPin), 0);
        ASSERT_OK("Set PIN with terminator counted → OK", ss);
        ASSERT_STR("Terminator not copied into the PIN", g_szLastPin, "1234");
    }
    {
        /* Non-ASCII PINs must survive the wide-to-narrow conversion. */
        WCHAR wszPin[] = L"pa\u00dfwort";
        g_szLastPin[0] = '\0';
        ss = KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY,
                (PBYTE)wszPin, (DWORD)(wcslen(wszPin) * sizeof(WCHAR)), 0);
        ASSERT_OK("Non-ASCII PIN → OK", ss);
        ASSERT_STR("Encoded as UTF-8", g_szLastPin, "pa\xc3\x9fwort");
    }
    {
        WCHAR wszPin[] = L"1234";

        ASSERT_EQ("Empty PIN → NTE_INVALID_PARAMETER",
            KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY,
                (PBYTE)wszPin, 0, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        ASSERT_EQ("pbInput=NULL → NTE_INVALID_PARAMETER",
            KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY, NULL, 8, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        ASSERT_EQ("pszProperty=NULL → NTE_INVALID_PARAMETER",
            KSP_SetProviderProperty(hProv, NULL, (PBYTE)wszPin, 8, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        ASSERT_EQ("Invalid provider → NTE_INVALID_HANDLE",
            KSP_SetProviderProperty(0, NCRYPT_PIN_PROPERTY,
                (PBYTE)wszPin, 8, 0),
            (SECURITY_STATUS)NTE_INVALID_HANDLE);

        /* A PIN longer than the fixed buffer must be refused, not
         * truncated: a truncated PIN would silently fail to log in. */
        {
            WCHAR wszLong[P11_MAX_PIN_LEN + 10];
            size_t i;
            for (i = 0; i < (sizeof wszLong / sizeof wszLong[0]) - 1; i++)
                wszLong[i] = L'x';
            wszLong[i] = L'\0';
            ASSERT_EQ("Over-long PIN → NTE_INVALID_PARAMETER",
                KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY,
                    (PBYTE)wszLong, (DWORD)(i * sizeof(WCHAR)), 0),
                (SECURITY_STATUS)NTE_INVALID_PARAMETER);
        }

        /* The boundary, both ways round. cbInput is the size of the buffer,
         * so a caller passing a maximum-length PIN may or may not count its
         * terminator; the one that does must not be refused. This path had
         * the same off-by-one the token label did, and for the same reason:
         * the length was bounded before the terminator was stripped. */
        {
            WCHAR wszMax[P11_MAX_PIN_LEN + 2];
            int   i;
            for (i = 0; i < P11_MAX_PIN_LEN; i++)
                wszMax[i] = L'9';
            wszMax[P11_MAX_PIN_LEN] = L'\0';

            ASSERT_OK("A maximum-length PIN counted WITHOUT its terminator",
                KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY,
                    (PBYTE)wszMax,
                    (DWORD)(P11_MAX_PIN_LEN * sizeof(WCHAR)), 0));
            ASSERT_EQ("reached the session layer whole",
                (int)strlen(g_szLastPin), P11_MAX_PIN_LEN);

            g_szLastPin[0] = '\0';
            ASSERT_OK("A maximum-length PIN counted WITH its terminator",
                KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY,
                    (PBYTE)wszMax,
                    (DWORD)((P11_MAX_PIN_LEN + 1) * sizeof(WCHAR)), 0));
            ASSERT_EQ("reached the session layer whole too",
                (int)strlen(g_szLastPin), P11_MAX_PIN_LEN);
        }

        /* A wide string cannot occupy an odd number of bytes. Truncating to
         * the next whole character would hand the token a PIN the caller
         * never typed. */
        ASSERT_EQ("Odd byte count → NTE_INVALID_PARAMETER",
            KSP_SetProviderProperty(hProv, NCRYPT_PIN_PROPERTY,
                (PBYTE)wszPin, 7, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        ASSERT_EQ("Unknown property → NTE_NOT_SUPPORTED",
            KSP_SetProviderProperty(hProv, L"No Such Property",
                (PBYTE)wszPin, 8, 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    }

    /* ── Suite : reading the selected slot back (OPS-04) ───────────────── */
    TEST_SUITE("KSP_GetProviderProperty — slot");
    {
        DWORD dwSlot = 0xFFFFFFFF;
        DWORD cb = 0;

        g_testCtx.slotId = 7;
        ss = KSP_GetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                (PBYTE)&dwSlot, sizeof dwSlot, &cb, 0);
        ASSERT_OK("Read slot → OK", ss);
        ASSERT_EQ("Reports the selected slot", dwSlot, 7U);
        ASSERT_EQ("cbResult = 4", cb, (DWORD)sizeof(DWORD));

        cb = 0;
        ss = KSP_GetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                NULL, 0, &cb, 0);
        ASSERT_OK("Size query → OK", ss);
        ASSERT_EQ("Size query returns 4", cb, (DWORD)sizeof(DWORD));

        ss = KSP_GetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                (PBYTE)&dwSlot, 2, &cb, 0);
        ASSERT_EQ("Short buffer → NTE_BUFFER_TOO_SMALL",
            ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

        g_testCtx.slotId = 0;
    }


    /* ── Suite : choosing the token through NCryptSetProperty (IFACE-04) ──
     *
     * The slot is no longer chosen inside P11_Initialize, so there is a
     * window between NCryptOpenStorageProvider and the first operation in
     * which a caller can still name the token. These assertions cover the
     * translation from the CNG property to the PKCS#11 selection; that the
     * selection then reaches the right token is a fact about a token and is
     * asserted in tests/linux against TWO real tokens, because a test with
     * one token cannot tell a working selection from an ignored one. */
    TEST_SUITE("KSP_SetProviderProperty — token selection");
    {
        g_bStubBound = FALSE;      /* an earlier suite bound it */
        g_bStubLabelSet = g_bStubSlotSet = FALSE;
        g_szStubLabel[0] = '\0';

        ASSERT_OK("Set token label → OK",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                (PBYTE)L"MyToken", 7 * sizeof(WCHAR), 0));
        ASSERT("Label reached the PKCS#11 layer", g_bStubLabelSet);
        ASSERT_STR("Label converted to UTF-8 narrow", g_szStubLabel, "MyToken");

        /* CNG passes the property as a counted buffer, and callers differ on
         * whether the count includes the terminator. Both must work.
         *
         * For a short label a trailing NUL is harmless — the narrow string
         * is NUL-terminated anyway, so strlen sees the same label either
         * way. It stops being harmless at the boundary: CKA_LABEL is 32
         * bytes, so a full-width label plus a terminator is 33 WCHARs, and
         * a length check that counts the terminator refuses a label that is
         * exactly legal. That is the case worth asserting, and the short
         * one below only documents that the easy path works. */
        g_szStubLabel[0] = '\0';
        ASSERT_OK("Label with a terminator → OK",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                (PBYTE)L"MyToken", 8 * sizeof(WCHAR), 0));
        ASSERT_STR("Terminator stripped", g_szStubLabel, "MyToken");

        {
            WCHAR wszFull[P11_TOKEN_LABEL_LEN + 1];
            char  szExpect[P11_TOKEN_LABEL_LEN + 1];
            int   i;
            for (i = 0; i < P11_TOKEN_LABEL_LEN; i++) {
                wszFull[i]  = L'z';
                szExpect[i] = 'z';
            }
            wszFull[P11_TOKEN_LABEL_LEN]  = L'\0';
            szExpect[P11_TOKEN_LABEL_LEN] = '\0';

            g_szStubLabel[0] = '\0';
            ASSERT_OK("A 32-byte label counted WITHOUT its terminator → OK",
                KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                    (PBYTE)wszFull,
                    P11_TOKEN_LABEL_LEN * sizeof(WCHAR), 0));
            ASSERT_STR("and arrives whole", g_szStubLabel, szExpect);

            g_szStubLabel[0] = '\0';
            ASSERT_OK("A 32-byte label counted WITH its terminator → OK",
                KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                    (PBYTE)wszFull,
                    (P11_TOKEN_LABEL_LEN + 1) * sizeof(WCHAR), 0));
            ASSERT_STR("and arrives whole too", g_szStubLabel, szExpect);
        }

        ASSERT_EQ("Empty label → NTE_INVALID_PARAMETER",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                (PBYTE)L"", 0, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);
        {
            /* PKCS#11 gives CKA_LABEL 32 bytes. A longer one cannot match
             * any token, so it is refused rather than truncated — a
             * truncated label would select a DIFFERENT token. */
            WCHAR wszLong[40];
            int   i;
            for (i = 0; i < 33; i++)
                wszLong[i] = L'x';
            ASSERT_EQ("Over-long label → NTE_INVALID_PARAMETER",
                KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                    (PBYTE)wszLong, 33 * sizeof(WCHAR), 0),
                (SECURITY_STATUS)NTE_INVALID_PARAMETER);
        }

        {
            DWORD dwSlot = 3;
            ASSERT_OK("Set slot → OK",
                KSP_SetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                    (PBYTE)&dwSlot, sizeof dwSlot, 0));
            ASSERT("Slot reached the PKCS#11 layer", g_bStubSlotSet);
            ASSERT_EQ("Slot value passed through",
                (DWORD)g_stubSlot, 3U);
            ASSERT("Slot supersedes the label", !g_bStubLabelSet);

            ASSERT_EQ("Slot of the wrong width → NTE_INVALID_PARAMETER",
                KSP_SetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                    (PBYTE)&dwSlot, 2, 0),
                (SECURITY_STATUS)NTE_INVALID_PARAMETER);

            /* Once the slot is bound, both are refused. Accepting them
             * would tell the caller it had switched token while every
             * operation continued against the old one. */
            g_bStubBound = TRUE;
            ASSERT_EQ("Set label after binding → NTE_INVALID_HANDLE",
                KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                    (PBYTE)L"Other", 5 * sizeof(WCHAR), 0),
                (SECURITY_STATUS)NTE_INVALID_HANDLE);
            ASSERT_EQ("Set slot after binding → NTE_INVALID_HANDLE",
                KSP_SetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                    (PBYTE)&dwSlot, sizeof dwSlot, 0),
                (SECURITY_STATUS)NTE_INVALID_HANDLE);
            g_bStubBound = FALSE;
        }
    }

    /* ── Suite : a capability answer binds the slot first ─────────────────
     *
     * P11_HasMechanism answers permissively when the probe has not run, so
     * an EnumAlgorithms called before anything had bound a slot would
     * advertise the full mapped list — algorithms the token may not have.
     * Both entry points therefore bind first. */
    TEST_SUITE("Capability queries bind the slot");
    {
        DWORD   dwCount = 0;
        void   *pList   = NULL;
        int     nBefore;

        g_nStubEnsure = 0;
        (void)KSP_IsAlgSupported(hProv, BCRYPT_RSA_ALGORITHM, 0);
        ASSERT("IsAlgSupported binds the slot", g_nStubEnsure >= 1);

        nBefore = g_nStubEnsure;
        if (KSP_EnumAlgorithms(hProv, NCRYPT_SIGNATURE_OPERATION,
                               &dwCount, (NCryptAlgorithmName **)&pList, 0)
                == ERROR_SUCCESS && pList)
            KSP_FreeBuffer(pList);
        ASSERT("EnumAlgorithms binds the slot",
            g_nStubEnsure > nBefore);
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
