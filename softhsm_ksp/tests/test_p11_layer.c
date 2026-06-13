/* test_p11_layer.c — Unit tests for the PKCS#11 layer
 * Compiles and runs independently of the KSP DLL.
 * Requires SoftHSM2 installed and SOFTHSM2_LIB set.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "pkcs11.h"
#include "p11_context.h"
#include "p11_session.h"
#include "p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/memory.h"

/* ── Test infrastructure ─────────────────────────────────────────────────── */
static int g_nPass = 0;
static int g_nFail = 0;

static void test_assert(const char *pszName, int bCond, const char *pszDetail)
{
    if (bCond) {
        printf("[PASS] %s\n", pszName);
        g_nPass++;
    } else {
        printf("[FAIL] %s : %s\n", pszName, pszDetail ? pszDetail : "");
        g_nFail++;
    }
}

#define ASSERT(name, cond)        test_assert(name, (cond), NULL)
#define ASSERT_EQ(name, a, b)     test_assert(name, (a) == (b), #a " != " #b)
#define ASSERT_NEQ(name, a, b)    test_assert(name, (a) != (b), #a " == " #b)
#define ASSERT_SS(name, ss)       test_assert(name, (ss) == ERROR_SUCCESS, "SECURITY_STATUS failed")

/* ── Test 1: initialisation with bad path ───────────────────────────────── */
static void test_bad_path(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 1: P11_Initialize with bad path ---\n");
    SetEnvironmentVariableA(SOFTHSM2_LIB_ENV, "C:\\nonexistent\\softhsm2.dll");

    /* Reset internal state to allow the test */
    ss = P11_Initialize();
    ASSERT("Bad path -> error", ss != ERROR_SUCCESS);

    /* Restore the environment variable to its default state */
    SetEnvironmentVariableA(SOFTHSM2_LIB_ENV, NULL);
}

/* ── Test 2: successful initialisation ──────────────────────────────────── */
static void test_initialize_ok(void)
{
    P11_CONTEXT    *pCtx;
    SECURITY_STATUS ss;

    printf("\n--- Test 2: P11_Initialize OK ---\n");

    /* Use the default path or SOFTHSM2_LIB */
    ss = P11_Initialize();
    ASSERT_SS("P11_Initialize returns ERROR_SUCCESS", ss);

    pCtx = P11_GetContext();
    ASSERT("Context not NULL", pCtx != NULL);
    ASSERT("bInitialized = TRUE", pCtx && pCtx->bInitialized);
    ASSERT("hModule not NULL", pCtx && pCtx->hModule != NULL);
    ASSERT("pFunctionList not NULL", pCtx && pCtx->pFunctionList != NULL);

    printf("  Selected slot: %lu\n", (unsigned long)(pCtx ? pCtx->slotId : 0));
}

/* ── Test 3: session pool initialisation ────────────────────────────────── */
static void test_session_pool_init(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 3: P11_SessionPool_Initialize ---\n");
    ss = P11_SessionPool_Initialize();
    ASSERT_SS("SessionPool_Initialize", ss);
}

/* ── Test 4: session acquisition ────────────────────────────────────────── */
static void test_acquire_session(void)
{
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;

    printf("\n--- Test 4: AcquireSession ---\n");
    ss = P11_AcquireSession(&hSession);
    ASSERT_SS("P11_AcquireSession returns ERROR_SUCCESS", ss);
    ASSERT("hSession valid", hSession != CK_INVALID_HANDLE);

    printf("  hSession = 0x%lX\n", (unsigned long)hSession);

    P11_ReleaseSession(hSession);
    ASSERT("ReleaseSession does not crash", 1);
}

/* ── Test 5: search for non-existent key ────────────────────────────────── */
static void test_find_nonexistent(void)
{
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hObj;

    printf("\n--- Test 5: FindObjectByLabel non-existent key ---\n");

    if (P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("AcquireSession for find", 0);
        return;
    }

    hObj = P11_FindObjectByLabel(hSession, CKO_PRIVATE_KEY,
                                 L"__nonexistent_key_ksp_test__");
    ASSERT("CKR_OK + null handle if absent",
           hObj == CK_INVALID_HANDLE);

    P11_ReleaseSession(hSession);
}

/* ── Test 6: RSA 2048 key generation ────────────────────────────────────── */
static CK_OBJECT_HANDLE g_hPrivRsa = CK_INVALID_HANDLE;
static CK_OBJECT_HANDLE g_hPubRsa  = CK_INVALID_HANDLE;
static const char       g_szRsaLabel[] = "KspTestRSA2048";

static void test_generate_rsa(void)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_MECHANISM      mech   = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_ULONG          ulBits = 2048;
    CK_BYTE           pubExp[] = { 0x01, 0x00, 0x01 };
    CK_BBOOL          bTrue  = CK_TRUE, bFalse = CK_FALSE;
    CK_OBJECT_CLASS   classPub  = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS   classPriv = CKO_PRIVATE_KEY;
    CK_RV             rv;

    printf("\n--- Test 6: GenerateKeyPair RSA 2048 ---\n");

    if (!pCtx || !pCtx->bInitialized ||
        P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("AcquireSession for RSA generate", 0);
        return;
    }

    CK_ATTRIBUTE aPub[] = {
        { CKA_CLASS,          &classPub,    sizeof(classPub)    },
        { CKA_TOKEN,          &bTrue,       sizeof(bTrue)       },
        { CKA_LABEL, (void*)g_szRsaLabel, sizeof(g_szRsaLabel)-1 },
        { CKA_MODULUS_BITS,   &ulBits,      sizeof(ulBits)      },
        { CKA_PUBLIC_EXPONENT, pubExp,      sizeof(pubExp)      },
        { CKA_VERIFY,         &bTrue,       sizeof(bTrue)       },
    };
    CK_ATTRIBUTE aPriv[] = {
        { CKA_CLASS,       &classPriv, sizeof(classPriv)        },
        { CKA_TOKEN,       &bTrue,     sizeof(bTrue)            },
        { CKA_LABEL, (void*)g_szRsaLabel, sizeof(g_szRsaLabel)-1 },
        { CKA_SENSITIVE,   &bTrue,     sizeof(bTrue)            },
        { CKA_EXTRACTABLE, &bFalse,    sizeof(bFalse)           },
        { CKA_SIGN,        &bTrue,     sizeof(bTrue)            },
    };

    rv = pCtx->pFunctionList->C_GenerateKeyPair(
        hSession, &mech,
        aPub,  (CK_ULONG)(sizeof(aPub)  / sizeof(CK_ATTRIBUTE)),
        aPriv, (CK_ULONG)(sizeof(aPriv) / sizeof(CK_ATTRIBUTE)),
        &g_hPubRsa, &g_hPrivRsa);

    P11_ReleaseSession(hSession);

    ASSERT("C_GenerateKeyPair RSA returns CKR_OK", rv == CKR_OK);
    ASSERT("hPrivRsa valid", g_hPrivRsa != CK_INVALID_HANDLE);
    ASSERT("hPubRsa valid",  g_hPubRsa  != CK_INVALID_HANDLE);

    printf("  hPrivRsa=0x%lX hPubRsa=0x%lX\n",
           (unsigned long)g_hPrivRsa, (unsigned long)g_hPubRsa);
}

/* ── Test 7: find key after generation ──────────────────────────────────── */
static void test_find_after_generate(void)
{
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hObj;
    WCHAR             wszLabel[64];

    printf("\n--- Test 7: FindObjectByLabel after generation ---\n");

    if (g_hPrivRsa == CK_INVALID_HANDLE) {
        ASSERT("Key generated (prerequisite)", 0);
        return;
    }

    if (P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("AcquireSession for find", 0);
        return;
    }

    MultiByteToWideChar(CP_UTF8, 0, g_szRsaLabel, -1, wszLabel, 64);
    hObj = P11_FindObjectByLabel(hSession, CKO_PRIVATE_KEY, wszLabel);
    ASSERT("FindObjectByLabel finds RSA key",
           hObj != CK_INVALID_HANDLE);

    P11_ReleaseSession(hSession);
}

/* ── Test 8: RSA PKCS1 signing ──────────────────────────────────────────── */
static void test_sign_rsa_pkcs1(void)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_MECHANISM      mech = { CKM_RSA_PKCS, NULL, 0 };
    CK_BYTE           hashBuf[32];
    CK_ULONG          cbSig = 0;
    CK_BYTE           sigBuf[512];
    CK_RV             rv;
    int               i;

    printf("\n--- Test 8: SignHash RSA PKCS1 ---\n");

    if (g_hPrivRsa == CK_INVALID_HANDLE || !pCtx ||
        P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("Prerequisite SignHash RSA", 0);
        return;
    }

    /* Fake SHA-256 hash (DigestInfo wrapping not needed for CKM_RSA_PKCS) */
    for (i = 0; i < 32; i++) hashBuf[i] = (CK_BYTE)(i + 1);

    rv = pCtx->pFunctionList->C_SignInit(hSession, &mech, g_hPrivRsa);
    ASSERT("C_SignInit RSA PKCS1", rv == CKR_OK);

    cbSig = sizeof(sigBuf);
    rv = pCtx->pFunctionList->C_Sign(hSession,
        hashBuf, 32, sigBuf, &cbSig);

    P11_ReleaseSession(hSession);

    ASSERT("C_Sign RSA PKCS1 returns CKR_OK", rv == CKR_OK);
    ASSERT("Signature not empty", cbSig > 0);

    printf("  RSA signature size: %lu bytes\n", (unsigned long)cbSig);
}

/* ── Test 9: RSA PSS signing ─────────────────────────────────────────────── */
static void test_sign_rsa_pss(void)
{
    P11_CONTEXT            *pCtx = P11_GetContext();
    CK_SESSION_HANDLE       hSession = CK_INVALID_HANDLE;
    CK_RSA_PKCS_PSS_PARAMS  pssParams = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_MECHANISM            mech = { CKM_RSA_PKCS_PSS,
                                     &pssParams, sizeof(pssParams) };
    CK_BYTE                 hashBuf[32];
    CK_ULONG                cbSig = 0;
    CK_BYTE                 sigBuf[512];
    CK_RV                   rv;
    int                     i;

    printf("\n--- Test 9: SignHash RSA PSS ---\n");

    if (g_hPrivRsa == CK_INVALID_HANDLE || !pCtx ||
        P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("Prerequisite SignHash PSS", 0);
        return;
    }

    for (i = 0; i < 32; i++) hashBuf[i] = (CK_BYTE)(0xFF - i);

    rv = pCtx->pFunctionList->C_SignInit(hSession, &mech, g_hPrivRsa);
    ASSERT("C_SignInit RSA PSS", rv == CKR_OK);

    cbSig = sizeof(sigBuf);
    rv = pCtx->pFunctionList->C_Sign(hSession,
        hashBuf, 32, sigBuf, &cbSig);

    P11_ReleaseSession(hSession);

    ASSERT("C_Sign RSA PSS returns CKR_OK", rv == CKR_OK);
    ASSERT("PSS signature not empty", cbSig > 0);

    printf("  PSS signature size: %lu bytes\n", (unsigned long)cbSig);
}

/* ── Test 10: key deletion ──────────────────────────────────────────────── */
static void test_destroy_key(void)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hObj;
    CK_RV             rv;
    WCHAR             wszLabel[64];

    printf("\n--- Test 10: DestroyObject ---\n");

    if (g_hPrivRsa == CK_INVALID_HANDLE || !pCtx ||
        P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("Prerequisite DestroyObject", 0);
        return;
    }

    rv = pCtx->pFunctionList->C_DestroyObject(hSession, g_hPrivRsa);
    ASSERT("C_DestroyObject RSA private key", rv == CKR_OK);

    rv = pCtx->pFunctionList->C_DestroyObject(hSession, g_hPubRsa);
    ASSERT("C_DestroyObject RSA public key", rv == CKR_OK);

    /* Verify the key is gone */
    MultiByteToWideChar(CP_UTF8, 0, g_szRsaLabel, -1, wszLabel, 64);
    hObj = P11_FindObjectByLabel(hSession, CKO_PRIVATE_KEY, wszLabel);
    ASSERT("Key destroyed: FindObjectByLabel returns INVALID_HANDLE",
           hObj == CK_INVALID_HANDLE);

    P11_ReleaseSession(hSession);
    g_hPrivRsa = CK_INVALID_HANDLE;
    g_hPubRsa  = CK_INVALID_HANDLE;
}

/* ── Entry point ─────────────────────────────────────────────────────────── */
int main(void)
{
    printf("=== PKCS#11 layer unit tests SoftHSM2 ===\n\n");

    SetEnvironmentVariableA("KSP_DEBUG", "1");
    Log_Initialize();

    /* Note: test_bad_path must run before P11_Initialize */
    test_bad_path();

    /* Reinit after the bad-path test */
    /* (InitOnceExecuteOnce is one-shot; this test assumes a dedicated binary) */

    test_initialize_ok();
    test_session_pool_init();
    test_acquire_session();
    test_find_nonexistent();
    test_generate_rsa();
    test_find_after_generate();
    test_sign_rsa_pkcs1();
    test_sign_rsa_pss();
    test_destroy_key();

    P11_SessionPool_Finalize();
    P11_Finalize();

    printf("\n══════════════════════════════════════\n");
    printf("Results: PASS=%d  FAIL=%d\n", g_nPass, g_nFail);
    printf("══════════════════════════════════════\n");

    return (g_nFail == 0) ? 0 : 1;
}
