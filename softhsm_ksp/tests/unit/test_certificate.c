/* test_certificate.c — PROP-14: NCRYPT_CERTIFICATE_PROPERTY
 *
 * Certificate enrolment is the flow this provider exists to serve, and it
 * has two halves: the CA signs a request with a key the KSP holds, then
 * hands the issued certificate back for the KSP to keep beside that key.
 * Until now the provider did only the first half.
 *
 * These cover the real implementation in ksp_key.c — the object actually
 * written to the token, not the property dispatch. test_ksp_key_props.c
 * covers the dispatch against a recording stub.
 *
 * The thing most worth asserting is not the round trip but the object's
 * shape: a certificate written as the wrong class, or without the scoped
 * label, would round-trip perfectly through this mock and be invisible to
 * every other lookup on a real token.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_properties.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/common/config.h"
#include "../../src/common/memory.h"
#include "test_framework.h"
#include <wchar.h>
#include <string.h>

/* ── PKCS#11 context / session stubs ────────────────────────────────────── */
static P11_CONTEXT g_testCtx;

P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }
SECURITY_STATUS P11_Initialize(void)             { return ERROR_SUCCESS; }
SECURITY_STATUS P11_SessionPool_Initialize(void) { return ERROR_SUCCESS; }

SECURITY_STATUS P11_AcquireSession(CK_SESSION_HANDLE *ph)
{
    *ph = (CK_SESSION_HANDLE)1;
    return ERROR_SUCCESS;
}
void P11_ReleaseSession(CK_SESSION_HANDLE h) { (void)h; }

/* A stand-in for a DER certificate. Nothing parses it — the provider
 * deliberately does not look inside — so its only requirement is to be
 * distinguishable from whatever else the mock might hand back. */
static BYTE g_cert[512];
static BYTE g_cert2[300];

static void InitCerts(void)
{
    DWORD i;
    for (i = 0; i < sizeof(g_cert); i++)  g_cert[i]  = (BYTE)(i & 0xFF);
    for (i = 0; i < sizeof(g_cert2); i++) g_cert2[i] = (BYTE)(0xFF - (i & 0xFF));
    g_cert[0]  = 0x30;   /* SEQUENCE, so it at least looks like a certificate */
    g_cert2[0] = 0x30;
}

/* Present a token that holds a certificate for the current key. */
static void TokenHasCert(const BYTE *pb, DWORD cb)
{
    P11Mock_GetConfig()->nCertObjects  = 1;
    P11Mock_GetConfig()->pbSecretValue = pb;
    P11Mock_GetConfig()->cbSecretValue = cb;
}

static void TokenHasNoCert(void)
{
    P11Mock_GetConfig()->nCertObjects = 0;
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE  hKey  = 0;
    KSP_KEY           *pKey;
    SECURITY_STATUS    ss;
    DWORD              cbResult = 0;
    BYTE               abOut[1024];

    InitCerts();
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    g_testCtx.slotId        = 0;
    P11_ProbeCapabilities();

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_OK("Provider opened", ss);

    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, L"enrol-key", 0,
                                NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Key created", ss);
    ss = KSP_FinalizeKey(hProv, hKey, 0);
    ASSERT_OK("Key finalised", ss);
    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    /* ── Suite 1 : storing the certificate ──────────────────────────────── */
    TEST_SUITE("KSP_StoreCertificate");

    P11Mock_ResetCalls();
    TokenHasNoCert();

    ss = KSP_StoreCertificate(pKey, g_cert, sizeof(g_cert));
    ASSERT_OK("Store a certificate", ss);
    ASSERT_EQ("One object created", P11Mock_GetCalls()->nCreateObject, 1);

    /* The shape of the object is what matters. A certificate written as
     * CKO_DATA would round-trip through this mock and be invisible to
     * every certificate-aware tool on a real token. */
    ASSERT_EQ("Written as CKO_CERTIFICATE",
        P11Mock_GetConfig()->lastCreateClass, (CK_OBJECT_CLASS)CKO_CERTIFICATE);
    ASSERT_EQ("Certificate type is CKC_X_509",
        P11Mock_GetConfig()->lastCreateCertType, (CK_ULONG)CKC_X_509);
    ASSERT_EQ("The whole certificate was stored",
        P11Mock_GetConfig()->cbLastCreateValue, (CK_ULONG)sizeof(g_cert));
    ASSERT("Bytes stored unaltered",
        memcmp(P11Mock_GetConfig()->lastCreateValue, g_cert,
               sizeof(g_cert)) == 0);

    /* The certificate must carry the key's scoped label, or the two stop
     * travelling together the moment machine and user scopes are both in
     * use. This key is a user key, so "u/enrol-key". */
    ASSERT("Label is the key's scoped label",
        strcmp(P11Mock_GetConfig()->lastLabel, "u/enrol-key") == 0);

    /* ── Suite 2 : reading it back ──────────────────────────────────────── */
    TEST_SUITE("KSP_LoadCertificate");

    TokenHasCert(g_cert, sizeof(g_cert));

    /* CNG's two-call convention: a NULL buffer reports the size. */
    cbResult = 0;
    ss = KSP_LoadCertificate(pKey, NULL, 0, &cbResult);
    ASSERT_OK("Size query succeeds", ss);
    ASSERT_EQ("Size is the certificate length",
        cbResult, (DWORD)sizeof(g_cert));

    memset(abOut, 0, sizeof(abOut));
    cbResult = 0;
    ss = KSP_LoadCertificate(pKey, abOut, sizeof(abOut), &cbResult);
    ASSERT_OK("Read back succeeds", ss);
    ASSERT_EQ("Length matches", cbResult, (DWORD)sizeof(g_cert));
    ASSERT("Contents match", memcmp(abOut, g_cert, sizeof(g_cert)) == 0);

    /* A short buffer must not be written past. */
    cbResult = 0;
    ss = KSP_LoadCertificate(pKey, abOut, 4, &cbResult);
    ASSERT_EQ("Short buffer → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);
    ASSERT_EQ("and the required size is still reported",
        cbResult, (DWORD)sizeof(g_cert));

    ASSERT_EQ("pcbResult=NULL → NTE_INVALID_PARAMETER",
        KSP_LoadCertificate(pKey, NULL, 0, NULL),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 3 : a key with no certificate ────────────────────────────── */
    TEST_SUITE("No certificate yet");

    TokenHasNoCert();

    cbResult = 0;
    ss = KSP_LoadCertificate(pKey, NULL, 0, &cbResult);
    /* Between generation and enrolment this is the normal state, so it is
     * NTE_NOT_FOUND rather than an error about the property itself. */
    ASSERT_EQ("No certificate → NTE_NOT_FOUND",
        ss, (SECURITY_STATUS)NTE_NOT_FOUND);

    /* ── Suite 4 : re-enrolment replaces, never accumulates ─────────────── */
    TEST_SUITE("Replacing a certificate");

    P11Mock_ResetCalls();
    TokenHasCert(g_cert, sizeof(g_cert));   /* one already present */

    ss = KSP_StoreCertificate(pKey, g_cert2, sizeof(g_cert2));
    ASSERT_OK("Store a replacement", ss);
    /* Without the destroy, a re-enrolled key ends up with two certificate
     * objects sharing a label and lookups become a coin toss. */
    ASSERT_EQ("The old certificate was destroyed",
        P11Mock_GetCalls()->nDestroyObject, 1);
    ASSERT_EQ("and exactly one new object created",
        P11Mock_GetCalls()->nCreateObject, 1);
    ASSERT_EQ("The replacement is what was written",
        P11Mock_GetConfig()->cbLastCreateValue, (CK_ULONG)sizeof(g_cert2));

    /* ── Suite 5 : machine and user scopes stay distinct ────────────────── */
    TEST_SUITE("Certificate scoping");

    {
        NCRYPT_KEY_HANDLE hMachine = 0;
        KSP_KEY          *pMachine;

        ss = KSP_CreatePersistedKey(hProv, &hMachine, ALG_RSA, L"enrol-key", 0,
                                    NCRYPT_PERSIST_ONLY_FLAG |
                                    NCRYPT_MACHINE_KEY_FLAG);
        ASSERT_OK("Machine key of the same name created", ss);
        ss = KSP_FinalizeKey(hProv, hMachine, 0);
        ASSERT_OK("Machine key finalised", ss);
        pMachine = (KSP_KEY *)(ULONG_PTR)hMachine;

        P11Mock_ResetCalls();
        TokenHasNoCert();
        ss = KSP_StoreCertificate(pMachine, g_cert, sizeof(g_cert));
        ASSERT_OK("Store against the machine key", ss);
        /* The whole point of the scope prefix: two keys named "enrol-key"
         * must not share one certificate object. */
        ASSERT("Machine certificate carries the m/ prefix",
            strcmp(P11Mock_GetConfig()->lastLabel, "m/enrol-key") == 0);

        KSP_FreeKey(hProv, hMachine);
    }

    /* ── Suite 6 : parameter handling and failure propagation ───────────── */
    TEST_SUITE("Error handling");

    ASSERT_EQ("NULL certificate → NTE_INVALID_PARAMETER",
        KSP_StoreCertificate(pKey, NULL, 10),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    ASSERT_EQ("Zero length → NTE_INVALID_PARAMETER",
        KSP_StoreCertificate(pKey, g_cert, 0),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    P11Mock_GetConfig()->rv_CreateObject = CKR_DEVICE_ERROR;
    ss = KSP_StoreCertificate(pKey, g_cert, sizeof(g_cert));
    ASSERT_ERR("A token failure propagates", ss);
    P11Mock_GetConfig()->rv_CreateObject = CKR_OK;

    TokenHasCert(g_cert, sizeof(g_cert));
    P11Mock_GetConfig()->rv_GetAttributeValue = CKR_DEVICE_ERROR;
    cbResult = 0;
    ss = KSP_LoadCertificate(pKey, NULL, 0, &cbResult);
    ASSERT_ERR("A failed attribute read propagates", ss);
    P11Mock_GetConfig()->rv_GetAttributeValue = CKR_OK;

    /* ── Suite 7 : through the CNG property interface ───────────────────── */
    TEST_SUITE("NCRYPT_CERTIFICATE_PROPERTY");

    P11Mock_ResetCalls();
    TokenHasNoCert();

    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CERTIFICATE_PROPERTY,
                            g_cert, sizeof(g_cert), 0);
    ASSERT_OK("Set through the property interface", ss);
    ASSERT_EQ("reached the token", P11Mock_GetCalls()->nCreateObject, 1);

    TokenHasCert(g_cert, sizeof(g_cert));
    cbResult = 0;
    ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_CERTIFICATE_PROPERTY,
                            NULL, 0, &cbResult, 0);
    ASSERT_OK("Get through the property interface", ss);
    ASSERT_EQ("reports the size", cbResult, (DWORD)sizeof(g_cert));

    memset(abOut, 0, sizeof(abOut));
    ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_CERTIFICATE_PROPERTY,
                            abOut, sizeof(abOut), &cbResult, 0);
    ASSERT_OK("and returns the certificate", ss);
    ASSERT("Contents match", memcmp(abOut, g_cert, sizeof(g_cert)) == 0);

    ASSERT_EQ("Set with no input → NTE_INVALID_PARAMETER",
        KSP_SetKeyProperty(hProv, hKey, NCRYPT_CERTIFICATE_PROPERTY,
                           NULL, 0, 0),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* A certificate attached to a key that was never generated would
     * outlive nothing, and would be found by the next key of that name. */
    {
        NCRYPT_KEY_HANDLE hPending = 0;

        ss = KSP_CreatePersistedKey(hProv, &hPending, ALG_RSA, L"not-yet", 0,
                                    NCRYPT_PERSIST_ONLY_FLAG);
        ASSERT_OK("Deferred key created", ss);

        P11Mock_ResetCalls();
        ss = KSP_SetKeyProperty(hProv, hPending, NCRYPT_CERTIFICATE_PROPERTY,
                                g_cert, sizeof(g_cert), 0);
        ASSERT_EQ("Certificate on an unfinalised key → NTE_INVALID_HANDLE",
            ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);
        ASSERT_EQ("and nothing was written",
            P11Mock_GetCalls()->nCreateObject, 0);

        KSP_FreeKey(hProv, hPending);
    }

    KSP_FreeKey(hProv, hKey);
    P11_ReleaseCapabilities();
    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
