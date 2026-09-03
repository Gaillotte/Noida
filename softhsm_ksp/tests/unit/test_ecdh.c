/* test_ecdh.c — Phase 4 unit tests
 * Covers KSP_SecretAgreement, KSP_DeriveKey, KSP_FreeSecret and
 * KSP_IsValidSecret across P-256, P-384 and P-521.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/common/config.h"
#include "../../src/common/memory.h"
#include "test_framework.h"
#include <wchar.h>

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

/* ── Key-layer stub (ksp_key.c is not linked here) ──────────────────────── */
BOOL KSP_IsValidKey(NCRYPT_KEY_HANDLE hKey)
{
    KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
    return (k && k->dwMagic == KSP_KEY_MAGIC);
}

/* ── Test helpers ───────────────────────────────────────────────────────── */

/* Build an in-memory key handle for a given curve */
static void MakeKey(KSP_KEY *k, LPCWSTR alg, DWORD bits,
                    CK_OBJECT_HANDLE priv, CK_OBJECT_HANDLE pub)
{
    memset(k, 0, sizeof(*k));
    k->dwMagic     = KSP_KEY_MAGIC;
    k->hPrivKey    = priv;
    k->hPubKey     = pub;
    k->hSecretKey  = CK_INVALID_HANDLE;
    k->bFinalized  = TRUE;
    k->dwKeyBitLen = bits;
    k->dwKeySpec   = AT_KEYEXCHANGE;
    k->dwKeyClass  = KSP_KEY_CLASS_ASYMMETRIC;
    wcscpy(k->szAlgId, alg);
}

/* A DER-wrapped uncompressed P-256 point (0x04 || X || Y), 67 bytes total */
static BYTE g_point256[67];
/* A DER-wrapped P-521 point uses the long-form length: 04 81 85 04 X Y */
static BYTE g_point521[136];
static BYTE g_secret32[32];
static BYTE g_secret66[66];

static void InitPoints(void)
{
    memset(g_point256, 0xA1, sizeof g_point256);
    g_point256[0] = 0x04;                    /* OCTET STRING */
    g_point256[1] = 0x41;                    /* length 65, short form */
    g_point256[2] = 0x04;                    /* uncompressed marker */

    memset(g_point521, 0xB2, sizeof g_point521);
    g_point521[0] = 0x04;                    /* OCTET STRING */
    g_point521[1] = 0x81;                    /* long form, 1 length byte */
    g_point521[2] = 0x85;                    /* length 133 */
    g_point521[3] = 0x04;                    /* uncompressed marker */

    memset(g_secret32, 0x5A, sizeof g_secret32);
    memset(g_secret66, 0x6B, sizeof g_secret66);
}

int main(void)
{
    NCRYPT_PROV_HANDLE   hProv = 0;
    NCRYPT_SECRET_HANDLE hSecret = 0;
    SECURITY_STATUS      ss;
    KSP_KEY              privKey, pubKey;
    DWORD                cbResult = 0;
    BYTE                 buf[128];

    InitPoints();

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    if (ss != ERROR_SUCCESS) {
        printf("KSP_OpenProvider failed: 0x%08lX\n", (unsigned long)ss);
        return 1;
    }

    /* ── Suite 1 : parameter validation ─────────────────────────────────── */
    TEST_SUITE("KSP_SecretAgreement — parameter validation");

    MakeKey(&privKey, ALG_ECDH_P256, 256, 0x10, CK_INVALID_HANDLE);
    MakeKey(&pubKey,  ALG_ECDH_P256, 256, CK_INVALID_HANDLE, 0x20);

    ss = KSP_SecretAgreement(0, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                             (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                             &hSecret, 0);
    ASSERT_EQ("Invalid provider → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_SecretAgreement(hProv, 0,
                             (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                             &hSecret, 0);
    ASSERT_EQ("Invalid private key → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_SecretAgreement(hProv, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                             0, &hSecret, 0);
    ASSERT_EQ("Invalid public key → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_SecretAgreement(hProv, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                             (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey, NULL, 0);
    ASSERT_EQ("NULL out handle → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* Private key without a PKCS#11 private object */
    {
        KSP_KEY noPriv;
        MakeKey(&noPriv, ALG_ECDH_P256, 256, CK_INVALID_HANDLE, 0x20);
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&noPriv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                                 &hSecret, 0);
        ASSERT_EQ("Missing private object → NTE_BAD_KEY", ss,
                  (SECURITY_STATUS)NTE_BAD_KEY);
    }

    /* Curve mismatch between the two keys */
    {
        KSP_KEY pub384;
        MakeKey(&pub384, ALG_ECDH_P384, 384, CK_INVALID_HANDLE, 0x20);
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pub384,
                                 &hSecret, 0);
        ASSERT_EQ("Curve mismatch → NTE_BAD_ALGID", ss,
                  (SECURITY_STATUS)NTE_BAD_ALGID);
    }

    /* Non-EC algorithm has no coordinate size */
    {
        KSP_KEY rsaPriv, rsaPub;
        MakeKey(&rsaPriv, ALG_RSA, 2048, 0x10, CK_INVALID_HANDLE);
        MakeKey(&rsaPub,  ALG_RSA, 2048, CK_INVALID_HANDLE, 0x20);
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&rsaPriv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&rsaPub,
                                 &hSecret, 0);
        ASSERT_EQ("RSA keys → NTE_BAD_ALGID", ss,
                  (SECURITY_STATUS)NTE_BAD_ALGID);
    }

    /* ── Suite 2 : successful agreement on P-256 ────────────────────────── */
    TEST_SUITE("KSP_SecretAgreement — P-256");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->pbEcPoint = (const char *)g_point256;
    P11Mock_GetConfig()->cbEcPoint = sizeof g_point256;

    hSecret = 0;
    ss = KSP_SecretAgreement(hProv, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                             (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                             &hSecret, 0);
    ASSERT_OK("P-256 agreement succeeds", ss);
    ASSERT_NEQ("Secret handle returned", hSecret, (NCRYPT_SECRET_HANDLE)0);
    ASSERT("Secret handle validates", KSP_IsValidSecret(hSecret));
    ASSERT_EQ("C_DeriveKey called once", P11Mock_GetCalls()->nDeriveKey, 1);
    ASSERT_EQ("CKM_ECDH1_DERIVE used",
              P11Mock_GetConfig()->lastDeriveMech,
              (CK_MECHANISM_TYPE)CKM_ECDH1_DERIVE);
    ASSERT_EQ("DER wrapper stripped from peer point (65 bytes)",
              P11Mock_GetConfig()->lastEcdhPublicDataLen, (CK_ULONG)65);

    {
        KSP_SECRET *pS = (KSP_SECRET *)(ULONG_PTR)hSecret;
        ASSERT_EQ("Secret length = 32 (P-256)", pS->dwSecretLen, 32U);
    }

    /* ── Suite 3 : KSP_DeriveKey ────────────────────────────────────────── */
    TEST_SUITE("KSP_DeriveKey");

    P11Mock_GetConfig()->pbSecretValue = g_secret32;
    P11Mock_GetConfig()->cbSecretValue = sizeof g_secret32;

    /* Size query */
    cbResult = 0;
    ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                       NULL, 0, &cbResult, 0);
    ASSERT_OK("Size query succeeds", ss);
    ASSERT_EQ("Size query returns 32", cbResult, 32U);

    /* Actual derivation */
    memset(buf, 0, sizeof buf);
    cbResult = 0;
    ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                       buf, sizeof buf, &cbResult, 0);
    ASSERT_OK("Raw secret derivation succeeds", ss);
    ASSERT_EQ("Derived length = 32", cbResult, 32U);
    ASSERT_MEM("Derived bytes match the agreed secret",
               buf, g_secret32, 32);

    /* NULL KDF is treated as the raw secret */
    cbResult = 0;
    ss = KSP_DeriveKey(hProv, hSecret, NULL, NULL,
                       buf, sizeof buf, &cbResult, 0);
    ASSERT_OK("NULL KDF accepted as raw", ss);

    /* Unsupported KDF */
    ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, NULL,
                       buf, sizeof buf, &cbResult, 0);
    ASSERT_EQ("Hash KDF → NTE_NOT_SUPPORTED", ss,
              (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Buffer too small reports the required size */
    cbResult = 0;
    ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                       buf, 8, &cbResult, 0);
    ASSERT_EQ("Small buffer → NTE_BUFFER_TOO_SMALL", ss,
              (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);
    ASSERT_EQ("Required size reported", cbResult, 32U);

    /* Invalid handles */
    ss = KSP_DeriveKey(hProv, 0, BCRYPT_KDF_RAW_SECRET, NULL,
                       buf, sizeof buf, &cbResult, 0);
    ASSERT_EQ("Invalid secret → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                       buf, sizeof buf, NULL, 0);
    ASSERT_EQ("NULL pcbResult → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 4 : KSP_FreeSecret ───────────────────────────────────────── */
    TEST_SUITE("KSP_FreeSecret");

    ss = KSP_FreeSecret(hProv, 0);
    ASSERT_EQ("Invalid handle → NTE_INVALID_HANDLE", ss,
              (SECURITY_STATUS)NTE_INVALID_HANDLE);

    ss = KSP_FreeSecret(hProv, hSecret);
    ASSERT_OK("Free succeeds", ss);
    ASSERT_EQ("Secret object destroyed",
              P11Mock_GetCalls()->nDestroyObject, 1);

    /* ── Suite 5 : P-384 and P-521 ──────────────────────────────────────── */
    TEST_SUITE("KSP_SecretAgreement — P-384 and P-521");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->pbEcPoint = (const char *)g_point256;
    P11Mock_GetConfig()->cbEcPoint = sizeof g_point256;

    {
        KSP_KEY priv384, pub384;
        MakeKey(&priv384, ALG_ECDH_P384, 384, 0x10, CK_INVALID_HANDLE);
        MakeKey(&pub384,  ALG_ECDH_P384, 384, CK_INVALID_HANDLE, 0x20);

        hSecret = 0;
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&priv384,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pub384,
                                 &hSecret, 0);
        ASSERT_OK("P-384 agreement succeeds", ss);
        {
            KSP_SECRET *pS = (KSP_SECRET *)(ULONG_PTR)hSecret;
            ASSERT_EQ("Secret length = 48 (P-384)", pS->dwSecretLen, 48U);
        }
        KSP_FreeSecret(hProv, hSecret);
    }

    /* P-521 uses a long-form DER length on the peer point */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->pbEcPoint = (const char *)g_point521;
    P11Mock_GetConfig()->cbEcPoint = sizeof g_point521;

    {
        KSP_KEY priv521, pub521;
        MakeKey(&priv521, ALG_ECDH_P521, 521, 0x10, CK_INVALID_HANDLE);
        MakeKey(&pub521,  ALG_ECDH_P521, 521, CK_INVALID_HANDLE, 0x20);

        hSecret = 0;
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&priv521,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pub521,
                                 &hSecret, 0);
        ASSERT_OK("P-521 agreement succeeds", ss);
        ASSERT_EQ("Long-form DER stripped (133 bytes)",
                  P11Mock_GetConfig()->lastEcdhPublicDataLen, (CK_ULONG)133);
        {
            KSP_SECRET *pS = (KSP_SECRET *)(ULONG_PTR)hSecret;
            ASSERT_EQ("Secret length = 66 (P-521)", pS->dwSecretLen, 66U);
        }

        /* Derive the full 66-byte secret */
        P11Mock_GetConfig()->pbSecretValue = g_secret66;
        P11Mock_GetConfig()->cbSecretValue = sizeof g_secret66;
        cbResult = 0;
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                           buf, sizeof buf, &cbResult, 0);
        ASSERT_OK("P-521 raw derivation succeeds", ss);
        ASSERT_EQ("P-521 derived length = 66", cbResult, 66U);
        ASSERT_MEM("P-521 derived bytes match", buf, g_secret66, 66);

        KSP_FreeSecret(hProv, hSecret);
    }

    /* ── Suite 6 : PKCS#11 error propagation ────────────────────────────── */
    TEST_SUITE("KSP_SecretAgreement — error propagation");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->pbEcPoint = (const char *)g_point256;
    P11Mock_GetConfig()->cbEcPoint = sizeof g_point256;
    P11Mock_GetConfig()->rv_DeriveKey = CKR_MECHANISM_INVALID;

    hSecret = 0;
    ss = KSP_SecretAgreement(hProv, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                             (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                             &hSecret, 0);
    ASSERT_EQ("C_DeriveKey failure → NTE_BAD_ALGID", ss,
              (SECURITY_STATUS)NTE_BAD_ALGID);

    /* Peer point unreadable */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_GetAttributeValue = CKR_ATTRIBUTE_SENSITIVE;

    hSecret = 0;
    ss = KSP_SecretAgreement(hProv, (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                             (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                             &hSecret, 0);
    ASSERT_EQ("Unreadable peer point → NTE_BAD_KEY", ss,
              (SECURITY_STATUS)NTE_BAD_KEY);

    /* ── Suite 7 : KSP_IsValidSecret ────────────────────────────────────── */
    TEST_SUITE("KSP_IsValidSecret");

    ASSERT("NULL handle is invalid", !KSP_IsValidSecret(0));
    {
        KSP_SECRET bogus;
        memset(&bogus, 0, sizeof bogus);
        bogus.dwMagic = 0xDEADBEEF;
        ASSERT("Wrong magic is invalid",
               !KSP_IsValidSecret((NCRYPT_SECRET_HANDLE)(ULONG_PTR)&bogus));
        bogus.dwMagic = KSP_SECRET_MAGIC;
        ASSERT("Correct magic is valid",
               KSP_IsValidSecret((NCRYPT_SECRET_HANDLE)(ULONG_PTR)&bogus));
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
