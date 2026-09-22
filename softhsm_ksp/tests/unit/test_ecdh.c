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

    /* KDFs still without an implementation. HMAC, TLS_PRF and HKDF need a
     * keyed primitive over Z, not a digest chain — ECDH-05. */
    ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_TLS_PRF, NULL,
                       buf, sizeof buf, &cbResult, 0);
    ASSERT_EQ("TLS_PRF KDF → NTE_NOT_SUPPORTED", ss,
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

    {
        /* Count only the destroy caused by FreeSecret. Earlier KDF work in
         * this suite creates and destroys temporary HMAC keys, so an
         * absolute count would drift every time a KDF is added. */
        int before = P11Mock_GetCalls()->nDestroyObject;
        ss = KSP_FreeSecret(hProv, hSecret);
        ASSERT_OK("Free succeeds", ss);
        ASSERT_EQ("Secret object destroyed",
                  P11Mock_GetCalls()->nDestroyObject - before, 1);
    }

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

    /* ── X25519 key agreement (EDDSA-03) ──────────────────────────────── */
    TEST_SUITE("KSP_SecretAgreement — X25519");
    {
        /* An X25519 public key is 32 RAW bytes with no DER wrapper, and
         * those bytes are effectively random. This one deliberately starts
         * with 0x04, which is also the DER OCTET STRING tag: stripping on
         * the tag alone would eat two bytes of real key material. */
        static const BYTE x25519Raw[32] = {
            0x04, 0x20, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
        };
        KSP_KEY xPriv, xPub;

        MakeKey(&xPriv, ALG_ECDH_X25519, 255, 0x10, CK_INVALID_HANDLE);
        MakeKey(&xPub,  ALG_ECDH_X25519, 255, CK_INVALID_HANDLE, 0x20);

        P11Mock_Reset();
        g_testCtx.pFunctionList = P11Mock_GetFunctionList();
        P11Mock_GetConfig()->pbEcPoint = (const char *)x25519Raw;
        P11Mock_GetConfig()->cbEcPoint = sizeof x25519Raw;

        hSecret = 0;
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&xPriv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&xPub,
                                 &hSecret, 0);
        ASSERT_OK("X25519 agreement succeeds", ss);
        ASSERT_EQ("CKM_ECDH1_DERIVE used",
                  P11Mock_GetConfig()->lastDeriveMech,
                  (CK_MECHANISM_TYPE)CKM_ECDH1_DERIVE);

        /* The whole 32 bytes must reach the token. 30 would mean the
         * leading 0x04 0x20 was mistaken for a DER header. */
        ASSERT_EQ("All 32 raw bytes passed through, nothing stripped",
                  P11Mock_GetConfig()->lastEcdhPublicDataLen, (CK_ULONG)32);

        if (hSecret) {
            KSP_SECRET *pS = (KSP_SECRET *)(ULONG_PTR)hSecret;
            ASSERT_EQ("Secret length = 32", pS->dwSecretLen, 32U);
            KSP_FreeSecret(hProv, hSecret);
            hSecret = 0;
        }
    }
    {
        /* A genuine DER-wrapped P-256 point must still be unwrapped: the
         * stricter check must not break the case it was guarding. */
        KSP_KEY p1, p2;
        MakeKey(&p1, ALG_ECDH_P256, 256, 0x10, CK_INVALID_HANDLE);
        MakeKey(&p2, ALG_ECDH_P256, 256, CK_INVALID_HANDLE, 0x20);

        P11Mock_Reset();
        g_testCtx.pFunctionList = P11Mock_GetFunctionList();
        P11Mock_GetConfig()->pbEcPoint = (const char *)g_point256;
        P11Mock_GetConfig()->cbEcPoint = sizeof g_point256;

        hSecret = 0;
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&p1,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&p2,
                                 &hSecret, 0);
        ASSERT_OK("P-256 still agrees", ss);
        ASSERT_EQ("DER wrapper still stripped",
                  P11Mock_GetConfig()->lastEcdhPublicDataLen, (CK_ULONG)65);
        if (hSecret) { KSP_FreeSecret(hProv, hSecret); hSecret = 0; }
    }
    {
        /* X25519 cannot agree with a NIST curve: the coordinate sizes
         * differ, so the existing curve check rejects it. */
        KSP_KEY xPriv, pPub;
        MakeKey(&xPriv, ALG_ECDH_X25519, 255, 0x10, CK_INVALID_HANDLE);
        MakeKey(&pPub,  ALG_ECDH_P384,   384, CK_INVALID_HANDLE, 0x20);
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&xPriv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pPub,
                                 &hSecret, 0);
        ASSERT_EQ("X25519 with P-384 → NTE_BAD_ALGID",
                  ss, (SECURITY_STATUS)NTE_BAD_ALGID);
    }

    /* ── BCRYPT_KDF_HASH (ECDH-04) ────────────────────────────────────── */
    TEST_SUITE("KSP_DeriveKey — BCRYPT_KDF_HASH");
    {
        static const BYTE pre[]  = { 0xA0, 0xA1, 0xA2, 0xA3 };
        static const BYTE post[] = { 0xB0, 0xB1 };
        NCryptBuffer     bufs[4];
        NCryptBufferDesc desc;
        BYTE             out[80];
        DWORD            cb = 0;

        /* Earlier suites freed hSecret; agree a fresh one. */
        P11Mock_Reset();
        g_testCtx.pFunctionList = P11Mock_GetFunctionList();
        P11Mock_GetConfig()->pbEcPoint = (const char *)g_point256;
        P11Mock_GetConfig()->cbEcPoint = sizeof g_point256;
        hSecret = 0;
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                                 &hSecret, 0);
        ASSERT_OK("Agree a secret for the KDF tests", ss);

        P11Mock_GetConfig()->pbSecretValue = g_secret32;
        P11Mock_GetConfig()->cbSecretValue = sizeof g_secret32;

        /* No parameters at all: CNG's documented default is SHA-1. */
        P11Mock_GetConfig()->cbDigestOut = 20;
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, NULL,
                           NULL, 0, &cb, 0);
        ASSERT_OK("Size query with no parameters → OK", ss);
        ASSERT_EQ("Defaults to SHA-1, 20 bytes", cb, 20U);

        cb = 0;
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, NULL,
                           out, sizeof out, &cb, 0);
        ASSERT_OK("Derive with no parameters → OK", ss);
        ASSERT_EQ("CKM_SHA_1 used",
                  P11Mock_GetConfig()->lastDigestMech,
                  (CK_MECHANISM_TYPE)CKM_SHA_1);
        ASSERT_EQ("Only Z was hashed",
                  P11Mock_GetConfig()->cbDigestFed, (CK_ULONG)32);
        ASSERT_MEM("...and it was the agreed secret",
                   P11Mock_GetConfig()->digestFed, g_secret32, 32);

        /* Hash algorithm selection. */
        desc.ulVersion = 0;
        desc.cBuffers  = 1;
        desc.pBuffers  = bufs;
        bufs[0].BufferType = KDF_HASH_ALGORITHM;
        bufs[0].pvBuffer   = (PVOID)BCRYPT_SHA256_ALGORITHM;
        bufs[0].cbBuffer   = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));

        P11Mock_GetConfig()->cbDigestOut = 32;
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, &desc,
                           out, sizeof out, &cb, 0);
        ASSERT_OK("SHA-256 requested → OK", ss);
        ASSERT_EQ("CKM_SHA256 used",
                  P11Mock_GetConfig()->lastDigestMech,
                  (CK_MECHANISM_TYPE)CKM_SHA256);
        ASSERT_EQ("32 bytes returned", cb, 32U);

        bufs[0].pvBuffer = (PVOID)BCRYPT_SHA512_ALGORITHM;
        P11Mock_GetConfig()->cbDigestOut = 64;
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, &desc,
                           out, sizeof out, &cb, 0);
        ASSERT_OK("SHA-512 requested → OK", ss);
        ASSERT_EQ("64 bytes returned", cb, 64U);

        bufs[0].pvBuffer = (PVOID)L"NOT_A_HASH";
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, &desc,
                           out, sizeof out, &cb, 0);
        ASSERT_EQ("Unknown hash → NTE_BAD_ALGID",
                  ss, (SECURITY_STATUS)NTE_BAD_ALGID);

        /* prepend || Z || append, in that order. This is the assertion
         * that would catch the buffers being concatenated backwards. */
        desc.cBuffers      = 3;
        bufs[0].BufferType = KDF_HASH_ALGORITHM;
        bufs[0].pvBuffer   = (PVOID)BCRYPT_SHA256_ALGORITHM;
        bufs[1].BufferType = KDF_SECRET_PREPEND;
        bufs[1].pvBuffer   = (PVOID)pre;
        bufs[1].cbBuffer   = (ULONG)sizeof pre;
        bufs[2].BufferType = KDF_SECRET_APPEND;
        bufs[2].pvBuffer   = (PVOID)post;
        bufs[2].cbBuffer   = (ULONG)sizeof post;

        P11Mock_GetConfig()->cbDigestOut = 32;
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, &desc,
                           out, sizeof out, &cb, 0);
        ASSERT_OK("prepend + Z + append → OK", ss);
        ASSERT_EQ("Hashed 4 + 32 + 2 bytes",
                  P11Mock_GetConfig()->cbDigestFed, (CK_ULONG)38);
        ASSERT_MEM("Prepend came first",
                   P11Mock_GetConfig()->digestFed, pre, 4);
        ASSERT_MEM("Z came next",
                   P11Mock_GetConfig()->digestFed + 4, g_secret32, 32);
        ASSERT_MEM("Append came last",
                   P11Mock_GetConfig()->digestFed + 36, post, 2);

        /* Several buffers of one type concatenate in order. */
        desc.cBuffers      = 4;
        bufs[3].BufferType = KDF_SECRET_PREPEND;
        bufs[3].pvBuffer   = (PVOID)post;
        bufs[3].cbBuffer   = (ULONG)sizeof post;
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, &desc,
                           out, sizeof out, &cb, 0);
        ASSERT_OK("Two prepend buffers → OK", ss);
        ASSERT_EQ("Both prepends hashed, 4 + 2 + 32 + 2",
                  P11Mock_GetConfig()->cbDigestFed, (CK_ULONG)40);

        /* A buffer too small reports the digest size and derives nothing. */
        desc.cBuffers = 1;
        bufs[0].pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, &desc,
                           out, 8, &cb, 0);
        ASSERT_EQ("Short buffer → NTE_BUFFER_TOO_SMALL",
                  ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);
        ASSERT_EQ("Reports the digest size", cb, 32U);
    }

    /* ── BCRYPT_KDF_HKDF, RFC 5869 (ECDH-05) ──────────────────────────── */
    TEST_SUITE("KSP_DeriveKey — BCRYPT_KDF_HKDF");
    {
        static const BYTE salt[] = { 0x51, 0x52, 0x53, 0x54 };
        static const BYTE info[] = { 0x61, 0x62, 0x63 };
        NCryptBuffer     bufs[3];
        NCryptBufferDesc desc;
        BYTE             out[128];
        DWORD            cb = 0;
        NCRYPT_SECRET_HANDLE hSec2 = 0;

        P11Mock_Reset();
        g_testCtx.pFunctionList = P11Mock_GetFunctionList();
        P11Mock_GetConfig()->pbEcPoint = (const char *)g_point256;
        P11Mock_GetConfig()->cbEcPoint = sizeof g_point256;
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                                 &hSec2, 0);
        ASSERT_OK("Agree a secret for HKDF", ss);

        P11Mock_GetConfig()->pbSecretValue = g_secret32;
        P11Mock_GetConfig()->cbSecretValue = sizeof g_secret32;
        /* Each HMAC returns 32 bytes, as SHA-256 would. */
        P11Mock_GetConfig()->cbSignature = 32;

        desc.ulVersion = 0;
        desc.cBuffers  = 3;
        desc.pBuffers  = bufs;
        bufs[0].BufferType = KDF_HASH_ALGORITHM;
        bufs[0].pvBuffer   = (PVOID)BCRYPT_SHA256_ALGORITHM;
        bufs[0].cbBuffer   = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
        bufs[1].BufferType = KDF_HKDF_SALT;
        bufs[1].pvBuffer   = (PVOID)salt;
        bufs[1].cbBuffer   = (ULONG)sizeof salt;
        bufs[2].BufferType = KDF_HKDF_INFO;
        bufs[2].pvBuffer   = (PVOID)info;
        bufs[2].cbBuffer   = (ULONG)sizeof info;

        /* One block: extract + a single expand round. */
        P11Mock_ResetCalls();
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSec2, BCRYPT_KDF_HKDF, &desc,
                           out, 32, &cb, 0);
        ASSERT_OK("HKDF, 32 bytes → OK", ss);
        ASSERT_EQ("Exactly 32 bytes returned", cb, 32U);
        ASSERT_EQ("CKM_SHA256_HMAC used",
                  P11Mock_GetConfig()->lastSignMech,
                  (CK_MECHANISM_TYPE)CKM_SHA256_HMAC);
        ASSERT_EQ("Two HMACs: one extract, one expand",
                  P11Mock_GetCalls()->nSign, 2);

        /* Every HMAC key is created and destroyed — an expansion that
         * leaked one object per round would fill the token. */
        ASSERT_EQ("Every temporary HMAC key was destroyed",
                  P11Mock_GetCalls()->nCreateObject,
                  P11Mock_GetCalls()->nDestroyObject);

        /* The final expand block is T(0) || info || 0x01, and T(0) is
         * empty on the first round, so it is info || 0x01. */
        ASSERT_EQ("First expand block is info || counter",
                  P11Mock_GetConfig()->cbLastSignData, (CK_ULONG)4);
        ASSERT_MEM("  info first",
                   P11Mock_GetConfig()->lastSignData, info, 3);
        ASSERT_EQ("  counter 1 last",
                  (CK_ULONG)P11Mock_GetConfig()->lastSignData[3], (CK_ULONG)1);

        /* Three blocks: 65 bytes needs ceil(65/32) = 3 expand rounds. */
        P11Mock_ResetCalls();
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSec2, BCRYPT_KDF_HKDF, &desc,
                           out, 65, &cb, 0);
        ASSERT_OK("HKDF, 65 bytes → OK", ss);
        ASSERT_EQ("Exactly 65 bytes returned", cb, 65U);
        ASSERT_EQ("Four HMACs: one extract, three expand",
                  P11Mock_GetCalls()->nSign, 4);
        ASSERT_EQ("Last block is T(2) || info || counter",
                  P11Mock_GetConfig()->cbLastSignData, (CK_ULONG)(32 + 3 + 1));
        ASSERT_EQ("  counter reached 3",
                  (CK_ULONG)P11Mock_GetConfig()->lastSignData[35], (CK_ULONG)3);
        ASSERT_EQ("No temporary key leaked",
                  P11Mock_GetCalls()->nCreateObject,
                  P11Mock_GetCalls()->nDestroyObject);

        /* Salt is optional; RFC 5869 treats it as absent. */
        desc.cBuffers = 1;
        P11Mock_ResetCalls();
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSec2, BCRYPT_KDF_HKDF, &desc,
                           out, 32, &cb, 0);
        ASSERT_OK("HKDF without salt or info → OK", ss);
        ASSERT_EQ("Still 32 bytes", cb, 32U);
        ASSERT_EQ("Expand block is just the counter",
                  P11Mock_GetConfig()->cbLastSignData, (CK_ULONG)1);

        /* An unusable hash is refused before any token work. */
        desc.cBuffers = 1;
        bufs[0].pvBuffer = (PVOID)L"NOPE";
        ASSERT_EQ("Unknown hash → NTE_BAD_ALGID",
            KSP_DeriveKey(hProv, hSec2, BCRYPT_KDF_HKDF, &desc,
                          out, 32, &cb, 0),
            (SECURITY_STATUS)NTE_BAD_ALGID);

        /* RFC 5869 caps output at 255 * HashLen. */
        bufs[0].pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;
        ASSERT_EQ("Over 255 blocks → NTE_INVALID_PARAMETER",
            KSP_DeriveKey(hProv, hSec2, BCRYPT_KDF_HKDF, &desc,
                          out, 255 * 32 + 1, &cb, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        /* A failing HMAC must not leave a partly-filled buffer behind. */
        memset(out, 0x7E, sizeof out);
        P11Mock_ResetCalls();
        P11Mock_GetConfig()->rv_Sign = CKR_DEVICE_ERROR;
        ss = KSP_DeriveKey(hProv, hSec2, BCRYPT_KDF_HKDF, &desc,
                           out, 32, &cb, 0);
        ASSERT_ERR("HMAC failure propagates", ss);
        ASSERT_EQ("Output buffer was cleared, not left partial",
                  (DWORD)out[0], 0U);
        P11Mock_GetConfig()->rv_Sign = CKR_OK;

        if (hSec2) KSP_FreeSecret(hProv, hSec2);
    }

    /* ── BCRYPT_KDF_HMAC (ECDH-05) ────────────────────────────────────── */
    TEST_SUITE("KSP_DeriveKey — BCRYPT_KDF_HMAC");
    {
        static const BYTE hmacKey[] = { 0x71, 0x72 };
        static const BYTE pre2[]    = { 0x81, 0x82 };
        static const BYTE post2[]   = { 0x91, 0x92 };
        NCryptBuffer     bufs[4];
        NCryptBufferDesc desc;
        BYTE             out[80];
        DWORD            cb = 0;
        NCRYPT_SECRET_HANDLE hSec3 = 0;

        P11Mock_Reset();
        g_testCtx.pFunctionList = P11Mock_GetFunctionList();
        P11Mock_GetConfig()->pbEcPoint = (const char *)g_point256;
        P11Mock_GetConfig()->cbEcPoint = sizeof g_point256;
        ss = KSP_SecretAgreement(hProv,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&privKey,
                                 (NCRYPT_KEY_HANDLE)(ULONG_PTR)&pubKey,
                                 &hSec3, 0);
        ASSERT_OK("Agree a secret for the HMAC KDF", ss);

        P11Mock_GetConfig()->pbSecretValue = g_secret32;
        P11Mock_GetConfig()->cbSecretValue = sizeof g_secret32;
        P11Mock_GetConfig()->cbSignature   = 32;

        desc.ulVersion = 0;
        desc.cBuffers  = 4;
        desc.pBuffers  = bufs;
        bufs[0].BufferType = KDF_HASH_ALGORITHM;
        bufs[0].pvBuffer   = (PVOID)BCRYPT_SHA256_ALGORITHM;
        bufs[0].cbBuffer   = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR));
        bufs[1].BufferType = KDF_HMAC_KEY;
        bufs[1].pvBuffer   = (PVOID)hmacKey;
        bufs[1].cbBuffer   = (ULONG)sizeof hmacKey;
        bufs[2].BufferType = KDF_SECRET_PREPEND;
        bufs[2].pvBuffer   = (PVOID)pre2;
        bufs[2].cbBuffer   = (ULONG)sizeof pre2;
        bufs[3].BufferType = KDF_SECRET_APPEND;
        bufs[3].pvBuffer   = (PVOID)post2;
        bufs[3].cbBuffer   = (ULONG)sizeof post2;

        P11Mock_ResetCalls();
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSec3, BCRYPT_KDF_HMAC, &desc,
                           out, sizeof out, &cb, 0);
        ASSERT_OK("HMAC KDF → OK", ss);
        ASSERT_EQ("One digest returned", cb, 32U);
        ASSERT_EQ("Exactly one HMAC", P11Mock_GetCalls()->nSign, 1);
        ASSERT_EQ("CKM_SHA256_HMAC used",
                  P11Mock_GetConfig()->lastSignMech,
                  (CK_MECHANISM_TYPE)CKM_SHA256_HMAC);

        /* Message is prepend || Z || append. */
        ASSERT_EQ("Message is 2 + 32 + 2 bytes",
                  P11Mock_GetConfig()->cbLastSignData, (CK_ULONG)36);
        ASSERT_MEM("  prepend first",
                   P11Mock_GetConfig()->lastSignData, pre2, 2);
        ASSERT_MEM("  Z in the middle",
                   P11Mock_GetConfig()->lastSignData + 2, g_secret32, 32);
        ASSERT_MEM("  append last",
                   P11Mock_GetConfig()->lastSignData + 34, post2, 2);

        /* The HMAC key is the one the caller supplied, not Z. */
        ASSERT_EQ("HMAC key is the caller's, 2 bytes",
                  P11Mock_GetConfig()->cbLastCreateValue, (CK_ULONG)2);
        ASSERT_MEM("  and its bytes match",
                   P11Mock_GetConfig()->lastCreateValue, hmacKey, 2);
        ASSERT_EQ("Temporary key destroyed",
                  P11Mock_GetCalls()->nCreateObject,
                  P11Mock_GetCalls()->nDestroyObject);

        /* KDF_USE_SECRET_AS_HMAC_KEY_FLAG swaps the roles: Z becomes the
         * key and leaves the message. */
        P11Mock_ResetCalls();
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSec3, BCRYPT_KDF_HMAC, &desc,
                           out, sizeof out, &cb,
                           KDF_USE_SECRET_AS_HMAC_KEY_FLAG);
        ASSERT_OK("Secret-as-key flag → OK", ss);
        ASSERT_EQ("Message is only prepend || append",
                  P11Mock_GetConfig()->cbLastSignData, (CK_ULONG)4);
        ASSERT_EQ("Key is now Z, 32 bytes",
                  P11Mock_GetConfig()->cbLastCreateValue, (CK_ULONG)32);
        ASSERT_MEM("  and it is the agreed secret",
                   P11Mock_GetConfig()->lastCreateValue, g_secret32, 32);

        /* No HMAC key buffer at all is legal — an empty key. */
        desc.cBuffers = 1;
        P11Mock_ResetCalls();
        cb = 0;
        ss = KSP_DeriveKey(hProv, hSec3, BCRYPT_KDF_HMAC, &desc,
                           out, sizeof out, &cb, 0);
        ASSERT_OK("No HMAC key buffer → OK", ss);
        ASSERT_EQ("Message is just Z",
                  P11Mock_GetConfig()->cbLastSignData, (CK_ULONG)32);

        cb = 0;
        ss = KSP_DeriveKey(hProv, hSec3, BCRYPT_KDF_HMAC, &desc,
                           NULL, 0, &cb, 0);
        ASSERT_OK("Size query → OK", ss);
        ASSERT_EQ("Reports one digest", cb, 32U);

        ss = KSP_DeriveKey(hProv, hSec3, BCRYPT_KDF_HMAC, &desc,
                           out, 4, &cb, 0);
        ASSERT_EQ("Short buffer → NTE_BUFFER_TOO_SMALL",
                  ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

        /* A prepend larger than the assembly buffer is refused rather
         * than truncated or overflowed. */
        {
            static BYTE huge[2048];
            memset(huge, 0x5A, sizeof huge);
            desc.cBuffers      = 2;
            bufs[1].BufferType = KDF_SECRET_PREPEND;
            bufs[1].pvBuffer   = (PVOID)huge;
            bufs[1].cbBuffer   = (ULONG)sizeof huge;
            ASSERT_EQ("Oversized prepend → NTE_INVALID_PARAMETER",
                KSP_DeriveKey(hProv, hSec3, BCRYPT_KDF_HMAC, &desc,
                              out, sizeof out, &cb, 0),
                (SECURITY_STATUS)NTE_INVALID_PARAMETER);
            desc.cBuffers = 1;
        }

        /* TLS_PRF is the one KDF still unimplemented. */
        ASSERT_EQ("TLS_PRF → NTE_NOT_SUPPORTED",
            KSP_DeriveKey(hProv, hSec3, BCRYPT_KDF_TLS_PRF, &desc,
                          out, sizeof out, &cb, 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);

        if (hSec3) KSP_FreeSecret(hProv, hSec3);
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
