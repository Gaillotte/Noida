/* test_ksp_crypto.c — Coverage of ksp_crypto.c
 * Tests: SignHash (RSA PKCS1, PSS, ECDSA), Decrypt (PKCS1, OAEP), ExportKey, ImportKey
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

/* ── Session stubs ────────────────────────────────────────────────────────── */
SECURITY_STATUS P11_AcquireSession(CK_SESSION_HANDLE *ph)
{
    *ph = (CK_SESSION_HANDLE)0xBEEF;
    return ERROR_SUCCESS;
}
void P11_ReleaseSession(CK_SESSION_HANDLE h) { (void)h; }

/* ── KSP_IsValidKey stub (defined in ksp_key.c, not linked here) ───────────── */
#include "../../src/ksp/ksp_key.h"
BOOL KSP_IsValidKey(NCRYPT_KEY_HANDLE hKey)
{
    KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
    return (k && k->dwMagic == KSP_KEY_MAGIC);
}

#include "../../src/ksp/ksp_provider.h"
#include "../../src/ksp/ksp_crypto.h"

/* ── Test key constructor ────────────────────────────────────────────────── */
static NCRYPT_KEY_HANDLE make_test_key(
    LPCWSTR szAlg, DWORD bits, DWORD spec, BOOL finalized)
{
    KSP_KEY *k = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
    k->dwMagic     = KSP_KEY_MAGIC;
    k->dwKeyBitLen = bits;
    k->dwKeySpec   = spec;
    k->hPrivKey    = finalized ? (CK_OBJECT_HANDLE)0x21 : CK_INVALID_HANDLE;
    k->hPubKey     = finalized ? (CK_OBJECT_HANDLE)0x20 : CK_INVALID_HANDLE;
    k->bFinalized  = finalized;
    k->slotId      = 0;
    wcscpy_s(k->szAlgId,   MAX_ALG_ID_LEN,   szAlg);
    wcscpy_s(k->szKeyName, MAX_KEY_LABEL_LEN, L"TestKey");
    return (NCRYPT_KEY_HANDLE)(ULONG_PTR)k;
}

/* ── Dummy DER P256 ECDSA signature ───────────────────────────────────────── */
/* 30 44 02 20 [r=0x11×32] 02 20 [s=0x22×32] */
static BYTE g_derSigP256[70];

static void build_der_p256_sig(void)
{
    g_derSigP256[0] = 0x30; g_derSigP256[1] = 0x44;
    g_derSigP256[2] = 0x02; g_derSigP256[3] = 0x20;
    memset(g_derSigP256 + 4,  0x11, 32);
    g_derSigP256[36] = 0x02; g_derSigP256[37] = 0x20;
    memset(g_derSigP256 + 38, 0x22, 32);
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS    ss;
    DWORD              cbResult;

    build_der_p256_sig();

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);

    /* ── Suite 1 : KSP_SignHash — RSA PKCS1 ─────────────────────────────── */
    TEST_SUITE("KSP_SignHash — RSA PKCS1");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    NCRYPT_KEY_HANDLE hRsa = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);
    BYTE hash[32]; memset(hash, 0xAA, sizeof hash);

    /* Size-only mode (pbSignature=NULL) */
    cbResult = 0;
    ss = KSP_SignHash(hProv, hRsa, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_OK("SignHash RSA PKCS1 size → OK", ss);
    ASSERT_EQ("cbResult = 256", cbResult, 256U);
    ASSERT_EQ("SignInit called", P11Mock_GetCalls()->nSignInit, 1);
    ASSERT_EQ("Sign called (size)", P11Mock_GetCalls()->nSign, 1);

    /* Actual signing mode */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    BYTE sigBuf[256]; memset(sigBuf, 0, sizeof sigBuf);
    cbResult = 0;
    ss = KSP_SignHash(hProv, hRsa, NULL, hash, sizeof hash,
        sigBuf, sizeof sigBuf, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_OK("SignHash RSA PKCS1 actual → OK", ss);
    ASSERT_EQ("cbResult = 256", cbResult, 256U);
    ASSERT_EQ("Sign called 2× (size + data)",
        P11Mock_GetCalls()->nSign, 2);
    ASSERT_EQ("first signature byte = 0xAB",
        sigBuf[0], (BYTE)0xAB);

    KSP_Free((void *)(ULONG_PTR)hRsa); hRsa = 0;

    /* ── Suite 2 : KSP_SignHash — RSA PSS ────────────────────────────────── */
    TEST_SUITE("KSP_SignHash — RSA PSS");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    NCRYPT_KEY_HANDLE hRsaPss = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);

    BCRYPT_PSS_PADDING_INFO pssInfo;
    pssInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    pssInfo.cbSalt   = 32;

    cbResult = 0;
    ss = KSP_SignHash(hProv, hRsaPss, &pssInfo, hash, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PSS_FLAG);
    ASSERT_OK("SignHash RSA PSS size → OK", ss);
    ASSERT_EQ("cbResult PSS = 256", cbResult, 256U);

    /* PSS with SHA1 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    BCRYPT_PSS_PADDING_INFO pssInfoSha1;
    pssInfoSha1.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    pssInfoSha1.cbSalt   = 20;

    cbResult = 0;
    ss = KSP_SignHash(hProv, hRsaPss, &pssInfoSha1, hash, 20,
        NULL, 0, &cbResult, NCRYPT_PAD_PSS_FLAG);
    ASSERT_OK("SignHash RSA PSS SHA1 size → OK", ss);
    ASSERT_EQ("PSS SHA-1 → hashAlg CKM_SHA_1",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.hashAlg, (CK_ULONG)CKM_SHA_1);
    ASSERT_EQ("PSS SHA-1 → mgf CKG_MGF1_SHA1",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.mgf, (CK_ULONG)CKG_MGF1_SHA1);
    ASSERT_EQ("PSS SHA-1 → salt 20 bytes",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.sLen, (CK_ULONG)20);

    /* PSS with SHA512 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    BCRYPT_PSS_PADDING_INFO pssInfoSha512;
    pssInfoSha512.pszAlgId = BCRYPT_SHA512_ALGORITHM;
    pssInfoSha512.cbSalt   = 64;

    cbResult = 0;
    ss = KSP_SignHash(hProv, hRsaPss, &pssInfoSha512, hash, 32,
        NULL, 0, &cbResult, NCRYPT_PAD_PSS_FLAG);
    ASSERT_OK("SignHash RSA PSS SHA512 size → OK", ss);
    ASSERT_EQ("PSS SHA-512 → hashAlg CKM_SHA512",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.hashAlg, (CK_ULONG)CKM_SHA512);
    ASSERT_EQ("PSS SHA-512 → mgf CKG_MGF1_SHA512",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.mgf, (CK_ULONG)CKG_MGF1_SHA512);
    ASSERT_EQ("PSS SHA-512 → salt 64 bytes",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.sLen, (CK_ULONG)64);

    /* PSS with SHA384 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    BCRYPT_PSS_PADDING_INFO pssInfoSha384;
    pssInfoSha384.pszAlgId = BCRYPT_SHA384_ALGORITHM;
    pssInfoSha384.cbSalt   = 48;

    cbResult = 0;
    ss = KSP_SignHash(hProv, hRsaPss, &pssInfoSha384, hash, 32,
        NULL, 0, &cbResult, NCRYPT_PAD_PSS_FLAG);
    ASSERT_OK("SignHash RSA PSS SHA384 size → OK", ss);
    ASSERT_EQ("PSS SHA-384 → hashAlg CKM_SHA384",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.hashAlg, (CK_ULONG)CKM_SHA384);
    ASSERT_EQ("PSS SHA-384 → mgf CKG_MGF1_SHA384",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.mgf, (CK_ULONG)CKG_MGF1_SHA384);
    ASSERT_EQ("PSS SHA-384 → salt 48 bytes",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.sLen, (CK_ULONG)48);

    /* PSS with SHA224 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    BCRYPT_PSS_PADDING_INFO pssInfoSha224;
    pssInfoSha224.pszAlgId = BCRYPT_SHA224_ALGORITHM;
    pssInfoSha224.cbSalt   = 28;

    cbResult = 0;
    ss = KSP_SignHash(hProv, hRsaPss, &pssInfoSha224, hash, 28,
        NULL, 0, &cbResult, NCRYPT_PAD_PSS_FLAG);
    ASSERT_OK("SignHash RSA PSS SHA224 size → OK", ss);
    ASSERT_EQ("PSS SHA-224 → hashAlg CKM_SHA224",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.hashAlg, (CK_ULONG)CKM_SHA224);
    ASSERT_EQ("PSS SHA-224 → mgf CKG_MGF1_SHA224",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.mgf, (CK_ULONG)CKG_MGF1_SHA224);
    ASSERT_EQ("PSS SHA-224 → salt 28 bytes",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.sLen, (CK_ULONG)28);

    /* PSS without pPaddingInfo → default parameters */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    cbResult = 0;
    ss = KSP_SignHash(hProv, hRsaPss, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PSS_FLAG);
    ASSERT_OK("SignHash RSA PSS without info → OK (default SHA256)", ss);
    ASSERT_EQ("PSS default → hashAlg CKM_SHA256",
        (CK_ULONG)P11Mock_GetConfig()->lastSignPss.hashAlg, (CK_ULONG)CKM_SHA256);

    KSP_Free((void *)(ULONG_PTR)hRsaPss); hRsaPss = 0;

    /* ── Suite 3 : KSP_SignHash — ECDSA P256 ─────────────────────────────── */
    TEST_SUITE("KSP_SignHash — ECDSA P256");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->pbSignature = g_derSigP256;
    P11Mock_GetConfig()->cbSignature = 70;

    NCRYPT_KEY_HANDLE hEc = make_test_key(ALG_ECDSA_P256, 256, AT_SIGNATURE, TRUE);

    /* Size only */
    cbResult = 0;
    ss = KSP_SignHash(hProv, hEc, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("SignHash ECDSA P256 size → OK", ss);
    ASSERT_EQ("cbResult ECDSA = 64 (r||s)", cbResult, 64U);

    /* Actual signature */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->pbSignature = g_derSigP256;
    P11Mock_GetConfig()->cbSignature = 70;

    BYTE ecSigBuf[64]; memset(ecSigBuf, 0, sizeof ecSigBuf);
    cbResult = sizeof ecSigBuf;
    ss = KSP_SignHash(hProv, hEc, NULL, hash, sizeof hash,
        ecSigBuf, sizeof ecSigBuf, &cbResult, 0);
    ASSERT_OK("SignHash ECDSA P256 actual → OK", ss);
    ASSERT_EQ("cbResult = 64", cbResult, 64U);
    /* r = 0x11 * 32 bytes */
    ASSERT_EQ("r[0] = 0x11", ecSigBuf[0], (BYTE)0x11);
    ASSERT_EQ("s[0] = 0x22", ecSigBuf[32], (BYTE)0x22);

    KSP_Free((void *)(ULONG_PTR)hEc); hEc = 0;

    /* ── Suite 4 : KSP_SignHash — cas d'erreur ────────────────────────────── */
    TEST_SUITE("KSP_SignHash — cas d'erreur");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    NCRYPT_KEY_HANDLE hErrKey = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);

    /* pcbResult = NULL */
    ss = KSP_SignHash(hProv, hErrKey, NULL, hash, sizeof hash,
        NULL, 0, NULL, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_EQ("pcbResult=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* pbHashValue = NULL */
    ss = KSP_SignHash(hProv, hErrKey, NULL, NULL, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_EQ("pbHash=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* invalid hKey */
    ss = KSP_SignHash(hProv, 0, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_EQ("hKey=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* invalid hProv */
    ss = KSP_SignHash(0, hErrKey, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* Unfinalized key → NTE_KEY_DOES_NOT_EXIST */
    NCRYPT_KEY_HANDLE hUnfin = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, FALSE);
    ss = KSP_SignHash(hProv, hUnfin, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_EQ("Unfinalized key → NTE_KEY_DOES_NOT_EXIST",
        ss, (SECURITY_STATUS)NTE_KEY_DOES_NOT_EXIST);
    KSP_Free((void *)(ULONG_PTR)hUnfin);

    /* Unknown mechanism */
    NCRYPT_KEY_HANDLE hBadAlg = make_test_key(L"DES", 0, AT_SIGNATURE, TRUE);
    ss = KSP_SignHash(hProv, hBadAlg, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, 0);
    ASSERT_EQ("Unknown mechanism → NTE_BAD_ALGID",
        ss, (SECURITY_STATUS)NTE_BAD_ALGID);
    KSP_Free((void *)(ULONG_PTR)hBadAlg);

    /* C_SignInit fails */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;
    P11Mock_GetConfig()->rv_SignInit  = CKR_FUNCTION_FAILED;
    ss = KSP_SignHash(hProv, hErrKey, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_ERR("C_SignInit fails → error", ss);

    /* C_Sign (size) fails */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;
    P11Mock_GetConfig()->rv_Sign     = CKR_FUNCTION_FAILED;
    ss = KSP_SignHash(hProv, hErrKey, NULL, hash, sizeof hash,
        NULL, 0, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_ERR("C_Sign (size) fails → error", ss);

    /* Output buffer too small (RSA) */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = 256;

    BYTE smallBuf[10];
    cbResult = 0;
    ss = KSP_SignHash(hProv, hErrKey, NULL, hash, sizeof hash,
        smallBuf, sizeof smallBuf, &cbResult, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_EQ("RSA buffer too small → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

    KSP_Free((void *)(ULONG_PTR)hErrKey);

    /* ── Suite 5 : KSP_Decrypt — PKCS1 ──────────────────────────────────── */
    TEST_SUITE("KSP_Decrypt — RSA PKCS1");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    NCRYPT_KEY_HANDLE hDecRsa = make_test_key(ALG_RSA, 2048, AT_KEYEXCHANGE, TRUE);
    BYTE ciphertext[256]; memset(ciphertext, 0xCC, sizeof ciphertext);

    /* Size-only mode (pbOutput=NULL) */
    cbResult = 0;
    ss = KSP_Decrypt(hProv, hDecRsa, ciphertext, sizeof ciphertext,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_OK("Decrypt RSA PKCS1 size → OK", ss);
    ASSERT_EQ("cbResult = 32 (mock)", cbResult, 32U);

    /* Actual decryption */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    BYTE plain[64]; memset(plain, 0, sizeof plain);
    cbResult = sizeof plain;
    ss = KSP_Decrypt(hProv, hDecRsa, ciphertext, sizeof ciphertext,
        NULL, plain, sizeof plain, &cbResult, 0);
    ASSERT_OK("Decrypt RSA PKCS1 actual → OK", ss);
    ASSERT_EQ("cbResult = 32", cbResult, 32U);
    ASSERT_EQ("plain[0] = 0x42 (mock)", plain[0], (BYTE)0x42);

    KSP_Free((void *)(ULONG_PTR)hDecRsa); hDecRsa = 0;

    /* ── Suite 6 : KSP_Decrypt — OAEP ───────────────────────────────────── */
    TEST_SUITE("KSP_Decrypt — RSA OAEP");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    NCRYPT_KEY_HANDLE hDecOaep = make_test_key(ALG_RSA, 2048, AT_KEYEXCHANGE, TRUE);

    /* OAEP SHA256 */
    BCRYPT_OAEP_PADDING_INFO oaepInfo;
    oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    oaepInfo.pbLabel  = NULL;
    oaepInfo.cbLabel  = 0;

    BYTE plainOaep[64]; memset(plainOaep, 0, sizeof plainOaep);
    cbResult = sizeof plainOaep;
    ss = KSP_Decrypt(hProv, hDecOaep, ciphertext, sizeof ciphertext,
        &oaepInfo, plainOaep, sizeof plainOaep, &cbResult,
        NCRYPT_PAD_OAEP_FLAG);
    ASSERT_OK("Decrypt RSA OAEP SHA256 → OK", ss);

    /* OAEP without info (SHA1 default) */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    cbResult = sizeof plainOaep;
    ss = KSP_Decrypt(hProv, hDecOaep, ciphertext, sizeof ciphertext,
        NULL, plainOaep, sizeof plainOaep, &cbResult,
        NCRYPT_PAD_OAEP_FLAG);
    ASSERT_OK("Decrypt RSA OAEP without info (SHA1) → OK", ss);

    /* OAEP with explicit SHA1 */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    BCRYPT_OAEP_PADDING_INFO oaepInfoSha1;
    oaepInfoSha1.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    oaepInfoSha1.pbLabel  = NULL;
    oaepInfoSha1.cbLabel  = 0;

    cbResult = sizeof plainOaep;
    ss = KSP_Decrypt(hProv, hDecOaep, ciphertext, sizeof ciphertext,
        &oaepInfoSha1, plainOaep, sizeof plainOaep, &cbResult,
        NCRYPT_PAD_OAEP_FLAG);
    ASSERT_OK("Decrypt RSA OAEP SHA1 → OK", ss);

    KSP_Free((void *)(ULONG_PTR)hDecOaep); hDecOaep = 0;

    /* ── Suite 7 : KSP_Decrypt — cas d'erreur ────────────────────────────── */
    TEST_SUITE("KSP_Decrypt — cas d'erreur");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    NCRYPT_KEY_HANDLE hDecErr = make_test_key(ALG_RSA, 2048, AT_KEYEXCHANGE, TRUE);

    /* Unfinalized key */
    NCRYPT_KEY_HANDLE hDecUnfin = make_test_key(ALG_RSA, 2048, AT_KEYEXCHANGE, FALSE);
    ss = KSP_Decrypt(hProv, hDecUnfin, ciphertext, sizeof ciphertext,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("Unfinalized key → NTE_KEY_DOES_NOT_EXIST",
        ss, (SECURITY_STATUS)NTE_KEY_DOES_NOT_EXIST);
    KSP_Free((void *)(ULONG_PTR)hDecUnfin);

    /* Invalid parameters */
    ss = KSP_Decrypt(hProv, hDecErr, NULL, 0, NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("pbInput=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_Decrypt(hProv, hDecErr, ciphertext, sizeof ciphertext,
        NULL, NULL, 0, NULL, 0);
    ASSERT_EQ("pcbResult=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_Decrypt(0, hDecErr, ciphertext, sizeof ciphertext,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_Decrypt(hProv, 0, ciphertext, sizeof ciphertext,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("hKey=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* C_DecryptInit fails */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_DecryptInit = CKR_FUNCTION_FAILED;
    ss = KSP_Decrypt(hProv, hDecErr, ciphertext, sizeof ciphertext,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_ERR("C_DecryptInit fails → error", ss);

    /* C_Decrypt fails */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_Decrypt = CKR_FUNCTION_FAILED;
    BYTE plainTmp[64]; cbResult = sizeof plainTmp;
    ss = KSP_Decrypt(hProv, hDecErr, ciphertext, sizeof ciphertext,
        NULL, plainTmp, sizeof plainTmp, &cbResult, 0);
    ASSERT_ERR("C_Decrypt fails → error", ss);

    KSP_Free((void *)(ULONG_PTR)hDecErr);

    /* ── Suite 8 : KSP_ExportKey ─────────────────────────────────────────── */
    TEST_SUITE("KSP_ExportKey");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    NCRYPT_KEY_HANDLE hExpRsa = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);

    /* RSA public blob size */
    cbResult = 0;
    ss = KSP_ExportKey(hProv, hExpRsa, 0, BCRYPT_RSAPUBLIC_BLOB,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_OK("ExportKey RSA public size → OK", ss);
    ASSERT("cbResult RSA > 0", cbResult > 0);

    /* Actual RSA public blob */
    BYTE *pbBlob = (BYTE *)KSP_Alloc(cbResult);
    ss = KSP_ExportKey(hProv, hExpRsa, 0, BCRYPT_RSAPUBLIC_BLOB,
        NULL, pbBlob, cbResult, &cbResult, 0);
    ASSERT_OK("ExportKey RSA public content → OK", ss);
    {
        BCRYPT_RSAKEY_BLOB *pHdr = (BCRYPT_RSAKEY_BLOB *)pbBlob;
        ASSERT_EQ("Magic = RSAPUBLIC", pHdr->Magic, (DWORD)BCRYPT_RSAPUBLIC_MAGIC);
        ASSERT_EQ("BitLength = 2048", pHdr->BitLength, 2048U);
    }
    KSP_Free(pbBlob); pbBlob = NULL;

    KSP_Free((void *)(ULONG_PTR)hExpRsa); hExpRsa = 0;

    /* Export EC public */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    NCRYPT_KEY_HANDLE hExpEc = make_test_key(ALG_ECDSA_P256, 256, AT_SIGNATURE, TRUE);

    cbResult = 0;
    ss = KSP_ExportKey(hProv, hExpEc, 0, BCRYPT_ECCPUBLIC_BLOB,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_OK("ExportKey EC P256 size → OK", ss);
    ASSERT("cbResult EC > 0", cbResult > 0);

    pbBlob = (BYTE *)KSP_Alloc(cbResult);
    ss = KSP_ExportKey(hProv, hExpEc, 0, BCRYPT_ECCPUBLIC_BLOB,
        NULL, pbBlob, cbResult, &cbResult, 0);
    ASSERT_OK("ExportKey EC P256 content → OK", ss);
    {
        BCRYPT_ECCKEY_BLOB *pHdr = (BCRYPT_ECCKEY_BLOB *)pbBlob;
        ASSERT_EQ("Magic = ECDSA_P256",
            pHdr->dwMagic, (DWORD)BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
        ASSERT_EQ("cbKey = 32", pHdr->cbKey, 32U);
    }
    KSP_Free(pbBlob); pbBlob = NULL;

    /* Buffer too small */
    ss = KSP_ExportKey(hProv, hExpEc, 0, BCRYPT_ECCPUBLIC_BLOB,
        NULL, (BYTE *)1, 1, &cbResult, 0);
    ASSERT_EQ("Buffer too small → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

    KSP_Free((void *)(ULONG_PTR)hExpEc); hExpEc = 0;

    /* Private blob types → NTE_NOT_SUPPORTED */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    NCRYPT_KEY_HANDLE hPrivExp = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);

    ss = KSP_ExportKey(hProv, hPrivExp, 0, BCRYPT_RSAPRIVATE_BLOB,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("Export RSA private → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    ss = KSP_ExportKey(hProv, hPrivExp, 0, BCRYPT_RSAFULLPRIVATE_BLOB,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("Export RSA full private → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    ss = KSP_ExportKey(hProv, hPrivExp, 0, BCRYPT_ECCPRIVATE_BLOB,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("Export EC private → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Unknown type */
    ss = KSP_ExportKey(hProv, hPrivExp, 0, L"UNKNOWNBLOB",
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("Unknown type → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Key without hPubKey */
    ((KSP_KEY *)(ULONG_PTR)hPrivExp)->hPubKey = CK_INVALID_HANDLE;
    ss = KSP_ExportKey(hProv, hPrivExp, 0, BCRYPT_RSAPUBLIC_BLOB,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("Key without pub → NTE_BAD_KEY",
        ss, (SECURITY_STATUS)NTE_BAD_KEY);

    KSP_Free((void *)(ULONG_PTR)hPrivExp);

    /* Invalid parameters */
    NCRYPT_KEY_HANDLE hExpValid = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);
    ss = KSP_ExportKey(hProv, hExpValid, 0, BCRYPT_RSAPUBLIC_BLOB,
        NULL, NULL, 0, NULL, 0);
    ASSERT_EQ("pcbResult=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_ExportKey(hProv, hExpValid, 0, NULL,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("pszBlobType=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_ExportKey(0, hExpValid, 0, BCRYPT_RSAPUBLIC_BLOB,
        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_Free((void *)(ULONG_PTR)hExpValid);

    /* ── Suite 9 : KSP_ImportKey ─────────────────────────────────────────── */
    TEST_SUITE("KSP_ImportKey");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    /* Import a manually-built RSA public blob */
    BYTE modulus[256]; memset(modulus, 0xCC, sizeof modulus);
    BYTE exponent[3] = { 0x01, 0x00, 0x01 };

    DWORD cbRsaBlob = (DWORD)(sizeof(BCRYPT_RSAKEY_BLOB) +
                               sizeof(exponent) + sizeof(modulus));
    BYTE *pbRsaBlob = (BYTE *)KSP_AllocZero(cbRsaBlob);
    BCRYPT_RSAKEY_BLOB *pRsaHdr = (BCRYPT_RSAKEY_BLOB *)pbRsaBlob;
    pRsaHdr->Magic       = BCRYPT_RSAPUBLIC_MAGIC;
    pRsaHdr->BitLength   = 2048;
    pRsaHdr->cbPublicExp = sizeof(exponent);
    pRsaHdr->cbModulus   = sizeof(modulus);
    pRsaHdr->cbPrime1    = 0;
    pRsaHdr->cbPrime2    = 0;
    memcpy(pbRsaBlob + sizeof(BCRYPT_RSAKEY_BLOB), exponent, sizeof(exponent));
    memcpy(pbRsaBlob + sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(exponent),
           modulus, sizeof(modulus));

    NCRYPT_KEY_HANDLE hImpRsa = 0;
    ss = KSP_ImportKey(hProv, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
        &hImpRsa, pbRsaBlob, cbRsaBlob, 0);
    ASSERT_OK("ImportKey RSA public → OK", ss);
    ASSERT_NOTNULL("hImpRsa non-null", (void *)(ULONG_PTR)hImpRsa);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hImpRsa;
        ASSERT("szAlgId = RSA", _wcsicmp(k->szAlgId, ALG_RSA) == 0);
        ASSERT_EQ("dwKeyBitLen = 2048", k->dwKeyBitLen, 2048U);
        ASSERT("bFinalized = TRUE", k->bFinalized == TRUE);
        ASSERT_EQ("hPrivKey = CK_INVALID_HANDLE",
            k->hPrivKey, (CK_OBJECT_HANDLE)CK_INVALID_HANDLE);
    }
    KSP_Free(pbRsaBlob);
    KSP_Free((void *)(ULONG_PTR)hImpRsa); hImpRsa = 0;

    /* CreateObject fails → error */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_CreateObject = CKR_FUNCTION_FAILED;

    pbRsaBlob = (BYTE *)KSP_AllocZero(cbRsaBlob);
    memcpy(pbRsaBlob, pRsaHdr, sizeof(BCRYPT_RSAKEY_BLOB));
    ss = KSP_ImportKey(hProv, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
        &hImpRsa, pbRsaBlob, cbRsaBlob, 0);
    ASSERT_ERR("ImportKey RSA CreateObject fails → error", ss);
    KSP_Free(pbRsaBlob);

    /* Import an EC P256 public blob */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    DWORD cbEccBlob = (DWORD)(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    BYTE *pbEccBlob = (BYTE *)KSP_AllocZero(cbEccBlob);
    BCRYPT_ECCKEY_BLOB *pEccHdr = (BCRYPT_ECCKEY_BLOB *)pbEccBlob;
    pEccHdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    pEccHdr->cbKey   = 32;
    memset(pbEccBlob + sizeof(BCRYPT_ECCKEY_BLOB), 0xAA, 64);

    NCRYPT_KEY_HANDLE hImpEc = 0;
    ss = KSP_ImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
        &hImpEc, pbEccBlob, cbEccBlob, 0);
    ASSERT_OK("ImportKey EC P256 → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hImpEc;
        ASSERT("szAlgId = ECDSA_P256",
               _wcsicmp(k->szAlgId, ALG_ECDSA_P256) == 0);
        ASSERT_EQ("dwKeyBitLen = 256", k->dwKeyBitLen, 256U);
    }
    KSP_Free(pbEccBlob);
    KSP_Free((void *)(ULONG_PTR)hImpEc); hImpEc = 0;

    /* Import EC P384 (cbKey = 48) */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    DWORD cbEcc384Blob = (DWORD)(sizeof(BCRYPT_ECCKEY_BLOB) + 96);
    BYTE *pbEcc384 = (BYTE *)KSP_AllocZero(cbEcc384Blob);
    BCRYPT_ECCKEY_BLOB *pEcc384Hdr = (BCRYPT_ECCKEY_BLOB *)pbEcc384;
    pEcc384Hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
    pEcc384Hdr->cbKey   = 48;

    NCRYPT_KEY_HANDLE hImpEc384 = 0;
    ss = KSP_ImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
        &hImpEc384, pbEcc384, cbEcc384Blob, 0);
    ASSERT_OK("ImportKey EC P384 → OK", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hImpEc384;
        ASSERT("szAlgId = ECDSA_P384",
               _wcsicmp(k->szAlgId, ALG_ECDSA_P384) == 0);
        ASSERT_EQ("dwKeyBitLen = 384", k->dwKeyBitLen, 384U);
    }
    KSP_Free(pbEcc384);
    KSP_Free((void *)(ULONG_PTR)hImpEc384);

    /* Import EC blob too short (< sizeof BCRYPT_ECCKEY_BLOB) */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    BYTE smallEcc[2] = {0};
    NCRYPT_KEY_HANDLE hSmallEc = 0;
    ss = KSP_ImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
        &hSmallEc, smallEcc, sizeof smallEcc, 0);
    ASSERT_EQ("ImportKey EC blob shorter than header → NTE_INVALID_PARAMETER",
              ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* Header present but coordinates truncated → still rejected */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        BYTE truncEcc[sizeof(BCRYPT_ECCKEY_BLOB) + 10];
        BCRYPT_ECCKEY_BLOB *pT = (BCRYPT_ECCKEY_BLOB *)truncEcc;
        NCRYPT_KEY_HANDLE hTrunc = 0;
        memset(truncEcc, 0, sizeof truncEcc);
        pT->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        pT->cbKey   = EC_P256_COORD_SIZE;   /* claims 32+32 but only 10 present */
        ss = KSP_ImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
            &hTrunc, truncEcc, sizeof truncEcc, 0);
        ASSERT_EQ("ImportKey EC truncated coordinates → NTE_INVALID_PARAMETER",
                  ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }

    /* Unknown coordinate size → NTE_BAD_ALGID */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        BYTE oddEcc[sizeof(BCRYPT_ECCKEY_BLOB) + 2 * 20];
        BCRYPT_ECCKEY_BLOB *pO = (BCRYPT_ECCKEY_BLOB *)oddEcc;
        NCRYPT_KEY_HANDLE hOdd = 0;
        memset(oddEcc, 0, sizeof oddEcc);
        pO->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        pO->cbKey   = 20;                   /* not a supported curve size */
        ss = KSP_ImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
            &hOdd, oddEcc, sizeof oddEcc, 0);
        ASSERT_EQ("ImportKey EC unknown curve size → NTE_BAD_ALGID",
                  ss, (SECURITY_STATUS)NTE_BAD_ALGID);
    }

    /* Private blob → NTE_NOT_SUPPORTED */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    NCRYPT_KEY_HANDLE hPrivImp = 0;
    ss = KSP_ImportKey(hProv, 0, BCRYPT_ECCPRIVATE_BLOB, NULL,
        &hPrivImp, (BYTE *)1, 1, 0);
    ASSERT_EQ("ImportKey private → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    ss = KSP_ImportKey(hProv, 0, BCRYPT_RSAPRIVATE_BLOB, NULL,
        &hPrivImp, (BYTE *)1, 1, 0);
    ASSERT_EQ("ImportKey RSA private → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Invalid parameters */
    ss = KSP_ImportKey(hProv, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
        NULL, (BYTE *)1, 1, 0);
    ASSERT_EQ("phKey=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_ImportKey(hProv, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
        &hImpRsa, NULL, 1, 0);
    ASSERT_EQ("pbData=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_ImportKey(0, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
        &hImpRsa, (BYTE *)1, 1, 0);
    ASSERT_EQ("hProv=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
