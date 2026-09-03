/* test_aes_keys.c — Phase 6 unit tests
 * Covers AES key generation (128/192/256), the chaining-mode and IV key
 * properties, KSP_Encrypt / KSP_Decrypt across ECB / CBC / CTR / GCM, and
 * HMAC generic-secret keys.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_properties.h"
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

/* Create an AES key of the given size through the KSP */
static NCRYPT_KEY_HANDLE MakeAesKey(NCRYPT_PROV_HANDLE hProv,
                                    DWORD dwBits, LPCWSTR pszName)
{
    NCRYPT_KEY_HANDLE h = 0;
    SECURITY_STATUS   ss;

    ss = KSP_CreatePersistedKey(hProv, &h, ALG_AES, pszName,
                                AT_KEYEXCHANGE, NCRYPT_PERSIST_ONLY_FLAG);
    if (ss != ERROR_SUCCESS) return 0;

    ss = KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                            (PBYTE)&dwBits, sizeof(dwBits), 0);
    if (ss != ERROR_SUCCESS) return 0;

    ss = KSP_FinalizeKey(hProv, h, 0);
    if (ss != ERROR_SUCCESS) return 0;

    return h;
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE  hKey  = 0;
    SECURITY_STATUS    ss;
    DWORD              cbResult = 0;
    BYTE               iv[AES_BLOCK_SIZE];
    BYTE               plain[32];
    BYTE               cipher[64];

    memset(iv, 0x3C, sizeof iv);
    memset(plain, 0x9E, sizeof plain);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    if (ss != ERROR_SUCCESS) {
        printf("KSP_OpenProvider failed: 0x%08lX\n", (unsigned long)ss);
        return 1;
    }

    /* ── Suite 1 : symmetric algorithm classifiers ──────────────────────── */
    TEST_SUITE("Symmetric algorithm classifiers");

    ASSERT("AES recognised",          KSP_IsSymmetricAlg(ALG_AES));
    ASSERT("HMAC-SHA1 recognised",    KSP_IsSymmetricAlg(ALG_HMAC_SHA1));
    ASSERT("HMAC-SHA256 recognised",  KSP_IsSymmetricAlg(ALG_HMAC_SHA256));
    ASSERT("HMAC-SHA384 recognised",  KSP_IsSymmetricAlg(ALG_HMAC_SHA384));
    ASSERT("HMAC-SHA512 recognised",  KSP_IsSymmetricAlg(ALG_HMAC_SHA512));
    ASSERT("RSA is not symmetric",   !KSP_IsSymmetricAlg(ALG_RSA));
    ASSERT("ECDSA is not symmetric", !KSP_IsSymmetricAlg(ALG_ECDSA_P256));
    ASSERT("NULL is not symmetric",  !KSP_IsSymmetricAlg(NULL));

    /* ── Suite 2 : AES key generation ───────────────────────────────────── */
    TEST_SUITE("AES key generation");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    hKey = MakeAesKey(hProv, 256, L"Aes256Key");
    ASSERT_NEQ("AES-256 key created", hKey, (NCRYPT_KEY_HANDLE)0);
    ASSERT_EQ("C_GenerateKey called", P11Mock_GetCalls()->nGenerateKey, 1);
    ASSERT_EQ("CKM_AES_KEY_GEN used",
              P11Mock_GetConfig()->lastGenerateMech,
              (CK_MECHANISM_TYPE)CKM_AES_KEY_GEN);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_EQ("Key class is symmetric", k->dwKeyClass,
                  (DWORD)KSP_KEY_CLASS_SYMMETRIC);
        ASSERT_EQ("Key length is 256 bits", k->dwKeyBitLen, 256U);
        ASSERT_NEQ("Secret object handle set", k->hSecretKey,
                   (CK_OBJECT_HANDLE)CK_INVALID_HANDLE);
        ASSERT_EQ("No private key object", k->hPrivKey,
                  (CK_OBJECT_HANDLE)CK_INVALID_HANDLE);
    }
    KSP_FreeKey(hProv, hKey);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    hKey = MakeAesKey(hProv, 128, L"Aes128Key");
    ASSERT_NEQ("AES-128 key created", hKey, (NCRYPT_KEY_HANDLE)0);
    KSP_FreeKey(hProv, hKey);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    hKey = MakeAesKey(hProv, 192, L"Aes192Key");
    ASSERT_NEQ("AES-192 key created", hKey, (NCRYPT_KEY_HANDLE)0);
    KSP_FreeKey(hProv, hKey);

    /* Invalid AES sizes are rejected at SetKeyProperty */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        NCRYPT_KEY_HANDLE h = 0;
        DWORD bad = 512;
        ss = KSP_CreatePersistedKey(hProv, &h, ALG_AES, L"AesBad",
                                    AT_KEYEXCHANGE, NCRYPT_PERSIST_ONLY_FLAG);
        ASSERT_OK("Deferred AES key created", ss);
        ss = KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                                (PBYTE)&bad, sizeof bad, 0);
        ASSERT_EQ("AES-512 → NTE_BAD_LEN", ss, (SECURITY_STATUS)NTE_BAD_LEN);

        bad = 64;
        ss = KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                                (PBYTE)&bad, sizeof bad, 0);
        ASSERT_EQ("AES-64 → NTE_BAD_LEN", ss, (SECURITY_STATUS)NTE_BAD_LEN);
        KSP_FreeKey(hProv, h);
    }

    /* ── Suite 3 : chaining mode and IV properties ──────────────────────── */
    TEST_SUITE("AES chaining mode and IV properties");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    hKey = MakeAesKey(hProv, 256, L"AesProps");

    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                            (DWORD)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) *
                                    sizeof(WCHAR)), 0);
    ASSERT_OK("GCM chaining mode accepted", ss);

    {
        WCHAR mode[64];
        cbResult = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                                (PBYTE)mode, sizeof mode, &cbResult, 0);
        ASSERT_OK("Chaining mode read back", ss);
        ASSERT_WSTR("Chaining mode is GCM", mode, BCRYPT_CHAIN_MODE_GCM);
    }

    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_CFB,
                            (DWORD)((wcslen(BCRYPT_CHAIN_MODE_CFB) + 1) *
                                    sizeof(WCHAR)), 0);
    ASSERT_EQ("CFB mode → NTE_NOT_SUPPORTED", ss,
              (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_INITIALIZATION_VECTOR,
                            iv, sizeof iv, 0);
    ASSERT_OK("16-byte IV accepted", ss);

    {
        BYTE readIv[AES_BLOCK_SIZE];
        cbResult = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_INITIALIZATION_VECTOR,
                                readIv, sizeof readIv, &cbResult, 0);
        ASSERT_OK("IV read back", ss);
        ASSERT_EQ("IV length is 16", cbResult, (DWORD)AES_BLOCK_SIZE);
        ASSERT_MEM("IV bytes match", readIv, iv, AES_BLOCK_SIZE);
    }

    {
        BYTE tooLong[AES_BLOCK_SIZE + 1];
        memset(tooLong, 0, sizeof tooLong);
        ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_INITIALIZATION_VECTOR,
                                tooLong, sizeof tooLong, 0);
        ASSERT_EQ("Oversized IV → NTE_INVALID_PARAMETER", ss,
                  (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }

    /* Block length is reported for AES keys */
    {
        DWORD dwBlock = 0;
        cbResult = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_BLOCK_LENGTH_PROPERTY,
                                (PBYTE)&dwBlock, sizeof dwBlock,
                                &cbResult, 0);
        ASSERT_OK("Block length read", ss);
        ASSERT_EQ("AES block length is 16", dwBlock, (DWORD)AES_BLOCK_SIZE);
    }

    /* Algorithm group and usage */
    {
        WCHAR group[32];
        DWORD dwUsage = 0;
        cbResult = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_ALGORITHM_GROUP_PROPERTY,
                                (PBYTE)group, sizeof group, &cbResult, 0);
        ASSERT_OK("Algorithm group read", ss);
        ASSERT_WSTR("Algorithm group is AES", group, ALG_GROUP_AES);

        cbResult = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_KEY_USAGE_PROPERTY,
                                (PBYTE)&dwUsage, sizeof dwUsage,
                                &cbResult, 0);
        ASSERT_OK("Key usage read", ss);
        ASSERT_EQ("AES allows decrypt", dwUsage,
                  (DWORD)NCRYPT_ALLOW_DECRYPT_FLAG);
    }
    KSP_FreeKey(hProv, hKey);

    /* Cipher properties are rejected on asymmetric keys */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        NCRYPT_KEY_HANDLE hRsa = 0;
        ss = KSP_CreatePersistedKey(hProv, &hRsa, ALG_RSA, L"RsaNoIv",
                                    AT_SIGNATURE, 0);
        ASSERT_OK("RSA key created", ss);
        ss = KSP_SetKeyProperty(hProv, hRsa, NCRYPT_INITIALIZATION_VECTOR,
                                iv, sizeof iv, 0);
        ASSERT_EQ("IV on RSA key → NTE_NOT_SUPPORTED", ss,
                  (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        ss = KSP_SetKeyProperty(hProv, hRsa, NCRYPT_CHAINING_MODE_PROPERTY,
                                (PBYTE)BCRYPT_CHAIN_MODE_CBC, 32, 0);
        ASSERT_EQ("Chaining mode on RSA key → NTE_NOT_SUPPORTED", ss,
                  (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        KSP_FreeKey(hProv, hRsa);
    }

    /* ── Suite 4 : AES encryption across modes ──────────────────────────── */
    TEST_SUITE("AES encryption — CBC / ECB / CTR / GCM");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbCiphertext = sizeof plain;

    hKey = MakeAesKey(hProv, 256, L"AesEnc");

    /* CBC requires an IV */
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_CBC, 32, 0);
    ASSERT_OK("CBC mode set", ss);

    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, 0);
    ASSERT_EQ("CBC without IV → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_INITIALIZATION_VECTOR,
                            iv, sizeof iv, 0);
    ASSERT_OK("IV set for CBC", ss);

    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, 0);
    ASSERT_OK("CBC encryption succeeds", ss);
    ASSERT_EQ("CKM_AES_CBC used", P11Mock_GetConfig()->lastEncryptMech,
              (CK_MECHANISM_TYPE)CKM_AES_CBC);
    ASSERT_EQ("Ciphertext length matches", cbResult, (DWORD)sizeof plain);

    /* NCRYPT_PAD_CIPHER_FLAG selects the padded variant */
    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, NCRYPT_PAD_CIPHER_FLAG);
    ASSERT_OK("Padded CBC encryption succeeds", ss);
    ASSERT_EQ("CKM_AES_CBC_PAD used", P11Mock_GetConfig()->lastEncryptMech,
              (CK_MECHANISM_TYPE)CKM_AES_CBC_PAD);

    /* ECB needs no IV */
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_ECB, 32, 0);
    ASSERT_OK("ECB mode set", ss);
    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, 0);
    ASSERT_OK("ECB encryption succeeds", ss);
    ASSERT_EQ("CKM_AES_ECB used", P11Mock_GetConfig()->lastEncryptMech,
              (CK_MECHANISM_TYPE)CKM_AES_ECB);

    /* CTR */
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)KSP_CHAIN_MODE_CTR, 40, 0);
    ASSERT_OK("CTR mode set", ss);
    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, 0);
    ASSERT_OK("CTR encryption succeeds", ss);
    ASSERT_EQ("CKM_AES_CTR used", P11Mock_GetConfig()->lastEncryptMech,
              (CK_MECHANISM_TYPE)CKM_AES_CTR);

    /* GCM */
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_GCM, 32, 0);
    ASSERT_OK("GCM mode set", ss);
    {
        BYTE nonce[12];
        memset(nonce, 0x5D, sizeof nonce);
        ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_INITIALIZATION_VECTOR,
                                nonce, sizeof nonce, 0);
        ASSERT_OK("12-byte GCM nonce set", ss);
    }
    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, 0);
    ASSERT_OK("GCM encryption succeeds", ss);
    ASSERT_EQ("CKM_AES_GCM used", P11Mock_GetConfig()->lastEncryptMech,
              (CK_MECHANISM_TYPE)CKM_AES_GCM);

    /* Size query returns the required length without writing output */
    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     NULL, 0, &cbResult, 0);
    ASSERT_OK("Encrypt size query succeeds", ss);
    ASSERT_EQ("Size query reports ciphertext length",
              cbResult, (DWORD)sizeof plain);

    KSP_FreeKey(hProv, hKey);

    /* ── Suite 5 : AES decryption ───────────────────────────────────────── */
    TEST_SUITE("AES decryption");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    hKey = MakeAesKey(hProv, 256, L"AesDec");
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_CBC, 32, 0);
    ASSERT_OK("CBC mode set for decrypt", ss);
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_INITIALIZATION_VECTOR,
                            iv, sizeof iv, 0);
    ASSERT_OK("IV set for decrypt", ss);

    cbResult = 0;
    ss = KSP_Decrypt(hProv, hKey, cipher, sizeof plain, NULL,
                     plain, sizeof plain, &cbResult, 0);
    ASSERT_OK("Symmetric decryption succeeds", ss);
    ASSERT_EQ("Symmetric decrypt used CKM_AES_CBC",
              P11Mock_GetConfig()->lastDecryptMech,
              (CK_MECHANISM_TYPE)CKM_AES_CBC);
    ASSERT_EQ("C_DecryptInit called", P11Mock_GetCalls()->nDecryptInit, 1);

    KSP_FreeKey(hProv, hKey);

    /* ── Suite 6 : Encrypt rejects asymmetric keys ──────────────────────── */
    TEST_SUITE("KSP_Encrypt — rejections");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        NCRYPT_KEY_HANDLE hRsa = 0;
        ss = KSP_CreatePersistedKey(hProv, &hRsa, ALG_RSA, L"RsaEnc",
                                    AT_KEYEXCHANGE, 0);
        ASSERT_OK("RSA key created", ss);

        cbResult = 0;
        ss = KSP_Encrypt(hProv, hRsa, plain, sizeof plain, NULL,
                         cipher, sizeof cipher, &cbResult, 0);
        ASSERT_EQ("RSA key → NTE_NOT_SUPPORTED", ss,
                  (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        KSP_FreeKey(hProv, hRsa);
    }

    ss = KSP_Encrypt(0, 0, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, 0);
    ASSERT_EQ("Invalid provider → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* PKCS#11 failure propagates */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    hKey = MakeAesKey(hProv, 256, L"AesFail");
    KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                       (PBYTE)BCRYPT_CHAIN_MODE_ECB, 32, 0);
    P11Mock_GetConfig()->rv_EncryptInit = CKR_KEY_FUNCTION_NOT_PERMITTED;
    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, 0);
    ASSERT_ERR("C_EncryptInit failure propagates", ss);
    KSP_FreeKey(hProv, hKey);

    /* ── Suite 7 : HMAC generic-secret keys ─────────────────────────────── */
    TEST_SUITE("HMAC keys");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_HMAC_SHA256,
                                L"HmacKey", AT_SIGNATURE, 0);
    ASSERT_OK("HMAC-SHA256 key created", ss);
    ASSERT_EQ("CKM_GENERIC_SECRET_KEY_GEN used",
              P11Mock_GetConfig()->lastGenerateMech,
              (CK_MECHANISM_TYPE)CKM_GENERIC_SECRET_KEY_GEN);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_EQ("HMAC key class is symmetric", k->dwKeyClass,
                  (DWORD)KSP_KEY_CLASS_SYMMETRIC);
        ASSERT_EQ("HMAC-SHA256 default length is 256 bits",
                  k->dwKeyBitLen, 256U);
    }

    {
        WCHAR group[32];
        cbResult = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_ALGORITHM_GROUP_PROPERTY,
                                (PBYTE)group, sizeof group, &cbResult, 0);
        ASSERT_OK("HMAC algorithm group read", ss);
        ASSERT_WSTR("Algorithm group is HMAC", group, ALG_GROUP_HMAC);
    }

    /* AES-specific properties do not apply to HMAC keys */
    {
        DWORD dwBlock = 0;
        cbResult = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_BLOCK_LENGTH_PROPERTY,
                                (PBYTE)&dwBlock, sizeof dwBlock,
                                &cbResult, 0);
        ASSERT_EQ("Block length on HMAC key → NTE_NOT_SUPPORTED", ss,
                  (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    }

    /* An HMAC key is not an AES block cipher */
    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     cipher, sizeof cipher, &cbResult, 0);
    ASSERT_EQ("Encrypt with HMAC key → NTE_BAD_ALGID", ss,
              (SECURITY_STATUS)NTE_BAD_ALGID);

    KSP_FreeKey(hProv, hKey);

    /* HMAC key lengths must be whole bytes and at least 128 bits */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    {
        NCRYPT_KEY_HANDLE h = 0;
        DWORD bits;
        ss = KSP_CreatePersistedKey(hProv, &h, ALG_HMAC_SHA512, L"HmacLen",
                                    AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
        ASSERT_OK("Deferred HMAC key created", ss);

        bits = 384;
        ss = KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                                (PBYTE)&bits, sizeof bits, 0);
        ASSERT_OK("384-bit HMAC key accepted", ss);

        bits = 64;
        ss = KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                                (PBYTE)&bits, sizeof bits, 0);
        ASSERT_EQ("64-bit HMAC key → NTE_BAD_LEN", ss,
                  (SECURITY_STATUS)NTE_BAD_LEN);

        bits = 260;   /* not a whole number of bytes */
        ss = KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                                (PBYTE)&bits, sizeof bits, 0);
        ASSERT_EQ("260-bit HMAC key → NTE_BAD_LEN", ss,
                  (SECURITY_STATUS)NTE_BAD_LEN);
        KSP_FreeKey(hProv, h);
    }

    /* ── Suite 8 : HMAC mechanism resolution ────────────────────────────── */
    TEST_SUITE("HMAC mechanism resolution");
    {
        CK_MECHANISM m;

        ss = P11_ResolveMechanism(ALG_HMAC_SHA1, 0, &m, NULL);
        ASSERT_OK("HMAC-SHA1 resolves", ss);
        ASSERT_EQ("→ CKM_SHA_1_HMAC", m.mechanism,
                  (CK_MECHANISM_TYPE)CKM_SHA_1_HMAC);

        ss = P11_ResolveMechanism(ALG_HMAC_SHA256, 0, &m, NULL);
        ASSERT_OK("HMAC-SHA256 resolves", ss);
        ASSERT_EQ("→ CKM_SHA256_HMAC", m.mechanism,
                  (CK_MECHANISM_TYPE)CKM_SHA256_HMAC);

        ss = P11_ResolveMechanism(ALG_HMAC_SHA384, 0, &m, NULL);
        ASSERT_OK("HMAC-SHA384 resolves", ss);
        ASSERT_EQ("→ CKM_SHA384_HMAC", m.mechanism,
                  (CK_MECHANISM_TYPE)CKM_SHA384_HMAC);

        ss = P11_ResolveMechanism(ALG_HMAC_SHA512, 0, &m, NULL);
        ASSERT_OK("HMAC-SHA512 resolves", ss);
        ASSERT_EQ("→ CKM_SHA512_HMAC", m.mechanism,
                  (CK_MECHANISM_TYPE)CKM_SHA512_HMAC);

        ss = P11_ResolveMechanism(ALG_AES, 0, &m, NULL);
        ASSERT_EQ("AES is not a signing algorithm → NTE_BAD_ALGID", ss,
                  (SECURITY_STATUS)NTE_BAD_ALGID);
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
