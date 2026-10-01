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
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/common/config.h"
#include "../../src/common/memory.h"
#include "test_framework.h"
#include <wchar.h>

/* ── PKCS#11 context / session stubs ────────────────────────────────────── */
static P11_CONTEXT g_testCtx;

P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }
SECURITY_STATUS P11_Initialize(void)             { return ERROR_SUCCESS; }
SECURITY_STATUS P11_SessionPool_Initialize(void) { return ERROR_SUCCESS; }

/* The scope parameter is not used here: these suites run against one mock
 * token, which is a single-token deployment, and PoolFor() collapses every
 * scope onto one pool in that configuration.
 *
 * p11_session.h is included above so the COMPILER checks this stub against
 * the real prototype. It was not, and when P11_AcquireSession gained the
 * scope parameter every one of these stubs kept its old shape: no
 * diagnostic, because the mismatch is across translation units, and then
 * ten segfaults as the scope argument arrived in the pointer parameter. A
 * stub that is not checked against the thing it stands in for is a trap
 * waiting for the next signature change. */
SECURITY_STATUS P11_AcquireSession(int nScope, CK_SESSION_HANDLE *ph)
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

    /* CFB and CCM are accepted here and gated at the point of use against
     * the capability probe. This used to assert NTE_NOT_SUPPORTED, which
     * was right while nothing could do them and wrong once the probe
     * existed: which modes are available is a property of the token, not
     * of a list compiled into the provider. */
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_CFB,
                            (DWORD)((wcslen(BCRYPT_CHAIN_MODE_CFB) + 1) *
                                    sizeof(WCHAR)), 0);
    ASSERT_OK("CFB mode accepted, gated at use", ss);

    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_CCM,
                            (DWORD)((wcslen(BCRYPT_CHAIN_MODE_CCM) + 1) *
                                    sizeof(WCHAR)), 0);
    ASSERT_OK("CCM mode accepted, gated at use", ss);

    /* A mode that is not a CNG chaining mode at all is still refused —
     * otherwise the check above would be vacuous. */
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)L"ChainingModeNonsense",
                            (DWORD)((wcslen(L"ChainingModeNonsense") + 1) *
                                    sizeof(WCHAR)), 0);
    ASSERT_EQ("An unknown chaining mode is still refused", ss,
              (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Back to GCM for the assertions that follow. */
    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_CHAINING_MODE_PROPERTY,
                            (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                            (DWORD)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1) *
                                    sizeof(WCHAR)), 0);
    ASSERT_OK("GCM reselected", ss);

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
    P11Mock_ResetCalls();
    cbResult = 0;
    ss = KSP_Encrypt(hProv, hKey, plain, sizeof plain, NULL,
                     NULL, 0, &cbResult, 0);
    ASSERT_OK("Encrypt size query succeeds", ss);
    /* An upper bound, computed here rather than asked of the token: one AES
     * block of headroom covers CBC_PAD's padding and GCM's tag alike. The
     * query used to run a real C_Encrypt and abandon it, leaving the
     * operation active on a pooled session. */
    ASSERT_EQ("Size query reports an upper bound without asking the token",
              cbResult, (DWORD)(sizeof plain + AES_BLOCK_SIZE));
    ASSERT_EQ("and the token was never asked",
              P11Mock_GetCalls()->nEncryptInit, 0);

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

    /* ── AES-CMAC (AES-10) ──────────────────────────────────────────────
     *
     * Unlike this provider's HMAC identifiers, BCRYPT_AES_CMAC_ALGORITHM is
     * a real CNG name, so a portable application can ask for it. The key is
     * an AES key that signs rather than encrypts. */
    TEST_SUITE("AES-CMAC");
    {
        CK_MECHANISM       m;
        NCRYPT_KEY_HANDLE  hCmac = 0;

        ss = P11_ResolveMechanism(BCRYPT_AES_CMAC_ALGORITHM, 0, &m, NULL);
        ASSERT_OK("AES-CMAC resolves", ss);
        ASSERT_EQ("→ CKM_AES_CMAC", m.mechanism,
                  (CK_MECHANISM_TYPE)CKM_AES_CMAC);

        P11Mock_ResetCalls();
        ss = KSP_CreatePersistedKey(hProv, &hCmac, BCRYPT_AES_CMAC_ALGORITHM,
                                    L"cmac-key", 0, 0);
        ASSERT_OK("CMAC key created", ss);
        ASSERT_EQ("generated with CKM_AES_KEY_GEN, not a generic secret",
                  P11Mock_GetConfig()->lastGenerateMech,
                  (CK_MECHANISM_TYPE)CKM_AES_KEY_GEN);

        {
            KSP_KEY *pCmac = (KSP_KEY *)(ULONG_PTR)hCmac;
            ASSERT("Classified as symmetric",
                   pCmac->dwKeyClass == KSP_KEY_CLASS_SYMMETRIC);
            ASSERT_EQ("Default length is 256 bits", pCmac->dwKeyBitLen, 256U);
        }

        /* A CMAC key belongs to the AES group, not the HMAC one — it is an
         * AES key, and a caller filtering by group would otherwise miss it. */
        {
            WCHAR wszGroup[64];
            DWORD cb = 0;
            ss = KSP_GetKeyProperty(hProv, hCmac,
                                    NCRYPT_ALGORITHM_GROUP_PROPERTY,
                                    (PBYTE)wszGroup, sizeof(wszGroup), &cb, 0);
            ASSERT_OK("Algorithm group readable", ss);
            ASSERT("Group is AES", _wcsicmp(wszGroup, ALG_GROUP_AES) == 0);
        }

        /* Sizes outside AES's three are refused, as for any AES key. */
        {
            NCRYPT_KEY_HANDLE hBad = 0;
            ss = KSP_CreatePersistedKey(hProv, &hBad,
                                        BCRYPT_AES_CMAC_ALGORITHM,
                                        L"cmac-bad", 0,
                                        NCRYPT_PERSIST_ONLY_FLAG);
            ASSERT_OK("Deferred CMAC key created", ss);
            ss = KSP_SetKeyProperty(hProv, hBad, NCRYPT_LENGTH_PROPERTY,
                                    (PBYTE)"\x40\x00\x00\x00", 4, 0);
            ASSERT_ERR("64-bit CMAC key refused", ss);
            KSP_FreeKey(hProv, hBad);
        }

        KSP_FreeKey(hProv, hCmac);
    }

    /* ── Symmetric signing reaches the secret key ────────────────────────
     *
     * KSP_SignHash passed pKey->hPrivKey to C_SignInit unconditionally, so
     * an HMAC or CMAC key — which has no private key, only hSecretKey —
     * was rejected before it got that far. HMAC signing had been advertised
     * since the mechanism work in session 4 and had never worked.
     *
     * Nothing caught it. These suites checked that HMAC resolved to the
     * right mechanism and never once called KSP_SignHash with an HMAC key,
     * so the gap was not hidden by the mock, it was simply never covered.
     * A run against a real token is what surfaced it. */
    TEST_SUITE("Symmetric keys can sign");
    {
        NCRYPT_KEY_HANDLE hMacKey = 0;
        BYTE   abData[32];
        BYTE   abMac[64];
        DWORD  cbMac = 0;

        memset(abData, 0x31, sizeof abData);
        P11Mock_Reset();
        g_testCtx.pFunctionList = P11Mock_GetFunctionList();
        P11Mock_GetConfig()->cbSignature = 32;

        ss = KSP_CreatePersistedKey(hProv, &hMacKey, ALG_HMAC_SHA256,
                                    L"mac-signs", 0, 0);
        ASSERT_OK("HMAC key created", ss);

        cbMac = 0;
        ss = KSP_SignHash(hProv, hMacKey, NULL, abData, sizeof abData,
                          abMac, sizeof abMac, &cbMac, 0);
        ASSERT_OK("An HMAC key can sign", ss);
        ASSERT_EQ("SHA-256 HMAC is 32 bytes", cbMac, 32U);

        {
            KSP_KEY *pMac = (KSP_KEY *)(ULONG_PTR)hMacKey;
            ASSERT_EQ("and the SECRET key object was handed to C_SignInit",
                      P11Mock_GetConfig()->lastSignKey, pMac->hSecretKey);
            ASSERT("not the private-key handle, which it does not have",
                   pMac->hPrivKey == CK_INVALID_HANDLE);
        }
        KSP_FreeKey(hProv, hMacKey);

        /* CMAC takes the same path. */
        hMacKey = 0;
        P11Mock_ResetCalls();
        P11Mock_GetConfig()->cbSignature = AES_BLOCK_SIZE;
        ss = KSP_CreatePersistedKey(hProv, &hMacKey, BCRYPT_AES_CMAC_ALGORITHM,
                                    L"cmac-signs", 0, 0);
        ASSERT_OK("CMAC key created", ss);
        cbMac = 0;
        ss = KSP_SignHash(hProv, hMacKey, NULL, abData, sizeof abData,
                          abMac, sizeof abMac, &cbMac, 0);
        ASSERT_OK("A CMAC key can sign", ss);
        ASSERT_EQ("CMAC is one AES block", cbMac, (DWORD)AES_BLOCK_SIZE);
        ASSERT_EQ("using CKM_AES_CMAC", P11Mock_GetConfig()->lastSignMech,
                  (CK_MECHANISM_TYPE)CKM_AES_CMAC);
        KSP_FreeKey(hProv, hMacKey);
    }

    /* ── Suite : CFB feedback size → mechanism (proposal D) ─────────────── */
    TEST_SUITE("CFB feedback size selects the mechanism");

    /* CNG states the feedback size in BYTES, PKCS#11 names a mechanism per
     * size in BITS, and all three sizes CNG can express have one.
     *
     * This is checked here rather than against a live token because NO
     * token available in this workspace implements CKM_AES_CFB64: SoftHSM2
     * has no CFB at all and Kryoptic advertises only CFB8 (0x2106) and
     * CFB128 (0x2107). The mapping is therefore verified against a mock
     * told to advertise it, and the live suite's CFB64 case is gated on the
     * probe and skips. Saying so is better than implying the mapping has
     * been proven end to end — it has not, and cannot be here. */
    {
        static const CK_MECHANISM_TYPE aCfbToken[] = {
            CKM_AES_KEY_GEN, CKM_AES_CBC, CKM_AES_ECB,
            CKM_AES_CFB8, CKM_AES_CFB64, CKM_AES_CFB128,
        };
        struct { DWORD cbBlock; CK_MECHANISM_TYPE mech; const char *szWhat; }
        aCases[] = {
            { 0,  CKM_AES_CFB8,   "unset  → CKM_AES_CFB8 (CNG's default)" },
            { 1,  CKM_AES_CFB8,   "1 byte → CKM_AES_CFB8" },
            { 8,  CKM_AES_CFB64,  "8 bytes → CKM_AES_CFB64" },
            { 16, CKM_AES_CFB128, "16 bytes → CKM_AES_CFB128" },
        };
        size_t i;

        for (i = 0; i < sizeof(aCases) / sizeof(aCases[0]); i++) {
            NCRYPT_KEY_HANDLE h = 0;
            BYTE  abIv[AES_BLOCK_SIZE];
            BYTE  abPlain[32], abCipher[128];
            DWORD cb = 0;

            memset(abIv, 0x22, sizeof(abIv));
            memset(abPlain, 0x33, sizeof(abPlain));

            P11Mock_Reset();
            g_testCtx.pFunctionList = P11Mock_GetFunctionList();
            P11Mock_SetMechanisms(aCfbToken,
                                  sizeof(aCfbToken) / sizeof(aCfbToken[0]));
            P11_ProbeCapabilities();
            P11Mock_GetConfig()->cbCiphertext = sizeof(abPlain);

            ss = KSP_CreatePersistedKey(hProv, &h, ALG_AES, L"CfbKey", 0, 0);
            ASSERT_OK("AES key created", ss);

            ss = KSP_SetKeyProperty(hProv, h, NCRYPT_CHAINING_MODE_PROPERTY,
                    (PBYTE)BCRYPT_CHAIN_MODE_CFB,
                    (DWORD)((wcslen(BCRYPT_CHAIN_MODE_CFB) + 1) * sizeof(WCHAR)),
                    0);
            ASSERT_OK("CFB selected", ss);

            if (aCases[i].cbBlock) {
                ss = KSP_SetKeyProperty(hProv, h, BCRYPT_MESSAGE_BLOCK_LENGTH,
                        (PBYTE)&aCases[i].cbBlock,
                        sizeof(aCases[i].cbBlock), 0);
                ASSERT_OK("Feedback size set", ss);
            }
            ss = KSP_SetKeyProperty(hProv, h, NCRYPT_INITIALIZATION_VECTOR,
                                    abIv, sizeof(abIv), 0);
            ASSERT_OK("IV set", ss);

            cb = 0;
            ss = KSP_Encrypt(hProv, h, abPlain, sizeof(abPlain), NULL,
                             abCipher, sizeof(abCipher), &cb, 0);
            ASSERT_OK("CFB encryption", ss);
            ASSERT_EQ(aCases[i].szWhat,
                      P11Mock_GetConfig()->lastEncryptMech, aCases[i].mech);

            KSP_FreeKey(hProv, h);
        }

        /* A token with CFB8 but not CFB64 must refuse 8 bytes rather than
         * fall back to a feedback size the caller did not ask for. */
        {
            static const CK_MECHANISM_TYPE aNoCfb64[] = {
                CKM_AES_KEY_GEN, CKM_AES_CBC, CKM_AES_CFB8, CKM_AES_CFB128,
            };
            NCRYPT_KEY_HANDLE h = 0;
            BYTE  abIv[AES_BLOCK_SIZE];
            BYTE  abPlain[32], abCipher[128];
            DWORD cb = 0, cbBlock = 8;

            memset(abIv, 0x22, sizeof(abIv));
            memset(abPlain, 0x33, sizeof(abPlain));

            P11Mock_Reset();
            g_testCtx.pFunctionList = P11Mock_GetFunctionList();
            P11Mock_SetMechanisms(aNoCfb64,
                                  sizeof(aNoCfb64) / sizeof(aNoCfb64[0]));
            P11_ProbeCapabilities();

            ss = KSP_CreatePersistedKey(hProv, &h, ALG_AES, L"CfbKey2", 0, 0);
            ASSERT_OK("AES key created", ss);
            (void)KSP_SetKeyProperty(hProv, h, NCRYPT_CHAINING_MODE_PROPERTY,
                    (PBYTE)BCRYPT_CHAIN_MODE_CFB,
                    (DWORD)((wcslen(BCRYPT_CHAIN_MODE_CFB) + 1) * sizeof(WCHAR)),
                    0);
            (void)KSP_SetKeyProperty(hProv, h, BCRYPT_MESSAGE_BLOCK_LENGTH,
                                     (PBYTE)&cbBlock, sizeof(cbBlock), 0);
            (void)KSP_SetKeyProperty(hProv, h, NCRYPT_INITIALIZATION_VECTOR,
                                     abIv, sizeof(abIv), 0);

            ss = KSP_Encrypt(hProv, h, abPlain, sizeof(abPlain), NULL,
                             abCipher, sizeof(abCipher), &cb, 0);
            ASSERT_EQ("A token without CFB64 refuses 8-byte feedback rather "
                      "than substituting another size",
                      ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);
            KSP_FreeKey(hProv, h);
        }

        P11_ReleaseCapabilities();
    }

    /* ── Suite : NCRYPT_EXPORT_POLICY_PROPERTY (proposal A) ─────────────── */
    TEST_SUITE("Export policy → CKA_SENSITIVE / CKA_EXTRACTABLE");

    /* The two CNG flags guard DIFFERENT operations and map to DIFFERENT
     * PKCS#11 attributes. CKA_EXTRACTABLE=FALSE is what makes C_WrapKey
     * refuse; CKA_SENSITIVE=TRUE is what makes CKA_VALUE unreadable. A
     * provider that collapsed them into one boolean would hand a caller who
     * asked only for wrapped export the ability to read the key in clear,
     * so each case below asserts BOTH attributes, not just the one the
     * flag is named after. */
    {
        struct {
            DWORD    dwPolicy;
            CK_BBOOL bSensitive;
            CK_BBOOL bExtractable;
            const char *szWhat;
        } aCases[] = {
            { 0,
              CK_TRUE,  CK_FALSE, "default: nothing leaves the token" },
            { NCRYPT_ALLOW_EXPORT_FLAG,
              CK_TRUE,  CK_TRUE,  "ALLOW_EXPORT: wrapped only" },
            { NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
              CK_FALSE, CK_TRUE,  "ALLOW_PLAINTEXT_EXPORT: readable" },
            { NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
              CK_FALSE, CK_TRUE,  "both flags: plaintext wins" },
        };
        size_t i;

        for (i = 0; i < sizeof(aCases) / sizeof(aCases[0]); i++) {
            NCRYPT_KEY_HANDLE h = 0;
            DWORD dwBits = 2048;

            P11Mock_Reset();
            g_testCtx.pFunctionList = P11Mock_GetFunctionList();

            ss = KSP_CreatePersistedKey(hProv, &h, ALG_RSA, L"PolicyKey",
                                        AT_SIGNATURE,
                                        NCRYPT_PERSIST_ONLY_FLAG);
            ASSERT_OK("Deferred key created", ss);

            if (aCases[i].dwPolicy) {
                ss = KSP_SetKeyProperty(hProv, h,
                        NCRYPT_EXPORT_POLICY_PROPERTY,
                        (PBYTE)&aCases[i].dwPolicy,
                        sizeof(aCases[i].dwPolicy), 0);
                ASSERT_OK("Export policy accepted before finalize", ss);
            }
            (void)KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                                     (PBYTE)&dwBits, sizeof(dwBits), 0);

            ss = KSP_FinalizeKey(hProv, h, 0);
            ASSERT_OK("Key generated", ss);

            ASSERT_EQ(aCases[i].szWhat,
                      (DWORD)P11Mock_GetConfig()->lastGenSensitive,
                      (DWORD)aCases[i].bSensitive);
            ASSERT_EQ("and the matching CKA_EXTRACTABLE",
                      (DWORD)P11Mock_GetConfig()->lastGenExtractable,
                      (DWORD)aCases[i].bExtractable);

            /* The policy reads back as asked, rather than the hard-coded
             * zero this property used to return whatever was set. */
            {
                DWORD dwRead = 0xFFFFFFFF, cb = 0;
                ss = KSP_GetKeyProperty(hProv, h,
                        NCRYPT_EXPORT_POLICY_PROPERTY,
                        (PBYTE)&dwRead, sizeof(dwRead), &cb, 0);
                ASSERT_OK("Export policy readable", ss);
                ASSERT_EQ("and reads back what was set",
                          dwRead, aCases[i].dwPolicy);
            }

            /* Too late now: the attributes are on the token. Accepting it
             * here would return success and change nothing. */
            {
                DWORD dwLate = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
                ASSERT_EQ("Setting the policy after finalize is refused",
                    KSP_SetKeyProperty(hProv, h,
                        NCRYPT_EXPORT_POLICY_PROPERTY,
                        (PBYTE)&dwLate, sizeof(dwLate), 0),
                    (SECURITY_STATUS)NTE_INVALID_HANDLE);
            }

            KSP_FreeKey(hProv, h);
        }
    }

    /* A symmetric key takes the same route — it is the one whose material
     * a caller can actually read back. */
    {
        NCRYPT_KEY_HANDLE h = 0;
        DWORD dwPolicy = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        DWORD dwBits = 256;

        P11Mock_Reset();
        g_testCtx.pFunctionList = P11Mock_GetFunctionList();

        ss = KSP_CreatePersistedKey(hProv, &h, ALG_AES, L"PolicyAes", 0,
                                    NCRYPT_PERSIST_ONLY_FLAG);
        ASSERT_OK("Deferred AES key created", ss);
        ASSERT_OK("Plaintext export policy set",
            KSP_SetKeyProperty(hProv, h, NCRYPT_EXPORT_POLICY_PROPERTY,
                               (PBYTE)&dwPolicy, sizeof(dwPolicy), 0));
        (void)KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                                 (PBYTE)&dwBits, sizeof(dwBits), 0);
        ASSERT_OK("AES key generated", KSP_FinalizeKey(hProv, h, 0));

        ASSERT_EQ("AES key is created non-sensitive",
                  (DWORD)P11Mock_GetConfig()->lastGenSensitive, (DWORD)CK_FALSE);
        ASSERT_EQ("and extractable",
                  (DWORD)P11Mock_GetConfig()->lastGenExtractable, (DWORD)CK_TRUE);
        KSP_FreeKey(hProv, h);
    }

    /* Flag validation. Archiving is a different feature with a different
     * threat model and is refused by name rather than quietly dropped. */
    {
        NCRYPT_KEY_HANDLE h = 0;
        DWORD dw;

        P11Mock_Reset();
        g_testCtx.pFunctionList = P11Mock_GetFunctionList();
        ss = KSP_CreatePersistedKey(hProv, &h, ALG_RSA, L"FlagKey",
                                    AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
        ASSERT_OK("Deferred key created", ss);

        dw = NCRYPT_ALLOW_ARCHIVING_FLAG;
        ASSERT_EQ("Archiving is refused, not silently ignored",
            KSP_SetKeyProperty(hProv, h, NCRYPT_EXPORT_POLICY_PROPERTY,
                               (PBYTE)&dw, sizeof(dw), 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);

        dw = 0x80000000;
        ASSERT_EQ("An unknown flag bit is refused",
            KSP_SetKeyProperty(hProv, h, NCRYPT_EXPORT_POLICY_PROPERTY,
                               (PBYTE)&dw, sizeof(dw), 0),
            (SECURITY_STATUS)NTE_BAD_FLAGS);

        dw = NCRYPT_ALLOW_EXPORT_FLAG;
        ASSERT_EQ("A wrong-sized value is refused",
            KSP_SetKeyProperty(hProv, h, NCRYPT_EXPORT_POLICY_PROPERTY,
                               (PBYTE)&dw, 2, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        KSP_FreeKey(hProv, h);
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
