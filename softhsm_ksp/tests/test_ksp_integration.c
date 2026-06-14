/* test_ksp_integration.c — End-to-end tests via the NCrypt API (full KSP)
 * Calls KSP functions directly without going through the Windows registry.
 *
 * Tests 1-14:  Original integration test suite
 * Tests 15-21: HLK-conformant Microsoft CNG KSP test scenarios
 *   15 — RSA PSS signing + BCrypt PSS verification
 *   16 — RSA PKCS1 BCrypt verification + extended key property queries
 *   17 — ECDSA P-256 end-to-end BCrypt verification
 *   18 — ECDSA P-384 key generation, signing and BCrypt verification
 *   19 — RSA 3072 deferred key generation, signing and BCrypt verification
 *   20 — RSA AT_KEYEXCHANGE + RSA OAEP decryption
 *   21 — Error conditions: invalid handles, missing key, forbidden export
 */
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "ksp_main.h"
#include "ksp_provider.h"
#include "ksp_key.h"
#include "ksp_crypto.h"
#include "ksp_properties.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/memory.h"

/* ── Infrastructure ─────────────────────────────────────────────────────── */
static int g_nPass = 0, g_nFail = 0;

static void test_assert(const char *pszName, int bCond, const char *pszDetail)
{
    if (bCond) {
        printf("[PASS] %s\n", pszName);
        g_nPass++;
    } else {
        printf("[FAIL] %s : %s\n", pszName, pszDetail ? pszDetail : "error");
        g_nFail++;
    }
}

#define ASSERT(name, cond)     test_assert(name, (cond), NULL)
#define ASSERT_SS(name, ss)    test_assert(name, (ss) == ERROR_SUCCESS, \
                                   "0x" #ss)

/* ── HLK helper — export KSP public key and import into BCrypt ──────────── */
static BCRYPT_KEY_HANDLE HlkImportPublicKey(
    NCRYPT_PROV_HANDLE hProv,
    NCRYPT_KEY_HANDLE  hKspKey,
    LPCWSTR            pszBlobType,   /* e.g. BCRYPT_RSAPUBLIC_BLOB */
    LPCWSTR            pszBCryptAlg)  /* e.g. BCRYPT_RSA_ALGORITHM  */
{
    SECURITY_STATUS   ss;
    BCRYPT_ALG_HANDLE hAlg     = NULL;
    BCRYPT_KEY_HANDLE hBcrypt  = NULL;
    BYTE             *pbBlob   = NULL;
    DWORD             cbBlob   = 0;

    ss = KSP_ExportKey(hProv, hKspKey, 0, pszBlobType, NULL, NULL, 0, &cbBlob, 0);
    if (ss != ERROR_SUCCESS || cbBlob == 0)
        return NULL;

    pbBlob = (BYTE *)KSP_Alloc(cbBlob);
    if (!pbBlob)
        return NULL;

    ss = KSP_ExportKey(hProv, hKspKey, 0, pszBlobType, NULL, pbBlob, cbBlob, &cbBlob, 0);
    if (ss != ERROR_SUCCESS)
        goto out;

    if (BCryptOpenAlgorithmProvider(&hAlg, pszBCryptAlg, NULL, 0) != 0)
        goto out;

    BCryptImportKeyPair(hAlg, NULL, pszBlobType, &hBcrypt, pbBlob, cbBlob, 0);

out:
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    KSP_Free(pbBlob);
    return hBcrypt;
}

/* ── Test 1 : OpenProvider ──────────────────────────────────────────────── */
static NCRYPT_PROV_HANDLE g_hProv = 0;

static void test_open_provider(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 1: OpenProvider ---\n");
    ss = KSP_OpenProvider(&g_hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_SS("KSP_OpenProvider", ss);
    ASSERT("hProvider not null", g_hProv != 0);
}

/* ── Test 2 : GetProviderProperty ──────────────────────────────────────── */
static void test_provider_property(void)
{
    SECURITY_STATUS ss;
    WCHAR  wszName[256];
    DWORD  cbResult = 0;
    DWORD  dwVersion = 0;
    DWORD  dwImpl    = 0;

    printf("\n--- Test 2: GetProviderProperty ---\n");

    ss = KSP_GetProviderProperty(g_hProv, NCRYPT_NAME_PROPERTY,
        (PBYTE)wszName, sizeof(wszName), &cbResult, 0);
    ASSERT_SS("GetProviderProperty NAME", ss);
    ASSERT("Name = SoftHSM KSP",
           _wcsicmp(wszName, KSP_PROVIDER_NAME) == 0);

    ss = KSP_GetProviderProperty(g_hProv, NCRYPT_VERSION_PROPERTY,
        (PBYTE)&dwVersion, sizeof(dwVersion), &cbResult, 0);
    ASSERT_SS("GetProviderProperty VERSION", ss);
    ASSERT("Version = 1", dwVersion == 1);

    ss = KSP_GetProviderProperty(g_hProv, NCRYPT_IMPL_TYPE_PROPERTY,
        (PBYTE)&dwImpl, sizeof(dwImpl), &cbResult, 0);
    ASSERT_SS("GetProviderProperty IMPL_TYPE", ss);
    ASSERT("ImplType = HARDWARE",
           (dwImpl & NCRYPT_IMPL_HARDWARE_FLAG) != 0);
}

/* ── Test 3 : CreatePersistedKey RSA ───────────────────────────────────── */
static NCRYPT_KEY_HANDLE g_hKeyRsa = 0;
static WCHAR g_wszRsaLabel[64];

static void test_create_rsa(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 3: CreatePersistedKey RSA 2048 ---\n");
    swprintf_s(g_wszRsaLabel, 64, L"IntTest_RSA_%u", GetTickCount());

    ss = KSP_CreatePersistedKey(g_hProv, &g_hKeyRsa,
        ALG_RSA, g_wszRsaLabel, AT_SIGNATURE, 0);
    ASSERT_SS("KSP_CreatePersistedKey RSA", ss);
    ASSERT("hKeyRsa not null", g_hKeyRsa != 0);
}

/* ── Test 4 : FinalizeKey ──────────────────────────────────────────────── */
static void test_finalize_rsa(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 4: FinalizeKey RSA ---\n");
    if (!g_hKeyRsa) { ASSERT("Prerequisite FinalizeKey", 0); return; }

    ss = KSP_FinalizeKey(g_hProv, g_hKeyRsa, 0);
    ASSERT_SS("KSP_FinalizeKey RSA", ss);
}

/* ── Test 5 : GetKeyProperty ───────────────────────────────────────────── */
static void test_key_properties(void)
{
    SECURITY_STATUS ss;
    WCHAR  wszAlg[64];
    DWORD  dwBits   = 0;
    DWORD  cbResult = 0;

    printf("\n--- Test 5: GetKeyProperty ---\n");
    if (!g_hKeyRsa) { ASSERT("Prerequisite GetKeyProperty", 0); return; }

    ss = KSP_GetKeyProperty(g_hProv, g_hKeyRsa, NCRYPT_ALGORITHM_PROPERTY,
        (PBYTE)wszAlg, sizeof(wszAlg), &cbResult, 0);
    ASSERT_SS("GetKeyProperty ALGORITHM", ss);
    ASSERT("Algorithm = RSA", _wcsicmp(wszAlg, ALG_RSA) == 0);

    ss = KSP_GetKeyProperty(g_hProv, g_hKeyRsa, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwBits, sizeof(dwBits), &cbResult, 0);
    ASSERT_SS("GetKeyProperty LENGTH", ss);
    ASSERT("Length = 2048", dwBits == 2048);
}

/* ── Test 6 : SignHash RSA PKCS1 ───────────────────────────────────────── */
static BYTE g_abHashSha256[32];
static BYTE g_abRsaSig[512];
static DWORD g_cbRsaSig = 0;

static void test_sign_rsa(void)
{
    SECURITY_STATUS ss;
    DWORD cbNeeded = 0;
    int   i;

    printf("\n--- Test 6: SignHash RSA PKCS1 ---\n");
    if (!g_hKeyRsa) { ASSERT("Prerequisite SignHash RSA", 0); return; }

    for (i = 0; i < 32; i++) g_abHashSha256[i] = (BYTE)(i * 7 + 3);

    /* Double-call: size first */
    ss = KSP_SignHash(g_hProv, g_hKeyRsa, NULL,
        g_abHashSha256, 32, NULL, 0, &cbNeeded,
        NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_SS("SignHash RSA (size)", ss);
    ASSERT("cbNeeded > 0", cbNeeded > 0);

    /* Actual signature */
    ss = KSP_SignHash(g_hProv, g_hKeyRsa, NULL,
        g_abHashSha256, 32,
        g_abRsaSig, sizeof(g_abRsaSig),
        &g_cbRsaSig, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_SS("SignHash RSA PKCS1", ss);
    ASSERT("Signature not empty", g_cbRsaSig > 0);

    printf("  RSA signature size: %lu\n", (unsigned long)g_cbRsaSig);
}

/* ── Test 7 : ExportKey RSA public ────────────────────────────────────── */
static void test_export_rsa_public(void)
{
    SECURITY_STATUS ss;
    DWORD cbNeeded = 0;
    BYTE *pbBlob   = NULL;

    printf("\n--- Test 7: ExportKey BCRYPT_RSAPUBLIC_BLOB ---\n");
    if (!g_hKeyRsa) { ASSERT("Prerequisite ExportKey", 0); return; }

    /* Size */
    ss = KSP_ExportKey(g_hProv, g_hKeyRsa, 0,
        BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &cbNeeded, 0);
    ASSERT_SS("ExportKey RSA (size)", ss);
    ASSERT("cbNeeded > 0", cbNeeded > 0);

    pbBlob = (BYTE *)KSP_Alloc(cbNeeded);
    ASSERT("Alloc blob", pbBlob != NULL);

    if (pbBlob) {
        DWORD cbResult = 0;
        ss = KSP_ExportKey(g_hProv, g_hKeyRsa, 0,
            BCRYPT_RSAPUBLIC_BLOB, NULL, pbBlob, cbNeeded, &cbResult, 0);
        ASSERT_SS("ExportKey RSA public", ss);
        ASSERT("RSAPUBLIC magic correct",
               cbResult >= sizeof(BCRYPT_RSAKEY_BLOB) &&
               ((BCRYPT_RSAKEY_BLOB *)pbBlob)->Magic == BCRYPT_RSAPUBLIC_MAGIC);

        printf("  Blob size=%lu bits=%lu\n",
               (unsigned long)cbResult,
               (unsigned long)((BCRYPT_RSAKEY_BLOB *)pbBlob)->BitLength);
        KSP_Free(pbBlob);
    }
}

/* ── Test 8 : ExportKey private key → NTE_NOT_SUPPORTED ─────────────────── */
static void test_export_private_refused(void)
{
    SECURITY_STATUS ss;
    DWORD cbNeeded = 0;

    printf("\n--- Test 8: ExportKey private key -> NTE_NOT_SUPPORTED ---\n");
    if (!g_hKeyRsa) { ASSERT("Prerequisite export private", 0); return; }

    ss = KSP_ExportKey(g_hProv, g_hKeyRsa, 0,
        BCRYPT_RSAFULLPRIVATE_BLOB, NULL, NULL, 0, &cbNeeded, 0);
    ASSERT("ExportKey private returns NTE_NOT_SUPPORTED",
           ss == NTE_NOT_SUPPORTED);
}

/* ── Test 9 : OpenKey ──────────────────────────────────────────────────── */
static NCRYPT_KEY_HANDLE g_hKeyRsaReopened = 0;

static void test_open_existing_key(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 9: OpenKey (reopen) ---\n");
    if (!g_hKeyRsa) { ASSERT("Prerequisite OpenKey", 0); return; }

    ss = KSP_OpenKey(g_hProv, &g_hKeyRsaReopened,
        g_wszRsaLabel, AT_SIGNATURE, 0);
    ASSERT_SS("KSP_OpenKey existing key", ss);
    ASSERT("Reopened handle not null", g_hKeyRsaReopened != 0);
}

/* ── Test 10 : CreatePersistedKey ECDSA P-256 ──────────────────────────── */
static NCRYPT_KEY_HANDLE g_hKeyEc = 0;
static WCHAR g_wszEcLabel[64];

static void test_create_ecdsa(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 10: CreatePersistedKey ECDSA P-256 ---\n");
    swprintf_s(g_wszEcLabel, 64, L"IntTest_EC_%u", GetTickCount());

    ss = KSP_CreatePersistedKey(g_hProv, &g_hKeyEc,
        ALG_ECDSA_P256, g_wszEcLabel, AT_SIGNATURE, 0);
    ASSERT_SS("KSP_CreatePersistedKey ECDSA_P256", ss);
    ASSERT("hKeyEc not null", g_hKeyEc != 0);
}

/* ── Test 11 : SignHash ECDSA ──────────────────────────────────────────── */
static void test_sign_ecdsa(void)
{
    SECURITY_STATUS ss;
    BYTE  sigBuf[128];
    DWORD cbResult  = 0;
    DWORD cbNeeded  = 0;

    printf("\n--- Test 11: SignHash ECDSA ---\n");
    if (!g_hKeyEc) { ASSERT("Prerequisite SignHash ECDSA", 0); return; }

    ss = KSP_SignHash(g_hProv, g_hKeyEc, NULL,
        g_abHashSha256, 32, NULL, 0, &cbNeeded, 0);
    ASSERT_SS("SignHash ECDSA (size)", ss);
    ASSERT("cbNeeded ECDSA = 64", cbNeeded == 64);

    ss = KSP_SignHash(g_hProv, g_hKeyEc, NULL,
        g_abHashSha256, 32, sigBuf, sizeof(sigBuf), &cbResult, 0);
    ASSERT_SS("SignHash ECDSA", ss);
    ASSERT("ECDSA signature = 64 bytes", cbResult == 64);

    printf("  First 8 bytes (r): %02X %02X %02X %02X %02X %02X %02X %02X\n",
           sigBuf[0], sigBuf[1], sigBuf[2], sigBuf[3],
           sigBuf[4], sigBuf[5], sigBuf[6], sigBuf[7]);
}

/* ── Test 12 : EnumKeys ────────────────────────────────────────────────── */
static void test_enum_keys(void)
{
    SECURITY_STATUS  ss;
    PVOID            pEnumState = NULL;
    NCryptKeyName   *pKeyName   = NULL;
    BOOL             bFoundRsa  = FALSE;
    BOOL             bFoundEc   = FALSE;
    int              nCount     = 0;

    printf("\n--- Test 12: EnumKeys ---\n");

    do {
        ss = KSP_EnumKeys(g_hProv, NULL, &pKeyName, &pEnumState, 0);
        if (ss == ERROR_SUCCESS && pKeyName) {
            /* pKeyName->pszName points just past the structure */
            LPWSTR pszN = pKeyName->pszName;
            printf("  Key: %ls\n", pszN ? pszN : L"(null)");

            if (pszN && _wcsicmp(pszN, g_wszRsaLabel) == 0) bFoundRsa = TRUE;
            if (pszN && _wcsicmp(pszN, g_wszEcLabel)  == 0) bFoundEc  = TRUE;

            KSP_FreeBuffer(pKeyName);
            pKeyName = NULL;
            nCount++;
        }
    } while (ss == ERROR_SUCCESS);

    ASSERT("EnumKeys finds RSA key",   bFoundRsa);
    ASSERT("EnumKeys finds ECDSA key", bFoundEc);
    printf("  Total keys: %d\n", nCount);
}

/* ── Test 13 : DeleteKey ───────────────────────────────────────────────── */
static void test_delete_keys(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 13: DeleteKey ---\n");

    if (g_hKeyRsaReopened) {
        KSP_FreeKey(g_hProv, g_hKeyRsaReopened);
        g_hKeyRsaReopened = 0;
    }

    if (g_hKeyRsa) {
        ss = KSP_DeleteKey(g_hProv, g_hKeyRsa, 0);
        ASSERT_SS("KSP_DeleteKey RSA", ss);
        g_hKeyRsa = 0;
    }

    if (g_hKeyEc) {
        ss = KSP_DeleteKey(g_hProv, g_hKeyEc, 0);
        ASSERT_SS("KSP_DeleteKey ECDSA", ss);
        g_hKeyEc = 0;
    }

    /* Verify the key is gone */
    {
        NCRYPT_KEY_HANDLE hTmp = 0;
        ss = KSP_OpenKey(g_hProv, &hTmp, g_wszRsaLabel, 0, 0);
        ASSERT("After DeleteKey, OpenKey returns error",
               ss != ERROR_SUCCESS);
        if (ss == ERROR_SUCCESS && hTmp)
            KSP_FreeKey(g_hProv, hTmp);
    }
}

/* ── Test 14 : SetKeyProperty NCRYPT_LENGTH ─────────────────────────────── */
static void test_set_key_length(void)
{
    SECURITY_STATUS   ss;
    NCRYPT_KEY_HANDLE hKeyTemp = 0;
    DWORD             dwBits   = 4096;
    DWORD             cbResult = 0;

    printf("\n--- Test 14: SetKeyProperty NCRYPT_LENGTH ---\n");

    ss = KSP_CreatePersistedKey(g_hProv, &hKeyTemp,
        ALG_RSA, L"_TmpKey4096_", AT_SIGNATURE,
        NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_SS("CreatePersistedKey RSA PERSIST_ONLY", ss);

    if (hKeyTemp) {
        ss = KSP_SetKeyProperty(g_hProv, hKeyTemp,
            NCRYPT_LENGTH_PROPERTY, (PBYTE)&dwBits, sizeof(dwBits), 0);
        ASSERT_SS("SetKeyProperty LENGTH=4096", ss);

        /* Verify the property */
        dwBits = 0;
        ss = KSP_GetKeyProperty(g_hProv, hKeyTemp, NCRYPT_LENGTH_PROPERTY,
            (PBYTE)&dwBits, sizeof(dwBits), &cbResult, 0);
        ASSERT_SS("GetKeyProperty LENGTH after SET", ss);
        ASSERT("LENGTH = 4096", dwBits == 4096);

        /* FinalizeKey to actually generate (may take a few seconds) */
        ss = KSP_FinalizeKey(g_hProv, hKeyTemp, 0);
        ASSERT_SS("FinalizeKey RSA 4096", ss);

        KSP_DeleteKey(g_hProv, hKeyTemp, 0);
        hKeyTemp = 0;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HLK-conformant tests (15–21)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Shared RSA key between tests 15 and 16 */
static NCRYPT_KEY_HANDLE g_hKeyHlkRsa = 0;
static WCHAR             g_wszHlkRsaLabel[64];

/* ── Test 15 : RSA PSS signing + BCrypt PSS verification ─────────────────── */
static void test_rsa_pss_sign_and_verify(void)
{
    SECURITY_STATUS       ss;
    BCRYPT_PSS_PADDING_INFO pss;
    BYTE                  abSig[512];
    DWORD                 cbNeeded = 0, cbSig = 0;
    BCRYPT_KEY_HANDLE     hBcryptKey;
    NTSTATUS              nt;

    printf("\n--- Test 15 (HLK): RSA PSS signing + BCrypt PSS verification ---\n");

    pss.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    pss.cbSalt   = 32;

    swprintf_s(g_wszHlkRsaLabel, 64, L"HlkRsa_%u", GetTickCount());
    ss = KSP_CreatePersistedKey(g_hProv, &g_hKeyHlkRsa,
        ALG_RSA, g_wszHlkRsaLabel, AT_SIGNATURE, 0);
    ASSERT_SS("HLK15 CreatePersistedKey RSA 2048", ss);
    if (!g_hKeyHlkRsa) return;

    ss = KSP_FinalizeKey(g_hProv, g_hKeyHlkRsa, 0);
    ASSERT_SS("HLK15 FinalizeKey RSA", ss);

    /* PSS size query */
    ss = KSP_SignHash(g_hProv, g_hKeyHlkRsa, &pss,
        g_abHashSha256, 32, NULL, 0, &cbNeeded, NCRYPT_PAD_PSS_FLAG);
    ASSERT_SS("HLK15 SignHash RSA PSS (size query)", ss);
    ASSERT("HLK15 PSS cbNeeded = 256 (RSA-2048)", cbNeeded == 256);

    /* PSS actual sign */
    ss = KSP_SignHash(g_hProv, g_hKeyHlkRsa, &pss,
        g_abHashSha256, 32, abSig, sizeof(abSig), &cbSig, NCRYPT_PAD_PSS_FLAG);
    ASSERT_SS("HLK15 SignHash RSA PSS", ss);
    ASSERT("HLK15 PSS signature = 256 bytes", cbSig == 256);

    /* BCrypt verification */
    hBcryptKey = HlkImportPublicKey(g_hProv, g_hKeyHlkRsa,
        BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALGORITHM);
    ASSERT("HLK15 Import RSA public key into BCrypt", hBcryptKey != NULL);
    if (hBcryptKey) {
        nt = BCryptVerifySignature(hBcryptKey, &pss,
                g_abHashSha256, 32, abSig, cbSig, BCRYPT_PAD_PSS);
        ASSERT("HLK15 BCryptVerifySignature RSA PSS", nt == 0);
        BCryptDestroyKey(hBcryptKey);
    }
}

/* ── Test 16 : RSA PKCS1 BCrypt verification + extended property queries ──── */
static void test_rsa_pkcs1_bcrypt_verify(void)
{
    SECURITY_STATUS          ss;
    BCRYPT_PKCS1_PADDING_INFO pkcs1;
    BYTE                     abSig[512];
    DWORD                    cbNeeded = 0, cbSig = 0, cbResult = 0;
    BCRYPT_KEY_HANDLE        hBcryptKey;
    NTSTATUS                 nt;
    DWORD                    dwProp = 0;
    WCHAR                    wszGroup[64];

    printf("\n--- Test 16 (HLK): RSA PKCS1 BCrypt verify + property queries ---\n");
    if (!g_hKeyHlkRsa) { ASSERT("HLK16 Prerequisite RSA key", 0); return; }

    pkcs1.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    /* PKCS1 sign */
    ss = KSP_SignHash(g_hProv, g_hKeyHlkRsa, &pkcs1,
        g_abHashSha256, 32, NULL, 0, &cbNeeded, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_SS("HLK16 SignHash RSA PKCS1 (size)", ss);
    ss = KSP_SignHash(g_hProv, g_hKeyHlkRsa, &pkcs1,
        g_abHashSha256, 32, abSig, sizeof(abSig), &cbSig, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_SS("HLK16 SignHash RSA PKCS1", ss);
    ASSERT("HLK16 PKCS1 sig = 256 bytes", cbSig == 256);

    /* BCrypt PKCS1 verify */
    hBcryptKey = HlkImportPublicKey(g_hProv, g_hKeyHlkRsa,
        BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALGORITHM);
    ASSERT("HLK16 Import RSA public key", hBcryptKey != NULL);
    if (hBcryptKey) {
        nt = BCryptVerifySignature(hBcryptKey, &pkcs1,
                g_abHashSha256, 32, abSig, cbSig, BCRYPT_PAD_PKCS1);
        ASSERT("HLK16 BCryptVerifySignature RSA PKCS1", nt == 0);
        BCryptDestroyKey(hBcryptKey);
    }

    /* NCRYPT_KEY_USAGE_PROPERTY → ALLOW_SIGNING for AT_SIGNATURE key */
    ss = KSP_GetKeyProperty(g_hProv, g_hKeyHlkRsa, NCRYPT_KEY_USAGE_PROPERTY,
        (PBYTE)&dwProp, sizeof(dwProp), &cbResult, 0);
    ASSERT_SS("HLK16 GetKeyProperty KEY_USAGE", ss);
    ASSERT("HLK16 KEY_USAGE has ALLOW_SIGNING flag",
           (dwProp & NCRYPT_ALLOW_SIGNING_FLAG) != 0);

    /* NCRYPT_EXPORT_POLICY_PROPERTY → 0 (non-exportable private key) */
    dwProp = 0xFFFFFFFF;
    ss = KSP_GetKeyProperty(g_hProv, g_hKeyHlkRsa, NCRYPT_EXPORT_POLICY_PROPERTY,
        (PBYTE)&dwProp, sizeof(dwProp), &cbResult, 0);
    ASSERT_SS("HLK16 GetKeyProperty EXPORT_POLICY", ss);
    ASSERT("HLK16 EXPORT_POLICY = 0 (no export)", dwProp == 0);

    /* NCRYPT_ALGORITHM_GROUP_PROPERTY → "RSA" */
    ss = KSP_GetKeyProperty(g_hProv, g_hKeyHlkRsa, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        (PBYTE)wszGroup, sizeof(wszGroup), &cbResult, 0);
    ASSERT_SS("HLK16 GetKeyProperty ALG_GROUP", ss);
    ASSERT("HLK16 ALG_GROUP = RSA",
           _wcsicmp(wszGroup, NCRYPT_RSA_ALGORITHM_GROUP) == 0);

    /* NCRYPT_UNIQUE_NAME_PROPERTY → key label */
    {
        WCHAR wszUnique[MAX_KEY_LABEL_LEN];
        ss = KSP_GetKeyProperty(g_hProv, g_hKeyHlkRsa, NCRYPT_UNIQUE_NAME_PROPERTY,
            (PBYTE)wszUnique, sizeof(wszUnique), &cbResult, 0);
        ASSERT_SS("HLK16 GetKeyProperty UNIQUE_NAME", ss);
        ASSERT("HLK16 UNIQUE_NAME = key label",
               _wcsicmp(wszUnique, g_wszHlkRsaLabel) == 0);
    }

    /* Cleanup the shared RSA key */
    KSP_DeleteKey(g_hProv, g_hKeyHlkRsa, 0);
    g_hKeyHlkRsa = 0;
}

/* ── Test 17 : ECDSA P-256 end-to-end BCrypt verification ───────────────── */
static void test_ecdsa_p256_bcrypt_verify(void)
{
    SECURITY_STATUS   ss;
    NCRYPT_KEY_HANDLE hKeyEc256  = 0;
    WCHAR             wszLabel[64];
    BYTE              abSig[128];
    DWORD             cbNeeded   = 0, cbSig = 0, cbResult = 0;
    DWORD             dwProp     = 0;
    WCHAR             wszGroup[64];
    BCRYPT_KEY_HANDLE hBcryptKey;
    NTSTATUS          nt;

    printf("\n--- Test 17 (HLK): ECDSA P-256 BCrypt verification ---\n");
    swprintf_s(wszLabel, 64, L"HlkEc256_%u", GetTickCount());

    ss = KSP_CreatePersistedKey(g_hProv, &hKeyEc256,
        ALG_ECDSA_P256, wszLabel, AT_SIGNATURE, 0);
    ASSERT_SS("HLK17 CreatePersistedKey ECDSA_P256", ss);
    if (!hKeyEc256) return;

    ss = KSP_FinalizeKey(g_hProv, hKeyEc256, 0);
    ASSERT_SS("HLK17 FinalizeKey ECDSA_P256", ss);

    /* Sign a SHA-256 hash (32 bytes) */
    ss = KSP_SignHash(g_hProv, hKeyEc256, NULL,
        g_abHashSha256, 32, NULL, 0, &cbNeeded, 0);
    ASSERT_SS("HLK17 SignHash ECDSA P-256 (size)", ss);
    ASSERT("HLK17 ECDSA P-256 cbNeeded = 64", cbNeeded == 64);

    ss = KSP_SignHash(g_hProv, hKeyEc256, NULL,
        g_abHashSha256, 32, abSig, sizeof(abSig), &cbSig, 0);
    ASSERT_SS("HLK17 SignHash ECDSA P-256", ss);
    ASSERT("HLK17 ECDSA P-256 sig = 64 bytes (r‖s)", cbSig == 64);

    /* BCrypt verify */
    hBcryptKey = HlkImportPublicKey(g_hProv, hKeyEc256,
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM);
    ASSERT("HLK17 Import ECDSA P-256 public key into BCrypt", hBcryptKey != NULL);
    if (hBcryptKey) {
        nt = BCryptVerifySignature(hBcryptKey, NULL,
                g_abHashSha256, 32, abSig, cbSig, 0);
        ASSERT("HLK17 BCryptVerifySignature ECDSA P-256", nt == 0);
        BCryptDestroyKey(hBcryptKey);
    }

    /* NCRYPT_ALGORITHM_GROUP_PROPERTY → "ECDSA" */
    ss = KSP_GetKeyProperty(g_hProv, hKeyEc256, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        (PBYTE)wszGroup, sizeof(wszGroup), &cbResult, 0);
    ASSERT_SS("HLK17 GetKeyProperty ALG_GROUP", ss);
    ASSERT("HLK17 ALG_GROUP = ECDSA",
           _wcsicmp(wszGroup, NCRYPT_ECDSA_ALGORITHM_GROUP) == 0);

    /* NCRYPT_KEY_USAGE_PROPERTY → ALLOW_SIGNING */
    ss = KSP_GetKeyProperty(g_hProv, hKeyEc256, NCRYPT_KEY_USAGE_PROPERTY,
        (PBYTE)&dwProp, sizeof(dwProp), &cbResult, 0);
    ASSERT_SS("HLK17 GetKeyProperty KEY_USAGE", ss);
    ASSERT("HLK17 ECDSA KEY_USAGE has ALLOW_SIGNING",
           (dwProp & NCRYPT_ALLOW_SIGNING_FLAG) != 0);

    KSP_DeleteKey(g_hProv, hKeyEc256, 0);
}

/* ── Test 18 : ECDSA P-384 generation, signing and BCrypt verification ────── */
static void test_ecdsa_p384(void)
{
    SECURITY_STATUS   ss;
    NCRYPT_KEY_HANDLE hKeyEc384 = 0;
    WCHAR             wszLabel[64];
    BYTE              abHashSha384[48]; /* SHA-384 output */
    BYTE              abSig[128];       /* P-384 raw sig = 96 bytes */
    DWORD             cbNeeded = 0, cbSig = 0;
    BCRYPT_KEY_HANDLE hBcryptKey;
    NTSTATUS          nt;
    int               i;

    printf("\n--- Test 18 (HLK): ECDSA P-384 generation and BCrypt verification ---\n");

    /* Synthetic SHA-384 hash */
    for (i = 0; i < 48; i++) abHashSha384[i] = (BYTE)(i * 5 + 11);

    swprintf_s(wszLabel, 64, L"HlkEc384_%u", GetTickCount());
    ss = KSP_CreatePersistedKey(g_hProv, &hKeyEc384,
        ALG_ECDSA_P384, wszLabel, AT_SIGNATURE, 0);
    ASSERT_SS("HLK18 CreatePersistedKey ECDSA_P384", ss);
    if (!hKeyEc384) return;

    ss = KSP_FinalizeKey(g_hProv, hKeyEc384, 0);
    ASSERT_SS("HLK18 FinalizeKey ECDSA_P384", ss);

    /* Sign a SHA-384 hash (48 bytes); expected signature = 96 bytes (r‖s) */
    ss = KSP_SignHash(g_hProv, hKeyEc384, NULL,
        abHashSha384, 48, NULL, 0, &cbNeeded, 0);
    ASSERT_SS("HLK18 SignHash ECDSA P-384 (size)", ss);
    ASSERT("HLK18 ECDSA P-384 cbNeeded = 96", cbNeeded == 96);

    ss = KSP_SignHash(g_hProv, hKeyEc384, NULL,
        abHashSha384, 48, abSig, sizeof(abSig), &cbSig, 0);
    ASSERT_SS("HLK18 SignHash ECDSA P-384", ss);
    ASSERT("HLK18 ECDSA P-384 sig = 96 bytes (r‖s)", cbSig == 96);

    /* BCrypt verify */
    hBcryptKey = HlkImportPublicKey(g_hProv, hKeyEc384,
        BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P384_ALGORITHM);
    ASSERT("HLK18 Import ECDSA P-384 public key into BCrypt", hBcryptKey != NULL);
    if (hBcryptKey) {
        nt = BCryptVerifySignature(hBcryptKey, NULL,
                abHashSha384, 48, abSig, cbSig, 0);
        ASSERT("HLK18 BCryptVerifySignature ECDSA P-384", nt == 0);
        BCryptDestroyKey(hBcryptKey);
    }

    KSP_DeleteKey(g_hProv, hKeyEc384, 0);
}

/* ── Test 19 : RSA 3072 deferred generation, signing and BCrypt verify ────── */
static void test_rsa_3072(void)
{
    SECURITY_STATUS          ss;
    NCRYPT_KEY_HANDLE        hKeyRsa3072 = 0;
    WCHAR                    wszLabel[64];
    DWORD                    dwBits    = 3072;
    DWORD                    cbResult  = 0;
    BCRYPT_PKCS1_PADDING_INFO pkcs1;
    BYTE                     abSig[512]; /* 3072/8 = 384 bytes */
    DWORD                    cbNeeded  = 0, cbSig = 0;
    BCRYPT_KEY_HANDLE        hBcryptKey;
    NTSTATUS                 nt;

    printf("\n--- Test 19 (HLK): RSA 3072 deferred generation + BCrypt verify ---\n");
    printf("  (Generating RSA 3072 — may take several seconds)\n");

    pkcs1.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    swprintf_s(wszLabel, 64, L"HlkRsa3072_%u", GetTickCount());

    ss = KSP_CreatePersistedKey(g_hProv, &hKeyRsa3072,
        ALG_RSA, wszLabel, AT_SIGNATURE, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_SS("HLK19 CreatePersistedKey RSA PERSIST_ONLY", ss);
    if (!hKeyRsa3072) return;

    ss = KSP_SetKeyProperty(g_hProv, hKeyRsa3072,
        NCRYPT_LENGTH_PROPERTY, (PBYTE)&dwBits, sizeof(dwBits), 0);
    ASSERT_SS("HLK19 SetKeyProperty LENGTH=3072", ss);

    /* Verify deferred length */
    dwBits = 0;
    ss = KSP_GetKeyProperty(g_hProv, hKeyRsa3072, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwBits, sizeof(dwBits), &cbResult, 0);
    ASSERT_SS("HLK19 GetKeyProperty LENGTH before finalize", ss);
    ASSERT("HLK19 LENGTH = 3072 before finalize", dwBits == 3072);

    ss = KSP_FinalizeKey(g_hProv, hKeyRsa3072, 0);
    ASSERT_SS("HLK19 FinalizeKey RSA 3072", ss);

    /* Sign with PKCS1 SHA-256; RSA-3072 signature = 384 bytes */
    ss = KSP_SignHash(g_hProv, hKeyRsa3072, &pkcs1,
        g_abHashSha256, 32, NULL, 0, &cbNeeded, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_SS("HLK19 SignHash RSA 3072 PKCS1 (size)", ss);
    ASSERT("HLK19 RSA 3072 cbNeeded = 384", cbNeeded == 384);

    ss = KSP_SignHash(g_hProv, hKeyRsa3072, &pkcs1,
        g_abHashSha256, 32, abSig, sizeof(abSig), &cbSig, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_SS("HLK19 SignHash RSA 3072 PKCS1", ss);
    ASSERT("HLK19 RSA 3072 sig = 384 bytes", cbSig == 384);

    /* BCrypt verify */
    hBcryptKey = HlkImportPublicKey(g_hProv, hKeyRsa3072,
        BCRYPT_RSAPUBLIC_BLOB, BCRYPT_RSA_ALGORITHM);
    ASSERT("HLK19 Import RSA 3072 public key into BCrypt", hBcryptKey != NULL);
    if (hBcryptKey) {
        nt = BCryptVerifySignature(hBcryptKey, &pkcs1,
                g_abHashSha256, 32, abSig, cbSig, BCRYPT_PAD_PKCS1);
        ASSERT("HLK19 BCryptVerifySignature RSA 3072 PKCS1", nt == 0);
        BCryptDestroyKey(hBcryptKey);
    }

    KSP_DeleteKey(g_hProv, hKeyRsa3072, 0);
}

/* ── Test 20 : RSA AT_KEYEXCHANGE + RSA OAEP encrypt/decrypt ────────────── */
static void test_rsa_oaep_decrypt(void)
{
    SECURITY_STATUS     ss;
    NCRYPT_KEY_HANDLE   hKeyKex = 0;
    WCHAR               wszLabel[64];
    DWORD               dwProp    = 0;
    DWORD               cbResult  = 0;
    BCRYPT_ALG_HANDLE   hAlg      = NULL;
    BCRYPT_KEY_HANDLE   hBcryptPub = NULL;
    BYTE               *pbBlob    = NULL;
    DWORD               cbBlob    = 0;
    BYTE                abPlain[] = "HLK OAEP test payload 12345";
    BYTE                abCipher[512];
    DWORD               cbCipher  = 0;
    BYTE                abDecrypted[256];
    DWORD               cbDecrypted = 0;
    BCRYPT_OAEP_PADDING_INFO oaep;
    NTSTATUS            nt;

    printf("\n--- Test 20 (HLK): RSA AT_KEYEXCHANGE + OAEP encrypt/decrypt ---\n");

    oaep.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    oaep.pbLabel  = NULL;
    oaep.cbLabel  = 0;

    swprintf_s(wszLabel, 64, L"HlkRsaKex_%u", GetTickCount());

    ss = KSP_CreatePersistedKey(g_hProv, &hKeyKex,
        ALG_RSA, wszLabel, AT_KEYEXCHANGE, 0);
    ASSERT_SS("HLK20 CreatePersistedKey RSA AT_KEYEXCHANGE", ss);
    if (!hKeyKex) return;

    ss = KSP_FinalizeKey(g_hProv, hKeyKex, 0);
    ASSERT_SS("HLK20 FinalizeKey RSA KEX", ss);

    /* KEY_USAGE for AT_KEYEXCHANGE → ALLOW_DECRYPT */
    ss = KSP_GetKeyProperty(g_hProv, hKeyKex, NCRYPT_KEY_USAGE_PROPERTY,
        (PBYTE)&dwProp, sizeof(dwProp), &cbResult, 0);
    ASSERT_SS("HLK20 GetKeyProperty KEY_USAGE", ss);
    ASSERT("HLK20 KEY_USAGE has ALLOW_DECRYPT flag",
           (dwProp & NCRYPT_ALLOW_DECRYPT_FLAG) != 0);

    /* Export public key, import into BCrypt, encrypt with OAEP */
    ss = KSP_ExportKey(g_hProv, hKeyKex, 0,
        BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &cbBlob, 0);
    if (ss != ERROR_SUCCESS || cbBlob == 0) goto cleanup20;

    pbBlob = (BYTE *)KSP_Alloc(cbBlob);
    if (!pbBlob) goto cleanup20;

    ss = KSP_ExportKey(g_hProv, hKeyKex, 0,
        BCRYPT_RSAPUBLIC_BLOB, NULL, pbBlob, cbBlob, &cbBlob, 0);
    ASSERT_SS("HLK20 ExportKey RSA public", ss);
    if (ss != ERROR_SUCCESS) goto cleanup20;

    nt = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);
    if (nt != 0) goto cleanup20;

    nt = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB,
            &hBcryptPub, pbBlob, cbBlob, 0);
    ASSERT("HLK20 BCryptImportKeyPair RSA public", nt == 0 && hBcryptPub != NULL);
    if (nt != 0 || !hBcryptPub) goto cleanup20;

    /* Encrypt: size query */
    nt = BCryptEncrypt(hBcryptPub,
            abPlain, (ULONG)sizeof(abPlain) - 1 /* exclude NUL */,
            &oaep, NULL, 0, NULL, 0, &cbCipher, BCRYPT_PAD_OAEP);
    if (nt != 0 || cbCipher == 0) {
        ASSERT("HLK20 BCryptEncrypt OAEP (size)", 0);
        goto cleanup20;
    }
    ASSERT("HLK20 BCryptEncrypt OAEP cbCipher = 256", cbCipher == 256);

    /* Encrypt: actual */
    nt = BCryptEncrypt(hBcryptPub,
            abPlain, (ULONG)sizeof(abPlain) - 1,
            &oaep, NULL, 0, abCipher, cbCipher, &cbCipher, BCRYPT_PAD_OAEP);
    ASSERT("HLK20 BCryptEncrypt OAEP", nt == 0);
    if (nt != 0) goto cleanup20;

    /* Decrypt with the KSP private key */
    ss = KSP_Decrypt(g_hProv, hKeyKex,
            abCipher, cbCipher, &oaep,
            NULL, 0, &cbDecrypted, NCRYPT_PAD_OAEP_FLAG);
    ASSERT_SS("HLK20 KSP_Decrypt OAEP (size query)", ss);

    ss = KSP_Decrypt(g_hProv, hKeyKex,
            abCipher, cbCipher, &oaep,
            abDecrypted, (DWORD)sizeof(abDecrypted), &cbDecrypted, NCRYPT_PAD_OAEP_FLAG);
    ASSERT_SS("HLK20 KSP_Decrypt OAEP", ss);

    if (ss == ERROR_SUCCESS) {
        ASSERT("HLK20 Decrypted length matches plaintext",
               cbDecrypted == (DWORD)(sizeof(abPlain) - 1));
        ASSERT("HLK20 Decrypted content matches plaintext",
               cbDecrypted == (DWORD)(sizeof(abPlain) - 1) &&
               memcmp(abDecrypted, abPlain, cbDecrypted) == 0);
        printf("  Decrypted: \"%.*s\" (%lu bytes)\n",
               (int)cbDecrypted, (char *)abDecrypted, (unsigned long)cbDecrypted);
    }

cleanup20:
    if (hBcryptPub) BCryptDestroyKey(hBcryptPub);
    if (hAlg)       BCryptCloseAlgorithmProvider(hAlg, 0);
    KSP_Free(pbBlob);
    if (hKeyKex) KSP_DeleteKey(g_hProv, hKeyKex, 0);
}

/* ── Test 21 : Error conditions ──────────────────────────────────────────── */
static void test_error_conditions(void)
{
    SECURITY_STATUS   ss;
    NCRYPT_KEY_HANDLE hTmp    = 0;
    DWORD             cbDummy = 0;

    printf("\n--- Test 21 (HLK): Error conditions ---\n");

    /* Invalid handle: SignHash with zero key handle */
    ss = KSP_SignHash(g_hProv, 0 /* invalid */, NULL,
        g_abHashSha256, 32, NULL, 0, &cbDummy, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT("HLK21 SignHash(invalid key) returns error", ss != ERROR_SUCCESS);

    /* Invalid handle: GetKeyProperty with zero key handle */
    {
        WCHAR wszBuf[64];
        ss = KSP_GetKeyProperty(g_hProv, 0 /* invalid */,
            NCRYPT_ALGORITHM_PROPERTY, (PBYTE)wszBuf, sizeof(wszBuf), &cbDummy, 0);
        ASSERT("HLK21 GetKeyProperty(invalid key) returns error", ss != ERROR_SUCCESS);
    }

    /* Non-existent key: OpenKey should fail */
    ss = KSP_OpenKey(g_hProv, &hTmp, L"_HLK21_NoSuchKey_", 0, 0);
    ASSERT("HLK21 OpenKey(non-existent) returns error", ss != ERROR_SUCCESS);
    if (ss == ERROR_SUCCESS && hTmp) {
        KSP_FreeKey(g_hProv, hTmp);
        hTmp = 0;
    }

    /* Invalid provider handle: OpenKey with NULL provider */
    ss = KSP_OpenKey(0 /* invalid */, &hTmp, L"AnyKey", 0, 0);
    ASSERT("HLK21 OpenKey(invalid provider) returns error", ss != ERROR_SUCCESS);
    if (ss == ERROR_SUCCESS && hTmp) KSP_FreeKey(g_hProv, hTmp);

    /* ExportKey private blob on a freshly opened (valid) key → NTE_NOT_SUPPORTED
     * We create a temporary key to have a valid handle for this test. */
    {
        NCRYPT_KEY_HANDLE hTmpKey = 0;
        WCHAR wszTmp[64];
        swprintf_s(wszTmp, 64, L"HlkErrKey_%u", GetTickCount());
        if (KSP_CreatePersistedKey(g_hProv, &hTmpKey, ALG_RSA, wszTmp, AT_SIGNATURE, 0)
                == ERROR_SUCCESS && hTmpKey) {
            KSP_FinalizeKey(g_hProv, hTmpKey, 0);
            ss = KSP_ExportKey(g_hProv, hTmpKey, 0,
                    BCRYPT_RSAFULLPRIVATE_BLOB, NULL, NULL, 0, &cbDummy, 0);
            ASSERT("HLK21 ExportKey(private blob) = NTE_NOT_SUPPORTED",
                   ss == NTE_NOT_SUPPORTED);
            KSP_DeleteKey(g_hProv, hTmpKey, 0);
        }
    }
}

/* ── Entry point ─────────────────────────────────────────────────────────── */
int main(void)
{
    printf("=== KSP SoftHSM2 Integration Tests (incl. HLK scenarios) ===\n\n");

    SetEnvironmentVariableA("KSP_DEBUG", "1");
    Log_Initialize();

    test_open_provider();
    if (!g_hProv) {
        printf("Provider not opened, aborting.\n");
        return 1;
    }

    /* ── Original suite (tests 1-14) ──────────────────────────────────────── */
    test_provider_property();
    test_create_rsa();
    test_finalize_rsa();
    test_key_properties();
    test_sign_rsa();
    test_export_rsa_public();
    test_export_private_refused();
    test_open_existing_key();
    test_create_ecdsa();
    test_sign_ecdsa();
    test_enum_keys();
    test_delete_keys();
    test_set_key_length();

    /* ── HLK-conformant suite (tests 15-21) ───────────────────────────────── */
    printf("\n══════════════════════════════════════\n");
    printf("HLK-conformant test scenarios (15-21)\n");
    printf("══════════════════════════════════════\n");
    test_rsa_pss_sign_and_verify();
    test_rsa_pkcs1_bcrypt_verify();
    test_ecdsa_p256_bcrypt_verify();
    test_ecdsa_p384();
    test_rsa_3072();
    test_rsa_oaep_decrypt();
    test_error_conditions();

    KSP_FreeProvider(g_hProv);

    printf("\n══════════════════════════════════════\n");
    printf("Results: PASS=%d  FAIL=%d\n", g_nPass, g_nFail);
    printf("══════════════════════════════════════\n");

    return (g_nFail == 0) ? 0 : 1;
}
