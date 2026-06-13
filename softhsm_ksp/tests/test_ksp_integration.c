/* test_ksp_integration.c — Tests end-to-end via l'API NCrypt (KSP complet)
 * Appelle directement les fonctions KSP sans passer par le registre Windows.
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
        printf("[FAIL] %s : %s\n", pszName, pszDetail ? pszDetail : "erreur");
        g_nFail++;
    }
}

#define ASSERT(name, cond)     test_assert(name, (cond), NULL)
#define ASSERT_SS(name, ss)    test_assert(name, (ss) == ERROR_SUCCESS, \
                                   "0x" #ss)

/* ── Test 1 : OpenProvider ──────────────────────────────────────────────── */
static NCRYPT_PROV_HANDLE g_hProv = 0;

static void test_open_provider(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 1 : OpenProvider ---\n");
    ss = KSP_OpenProvider(&g_hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_SS("KSP_OpenProvider", ss);
    ASSERT("hProvider non nul", g_hProv != 0);
}

/* ── Test 2 : GetProviderProperty ──────────────────────────────────────── */
static void test_provider_property(void)
{
    SECURITY_STATUS ss;
    WCHAR  wszName[256];
    DWORD  cbResult = 0;
    DWORD  dwVersion = 0;
    DWORD  dwImpl    = 0;

    printf("\n--- Test 2 : GetProviderProperty ---\n");

    ss = KSP_GetProviderProperty(g_hProv, NCRYPT_NAME_PROPERTY,
        (PBYTE)wszName, sizeof(wszName), &cbResult, 0);
    ASSERT_SS("GetProviderProperty NAME", ss);
    ASSERT("Nom = SoftHSM KSP",
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

    printf("\n--- Test 3 : CreatePersistedKey RSA 2048 ---\n");
    swprintf_s(g_wszRsaLabel, 64, L"IntTest_RSA_%u", GetTickCount());

    ss = KSP_CreatePersistedKey(g_hProv, &g_hKeyRsa,
        ALG_RSA, g_wszRsaLabel, AT_SIGNATURE, 0);
    ASSERT_SS("KSP_CreatePersistedKey RSA", ss);
    ASSERT("hKeyRsa non nul", g_hKeyRsa != 0);
}

/* ── Test 4 : FinalizeKey ──────────────────────────────────────────────── */
static void test_finalize_rsa(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 4 : FinalizeKey RSA ---\n");
    if (!g_hKeyRsa) { ASSERT("Prérequis FinalizeKey", 0); return; }

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

    printf("\n--- Test 5 : GetKeyProperty ---\n");
    if (!g_hKeyRsa) { ASSERT("Prérequis GetKeyProperty", 0); return; }

    ss = KSP_GetKeyProperty(g_hProv, g_hKeyRsa, NCRYPT_ALGORITHM_PROPERTY,
        (PBYTE)wszAlg, sizeof(wszAlg), &cbResult, 0);
    ASSERT_SS("GetKeyProperty ALGORITHM", ss);
    ASSERT("Algorithm = RSA", _wcsicmp(wszAlg, ALG_RSA) == 0);

    ss = KSP_GetKeyProperty(g_hProv, g_hKeyRsa, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwBits, sizeof(dwBits), &cbResult, 0);
    ASSERT_SS("GetKeyProperty LENGTH", ss);
    ASSERT("Longueur = 2048", dwBits == 2048);
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

    printf("\n--- Test 6 : SignHash RSA PKCS1 ---\n");
    if (!g_hKeyRsa) { ASSERT("Prérequis SignHash RSA", 0); return; }

    for (i = 0; i < 32; i++) g_abHashSha256[i] = (BYTE)(i * 7 + 3);

    /* Double-appel : taille d'abord */
    ss = KSP_SignHash(g_hProv, g_hKeyRsa, NULL,
        g_abHashSha256, 32, NULL, 0, &cbNeeded,
        NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_SS("SignHash RSA (taille)", ss);
    ASSERT("cbNeeded > 0", cbNeeded > 0);

    /* Signature effective */
    ss = KSP_SignHash(g_hProv, g_hKeyRsa, NULL,
        g_abHashSha256, 32,
        g_abRsaSig, sizeof(g_abRsaSig),
        &g_cbRsaSig, NCRYPT_PAD_PKCS1_FLAG);
    ASSERT_SS("SignHash RSA PKCS1 effective", ss);
    ASSERT("Signature non vide", g_cbRsaSig > 0);

    printf("  Taille signature RSA : %lu\n", (unsigned long)g_cbRsaSig);
}

/* ── Test 7 : ExportKey RSA public ────────────────────────────────────── */
static void test_export_rsa_public(void)
{
    SECURITY_STATUS ss;
    DWORD cbNeeded = 0;
    BYTE *pbBlob   = NULL;

    printf("\n--- Test 7 : ExportKey BCRYPT_RSAPUBLIC_BLOB ---\n");
    if (!g_hKeyRsa) { ASSERT("Prérequis ExportKey", 0); return; }

    /* Taille */
    ss = KSP_ExportKey(g_hProv, g_hKeyRsa, 0,
        BCRYPT_RSAPUBLIC_BLOB, NULL, NULL, 0, &cbNeeded, 0);
    ASSERT_SS("ExportKey RSA (taille)", ss);
    ASSERT("cbNeeded > 0", cbNeeded > 0);

    pbBlob = (BYTE *)KSP_Alloc(cbNeeded);
    ASSERT("Alloc blob", pbBlob != NULL);

    if (pbBlob) {
        DWORD cbResult = 0;
        ss = KSP_ExportKey(g_hProv, g_hKeyRsa, 0,
            BCRYPT_RSAPUBLIC_BLOB, NULL, pbBlob, cbNeeded, &cbResult, 0);
        ASSERT_SS("ExportKey RSA pub effective", ss);
        ASSERT("Magic RSAPUBLIC correct",
               cbResult >= sizeof(BCRYPT_RSAKEY_BLOB) &&
               ((BCRYPT_RSAKEY_BLOB *)pbBlob)->Magic == BCRYPT_RSAPUBLIC_MAGIC);

        printf("  Blob taille=%lu bits=%lu\n",
               (unsigned long)cbResult,
               (unsigned long)((BCRYPT_RSAKEY_BLOB *)pbBlob)->BitLength);
        KSP_Free(pbBlob);
    }
}

/* ── Test 8 : ExportKey clé privée → NTE_NOT_SUPPORTED ─────────────────── */
static void test_export_private_refused(void)
{
    SECURITY_STATUS ss;
    DWORD cbNeeded = 0;

    printf("\n--- Test 8 : ExportKey clé privée -> NTE_NOT_SUPPORTED ---\n");
    if (!g_hKeyRsa) { ASSERT("Prérequis export privée", 0); return; }

    ss = KSP_ExportKey(g_hProv, g_hKeyRsa, 0,
        BCRYPT_RSAFULLPRIVATE_BLOB, NULL, NULL, 0, &cbNeeded, 0);
    ASSERT("ExportKey privée retourne NTE_NOT_SUPPORTED",
           ss == NTE_NOT_SUPPORTED);
}

/* ── Test 9 : OpenKey ──────────────────────────────────────────────────── */
static NCRYPT_KEY_HANDLE g_hKeyRsaReopened = 0;

static void test_open_existing_key(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 9 : OpenKey (reouverture) ---\n");
    if (!g_hKeyRsa) { ASSERT("Prérequis OpenKey", 0); return; }

    ss = KSP_OpenKey(g_hProv, &g_hKeyRsaReopened,
        g_wszRsaLabel, AT_SIGNATURE, 0);
    ASSERT_SS("KSP_OpenKey clé existante", ss);
    ASSERT("Handle réouvert non nul", g_hKeyRsaReopened != 0);
}

/* ── Test 10 : CreatePersistedKey ECDSA P-256 ──────────────────────────── */
static NCRYPT_KEY_HANDLE g_hKeyEc = 0;
static WCHAR g_wszEcLabel[64];

static void test_create_ecdsa(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 10 : CreatePersistedKey ECDSA P-256 ---\n");
    swprintf_s(g_wszEcLabel, 64, L"IntTest_EC_%u", GetTickCount());

    ss = KSP_CreatePersistedKey(g_hProv, &g_hKeyEc,
        ALG_ECDSA_P256, g_wszEcLabel, AT_SIGNATURE, 0);
    ASSERT_SS("KSP_CreatePersistedKey ECDSA_P256", ss);
    ASSERT("hKeyEc non nul", g_hKeyEc != 0);
}

/* ── Test 11 : SignHash ECDSA ──────────────────────────────────────────── */
static void test_sign_ecdsa(void)
{
    SECURITY_STATUS ss;
    BYTE  sigBuf[128];
    DWORD cbResult  = 0;
    DWORD cbNeeded  = 0;

    printf("\n--- Test 11 : SignHash ECDSA ---\n");
    if (!g_hKeyEc) { ASSERT("Prérequis SignHash ECDSA", 0); return; }

    ss = KSP_SignHash(g_hProv, g_hKeyEc, NULL,
        g_abHashSha256, 32, NULL, 0, &cbNeeded, 0);
    ASSERT_SS("SignHash ECDSA (taille)", ss);
    ASSERT("cbNeeded ECDSA = 64", cbNeeded == 64);

    ss = KSP_SignHash(g_hProv, g_hKeyEc, NULL,
        g_abHashSha256, 32, sigBuf, sizeof(sigBuf), &cbResult, 0);
    ASSERT_SS("SignHash ECDSA effective", ss);
    ASSERT("Signature ECDSA = 64 octets", cbResult == 64);

    printf("  Premiers 8 octets (r) : %02X %02X %02X %02X %02X %02X %02X %02X\n",
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

    printf("\n--- Test 12 : EnumKeys ---\n");

    do {
        ss = KSP_EnumKeys(g_hProv, NULL, &pKeyName, &pEnumState, 0);
        if (ss == ERROR_SUCCESS && pKeyName) {
            /* pKeyName->pszName pointe juste après la structure */
            LPWSTR pszN = pKeyName->pszName;
            printf("  Clé : %ls\n", pszN ? pszN : L"(null)");

            if (pszN && _wcsicmp(pszN, g_wszRsaLabel) == 0) bFoundRsa = TRUE;
            if (pszN && _wcsicmp(pszN, g_wszEcLabel)  == 0) bFoundEc  = TRUE;

            KSP_FreeBuffer(pKeyName);
            pKeyName = NULL;
            nCount++;
        }
    } while (ss == ERROR_SUCCESS);

    ASSERT("EnumKeys trouve clé RSA",   bFoundRsa);
    ASSERT("EnumKeys trouve clé ECDSA", bFoundEc);
    printf("  Total clés : %d\n", nCount);
}

/* ── Test 13 : DeleteKey ───────────────────────────────────────────────── */
static void test_delete_keys(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 13 : DeleteKey ---\n");

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

    /* Vérifie que la clé a bien disparu */
    {
        NCRYPT_KEY_HANDLE hTmp = 0;
        ss = KSP_OpenKey(g_hProv, &hTmp, g_wszRsaLabel, 0, 0);
        ASSERT("Après DeleteKey, OpenKey retourne erreur",
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

    printf("\n--- Test 14 : SetKeyProperty NCRYPT_LENGTH ---\n");

    ss = KSP_CreatePersistedKey(g_hProv, &hKeyTemp,
        ALG_RSA, L"_TmpKey4096_", AT_SIGNATURE,
        NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_SS("CreatePersistedKey RSA PERSIST_ONLY", ss);

    if (hKeyTemp) {
        ss = KSP_SetKeyProperty(g_hProv, hKeyTemp,
            NCRYPT_LENGTH_PROPERTY, (PBYTE)&dwBits, sizeof(dwBits), 0);
        ASSERT_SS("SetKeyProperty LENGTH=4096", ss);

        /* Vérifie la propriété */
        dwBits = 0;
        ss = KSP_GetKeyProperty(g_hProv, hKeyTemp, NCRYPT_LENGTH_PROPERTY,
            (PBYTE)&dwBits, sizeof(dwBits), &cbResult, 0);
        ASSERT_SS("GetKeyProperty LENGTH après SET", ss);
        ASSERT("LENGTH = 4096", dwBits == 4096);

        /* FinalizeKey pour générer réellement (peut prendre quelques secondes) */
        ss = KSP_FinalizeKey(g_hProv, hKeyTemp, 0);
        ASSERT_SS("FinalizeKey RSA 4096", ss);

        KSP_DeleteKey(g_hProv, hKeyTemp, 0);
        hKeyTemp = 0;
    }
}

/* ── Point d'entrée ─────────────────────────────────────────────────────── */
int main(void)
{
    printf("=== Tests d'intégration KSP SoftHSM2 ===\n\n");

    SetEnvironmentVariableA("KSP_DEBUG", "1");
    Log_Initialize();

    test_open_provider();
    if (!g_hProv) {
        printf("Provider non ouvert, abandon.\n");
        return 1;
    }

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

    KSP_FreeProvider(g_hProv);

    printf("\n══════════════════════════════════════\n");
    printf("Résultats : PASS=%d  FAIL=%d\n", g_nPass, g_nFail);
    printf("══════════════════════════════════════\n");

    return (g_nFail == 0) ? 0 : 1;
}
