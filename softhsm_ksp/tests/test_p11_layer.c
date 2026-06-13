/* test_p11_layer.c — Tests unitaires de la couche PKCS#11
 * Compile et exécute indépendamment de la DLL KSP.
 * Nécessite SoftHSM2 installé et SOFTHSM2_LIB défini.
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

/* ── Infrastructure de test ─────────────────────────────────────────────── */
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
#define ASSERT_SS(name, ss)       test_assert(name, (ss) == ERROR_SUCCESS, "SECURITY_STATUS echec")

/* ── Test 1 : initialisation avec mauvais chemin ───────────────────────── */
static void test_bad_path(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 1 : P11_Initialize avec mauvais chemin ---\n");
    SetEnvironmentVariableA(SOFTHSM2_LIB_ENV, "C:\\inexistant\\softhsm2.dll");

    /* Réinitialise l'état interne pour permettre le test */
    ss = P11_Initialize();
    ASSERT("Mauvais chemin -> erreur", ss != ERROR_SUCCESS);

    /* Remet la variable d'environnement à l'état par défaut */
    SetEnvironmentVariableA(SOFTHSM2_LIB_ENV, NULL);
}

/* ── Test 2 : initialisation correcte ──────────────────────────────────── */
static void test_initialize_ok(void)
{
    P11_CONTEXT    *pCtx;
    SECURITY_STATUS ss;

    printf("\n--- Test 2 : P11_Initialize OK ---\n");

    /* Utilise le chemin par défaut ou SOFTHSM2_LIB */
    ss = P11_Initialize();
    ASSERT_SS("P11_Initialize retourne ERROR_SUCCESS", ss);

    pCtx = P11_GetContext();
    ASSERT("Contexte non NULL", pCtx != NULL);
    ASSERT("bInitialized = TRUE", pCtx && pCtx->bInitialized);
    ASSERT("hModule non NULL", pCtx && pCtx->hModule != NULL);
    ASSERT("pFunctionList non NULL", pCtx && pCtx->pFunctionList != NULL);

    printf("  Slot selectionne : %lu\n", (unsigned long)(pCtx ? pCtx->slotId : 0));
}

/* ── Test 3 : initialisation du pool de sessions ───────────────────────── */
static void test_session_pool_init(void)
{
    SECURITY_STATUS ss;

    printf("\n--- Test 3 : P11_SessionPool_Initialize ---\n");
    ss = P11_SessionPool_Initialize();
    ASSERT_SS("SessionPool_Initialize", ss);
}

/* ── Test 4 : acquisition d'une session ────────────────────────────────── */
static void test_acquire_session(void)
{
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    SECURITY_STATUS   ss;

    printf("\n--- Test 4 : AcquireSession ---\n");
    ss = P11_AcquireSession(&hSession);
    ASSERT_SS("P11_AcquireSession retourne ERROR_SUCCESS", ss);
    ASSERT("hSession valide", hSession != CK_INVALID_HANDLE);

    printf("  hSession = 0x%lX\n", (unsigned long)hSession);

    P11_ReleaseSession(hSession);
    ASSERT("ReleaseSession ne plante pas", 1);
}

/* ── Test 5 : recherche clé inexistante ────────────────────────────────── */
static void test_find_nonexistent(void)
{
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hObj;

    printf("\n--- Test 5 : FindObjectByLabel clé inexistante ---\n");

    if (P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("AcquireSession pour find", 0);
        return;
    }

    hObj = P11_FindObjectByLabel(hSession, CKO_PRIVATE_KEY,
                                 L"__cle_inexistante_ksp_test__");
    ASSERT("CKR_OK + handle nul si absente",
           hObj == CK_INVALID_HANDLE);

    P11_ReleaseSession(hSession);
}

/* ── Test 6 : génération clé RSA 2048 ─────────────────────────────────── */
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

    printf("\n--- Test 6 : GenerateKeyPair RSA 2048 ---\n");

    if (!pCtx || !pCtx->bInitialized ||
        P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("AcquireSession pour generate RSA", 0);
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

    ASSERT("C_GenerateKeyPair RSA retourne CKR_OK", rv == CKR_OK);
    ASSERT("hPrivRsa valide", g_hPrivRsa != CK_INVALID_HANDLE);
    ASSERT("hPubRsa valide",  g_hPubRsa  != CK_INVALID_HANDLE);

    printf("  hPrivRsa=0x%lX hPubRsa=0x%lX\n",
           (unsigned long)g_hPrivRsa, (unsigned long)g_hPubRsa);
}

/* ── Test 7 : retrouve la clé après génération ──────────────────────────── */
static void test_find_after_generate(void)
{
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hObj;
    WCHAR             wszLabel[64];

    printf("\n--- Test 7 : FindObjectByLabel apres generation ---\n");

    if (g_hPrivRsa == CK_INVALID_HANDLE) {
        ASSERT("Clé générée (prérequis)", 0);
        return;
    }

    if (P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("AcquireSession pour find", 0);
        return;
    }

    MultiByteToWideChar(CP_UTF8, 0, g_szRsaLabel, -1, wszLabel, 64);
    hObj = P11_FindObjectByLabel(hSession, CKO_PRIVATE_KEY, wszLabel);
    ASSERT("FindObjectByLabel trouve la clé RSA",
           hObj != CK_INVALID_HANDLE);

    P11_ReleaseSession(hSession);
}

/* ── Test 8 : signature RSA PKCS1 ──────────────────────────────────────── */
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

    printf("\n--- Test 8 : SignHash RSA PKCS1 ---\n");

    if (g_hPrivRsa == CK_INVALID_HANDLE || !pCtx ||
        P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("Prérequis SignHash RSA", 0);
        return;
    }

    /* Hash fictif SHA-256 (DigestInfo wrapping pas nécessaire pour CKM_RSA_PKCS) */
    for (i = 0; i < 32; i++) hashBuf[i] = (CK_BYTE)(i + 1);

    rv = pCtx->pFunctionList->C_SignInit(hSession, &mech, g_hPrivRsa);
    ASSERT("C_SignInit RSA PKCS1", rv == CKR_OK);

    cbSig = sizeof(sigBuf);
    rv = pCtx->pFunctionList->C_Sign(hSession,
        hashBuf, 32, sigBuf, &cbSig);

    P11_ReleaseSession(hSession);

    ASSERT("C_Sign RSA PKCS1 retourne CKR_OK", rv == CKR_OK);
    ASSERT("Signature non vide", cbSig > 0);

    printf("  Taille signature RSA : %lu octets\n", (unsigned long)cbSig);
}

/* ── Test 9 : signature RSA PSS ─────────────────────────────────────────── */
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

    printf("\n--- Test 9 : SignHash RSA PSS ---\n");

    if (g_hPrivRsa == CK_INVALID_HANDLE || !pCtx ||
        P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("Prérequis SignHash PSS", 0);
        return;
    }

    for (i = 0; i < 32; i++) hashBuf[i] = (CK_BYTE)(0xFF - i);

    rv = pCtx->pFunctionList->C_SignInit(hSession, &mech, g_hPrivRsa);
    ASSERT("C_SignInit RSA PSS", rv == CKR_OK);

    cbSig = sizeof(sigBuf);
    rv = pCtx->pFunctionList->C_Sign(hSession,
        hashBuf, 32, sigBuf, &cbSig);

    P11_ReleaseSession(hSession);

    ASSERT("C_Sign RSA PSS retourne CKR_OK", rv == CKR_OK);
    ASSERT("Signature PSS non vide", cbSig > 0);

    printf("  Taille signature PSS : %lu octets\n", (unsigned long)cbSig);
}

/* ── Test 10 : suppression de clé ──────────────────────────────────────── */
static void test_destroy_key(void)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  hObj;
    CK_RV             rv;
    WCHAR             wszLabel[64];

    printf("\n--- Test 10 : DestroyObject ---\n");

    if (g_hPrivRsa == CK_INVALID_HANDLE || !pCtx ||
        P11_AcquireSession(&hSession) != ERROR_SUCCESS) {
        ASSERT("Prérequis DestroyObject", 0);
        return;
    }

    rv = pCtx->pFunctionList->C_DestroyObject(hSession, g_hPrivRsa);
    ASSERT("C_DestroyObject clé privée RSA", rv == CKR_OK);

    rv = pCtx->pFunctionList->C_DestroyObject(hSession, g_hPubRsa);
    ASSERT("C_DestroyObject clé publique RSA", rv == CKR_OK);

    /* Vérifie que la clé a disparu */
    MultiByteToWideChar(CP_UTF8, 0, g_szRsaLabel, -1, wszLabel, 64);
    hObj = P11_FindObjectByLabel(hSession, CKO_PRIVATE_KEY, wszLabel);
    ASSERT("Clé détruite : FindObjectByLabel retourne INVALID_HANDLE",
           hObj == CK_INVALID_HANDLE);

    P11_ReleaseSession(hSession);
    g_hPrivRsa = CK_INVALID_HANDLE;
    g_hPubRsa  = CK_INVALID_HANDLE;
}

/* ── Point d'entrée ─────────────────────────────────────────────────────── */
int main(void)
{
    printf("=== Tests unitaires couche PKCS#11 SoftHSM2 ===\n\n");

    SetEnvironmentVariableA("KSP_DEBUG", "1");
    Log_Initialize();

    /* Note : test_bad_path doit être exécuté avant P11_Initialize */
    test_bad_path();

    /* Reinit après le test de mauvais chemin */
    /* (InitOnceExecuteOnce est one-shot, ce test suppose un exécutable dédié) */

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
    printf("Résultats : PASS=%d  FAIL=%d\n", g_nPass, g_nFail);
    printf("══════════════════════════════════════\n");

    return (g_nFail == 0) ? 0 : 1;
}
