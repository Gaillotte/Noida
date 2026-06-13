/* test_mechanism_resolve.c — Couverture complète de P11_ResolveMechanism()
 * Toutes les combinaisons algorithme × flags.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "test_framework.h"

SECURITY_STATUS P11_ResolveMechanism(
    LPCWSTR pszAlgId, DWORD dwFlags,
    CK_MECHANISM *pMechanism, CK_RSA_PKCS_PSS_PARAMS *pPssParams);

int main(void)
{
    CK_MECHANISM          mech;
    CK_RSA_PKCS_PSS_PARAMS pss;
    SECURITY_STATUS        ss;

    /* ── Suite 1 : RSA PKCS1 ─────────────────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — RSA PKCS1");

    ss = P11_ResolveMechanism(L"RSA", NCRYPT_PAD_PKCS1_FLAG, &mech, &pss);
    ASSERT_OK("RSA + PKCS1_FLAG → OK", ss);
    ASSERT_EQ("Mécanisme = CKM_RSA_PKCS", mech.mechanism, (CK_ULONG)CKM_RSA_PKCS);
    ASSERT_NULL("Pas de paramètre", mech.pParameter);
    ASSERT_EQ("Longueur paramètre = 0", mech.ulParameterLen, 0U);

    /* Sans flag → PKCS1 par défaut */
    ss = P11_ResolveMechanism(L"RSA", 0, &mech, &pss);
    ASSERT_OK("RSA + flags=0 → PKCS1 par défaut", ss);
    ASSERT_EQ("Mécanisme = CKM_RSA_PKCS (défaut)", mech.mechanism, (CK_ULONG)CKM_RSA_PKCS);

    /* ── Suite 2 : RSA PSS ───────────────────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — RSA PSS");

    ss = P11_ResolveMechanism(L"RSA", NCRYPT_PAD_PSS_FLAG, &mech, &pss);
    ASSERT_OK("RSA + PSS_FLAG → OK", ss);
    ASSERT_EQ("Mécanisme = CKM_RSA_PKCS_PSS", mech.mechanism, (CK_ULONG)CKM_RSA_PKCS_PSS);
    ASSERT_NOTNULL("Paramètre PSS non NULL", mech.pParameter);
    ASSERT_EQ("Longueur paramètre = sizeof pss",
        mech.ulParameterLen, (CK_ULONG)sizeof(CK_RSA_PKCS_PSS_PARAMS));
    ASSERT_EQ("hashAlg = CKM_SHA256 (défaut PSS)",
        pss.hashAlg, (CK_ULONG)CKM_SHA256);
    ASSERT_EQ("mgf = CKG_MGF1_SHA256 (défaut PSS)",
        pss.mgf, (CK_ULONG)CKG_MGF1_SHA256);
    ASSERT_EQ("sLen = 32 (défaut PSS)", pss.sLen, 32U);

    /* PSS sans buffer pPssParams (NULL) : mécanisme défini mais paramètres non remplis */
    ss = P11_ResolveMechanism(L"RSA", NCRYPT_PAD_PSS_FLAG, &mech, NULL);
    ASSERT_OK("RSA + PSS + pPssParams=NULL → OK", ss);
    ASSERT_EQ("CKM_RSA_PKCS_PSS même sans pPssParams",
        mech.mechanism, (CK_ULONG)CKM_RSA_PKCS_PSS);

    /* ── Suite 3 : ECDSA ─────────────────────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — ECDSA");

    ss = P11_ResolveMechanism(L"ECDSA_P256", 0, &mech, &pss);
    ASSERT_OK("ECDSA_P256 → OK", ss);
    ASSERT_EQ("Mécanisme = CKM_ECDSA", mech.mechanism, (CK_ULONG)CKM_ECDSA);
    ASSERT_NULL("Pas de paramètre ECDSA", mech.pParameter);

    ss = P11_ResolveMechanism(L"ECDSA_P384", 0, &mech, &pss);
    ASSERT_OK("ECDSA_P384 → OK", ss);
    ASSERT_EQ("CKM_ECDSA pour P-384", mech.mechanism, (CK_ULONG)CKM_ECDSA);

    /* ECDSA insensible à la casse */
    ss = P11_ResolveMechanism(L"ecdsa_p256", 0, &mech, &pss);
    ASSERT_OK("ecdsa_p256 (minuscule) → OK", ss);

    /* ── Suite 4 : Algorithme inconnu ──────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — algorithmes non supportés");

    ss = P11_ResolveMechanism(L"AES", 0, &mech, &pss);
    ASSERT_EQ("AES → NTE_BAD_ALGID", ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    ss = P11_ResolveMechanism(L"DH", 0, &mech, &pss);
    ASSERT_EQ("DH → NTE_BAD_ALGID", ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    ss = P11_ResolveMechanism(L"", 0, &mech, &pss);
    ASSERT_EQ("Chaîne vide → NTE_BAD_ALGID", ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    /* ── Suite 5 : Paramètres invalides ─────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — paramètres invalides");

    ss = P11_ResolveMechanism(NULL, 0, &mech, &pss);
    ASSERT_EQ("pszAlgId=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = P11_ResolveMechanism(L"RSA", NCRYPT_PAD_PKCS1_FLAG, NULL, &pss);
    ASSERT_EQ("pMechanism=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = P11_ResolveMechanism(NULL, 0, NULL, NULL);
    ASSERT_EQ("Tous NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 6 : Combinaisons flags multiples ──────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — flags combinés");

    /* PSS a priorité sur PKCS1 si les deux sont présents */
    ss = P11_ResolveMechanism(L"RSA",
        NCRYPT_PAD_PSS_FLAG | NCRYPT_PAD_PKCS1_FLAG, &mech, &pss);
    ASSERT_OK("PSS | PKCS1 → OK", ss);
    ASSERT_EQ("PSS | PKCS1 → CKM_RSA_PKCS_PSS (PSS prioritaire)",
        mech.mechanism, (CK_ULONG)CKM_RSA_PKCS_PSS);

    TEST_REPORT();
    TEST_EXIT();
}
