/* test_mechanism_resolve.c — Full coverage of P11_ResolveMechanism()
 * All algorithm × flags combinations.
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
    ASSERT_EQ("Mechanism = CKM_RSA_PKCS", mech.mechanism, (CK_ULONG)CKM_RSA_PKCS);
    ASSERT_NULL("No parameter", mech.pParameter);
    ASSERT_EQ("Parameter length = 0", mech.ulParameterLen, 0U);

    /* No flag → PKCS1 by default */
    ss = P11_ResolveMechanism(L"RSA", 0, &mech, &pss);
    ASSERT_OK("RSA + flags=0 → PKCS1 by default", ss);
    ASSERT_EQ("Mechanism = CKM_RSA_PKCS (default)", mech.mechanism, (CK_ULONG)CKM_RSA_PKCS);

    /* ── Suite 2 : RSA PSS ───────────────────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — RSA PSS");

    ss = P11_ResolveMechanism(L"RSA", NCRYPT_PAD_PSS_FLAG, &mech, &pss);
    ASSERT_OK("RSA + PSS_FLAG → OK", ss);
    ASSERT_EQ("Mechanism = CKM_RSA_PKCS_PSS", mech.mechanism, (CK_ULONG)CKM_RSA_PKCS_PSS);
    ASSERT_NOTNULL("Non-NULL PSS parameter", mech.pParameter);
    ASSERT_EQ("Parameter length = sizeof pss",
        mech.ulParameterLen, (CK_ULONG)sizeof(CK_RSA_PKCS_PSS_PARAMS));
    ASSERT_EQ("hashAlg = CKM_SHA256 (PSS default)",
        pss.hashAlg, (CK_ULONG)CKM_SHA256);
    ASSERT_EQ("mgf = CKG_MGF1_SHA256 (PSS default)",
        pss.mgf, (CK_ULONG)CKG_MGF1_SHA256);
    ASSERT_EQ("sLen = 32 (PSS default)", pss.sLen, 32U);

    /* PSS without pPssParams buffer (NULL): mechanism set but parameters not filled */
    ss = P11_ResolveMechanism(L"RSA", NCRYPT_PAD_PSS_FLAG, &mech, NULL);
    ASSERT_OK("RSA + PSS + pPssParams=NULL → OK", ss);
    ASSERT_EQ("CKM_RSA_PKCS_PSS even without pPssParams",
        mech.mechanism, (CK_ULONG)CKM_RSA_PKCS_PSS);

    /* ── Suite 3 : ECDSA ─────────────────────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — ECDSA");

    ss = P11_ResolveMechanism(L"ECDSA_P256", 0, &mech, &pss);
    ASSERT_OK("ECDSA_P256 → OK", ss);
    ASSERT_EQ("Mechanism = CKM_ECDSA", mech.mechanism, (CK_ULONG)CKM_ECDSA);
    ASSERT_NULL("No ECDSA parameter", mech.pParameter);

    ss = P11_ResolveMechanism(L"ECDSA_P384", 0, &mech, &pss);
    ASSERT_OK("ECDSA_P384 → OK", ss);
    ASSERT_EQ("CKM_ECDSA for P-384", mech.mechanism, (CK_ULONG)CKM_ECDSA);

    /* ECDSA case-insensitive */
    ss = P11_ResolveMechanism(L"ecdsa_p256", 0, &mech, &pss);
    ASSERT_OK("ecdsa_p256 (lowercase) → OK", ss);

    /* ── Suite 4 : Algorithme inconnu ──────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — unsupported algorithms");

    ss = P11_ResolveMechanism(L"AES", 0, &mech, &pss);
    ASSERT_EQ("AES → NTE_BAD_ALGID", ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    ss = P11_ResolveMechanism(L"DH", 0, &mech, &pss);
    ASSERT_EQ("DH → NTE_BAD_ALGID", ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    ss = P11_ResolveMechanism(L"", 0, &mech, &pss);
    ASSERT_EQ("Empty string → NTE_BAD_ALGID", ss, (SECURITY_STATUS)NTE_BAD_ALGID);

    /* ── Suite 5 : Paramètres invalides ─────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — invalid parameters");

    ss = P11_ResolveMechanism(NULL, 0, &mech, &pss);
    ASSERT_EQ("pszAlgId=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = P11_ResolveMechanism(L"RSA", NCRYPT_PAD_PKCS1_FLAG, NULL, &pss);
    ASSERT_EQ("pMechanism=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = P11_ResolveMechanism(NULL, 0, NULL, NULL);
    ASSERT_EQ("All NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 6 : Combinaisons flags multiples ──────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — combined flags");

    /* PSS takes priority over PKCS1 when both are present */
    ss = P11_ResolveMechanism(L"RSA",
        NCRYPT_PAD_PSS_FLAG | NCRYPT_PAD_PKCS1_FLAG, &mech, &pss);
    ASSERT_OK("PSS | PKCS1 → OK", ss);
    ASSERT_EQ("PSS | PKCS1 → CKM_RSA_PKCS_PSS (PSS takes priority)",
        mech.mechanism, (CK_ULONG)CKM_RSA_PKCS_PSS);

    TEST_REPORT();
    TEST_EXIT();
}
