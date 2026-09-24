/* test_mechanism_resolve.c — Full coverage of P11_ResolveMechanism()
 * All algorithm × flags combinations.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <string.h>

SECURITY_STATUS P11_ResolveMechanism(
    LPCWSTR pszAlgId, DWORD dwFlags,
    CK_MECHANISM *pMechanism, CK_RSA_PKCS_PSS_PARAMS *pPssParams);
DWORD       P11_EcCoordSize(LPCWSTR pszAlgId);
const char *P11_GetCurveOid(LPCWSTR pszAlgId, CK_ULONG *pcbOid);
LPCWSTR     P11_CurveNameToAlgId(LPCWSTR pszCurveName, BOOL bAgreement);
LPCWSTR     P11_CurveAlgFromOid(const BYTE *pbOid, DWORD cbOid,
                                BOOL bDerive, DWORD *pdwBits);

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


    /* ── Gaps ECDSA-05 and HMAC-02 ──────────────────────────────────────── */
    TEST_SUITE("P11_ResolveMechanism — secp256k1 and HMAC-SHA224");

    ss = P11_ResolveMechanism(L"ECDSA_SECP256K1", 0, &mech, NULL);
    ASSERT_OK("secp256k1 resolves", ss);
    ASSERT_EQ("secp256k1 -> CKM_ECDSA", mech.mechanism,
              (CK_MECHANISM_TYPE)CKM_ECDSA);
    ASSERT_NULL("secp256k1 takes no mechanism parameter", mech.pParameter);

    ss = P11_ResolveMechanism(L"HMAC_SHA224", 0, &mech, NULL);
    ASSERT_OK("HMAC-SHA224 resolves", ss);
    ASSERT_EQ("HMAC-SHA224 -> CKM_SHA224_HMAC", mech.mechanism,
              (CK_MECHANISM_TYPE)CKM_SHA224_HMAC);

    /* Still distinct from the neighbouring HMAC mechanisms */
    ss = P11_ResolveMechanism(L"HMAC_SHA256", 0, &mech, NULL);
    ASSERT_EQ("HMAC-SHA256 unaffected", mech.mechanism,
              (CK_MECHANISM_TYPE)CKM_SHA256_HMAC);

    /* ── Brainpool curves (ECDSA-04) ──────────────────────────────────── */
    TEST_SUITE("Brainpool curves");
    {
        CK_MECHANISM mech;
        CK_ULONG     cbOid = 0;
        const char  *pbOid;

        memset(&mech, 0, sizeof mech);
        ASSERT_OK("brainpoolP256r1 resolves",
            P11_ResolveMechanism(ALG_ECDSA_BP256, 0, &mech, NULL));
        ASSERT_EQ("→ CKM_ECDSA", (CK_ULONG)mech.mechanism,
                  (CK_ULONG)CKM_ECDSA);
        ASSERT_OK("brainpoolP384r1 resolves",
            P11_ResolveMechanism(ALG_ECDSA_BP384, 0, &mech, NULL));
        ASSERT_OK("brainpoolP512r1 resolves",
            P11_ResolveMechanism(ALG_ECDSA_BP512, 0, &mech, NULL));

        /* Coordinate sizes drive signature length, so a wrong one would
         * truncate every signature on that curve. */
        ASSERT_EQ("P256r1 coordinate is 32 bytes",
                  P11_EcCoordSize(ALG_ECDSA_BP256), 32U);
        ASSERT_EQ("P384r1 coordinate is 48 bytes",
                  P11_EcCoordSize(ALG_ECDSA_BP384), 48U);
        ASSERT_EQ("P512r1 coordinate is 64 bytes",
                  P11_EcCoordSize(ALG_ECDSA_BP512), 64U);

        /* OIDs taken from `openssl ecparam -outform DER`. All three are
         * 11 bytes and differ only in the final byte, so the full string
         * is compared — the same trap P-384 and P-521 pose. */
        pbOid = P11_GetCurveOid(ALG_ECDSA_BP256, &cbOid);
        ASSERT_NOTNULL("P256r1 has an OID", (void *)pbOid);
        ASSERT_EQ("  11 bytes", (CK_ULONG)cbOid, (CK_ULONG)11);
        ASSERT_EQ("  final byte 0x07", (CK_ULONG)(BYTE)pbOid[10], (CK_ULONG)0x07);

        pbOid = P11_GetCurveOid(ALG_ECDSA_BP384, &cbOid);
        ASSERT_EQ("P384r1 final byte 0x0B",
                  (CK_ULONG)(BYTE)pbOid[10], (CK_ULONG)0x0B);

        pbOid = P11_GetCurveOid(ALG_ECDSA_BP512, &cbOid);
        ASSERT_EQ("P512r1 final byte 0x0D",
                  (CK_ULONG)(BYTE)pbOid[10], (CK_ULONG)0x0D);

        /* The three must be distinct, not aliases of one another. */
        ASSERT("P256r1 and P384r1 differ",
               memcmp(P11_GetCurveOid(ALG_ECDSA_BP256, &cbOid),
                      P11_GetCurveOid(ALG_ECDSA_BP384, &cbOid), 11) != 0);
        ASSERT("P384r1 and P512r1 differ",
               memcmp(P11_GetCurveOid(ALG_ECDSA_BP384, &cbOid),
                      P11_GetCurveOid(ALG_ECDSA_BP512, &cbOid), 11) != 0);
    }

    /* ── CNG curve names → provider identifiers ───────────────────────── */
    TEST_SUITE("P11_CurveNameToAlgId");
    {
        /* A NIST curve is ECDSA or ECDH depending on which generic
         * algorithm the caller started from. */
        ASSERT_WSTR("nistP256 signing", 
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_NISTP256, FALSE),
            ALG_ECDSA_P256);
        ASSERT_WSTR("nistP256 agreement",
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_NISTP256, TRUE),
            ALG_ECDH_P256);
        ASSERT_WSTR("nistP384 agreement",
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_NISTP384, TRUE),
            ALG_ECDH_P384);
        ASSERT_WSTR("nistP521 signing",
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_NISTP521, FALSE),
            ALG_ECDSA_P521);

        ASSERT_WSTR("secp256k1 signing",
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_SECP256K1, FALSE),
            ALG_ECDSA_SECP256K1);
        ASSERT_WSTR("brainpoolP256r1",
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_BRAINPOOLP256R1, FALSE),
            ALG_ECDSA_BP256);
        ASSERT_WSTR("brainpoolP384r1",
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_BRAINPOOLP384R1, FALSE),
            ALG_ECDSA_BP384);
        ASSERT_WSTR("brainpoolP512r1",
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_BRAINPOOLP512R1, FALSE),
            ALG_ECDSA_BP512);
        ASSERT_WSTR("curve25519 agreement",
            P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_25519, TRUE),
            ALG_ECDH_X25519);

        /* Case-insensitive, because CNG spells one "secP256k1". */
        ASSERT_WSTR("Mixed case still matches",
            P11_CurveNameToAlgId(L"BrAiNpOoLp384R1", FALSE),
            ALG_ECDSA_BP384);

        /* A curve that cannot do what was asked returns NULL rather than
         * silently giving back something that can. */
        ASSERT_NULL("curve25519 cannot sign",
            (void *)P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_25519, FALSE));
        ASSERT_NULL("secp256k1 has no ECDH form here",
            (void *)P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_SECP256K1, TRUE));
        ASSERT_NULL("brainpool has no ECDH form here",
            (void *)P11_CurveNameToAlgId(BCRYPT_ECC_CURVE_BRAINPOOLP256R1, TRUE));

        ASSERT_NULL("Unknown curve",
            (void *)P11_CurveNameToAlgId(L"nistP192", FALSE));
        ASSERT_NULL("NULL name", (void *)P11_CurveNameToAlgId(NULL, FALSE));
    }

    /* ── Curve OID round trip ───────────────────────────────────────────── */
    TEST_SUITE("Curve OID round trip");

    /* Name -> OID -> name, for every curve the provider can generate.
     *
     * The two directions used to be separate hand-written chains and the
     * reverse one covered five of ten curves; the rest fell through to a
     * final else that named them P-384, so a reopened X25519, secp256k1 or
     * Brainpool key came back as something it was not. They now read one
     * table, and this asserts the property that makes that worth doing:
     * whatever goes out as an OID comes back as the same algorithm. */
    {
        struct { LPCWSTR szAlg; BOOL bDerive; DWORD dwBits; } aCurves[] = {
            { ALG_ECDSA_P256,      FALSE, 256 },
            { ALG_ECDSA_P384,      FALSE, 384 },
            { ALG_ECDSA_P521,      FALSE, 521 },
            { ALG_ECDH_P256,       TRUE,  256 },
            { ALG_ECDH_P384,       TRUE,  384 },
            { ALG_ECDH_P521,       TRUE,  521 },
            { ALG_ECDSA_SECP256K1, FALSE, 256 },
            { ALG_ECDSA_BP256,     FALSE, 256 },
            { ALG_ECDSA_BP384,     FALSE, 384 },
            { ALG_ECDSA_BP512,     FALSE, 512 },
            { ALG_EDDSA_ED25519,   FALSE, 255 },
            { ALG_EDDSA_ED448,     FALSE, 448 },
            { ALG_ECDH_X25519,     TRUE,  255 },
        };
        size_t i;

        for (i = 0; i < sizeof(aCurves) / sizeof(aCurves[0]); i++) {
            CK_ULONG    cbOid = 0;
            const char *pbOid = P11_GetCurveOid(aCurves[i].szAlg, &cbOid);
            DWORD       dwBits = 0;
            LPCWSTR     szBack;

            ASSERT("Every curve has an OID", pbOid != NULL && cbOid > 0);
            if (!pbOid)
                continue;

            szBack = P11_CurveAlgFromOid((const BYTE *)pbOid, (DWORD)cbOid,
                                         aCurves[i].bDerive, &dwBits);
            ASSERT("and the OID maps back to an algorithm", szBack != NULL);
            if (szBack) {
                ASSERT("and back to the SAME algorithm",
                       _wcsicmp(szBack, aCurves[i].szAlg) == 0);
                ASSERT("carrying the right key size",
                       dwBits == aCurves[i].dwBits);
            }
        }

        /* An OID the provider does not know must be refused, not guessed.
         * P-192, which this provider deliberately does not support. */
        {
            static const BYTE abP192[] =
                { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01 };
            DWORD dwBits = 0;
            ASSERT_NULL("An unknown curve OID is refused, not guessed",
                (void *)P11_CurveAlgFromOid(abP192, sizeof(abP192),
                                            FALSE, &dwBits));
        }
        {
            DWORD dwBits = 0;
            ASSERT_NULL("NULL OID",
                (void *)P11_CurveAlgFromOid(NULL, 5, FALSE, &dwBits));
            ASSERT_NULL("Zero-length OID",
                (void *)P11_CurveAlgFromOid((const BYTE *)"\x06", 0, FALSE,
                                            &dwBits));
        }
    }

    TEST_REPORT();
    TEST_EXIT();
}
