/* test_oaep_params.c — Phase 2 unit tests
 * Covers P11_MapHashAlg and P11_BuildOaepParams: the full OAEP hash range
 * (SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512), label pass-through and
 * rejection of unsupported hashes.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <wchar.h>

int main(void)
{
    SECURITY_STATUS          ss;
    CK_MECHANISM_TYPE        hashMech;
    CK_ULONG                 mgf;
    CK_RSA_PKCS_OAEP_PARAMS  params;
    BCRYPT_OAEP_PADDING_INFO oaep;

    /* ── Suite 1 : P11_MapHashAlg — every supported hash ────────────────── */
    TEST_SUITE("P11_MapHashAlg — supported hashes");

    ss = P11_MapHashAlg(BCRYPT_SHA1_ALGORITHM, &hashMech, &mgf);
    ASSERT_OK("SHA-1 accepted", ss);
    ASSERT_EQ("SHA-1 → CKM_SHA_1",      hashMech, (CK_MECHANISM_TYPE)CKM_SHA_1);
    ASSERT_EQ("SHA-1 → CKG_MGF1_SHA1",  mgf,      (CK_ULONG)CKG_MGF1_SHA1);

    ss = P11_MapHashAlg(BCRYPT_SHA224_ALGORITHM, &hashMech, &mgf);
    ASSERT_OK("SHA-224 accepted", ss);
    ASSERT_EQ("SHA-224 → CKM_SHA224",     hashMech, (CK_MECHANISM_TYPE)CKM_SHA224);
    ASSERT_EQ("SHA-224 → CKG_MGF1_SHA224", mgf,     (CK_ULONG)CKG_MGF1_SHA224);

    ss = P11_MapHashAlg(BCRYPT_SHA256_ALGORITHM, &hashMech, &mgf);
    ASSERT_OK("SHA-256 accepted", ss);
    ASSERT_EQ("SHA-256 → CKM_SHA256",      hashMech, (CK_MECHANISM_TYPE)CKM_SHA256);
    ASSERT_EQ("SHA-256 → CKG_MGF1_SHA256", mgf,      (CK_ULONG)CKG_MGF1_SHA256);

    ss = P11_MapHashAlg(BCRYPT_SHA384_ALGORITHM, &hashMech, &mgf);
    ASSERT_OK("SHA-384 accepted", ss);
    ASSERT_EQ("SHA-384 → CKM_SHA384",      hashMech, (CK_MECHANISM_TYPE)CKM_SHA384);
    ASSERT_EQ("SHA-384 → CKG_MGF1_SHA384", mgf,      (CK_ULONG)CKG_MGF1_SHA384);

    ss = P11_MapHashAlg(BCRYPT_SHA512_ALGORITHM, &hashMech, &mgf);
    ASSERT_OK("SHA-512 accepted", ss);
    ASSERT_EQ("SHA-512 → CKM_SHA512",      hashMech, (CK_MECHANISM_TYPE)CKM_SHA512);
    ASSERT_EQ("SHA-512 → CKG_MGF1_SHA512", mgf,      (CK_ULONG)CKG_MGF1_SHA512);

    /* ── Suite 2 : P11_MapHashAlg — rejections ──────────────────────────── */
    TEST_SUITE("P11_MapHashAlg — rejections");

    ss = P11_MapHashAlg(L"MD5", &hashMech, &mgf);
    ASSERT_EQ("MD5 → NTE_NOT_SUPPORTED", ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    ss = P11_MapHashAlg(L"SHA3-256", &hashMech, &mgf);
    ASSERT_EQ("SHA3-256 → NTE_NOT_SUPPORTED", ss,
              (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    ss = P11_MapHashAlg(L"", &hashMech, &mgf);
    ASSERT_EQ("Empty name → NTE_NOT_SUPPORTED", ss,
              (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    ss = P11_MapHashAlg(NULL, &hashMech, &mgf);
    ASSERT_EQ("NULL name → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = P11_MapHashAlg(BCRYPT_SHA256_ALGORITHM, NULL, &mgf);
    ASSERT_EQ("NULL out mech → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ss = P11_MapHashAlg(BCRYPT_SHA256_ALGORITHM, &hashMech, NULL);
    ASSERT_EQ("NULL out mgf → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 3 : P11_BuildOaepParams — hash selection ─────────────────── */
    TEST_SUITE("P11_BuildOaepParams — hash selection");

    oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    oaep.pbLabel  = NULL;
    oaep.cbLabel  = 0;
    ss = P11_BuildOaepParams(&oaep, &params);
    ASSERT_OK("SHA-256 OAEP built", ss);
    ASSERT_EQ("hashAlg = CKM_SHA256", params.hashAlg,
              (CK_MECHANISM_TYPE)CKM_SHA256);
    ASSERT_EQ("mgf = CKG_MGF1_SHA256", params.mgf, (CK_ULONG)CKG_MGF1_SHA256);
    ASSERT_EQ("source = CKZ_DATA_SPECIFIED", params.source,
              (CK_ULONG)CKZ_DATA_SPECIFIED);
    ASSERT_NULL("No label → pSourceData NULL", params.pSourceData);
    ASSERT_EQ("No label → ulSourceDataLen 0", params.ulSourceDataLen,
              (CK_ULONG)0);

    oaep.pszAlgId = BCRYPT_SHA384_ALGORITHM;
    ss = P11_BuildOaepParams(&oaep, &params);
    ASSERT_OK("SHA-384 OAEP built", ss);
    ASSERT_EQ("hashAlg = CKM_SHA384", params.hashAlg,
              (CK_MECHANISM_TYPE)CKM_SHA384);
    ASSERT_EQ("mgf = CKG_MGF1_SHA384", params.mgf, (CK_ULONG)CKG_MGF1_SHA384);

    oaep.pszAlgId = BCRYPT_SHA512_ALGORITHM;
    ss = P11_BuildOaepParams(&oaep, &params);
    ASSERT_OK("SHA-512 OAEP built", ss);
    ASSERT_EQ("hashAlg = CKM_SHA512", params.hashAlg,
              (CK_MECHANISM_TYPE)CKM_SHA512);
    ASSERT_EQ("mgf = CKG_MGF1_SHA512", params.mgf, (CK_ULONG)CKG_MGF1_SHA512);

    oaep.pszAlgId = BCRYPT_SHA224_ALGORITHM;
    ss = P11_BuildOaepParams(&oaep, &params);
    ASSERT_OK("SHA-224 OAEP built", ss);
    ASSERT_EQ("hashAlg = CKM_SHA224", params.hashAlg,
              (CK_MECHANISM_TYPE)CKM_SHA224);

    oaep.pszAlgId = BCRYPT_SHA1_ALGORITHM;
    ss = P11_BuildOaepParams(&oaep, &params);
    ASSERT_OK("SHA-1 OAEP built", ss);
    ASSERT_EQ("hashAlg = CKM_SHA_1", params.hashAlg,
              (CK_MECHANISM_TYPE)CKM_SHA_1);

    /* ── Suite 4 : P11_BuildOaepParams — defaults and labels ────────────── */
    TEST_SUITE("P11_BuildOaepParams — defaults and labels");

    ss = P11_BuildOaepParams(NULL, &params);
    ASSERT_OK("NULL padding info accepted", ss);
    ASSERT_EQ("NULL info defaults to SHA-1", params.hashAlg,
              (CK_MECHANISM_TYPE)CKM_SHA_1);
    ASSERT_EQ("NULL info defaults to MGF1-SHA1", params.mgf,
              (CK_ULONG)CKG_MGF1_SHA1);

    oaep.pszAlgId = NULL;
    oaep.pbLabel  = NULL;
    oaep.cbLabel  = 0;
    ss = P11_BuildOaepParams(&oaep, &params);
    ASSERT_OK("NULL algId accepted", ss);
    ASSERT_EQ("NULL algId defaults to SHA-1", params.hashAlg,
              (CK_MECHANISM_TYPE)CKM_SHA_1);

    {
        BYTE label[] = { 0x01, 0x02, 0x03, 0x04 };
        oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        oaep.pbLabel  = label;
        oaep.cbLabel  = sizeof(label);
        ss = P11_BuildOaepParams(&oaep, &params);
        ASSERT_OK("Labelled OAEP built", ss);
        ASSERT_EQ("Label passed through", params.pSourceData, (void *)label);
        ASSERT_EQ("Label length passed through", params.ulSourceDataLen,
                  (CK_ULONG)sizeof(label));
    }

    /* A zero-length label must be treated as absent */
    {
        BYTE label[] = { 0xFF };
        oaep.pbLabel = label;
        oaep.cbLabel = 0;
        ss = P11_BuildOaepParams(&oaep, &params);
        ASSERT_OK("Zero-length label accepted", ss);
        ASSERT_NULL("Zero-length label → pSourceData NULL", params.pSourceData);
    }

    /* ── Suite 5 : P11_BuildOaepParams — errors ─────────────────────────── */
    TEST_SUITE("P11_BuildOaepParams — errors");

    oaep.pszAlgId = L"MD5";
    oaep.pbLabel  = NULL;
    oaep.cbLabel  = 0;
    ss = P11_BuildOaepParams(&oaep, &params);
    ASSERT_EQ("Unsupported hash → NTE_NOT_SUPPORTED", ss,
              (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    ss = P11_BuildOaepParams(&oaep, NULL);
    ASSERT_EQ("NULL params → NTE_INVALID_PARAMETER", ss,
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    TEST_REPORT();
    TEST_EXIT();
}
