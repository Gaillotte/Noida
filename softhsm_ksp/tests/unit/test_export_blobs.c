/* test_export_blobs.c — Coverage of P11_ExportRsaPublicKey and P11_ExportEcPublicKey
 * Uses the PKCS#11 mock to control returned attributes.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "test_framework.h"

/* P11 context stubs to bypass the singleton */
typedef struct { void *hModule; CK_FUNCTION_LIST_PTR pFunctionList;
                 CK_SLOT_ID slotId; BOOL bInitialized; } P11_CONTEXT;

static P11_CONTEXT g_testCtx;
P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }

/* Functions under test */
SECURITY_STATUS P11_ExportRsaPublicKey(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hPubKey, BYTE **ppBlob, DWORD *pcbBlob);
SECURITY_STATUS P11_ExportEcPublicKey(CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hPubKey, BYTE **ppBlob, DWORD *pcbBlob);
CK_OBJECT_HANDLE P11_FindObjectByLabel(CK_SESSION_HANDLE hSession,
    CK_OBJECT_CLASS ulClass, LPCWSTR pszLabel);
CK_RV P11_GetUlongAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
    CK_ATTRIBUTE_TYPE attrType, CK_ULONG *pulValue);

void *KSP_Alloc(SIZE_T n);
void *KSP_AllocZero(SIZE_T n);
void  KSP_Free(void *p);

/* Log stubs */
void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }

int main(void)
{
    BYTE    *pbBlob = NULL;
    DWORD    cbBlob = 0;
    SECURITY_STATUS ss;

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;

    /* ── Suite 1: Nominal RSA public key export ─────────────────────────── */
    TEST_SUITE("P11_ExportRsaPublicKey — nominal cases");

    /* RSA 2048 bits (modulus=256 bytes, exponent=3 bytes) */
    ss = P11_ExportRsaPublicKey(0xBEEF, 0x05, &pbBlob, &cbBlob);
    ASSERT_OK("Export RSA 2048 → ERROR_SUCCESS", ss);
    ASSERT_NOTNULL("pbBlob non-NULL", pbBlob);

    DWORD cbExpected = (DWORD)(sizeof(BCRYPT_RSAKEY_BLOB) + 3 + 256);
    ASSERT_EQ("Taille blob correcte", cbBlob, cbExpected);

    BCRYPT_RSAKEY_BLOB *pHdr = (BCRYPT_RSAKEY_BLOB *)pbBlob;
    ASSERT_EQ("Magic = RSAPUBLIC_MAGIC",
        pHdr->Magic, (DWORD)BCRYPT_RSAPUBLIC_MAGIC);
    ASSERT_EQ("BitLength = 2048", pHdr->BitLength, 2048U);
    ASSERT_EQ("cbPublicExp = 3",  pHdr->cbPublicExp, 3U);
    ASSERT_EQ("cbModulus = 256",  pHdr->cbModulus, 256U);
    ASSERT_EQ("cbPrime1 = 0",     pHdr->cbPrime1, 0U);
    ASSERT_EQ("cbPrime2 = 0",     pHdr->cbPrime2, 0U);

    /* Verify the exponent (01 00 01 = 65537) */
    BYTE *pbExp = pbBlob + sizeof(BCRYPT_RSAKEY_BLOB);
    ASSERT_EQ("Exp[0] = 0x01", pbExp[0], 0x01);
    ASSERT_EQ("Exp[1] = 0x00", pbExp[1], 0x00);
    ASSERT_EQ("Exp[2] = 0x01", pbExp[2], 0x01);

    KSP_Free(pbBlob); pbBlob = NULL; cbBlob = 0;

    /* ── Suite 2: RSA export with injected attribute errors ─────────── */
    TEST_SUITE("P11_ExportRsaPublicKey — injected errors");

    P11Mock_GetConfig()->rv_GetAttributeValue = CKR_ATTRIBUTE_SENSITIVE;
    ss = P11_ExportRsaPublicKey(0xBEEF, 0x05, &pbBlob, &cbBlob);
    ASSERT_ERR("GetAttributeValue fails → error", ss);
    ASSERT_NULL("pbBlob NULL on error", pbBlob);
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    /* ── Suite 3: Nominal P-256 EC public key export ───────────────── */
    TEST_SUITE("P11_ExportEcPublicKey — P-256 nominal case");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    ss = P11_ExportEcPublicKey(0xBEEF, 0x05, &pbBlob, &cbBlob);
    ASSERT_OK("Export EC P-256 → ERROR_SUCCESS", ss);
    ASSERT_NOTNULL("pbBlob EC non-NULL", pbBlob);

    DWORD cbExpectedEc = (DWORD)(sizeof(BCRYPT_ECCKEY_BLOB) + 64);
    ASSERT_EQ("Taille blob EC correcte", cbBlob, cbExpectedEc);

    BCRYPT_ECCKEY_BLOB *pEcc = (BCRYPT_ECCKEY_BLOB *)pbBlob;
    ASSERT_EQ("Magic = ECDSA_P256",
        pEcc->dwMagic, (DWORD)BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
    ASSERT_EQ("cbKey = 32", pEcc->cbKey, 32U);

    /* Verify Qx (first 32 bytes after header) */
    BYTE *pbQx = pbBlob + sizeof(BCRYPT_ECCKEY_BLOB);
    ASSERT_EQ("Qx[0] = 0xAA (first dummy byte)", pbQx[0], 0xAA);

    KSP_Free(pbBlob); pbBlob = NULL; cbBlob = 0;

    /* ── Suite 4: EC P-384 export ──────────────────────────────────────── */
    TEST_SUITE("P11_ExportEcPublicKey — P-384");

    static const char oidP384[] = "\x06\x05\x2b\x81\x04\x00\x22";
    /* Dummy P-384 point: DER wrapper + 04 + Qx(48) + Qy(48) = 2 + 97 = 99 */
    static char ecPt384[99];
    ecPt384[0] = 0x04; ecPt384[1] = 0x61; /* DER wrapper */
    ecPt384[2] = 0x04;                     /* uncompressed */
    memset(ecPt384 + 3, 0xBB, 96);         /* Dummy Qx + Qy */

    P11Mock_GetConfig()->pbEcParams = oidP384;
    P11Mock_GetConfig()->cbEcParams = 7;
    P11Mock_GetConfig()->pbEcPoint  = ecPt384;
    P11Mock_GetConfig()->cbEcPoint  = 99;

    ss = P11_ExportEcPublicKey(0xBEEF, 0x05, &pbBlob, &cbBlob);
    ASSERT_OK("Export EC P-384 → ERROR_SUCCESS", ss);
    ASSERT_NOTNULL("pbBlob P-384 non-NULL", pbBlob);
    ASSERT_EQ("P-384 blob size = 8 + 96",
        cbBlob, (DWORD)(sizeof(BCRYPT_ECCKEY_BLOB) + 96));

    BCRYPT_ECCKEY_BLOB *pEcc384 = (BCRYPT_ECCKEY_BLOB *)pbBlob;
    ASSERT_EQ("Magic = ECDSA_P384",
        pEcc384->dwMagic, (DWORD)BCRYPT_ECDSA_PUBLIC_P384_MAGIC);
    ASSERT_EQ("cbKey = 48", pEcc384->cbKey, 48U);

    KSP_Free(pbBlob); pbBlob = NULL; cbBlob = 0;

    /* ── Suite 5: EC export with injected errors ────────────────────────── */
    TEST_SUITE("P11_ExportEcPublicKey — errors");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    /* Compressed point (starts with 0x02) → rejected */
    static char badPoint[67];
    badPoint[0] = 0x04; badPoint[1] = 0x41;
    badPoint[2] = 0x02; /* 0x02 = compressed, not 0x04 */
    P11Mock_GetConfig()->pbEcPoint = badPoint;
    P11Mock_GetConfig()->cbEcPoint = 67;

    ss = P11_ExportEcPublicKey(0xBEEF, 0x05, &pbBlob, &cbBlob);
    ASSERT_ERR("Compressed EC point → NTE_BAD_KEY", ss);
    ASSERT_NULL("pbBlob NULL on EC error", pbBlob);

    /* GetAttributeValue fails */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_GetAttributeValue = CKR_OBJECT_HANDLE_INVALID;
    ss = P11_ExportEcPublicKey(0xBEEF, 0x05, &pbBlob, &cbBlob);
    ASSERT_ERR("GetAttributeValue fails (EC) → error", ss);

    /* ── Suite 6: P11_FindObjectByLabel ───────────────────────────────────── */
    TEST_SUITE("P11_FindObjectByLabel");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;

    /* Existing label → valid handle */
    CK_OBJECT_HANDLE hFound;
    hFound = P11_FindObjectByLabel(0xBEEF, CKO_PRIVATE_KEY, L"TestKey");
    ASSERT("FindObjectByLabel → valid handle",
           hFound != CK_INVALID_HANDLE);

    /* pszLabel = NULL → CK_INVALID_HANDLE */
    hFound = P11_FindObjectByLabel(0xBEEF, CKO_PRIVATE_KEY, NULL);
    ASSERT_EQ("FindObjectByLabel(NULL) → CK_INVALID_HANDLE",
              hFound, CK_INVALID_HANDLE);

    /* No key found → CK_INVALID_HANDLE */
    P11Mock_GetConfig()->nKeyObjects = 0;
    hFound = P11_FindObjectByLabel(0xBEEF, CKO_PRIVATE_KEY, L"Absent");
    ASSERT_EQ("FindObjectByLabel(absent) → CK_INVALID_HANDLE",
              hFound, CK_INVALID_HANDLE);

    /* FindObjectsInit fails → CK_INVALID_HANDLE */
    P11Mock_GetConfig()->nKeyObjects   = 1;
    P11Mock_GetConfig()->rv_FindObjectsInit = CKR_DEVICE_ERROR;
    hFound = P11_FindObjectByLabel(0xBEEF, CKO_PRIVATE_KEY, L"TestKey");
    ASSERT_EQ("FindObjectsInit fails → CK_INVALID_HANDLE",
              hFound, CK_INVALID_HANDLE);

    /* FindObjects fails → CK_INVALID_HANDLE */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->nKeyObjects = 1;
    P11Mock_GetConfig()->rv_FindObjects = CKR_DEVICE_ERROR;
    hFound = P11_FindObjectByLabel(0xBEEF, CKO_PRIVATE_KEY, L"TestKey");
    ASSERT_EQ("FindObjects fails → CK_INVALID_HANDLE",
              hFound, CK_INVALID_HANDLE);

    /* ── Suite 7: P11_GetUlongAttr ─────────────────────────────────────────── */
    TEST_SUITE("P11_GetUlongAttr");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->ulKeyType = CKK_RSA;
    P11Mock_GetConfig()->ulModBits = 4096;

    CK_ULONG ulVal = 0;
    CK_RV rv;

    /* CKA_KEY_TYPE → CKK_RSA */
    rv = P11_GetUlongAttr(0xBEEF, 0x10, CKA_KEY_TYPE, &ulVal);
    ASSERT_EQ("GetUlongAttr CKA_KEY_TYPE → CKR_OK", rv, (CK_RV)CKR_OK);
    ASSERT_EQ("ulVal = CKK_RSA", ulVal, (CK_ULONG)CKK_RSA);

    /* CKA_MODULUS_BITS → 4096 */
    rv = P11_GetUlongAttr(0xBEEF, 0x10, CKA_MODULUS_BITS, &ulVal);
    ASSERT_EQ("GetUlongAttr CKA_MODULUS_BITS → CKR_OK", rv, (CK_RV)CKR_OK);
    ASSERT_EQ("ulVal = 4096", ulVal, (CK_ULONG)4096);

    /* GetAttributeValue fails */
    P11Mock_GetConfig()->rv_GetAttributeValue = CKR_SESSION_HANDLE_INVALID;
    rv = P11_GetUlongAttr(0xBEEF, 0x10, CKA_KEY_TYPE, &ulVal);
    ASSERT_NEQ("GetUlongAttr (error) → != CKR_OK", rv, (CK_RV)CKR_OK);

    TEST_REPORT();
    TEST_EXIT();
}
