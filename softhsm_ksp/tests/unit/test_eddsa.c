/* test_eddsa.c — Phase 5 unit tests
 * Covers Ed25519 / Ed448 key generation, mechanism resolution, signing and
 * public key export, plus the curve-OID mapping shared with the NIST curves.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
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

/* Ed25519 public key: DER OCTET STRING wrapping 32 raw bytes */
static BYTE g_ed25519Point[34];
/* Ed448 public key: DER OCTET STRING wrapping 57 raw bytes */
static BYTE g_ed448Point[59];

static void InitPoints(void)
{
    memset(g_ed25519Point, 0xE2, sizeof g_ed25519Point);
    g_ed25519Point[0] = 0x04;   /* OCTET STRING */
    g_ed25519Point[1] = 0x20;   /* length 32 */

    memset(g_ed448Point, 0xE4, sizeof g_ed448Point);
    g_ed448Point[0] = 0x04;     /* OCTET STRING */
    g_ed448Point[1] = 0x39;     /* length 57 */
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE  hKey  = 0;
    SECURITY_STATUS    ss;
    CK_MECHANISM       mech;
    CK_ULONG           cbOid;
    const char        *pbOid;

    InitPoints();
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    if (ss != ERROR_SUCCESS) {
        printf("KSP_OpenProvider failed: 0x%08lX\n", (unsigned long)ss);
        return 1;
    }

    /* ── Suite 1 : algorithm classifiers ────────────────────────────────── */
    TEST_SUITE("EdDSA algorithm classifiers");

    ASSERT("Ed25519 recognised", KSP_IsEddsaAlg(ALG_EDDSA_ED25519));
    ASSERT("Ed448 recognised",   KSP_IsEddsaAlg(ALG_EDDSA_ED448));
    ASSERT("ECDSA P-256 is not EdDSA", !KSP_IsEddsaAlg(ALG_ECDSA_P256));
    ASSERT("RSA is not EdDSA",         !KSP_IsEddsaAlg(ALG_RSA));
    ASSERT("NULL is not EdDSA",        !KSP_IsEddsaAlg(NULL));
    ASSERT("Ed25519 is not symmetric", !KSP_IsSymmetricAlg(ALG_EDDSA_ED25519));
    ASSERT("Ed25519 is not ECDH",      !KSP_IsEcdhAlg(ALG_EDDSA_ED25519));

    /* ── Suite 2 : curve OID mapping ────────────────────────────────────── */
    TEST_SUITE("EdDSA curve OIDs");

    pbOid = P11_GetCurveOid(ALG_EDDSA_ED25519, &cbOid);
    ASSERT_NOTNULL("Ed25519 OID found", pbOid);
    ASSERT_EQ("Ed25519 OID length = 5", cbOid, (CK_ULONG)EC_OID_ED25519_LEN);
    ASSERT_MEM("Ed25519 OID bytes (1.3.101.112)",
               pbOid, EC_OID_ED25519, EC_OID_ED25519_LEN);

    pbOid = P11_GetCurveOid(ALG_EDDSA_ED448, &cbOid);
    ASSERT_NOTNULL("Ed448 OID found", pbOid);
    ASSERT_EQ("Ed448 OID length = 5", cbOid, (CK_ULONG)EC_OID_ED448_LEN);
    ASSERT_MEM("Ed448 OID bytes (1.3.101.113)",
               pbOid, EC_OID_ED448, EC_OID_ED448_LEN);

    pbOid = P11_GetCurveOid(ALG_RSA, &cbOid);
    ASSERT_NULL("RSA has no curve OID", pbOid);

    /* ── Suite 3 : mechanism resolution ─────────────────────────────────── */
    TEST_SUITE("EdDSA mechanism resolution");

    ss = P11_ResolveMechanism(ALG_EDDSA_ED25519, 0, &mech, NULL);
    ASSERT_OK("Ed25519 resolves", ss);
    ASSERT_EQ("Ed25519 → CKM_EDDSA", mech.mechanism,
              (CK_MECHANISM_TYPE)CKM_EDDSA);
    ASSERT_NULL("EdDSA takes no parameters", mech.pParameter);
    ASSERT_EQ("EdDSA parameter length 0", mech.ulParameterLen, (CK_ULONG)0);

    ss = P11_ResolveMechanism(ALG_EDDSA_ED448, 0, &mech, NULL);
    ASSERT_OK("Ed448 resolves", ss);
    ASSERT_EQ("Ed448 → CKM_EDDSA", mech.mechanism,
              (CK_MECHANISM_TYPE)CKM_EDDSA);

    /* Padding flags are ignored for EdDSA — it is never padded */
    ss = P11_ResolveMechanism(ALG_EDDSA_ED25519, NCRYPT_PAD_PSS_FLAG,
                              &mech, NULL);
    ASSERT_OK("Ed25519 resolves with PSS flag set", ss);
    ASSERT_EQ("PSS flag does not change the mechanism", mech.mechanism,
              (CK_MECHANISM_TYPE)CKM_EDDSA);

    /* ── Suite 4 : key generation ───────────────────────────────────────── */
    TEST_SUITE("EdDSA key generation");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_EDDSA_ED25519,
                                L"EdKey25519", AT_SIGNATURE, 0);
    ASSERT_OK("Ed25519 key created", ss);
    ASSERT_NEQ("Key handle returned", hKey, (NCRYPT_KEY_HANDLE)0);
    ASSERT_EQ("C_GenerateKeyPair called",
              P11Mock_GetCalls()->nGenerateKeyPair, 1);

    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_WSTR("Algorithm is EDDSA_ED25519", k->szAlgId,
                    ALG_EDDSA_ED25519);
        ASSERT_EQ("Ed25519 length = 255 bits", k->dwKeyBitLen, 255U);
        ASSERT_EQ("Key class is asymmetric", k->dwKeyClass,
                  (DWORD)KSP_KEY_CLASS_ASYMMETRIC);
        ASSERT("Key is finalized", k->bFinalized);
    }
    KSP_FreeKey(hProv, hKey);

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_EDDSA_ED448,
                                L"EdKey448", AT_SIGNATURE, 0);
    ASSERT_OK("Ed448 key created", ss);
    {
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
        ASSERT_WSTR("Algorithm is EDDSA_ED448", k->szAlgId, ALG_EDDSA_ED448);
        ASSERT_EQ("Ed448 length = 448 bits", k->dwKeyBitLen, 448U);
    }
    KSP_FreeKey(hProv, hKey);

    /* Deferred generation */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_EDDSA_ED25519,
                                L"EdDeferred", AT_SIGNATURE,
                                NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Deferred Ed25519 key created", ss);
    ASSERT_EQ("No generation before finalize",
              P11Mock_GetCalls()->nGenerateKeyPair, 0);

    ss = KSP_FinalizeKey(hProv, hKey, 0);
    ASSERT_OK("Finalize generates the pair", ss);
    ASSERT_EQ("C_GenerateKeyPair called on finalize",
              P11Mock_GetCalls()->nGenerateKeyPair, 1);
    KSP_FreeKey(hProv, hKey);

    /* Generation failure propagates */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->rv_GenerateKeyPair = CKR_MECHANISM_INVALID;

    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_EDDSA_ED25519,
                                L"EdFail", AT_SIGNATURE, 0);
    ASSERT_EQ("Generation failure → NTE_BAD_ALGID", ss,
              (SECURITY_STATUS)NTE_BAD_ALGID);

    /* ── Suite 5 : signing ──────────────────────────────────────────────── */
    TEST_SUITE("EdDSA signing");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = ED25519_SIG_SIZE;

    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_EDDSA_ED25519,
                                L"EdSign", AT_SIGNATURE, 0);
    ASSERT_OK("Signing key created", ss);

    {
        BYTE  hash[32];
        BYTE  sig[128];
        DWORD cbSig = 0;

        memset(hash, 0x7C, sizeof hash);

        /* Size query */
        ss = KSP_SignHash(hProv, hKey, NULL, hash, sizeof hash,
                          NULL, 0, &cbSig, 0);
        ASSERT_OK("Ed25519 size query succeeds", ss);
        ASSERT_EQ("Ed25519 signature is 64 bytes", cbSig,
                  (DWORD)ED25519_SIG_SIZE);

        /* Actual signature — EdDSA output is raw, no DER decoding */
        cbSig = 0;
        ss = KSP_SignHash(hProv, hKey, NULL, hash, sizeof hash,
                          sig, sizeof sig, &cbSig, 0);
        ASSERT_OK("Ed25519 signing succeeds", ss);
        ASSERT_EQ("Signature length is 64", cbSig, (DWORD)ED25519_SIG_SIZE);
        ASSERT_EQ("CKM_EDDSA used for signing",
                  P11Mock_GetConfig()->lastSignMech,
                  (CK_MECHANISM_TYPE)CKM_EDDSA);
    }
    KSP_FreeKey(hProv, hKey);

    /* Ed448 produces a 114-byte signature */
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    P11Mock_GetConfig()->cbSignature = ED448_SIG_SIZE;

    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_EDDSA_ED448,
                                L"Ed448Sign", AT_SIGNATURE, 0);
    ASSERT_OK("Ed448 signing key created", ss);
    {
        BYTE  hash[64];
        BYTE  sig[256];
        DWORD cbSig = 0;
        memset(hash, 0x4D, sizeof hash);

        ss = KSP_SignHash(hProv, hKey, NULL, hash, sizeof hash,
                          sig, sizeof sig, &cbSig, 0);
        ASSERT_OK("Ed448 signing succeeds", ss);
        ASSERT_EQ("Ed448 signature is 114 bytes", cbSig,
                  (DWORD)ED448_SIG_SIZE);
    }
    KSP_FreeKey(hProv, hKey);

    /* ── Suite 6 : public key export ────────────────────────────────────── */
    TEST_SUITE("EdDSA public key export");

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    {
        BYTE *pbBlob = NULL;
        DWORD cbBlob = 0;

        P11Mock_GetConfig()->pbEcPoint = (const char *)g_ed25519Point;
        P11Mock_GetConfig()->cbEcPoint = sizeof g_ed25519Point;

        ss = P11_ExportEddsaPublicKey((CK_SESSION_HANDLE)1, 0x20,
                                      ALG_EDDSA_ED25519, &pbBlob, &cbBlob);
        ASSERT_OK("Ed25519 export succeeds", ss);
        ASSERT_EQ("Blob size = header + 32",
                  cbBlob, (DWORD)(sizeof(BCRYPT_ECCKEY_BLOB) + 32));
        {
            BCRYPT_ECCKEY_BLOB *pB = (BCRYPT_ECCKEY_BLOB *)pbBlob;
            ASSERT_EQ("Generic ECC magic used", pB->dwMagic,
                      (DWORD)BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC);
            ASSERT_EQ("cbKey = 32", pB->cbKey, (DWORD)ED25519_PUBKEY_SIZE);
            ASSERT_MEM("Raw key bytes copied after the header",
                       pbBlob + sizeof(BCRYPT_ECCKEY_BLOB),
                       g_ed25519Point + 2, 32);
        }
        KSP_Free(pbBlob);
    }

    {
        BYTE *pbBlob = NULL;
        DWORD cbBlob = 0;

        P11Mock_GetConfig()->pbEcPoint = (const char *)g_ed448Point;
        P11Mock_GetConfig()->cbEcPoint = sizeof g_ed448Point;

        ss = P11_ExportEddsaPublicKey((CK_SESSION_HANDLE)1, 0x20,
                                      ALG_EDDSA_ED448, &pbBlob, &cbBlob);
        ASSERT_OK("Ed448 export succeeds", ss);
        ASSERT_EQ("Blob size = header + 57",
                  cbBlob, (DWORD)(sizeof(BCRYPT_ECCKEY_BLOB) + 57));
        {
            BCRYPT_ECCKEY_BLOB *pB = (BCRYPT_ECCKEY_BLOB *)pbBlob;
            ASSERT_EQ("cbKey = 57", pB->cbKey, (DWORD)ED448_PUBKEY_SIZE);
        }
        KSP_Free(pbBlob);
    }

    /* Size mismatch between the curve and the stored point is rejected */
    {
        BYTE *pbBlob = NULL;
        DWORD cbBlob = 0;

        P11Mock_GetConfig()->pbEcPoint = (const char *)g_ed448Point;
        P11Mock_GetConfig()->cbEcPoint = sizeof g_ed448Point;

        ss = P11_ExportEddsaPublicKey((CK_SESSION_HANDLE)1, 0x20,
                                      ALG_EDDSA_ED25519, &pbBlob, &cbBlob);
        ASSERT_EQ("Ed448 point with Ed25519 alg → NTE_BAD_KEY", ss,
                  (SECURITY_STATUS)NTE_BAD_KEY);
    }

    /* Parameter validation */
    {
        BYTE *pbBlob = NULL;
        DWORD cbBlob = 0;
        ss = P11_ExportEddsaPublicKey((CK_SESSION_HANDLE)1, 0x20,
                                      NULL, &pbBlob, &cbBlob);
        ASSERT_EQ("NULL algorithm → NTE_INVALID_PARAMETER", ss,
                  (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        ss = P11_ExportEddsaPublicKey((CK_SESSION_HANDLE)1, 0x20,
                                      ALG_EDDSA_ED25519, NULL, &cbBlob);
        ASSERT_EQ("NULL blob out → NTE_INVALID_PARAMETER", ss,
                  (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }

    /* Unreadable point propagates as NTE_BAD_KEY */
    {
        BYTE *pbBlob = NULL;
        DWORD cbBlob = 0;
        P11Mock_GetConfig()->rv_GetAttributeValue = CKR_ATTRIBUTE_SENSITIVE;
        ss = P11_ExportEddsaPublicKey((CK_SESSION_HANDLE)1, 0x20,
                                      ALG_EDDSA_ED25519, &pbBlob, &cbBlob);
        ASSERT_EQ("Unreadable point → NTE_BAD_KEY", ss,
                  (SECURITY_STATUS)NTE_BAD_KEY);
        P11Mock_GetConfig()->rv_GetAttributeValue = CKR_OK;
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
