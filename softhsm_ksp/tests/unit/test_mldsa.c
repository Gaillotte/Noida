/* test_mldsa.c — Phase 4: the capability probe and post-quantum gating.
 *
 * Two things are under test here, and they are really one thing.
 *
 * The provider used to answer NCryptEnumAlgorithms from a list compiled into
 * the DLL — a list describing SoftHSM2 2.7.0 and no other token. Now it
 * answers from the intersection of that list with what C_GetMechanismList
 * says the token implements. These tests drive the mock through several
 * different tokens and check the provider's answers change with them.
 *
 * ML-DSA is the case that matters. The mechanisms are PKCS#11 v3.2 and
 * SoftHSM2 2.7.0 implements none of them, so on the default backend nothing
 * here must ever be advertised or generated. On a token that does implement
 * them, the same code must reach them with no rebuild. Both directions are
 * asserted, because a gate that never opens and a gate that never closes
 * both pass a one-sided test.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_properties.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/common/config.h"
#include "../../src/common/memory.h"
#include "test_framework.h"
#include <wchar.h>
#include <string.h>

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

/* A PKCS#11 v3.2 token: everything SoftHSM2 has, plus the PQC mechanisms. */
static const CK_MECHANISM_TYPE g_pqcToken[] = {
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDH1_DERIVE,
    CKM_AES_KEY_GEN, CKM_AES_CBC,
    CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA,
    CKM_ML_KEM_KEY_PAIR_GEN, CKM_ML_KEM,
};

/* A token that signs with RSA and nothing else. */
static const CK_MECHANISM_TYPE g_rsaOnlyToken[] = {
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS,
};

/* An EC token that can generate and sign but cannot derive — the case a
 * presence-only check on CKM_EC_KEY_PAIR_GEN would get wrong. */
static const CK_MECHANISM_TYPE g_noDeriveToken[] = {
    CKM_EC_KEY_PAIR_GEN, CKM_ECDSA,
};

static void UseToken(const CK_MECHANISM_TYPE *pMechs, CK_ULONG n,
                     CK_BYTE bMajor, CK_BYTE bMinor)
{
    P11Mock_SetMechanisms(pMechs, n);
    P11Mock_SetCryptokiVersion(bMajor, bMinor);
    P11_ProbeCapabilities();
}

/* Is pszName in the list EnumAlgorithms returned? */
static BOOL Advertises(NCryptAlgorithmName *pList, DWORD cCount, LPCWSTR pszName)
{
    DWORD i;
    for (i = 0; i < cCount; i++) {
        if (pList[i].pszName && _wcsicmp(pList[i].pszName, pszName) == 0)
            return TRUE;
    }
    return FALSE;
}

int main(void)
{
    NCRYPT_PROV_HANDLE   hProv = 0;
    NCRYPT_KEY_HANDLE    hKey  = 0;
    SECURITY_STATUS      ss;
    CK_MECHANISM         mech;
    NCryptAlgorithmName *pList = NULL;
    DWORD                cAlgs = 0;
    DWORD                cbResult = 0;
    DWORD                dwLen    = 0;

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    g_testCtx.slotId        = 0;

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_OK("Provider opened", ss);

    /* ── Suite 1 : the parameter set table ──────────────────────────────── */
    TEST_SUITE("ML-DSA parameter sets");

    ASSERT_EQ("ML-DSA-44 → CKP_ML_DSA_44",
        P11_MlDsaParameterSet(ALG_MLDSA_44), (CK_ULONG)CKP_ML_DSA_44);
    ASSERT_EQ("ML-DSA-65 → CKP_ML_DSA_65",
        P11_MlDsaParameterSet(ALG_MLDSA_65), (CK_ULONG)CKP_ML_DSA_65);
    ASSERT_EQ("ML-DSA-87 → CKP_ML_DSA_87",
        P11_MlDsaParameterSet(ALG_MLDSA_87), (CK_ULONG)CKP_ML_DSA_87);

    /* 0 doubles as "not ML-DSA", which only works because PKCS#11 assigns
     * no parameter set the value 0. */
    ASSERT_EQ("RSA is not an ML-DSA identifier",
        P11_MlDsaParameterSet(ALG_RSA), (CK_ULONG)0);
    ASSERT_EQ("Ed25519 is not an ML-DSA identifier",
        P11_MlDsaParameterSet(ALG_EDDSA_ED25519), (CK_ULONG)0);
    ASSERT_EQ("NULL is not an ML-DSA identifier",
        P11_MlDsaParameterSet(NULL), (CK_ULONG)0);

    /* Sizes from liboqs, not from this project's own arithmetic. */
    ASSERT_EQ("ML-DSA-44 signature is 2420 bytes",
        P11_MlDsaSignatureSize(ALG_MLDSA_44), (DWORD)2420);
    ASSERT_EQ("ML-DSA-65 signature is 3309 bytes",
        P11_MlDsaSignatureSize(ALG_MLDSA_65), (DWORD)3309);
    ASSERT_EQ("ML-DSA-87 signature is 4627 bytes",
        P11_MlDsaSignatureSize(ALG_MLDSA_87), (DWORD)4627);
    ASSERT_EQ("ML-DSA-44 public key is 1312 bytes",
        P11_MlDsaPublicKeySize(ALG_MLDSA_44), (DWORD)1312);
    ASSERT_EQ("ML-DSA-65 public key is 1952 bytes",
        P11_MlDsaPublicKeySize(ALG_MLDSA_65), (DWORD)1952);
    ASSERT_EQ("ML-DSA-87 public key is 2592 bytes",
        P11_MlDsaPublicKeySize(ALG_MLDSA_87), (DWORD)2592);
    ASSERT_EQ("A non-ML-DSA name has no signature size",
        P11_MlDsaSignatureSize(ALG_RSA), (DWORD)0);

    /* ── Suite 2 : mechanism resolution ─────────────────────────────────── */
    TEST_SUITE("ML-DSA mechanism resolution");

    memset(&mech, 0, sizeof(mech));
    ss = P11_ResolveMechanism(ALG_MLDSA_65, 0, &mech, NULL);
    ASSERT_OK("ML-DSA-65 resolves", ss);
    ASSERT_EQ("→ CKM_ML_DSA", mech.mechanism, (CK_MECHANISM_TYPE)CKM_ML_DSA);

    /* The parameter set belongs to the key, not the signature, so nothing
     * is attached to the mechanism — the same shape as EdDSA. */
    ASSERT("No mechanism parameter", mech.pParameter == NULL);
    ASSERT_EQ("No parameter length", mech.ulParameterLen, (CK_ULONG)0);

    memset(&mech, 0, sizeof(mech));
    ss = P11_ResolveMechanism(ALG_MLDSA_44, NCRYPT_PAD_PSS_FLAG, &mech, NULL);
    ASSERT_OK("A padding flag does not upset ML-DSA", ss);
    ASSERT_EQ("Still CKM_ML_DSA — PQC signatures take no padding",
        mech.mechanism, (CK_MECHANISM_TYPE)CKM_ML_DSA);

    /* ── Suite 3 : the probe reads the token ────────────────────────────── */
    TEST_SUITE("P11_ProbeCapabilities");

    P11_ReleaseCapabilities();
    ASSERT("Before any probe, nothing has been probed", !P11_CapsProbed());
    /* With no probe the provider must not lose functionality, so the
     * unanswered question is answered permissively. */
    ASSERT("Unprobed, every mechanism reads as present",
        P11_HasMechanism(CKM_ML_DSA));

    UseToken(g_pqcToken, sizeof(g_pqcToken) / sizeof(g_pqcToken[0]), 3, 2);
    ASSERT("Probe succeeded", P11_CapsProbed());
    ASSERT_EQ("C_GetMechanismList was called twice (count, then fill)",
        P11Mock_GetCalls()->nGetMechanismList, 2);
    ASSERT("CKM_ML_DSA found", P11_HasMechanism(CKM_ML_DSA));
    ASSERT("CKM_EDDSA absent from this token", !P11_HasMechanism(CKM_EDDSA));

    {
        CK_BYTE bMajor = 0, bMinor = 0;
        P11_GetCryptokiVersion(&bMajor, &bMinor);
        ASSERT_EQ("Cryptoki major is 3", (DWORD)bMajor, 3U);
        ASSERT_EQ("Cryptoki minor is 2", (DWORD)bMinor, 2U);
    }
    ASSERT("Reports at least 3.0", P11_CryptokiAtLeast(3, 0));
    ASSERT("Reports at least 3.2", P11_CryptokiAtLeast(3, 2));
    ASSERT("Does not report 3.3", !P11_CryptokiAtLeast(3, 3));
    ASSERT("A 3.2 token is at least 2.40", P11_CryptokiAtLeast(2, 40));

    /* Mechanism flags come from C_GetMechanismInfo and are kept. */
    ASSERT("Flags were read for a listed mechanism",
        P11_MechanismFlags(CKM_ML_DSA) != 0);
    ASSERT_EQ("An unlisted mechanism has no flags",
        P11_MechanismFlags(CKM_EDDSA), (CK_FLAGS)0);

    /* A 2.40 token must not be mistaken for a 3.x one. */
    UseToken(g_rsaOnlyToken,
             sizeof(g_rsaOnlyToken) / sizeof(g_rsaOnlyToken[0]), 2, 40);
    ASSERT("A 2.40 token does not report 3.0", !P11_CryptokiAtLeast(3, 0));
    ASSERT("but is at least 2.40", P11_CryptokiAtLeast(2, 40));

    /* A token that refuses the question leaves the provider unfiltered,
     * rather than stripped of every algorithm. */
    P11_ReleaseCapabilities();
    P11Mock_GetConfig()->rv_GetMechanismList = CKR_FUNCTION_NOT_SUPPORTED;
    ss = P11_ProbeCapabilities();
    ASSERT_ERR("A refused C_GetMechanismList is reported", ss);
    ASSERT("and leaves the probe unset", !P11_CapsProbed());
    ASSERT("so mechanisms read as present again",
        P11_HasMechanism(CKM_ML_DSA));
    P11Mock_GetConfig()->rv_GetMechanismList = CKR_OK;

    /* A token with a huge list must not be able to make the provider
     * allocate without bound. */
    {
        static CK_MECHANISM_TYPE aHuge[P11_MOCK_MAX_MECHS];
        CK_ULONG i;
        for (i = 0; i < P11_MOCK_MAX_MECHS; i++)
            aHuge[i] = (CK_MECHANISM_TYPE)(0x80000000UL + i);

        P11_ReleaseCapabilities();
        P11Mock_SetMechanisms(aHuge, P11_MOCK_MAX_MECHS);
        ss = P11_ProbeCapabilities();

        /* P11_MOCK_MAX_MECHS exceeds P11_MAX_MECHANISMS. The probe is
         * abandoned rather than truncated: half a capability view would
         * make the provider refuse algorithms the token really has, while
         * no view is answered permissively and costs nothing. */
        ASSERT_ERR("An implausible mechanism count is refused", ss);
        ASSERT("and leaves the probe unset", !P11_CapsProbed());
        ASSERT("so nothing is filtered out",
            P11_HasMechanism((CK_MECHANISM_TYPE)0x80000000UL));
    }

    /* An empty token is recorded as empty, not treated as unprobed. */
    UseToken(NULL, 0, 2, 40);
    ASSERT("An empty mechanism list still counts as probed",
        P11_CapsProbed());
    ASSERT("and nothing is claimed", !P11_HasMechanism(CKM_RSA_PKCS));

    /* A module that cannot answer C_GetInfo still has a usable mechanism
     * list. Only the version is lost, and losing it can only withhold
     * features, never grant them. */
    P11_ReleaseCapabilities();
    P11Mock_GetConfig()->rv_GetInfo = CKR_FUNCTION_FAILED;
    UseToken(g_pqcToken, sizeof(g_pqcToken) / sizeof(g_pqcToken[0]), 3, 2);
    ASSERT("A failed C_GetInfo does not abandon the probe", P11_CapsProbed());
    ASSERT("Mechanisms are still known", P11_HasMechanism(CKM_ML_DSA));
    {
        CK_BYTE bMajor = 1, bMinor = 1;
        P11_GetCryptokiVersion(&bMajor, &bMinor);
        ASSERT_EQ("but the version reads as 0.0", (DWORD)bMajor, 0U);
        ASSERT_EQ("both halves", (DWORD)bMinor, 0U);
    }
    ASSERT("and the module is not treated as 3.x", !P11_CryptokiAtLeast(3, 0));
    P11Mock_GetConfig()->rv_GetInfo = CKR_OK;

    /* C_GetMechanismInfo is detail, not authority: a mechanism the token
     * lists but will not describe is still present. */
    P11_ReleaseCapabilities();
    P11Mock_GetConfig()->rv_GetMechanismInfo = CKR_FUNCTION_FAILED;
    UseToken(g_pqcToken, sizeof(g_pqcToken) / sizeof(g_pqcToken[0]), 3, 2);
    ASSERT("Probe succeeds without mechanism info", P11_CapsProbed());
    ASSERT("Mechanism still counts as present", P11_HasMechanism(CKM_ML_DSA));
    ASSERT_EQ("but carries no flags",
        P11_MechanismFlags(CKM_ML_DSA), (CK_FLAGS)0);
    P11Mock_GetConfig()->rv_GetMechanismInfo = CKR_OK;

    /* No function list at all — the probe must not dereference it. */
    P11_ReleaseCapabilities();
    g_testCtx.pFunctionList = NULL;
    ss = P11_ProbeCapabilities();
    ASSERT_ERR("Probing without a loaded module fails cleanly", ss);
    ASSERT("and leaves the probe unset", !P11_CapsProbed());
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();

    /* ── Suite 4 : advertisement follows the token ──────────────────────── */
    TEST_SUITE("EnumAlgorithms tracks the token");

    /* SoftHSM2 2.7.0 as the mock presents it by default. */
    P11Mock_Reset();
    P11_ProbeCapabilities();

    ss = KSP_EnumAlgorithms(hProv, 0, &cAlgs, &pList, 0);
    ASSERT_OK("EnumAlgorithms on a SoftHSM2-like token", ss);
    ASSERT("RSA advertised", Advertises(pList, cAlgs, ALG_RSA));
    ASSERT("ECDSA_P256 advertised", Advertises(pList, cAlgs, ALG_ECDSA_P256));
    ASSERT("ECDH_P256 advertised", Advertises(pList, cAlgs, ALG_ECDH_P256));
    ASSERT("AES advertised", Advertises(pList, cAlgs, ALG_AES));
    /* The point of the whole exercise: no PQC claim on a token that has none. */
    ASSERT("ML-DSA-44 NOT advertised",
        !Advertises(pList, cAlgs, ALG_MLDSA_44));
    ASSERT("ML-DSA-65 NOT advertised",
        !Advertises(pList, cAlgs, ALG_MLDSA_65));
    ASSERT("ML-DSA-87 NOT advertised",
        !Advertises(pList, cAlgs, ALG_MLDSA_87));
    KSP_FreeBuffer(pList);

    ASSERT_OK("IsAlgSupported(RSA) on SoftHSM2",
        KSP_IsAlgSupported(hProv, ALG_RSA, 0));
    ASSERT_EQ("IsAlgSupported(ML-DSA-65) → NTE_NOT_SUPPORTED",
        KSP_IsAlgSupported(hProv, ALG_MLDSA_65, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Same binary, PQC token. */
    UseToken(g_pqcToken, sizeof(g_pqcToken) / sizeof(g_pqcToken[0]), 3, 2);

    pList = NULL; cAlgs = 0;
    ss = KSP_EnumAlgorithms(hProv, 0, &cAlgs, &pList, 0);
    ASSERT_OK("EnumAlgorithms on a v3.2 token", ss);
    ASSERT("ML-DSA-44 now advertised", Advertises(pList, cAlgs, ALG_MLDSA_44));
    ASSERT("ML-DSA-65 now advertised", Advertises(pList, cAlgs, ALG_MLDSA_65));
    ASSERT("ML-DSA-87 now advertised", Advertises(pList, cAlgs, ALG_MLDSA_87));
    ASSERT("RSA still advertised", Advertises(pList, cAlgs, ALG_RSA));
    KSP_FreeBuffer(pList);

    ASSERT_OK("IsAlgSupported(ML-DSA-65) on a v3.2 token",
        KSP_IsAlgSupported(hProv, ALG_MLDSA_65, 0));

    /* Signature-class filtering must still work over the filtered list. */
    pList = NULL; cAlgs = 0;
    ss = KSP_EnumAlgorithms(hProv, NCRYPT_SIGNATURE_OPERATION,
                            &cAlgs, &pList, 0);
    ASSERT_OK("EnumAlgorithms(signature only)", ss);
    ASSERT("ML-DSA-65 is a signature algorithm",
        Advertises(pList, cAlgs, ALG_MLDSA_65));
    ASSERT("AES is not in the signature class",
        !Advertises(pList, cAlgs, ALG_AES));
    KSP_FreeBuffer(pList);

    /* An RSA-only token loses everything else. */
    UseToken(g_rsaOnlyToken,
             sizeof(g_rsaOnlyToken) / sizeof(g_rsaOnlyToken[0]), 2, 40);

    pList = NULL; cAlgs = 0;
    ss = KSP_EnumAlgorithms(hProv, 0, &cAlgs, &pList, 0);
    ASSERT_OK("EnumAlgorithms on an RSA-only token", ss);
    ASSERT_EQ("Exactly one algorithm", cAlgs, 1U);
    ASSERT("RSA advertised", Advertises(pList, cAlgs, ALG_RSA));
    ASSERT("ECDSA_P256 not advertised",
        !Advertises(pList, cAlgs, ALG_ECDSA_P256));
    ASSERT("AES not advertised", !Advertises(pList, cAlgs, ALG_AES));
    KSP_FreeBuffer(pList);

    ASSERT_EQ("IsAlgSupported(AES) → NTE_NOT_SUPPORTED",
        KSP_IsAlgSupported(hProv, ALG_AES, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Generation and use are checked separately: a token that can make EC
     * keys but cannot derive must advertise ECDSA and not ECDH. */
    UseToken(g_noDeriveToken,
             sizeof(g_noDeriveToken) / sizeof(g_noDeriveToken[0]), 2, 40);

    pList = NULL; cAlgs = 0;
    ss = KSP_EnumAlgorithms(hProv, 0, &cAlgs, &pList, 0);
    ASSERT_OK("EnumAlgorithms on a sign-only EC token", ss);
    ASSERT("ECDSA_P256 advertised", Advertises(pList, cAlgs, ALG_ECDSA_P256));
    ASSERT("ECDH_P256 NOT advertised — no CKM_ECDH1_DERIVE",
        !Advertises(pList, cAlgs, ALG_ECDH_P256));
    KSP_FreeBuffer(pList);

    /* The count and the contents come from one predicate; this is the
     * assertion that would fail if they ever stopped agreeing. */
    ASSERT_EQ("Count matches the three ECDSA curves", cAlgs, 3U);

    /* ── Suite 5 : key generation is gated too ──────────────────────────── */
    TEST_SUITE("ML-DSA key generation");

    /* A caller may name an algorithm it never asked about, so the gate is
     * repeated at the point of use rather than trusted to advertisement. */
    P11Mock_Reset();
    P11_ProbeCapabilities();          /* SoftHSM2-like: no PQC */

    /* Without NCRYPT_PERSIST_ONLY_FLAG the key is generated during the
     * create call, so the refusal surfaces there. */
    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_MLDSA_65, L"pqc-key", 0, 0);
    ASSERT_EQ("Immediate CreatePersistedKey → NTE_NOT_SUPPORTED without ML-DSA",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    ASSERT_EQ("and no key pair was generated",
        P11Mock_GetCalls()->nGenerateKeyPair, 0);

    /* The deferred route reaches the same refusal one call later, which is
     * the path NCryptCreatePersistedKey + NCryptFinalizeKey actually takes. */
    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_MLDSA_65, L"pqc-key",
                                0, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("Deferred CreatePersistedKey accepts the name", ss);
    ASSERT("Key handle returned", hKey != 0);

    ss = KSP_FinalizeKey(hProv, hKey, 0);
    ASSERT_EQ("FinalizeKey → NTE_NOT_SUPPORTED on a token without ML-DSA",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    ASSERT_EQ("and still no key pair was generated",
        P11Mock_GetCalls()->nGenerateKeyPair, 0);
    KSP_FreeKey(hProv, hKey);

    /* Same call, token that implements ML-DSA. */
    UseToken(g_pqcToken, sizeof(g_pqcToken) / sizeof(g_pqcToken[0]), 3, 2);
    P11Mock_ResetCalls();

    hKey = 0;
    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_MLDSA_65, L"pqc-key",
                                0, NCRYPT_PERSIST_ONLY_FLAG);
    ASSERT_OK("CreatePersistedKey", ss);

    ss = KSP_FinalizeKey(hProv, hKey, 0);
    ASSERT_OK("FinalizeKey succeeds on a v3.2 token", ss);
    ASSERT_EQ("C_GenerateKeyPair was called once",
        P11Mock_GetCalls()->nGenerateKeyPair, 1);
    ASSERT_EQ("with CKM_ML_DSA_KEY_PAIR_GEN",
        P11Mock_GetConfig()->lastGenerateKeyPairMech,
        (CK_MECHANISM_TYPE)CKM_ML_DSA_KEY_PAIR_GEN);

    /* ── Suite 6 : key properties ───────────────────────────────────────── */
    TEST_SUITE("ML-DSA key properties");

    {
        WCHAR wszGroup[64];

        /* Before ML-DSA had its own branch, the group lookup ended in an
         * else that returned "ECDSA" — so an ML-DSA key would have told a
         * caller it was elliptic-curve. */
        cbResult = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_ALGORITHM_GROUP_PROPERTY,
                                (PBYTE)wszGroup, sizeof(wszGroup),
                                &cbResult, 0);
        ASSERT_OK("Algorithm group readable", ss);
        ASSERT("Group is ML-DSA, not ECDSA",
            _wcsicmp(wszGroup, ALG_GROUP_MLDSA) == 0);

        /* NCRYPT_LENGTH_PROPERTY must be something a caller can use. ML-DSA
         * has no key size in the RSA sense, so the public key length is
         * reported rather than zero, which reads as an error. */
        cbResult = 0;
        dwLen    = 0;
        ss = KSP_GetKeyProperty(hProv, hKey, NCRYPT_LENGTH_PROPERTY,
                                (PBYTE)&dwLen, sizeof(dwLen), &cbResult, 0);
        ASSERT_OK("Length readable", ss);
        ASSERT_EQ("ML-DSA-65 length is its public key in bits",
            dwLen, (DWORD)(MLDSA_65_PUBKEY_SIZE * 8));
    }

    /* ── Suite 7 : export refuses rather than guesses ───────────────────── */
    TEST_SUITE("ML-DSA export");

    /* The CNG post-quantum public key blob layout is not available in this
     * workspace. Emitting a guessed one would pass our own tests and fail
     * on Windows, which is the exact failure this project already had with
     * an invented algorithm identifier. */
    cbResult = 0;
    ss = KSP_ExportKey(hProv, hKey, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
                       NULL, 0, &cbResult, 0);
    ASSERT_EQ("Export of an ML-DSA public key → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    KSP_FreeKey(hProv, hKey);

    /* ── Suite 8 : ML-KEM is recognised but unreachable ─────────────────── */
    TEST_SUITE("ML-KEM");

    /* The token in this suite implements ML-KEM, and the provider still
     * offers nothing — deliberately. Encapsulation and decapsulation have
     * no slot in the key-storage function table this project builds
     * against, so there is no CNG entry point to serve. Advertising a
     * key-encapsulation algorithm a caller cannot then use would be worse
     * than silence. See docs/13-roadmap.md. */
    ASSERT("The token does implement ML-KEM", P11_HasMechanism(CKM_ML_KEM));

    pList = NULL; cAlgs = 0;
    ss = KSP_EnumAlgorithms(hProv, 0, &cAlgs, &pList, 0);
    ASSERT_OK("EnumAlgorithms", ss);
    ASSERT("ML-KEM is not advertised", !Advertises(pList, cAlgs, L"ML-KEM"));
    KSP_FreeBuffer(pList);

    ASSERT_EQ("IsAlgSupported(ML-KEM) → NTE_NOT_SUPPORTED",
        KSP_IsAlgSupported(hProv, L"ML-KEM", 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    P11_ReleaseCapabilities();
    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
