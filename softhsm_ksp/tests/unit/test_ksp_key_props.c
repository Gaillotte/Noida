/* test_ksp_key_props.c — Full coverage of ksp_properties.c
 * All read/write properties, all error paths.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <stdio.h>
#include <wchar.h>
#include <string.h>

typedef struct { void *hModule; CK_FUNCTION_LIST_PTR pFunctionList;
                 CK_SLOT_ID slotId; BOOL bInitialized; } P11_CONTEXT;
static P11_CONTEXT g_testCtx;
P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }
SECURITY_STATUS P11_Initialize(void)            { return ERROR_SUCCESS; }
SECURITY_STATUS P11_SessionPool_Initialize(void){ return ERROR_SUCCESS; }
void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }
void Log_Initialize(void) {}

void *KSP_Alloc(SIZE_T n);
void *KSP_AllocZero(SIZE_T n);
void  KSP_Free(void *p);

#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_properties.h"
#include "../../src/ksp/ksp_provider.h"

/* Creates a test KSP_KEY without going through PKCS#11 */
static NCRYPT_KEY_HANDLE make_test_key(
    LPCWSTR szAlg, DWORD bits, DWORD spec, BOOL finalized)
{
    KSP_KEY *k = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
    k->dwMagic     = KSP_KEY_MAGIC;
    k->dwKeyBitLen = bits;
    k->dwKeySpec   = spec;
    k->hPrivKey    = finalized ? (CK_OBJECT_HANDLE)0x10 : CK_INVALID_HANDLE;
    k->hPubKey     = finalized ? (CK_OBJECT_HANDLE)0x11 : CK_INVALID_HANDLE;
    k->bFinalized  = finalized;
    k->slotId      = 0;
    wcscpy_s(k->szAlgId,   MAX_ALG_ID_LEN,      szAlg);
    wcscpy_s(k->szKeyName, MAX_KEY_LABEL_LEN,    L"MyTestKey");
    return (NCRYPT_KEY_HANDLE)(ULONG_PTR)k;
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv;
    SECURITY_STATUS    ss;
    DWORD cbResult, dwVal;
    WCHAR wszBuf[256];

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);

    /* ── Suite 1 : GetKeyProperty — RSA key ────────────────────────────── */
    TEST_SUITE("KSP_GetKeyProperty — RSA 2048");

    NCRYPT_KEY_HANDLE hRsa = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);

    /* NCRYPT_ALGORITHM_PROPERTY */
    cbResult = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_ALGORITHM_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("ALG → size OK", ss);
    ASSERT("cbResult > 0", cbResult > 0);

    memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_ALGORITHM_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("ALG → content OK", ss);
    ASSERT("szAlgId = RSA", _wcsicmp(wszBuf, ALG_RSA) == 0);

    /* NCRYPT_LENGTH_PROPERTY */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("LENGTH → OK", ss);
    ASSERT_EQ("dwKeyBitLen = 2048", dwVal, 2048U);

    /* NCRYPT_KEY_TYPE_PROPERTY */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_KEY_TYPE_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("KEY_TYPE → OK", ss);
    ASSERT_EQ("dwKeySpec = AT_SIGNATURE", dwVal, (DWORD)AT_SIGNATURE);

    /* NCRYPT_NAME_PROPERTY */
    cbResult = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_NAME_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("NAME size → OK", ss);

    memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_NAME_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("NAME content → OK", ss);
    ASSERT("szKeyName = MyTestKey",
           _wcsicmp(wszBuf, L"MyTestKey") == 0);

    /* NCRYPT_UNIQUE_NAME_PROPERTY */
    cbResult = 0; memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_UNIQUE_NAME_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("UNIQUE_NAME size → OK", ss);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_UNIQUE_NAME_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("UNIQUE_NAME content → OK", ss);
    ASSERT("Unique name = szKeyName", _wcsicmp(wszBuf, L"MyTestKey") == 0);

    /* NCRYPT_EXPORT_POLICY_PROPERTY */
    dwVal = 0xFF;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_EXPORT_POLICY_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("EXPORT_POLICY → OK", ss);
    ASSERT_EQ("EXPORT_POLICY = 0 (non exportable)", dwVal, 0U);

    /* NCRYPT_KEY_USAGE_PROPERTY — AT_SIGNATURE */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_KEY_USAGE_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("KEY_USAGE AT_SIGNATURE → OK", ss);
    ASSERT("ALLOW_SIGNING_FLAG set",
           (dwVal & NCRYPT_ALLOW_SIGNING_FLAG) != 0);

    /* NCRYPT_ALGORITHM_GROUP_PROPERTY — RSA */
    cbResult = 0; memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        NULL, 0, &cbResult, 0);
    ASSERT_OK("ALGORITHM_GROUP RSA size → OK", ss);
    ss = KSP_GetKeyProperty(hProv, hRsa, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("ALGORITHM_GROUP RSA content → OK", ss);
    ASSERT("Group = RSA", _wcsicmp(wszBuf, NCRYPT_RSA_ALGORITHM_GROUP) == 0);

    KSP_Free((void *)(ULONG_PTR)hRsa);

    /* ── Suite 2 : GetKeyProperty — ECDSA key ───────────────────────────── */
    TEST_SUITE("KSP_GetKeyProperty — ECDSA P-256");

    NCRYPT_KEY_HANDLE hEc = make_test_key(ALG_ECDSA_P256, 256, AT_KEYEXCHANGE, TRUE);

    /* KEY_USAGE AT_KEYEXCHANGE */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hEc, NCRYPT_KEY_USAGE_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("KEY_USAGE AT_KEYEXCHANGE → OK", ss);
    ASSERT("ALLOW_DECRYPT_FLAG set",
           (dwVal & NCRYPT_ALLOW_DECRYPT_FLAG) != 0);

    /* ALGORITHM_GROUP → ECDSA */
    cbResult = 0; memset(wszBuf, 0, sizeof wszBuf);
    ss = KSP_GetKeyProperty(hProv, hEc, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        NULL, 0, &cbResult, 0);
    ss = KSP_GetKeyProperty(hProv, hEc, NCRYPT_ALGORITHM_GROUP_PROPERTY,
        (PBYTE)wszBuf, cbResult, &cbResult, 0);
    ASSERT_OK("ALGORITHM_GROUP ECDSA → OK", ss);
    ASSERT("Group = ECDSA", _wcsicmp(wszBuf, NCRYPT_ECDSA_ALGORITHM_GROUP) == 0);

    KSP_Free((void *)(ULONG_PTR)hEc);

    /* ── Suite 3 : GetKeyProperty erreurs ───────────────────────────────── */
    TEST_SUITE("KSP_GetKeyProperty — error cases");

    NCRYPT_KEY_HANDLE hK = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);

    /* Unknown property */
    ss = KSP_GetKeyProperty(hProv, hK, L"PourquoiPas",
        NULL, 0, &cbResult, 0);
    ASSERT_EQ("Unknown prop → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Invalid key handle */
    ss = KSP_GetKeyProperty(hProv, 0,
        NCRYPT_ALGORITHM_PROPERTY, NULL, 0, &cbResult, 0);
    ASSERT_EQ("hKey=0 → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* Buffer too small for LENGTH */
    ss = KSP_GetKeyProperty(hProv, hK, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwVal, 1, &cbResult, 0);
    ASSERT_EQ("Buffer too small (LENGTH) → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);

    /* pcbResult NULL */
    ss = KSP_GetKeyProperty(hProv, hK, NCRYPT_ALGORITHM_PROPERTY,
        NULL, 0, NULL, 0);
    ASSERT_EQ("pcbResult=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_Free((void *)(ULONG_PTR)hK);

    /* ── Suite 4 : SetKeyProperty ───────────────────────────────────────── */
    TEST_SUITE("KSP_SetKeyProperty");

    /* Modify length before FinalizeKey */
    NCRYPT_KEY_HANDLE hPre = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, FALSE);
    DWORD newBits = 4096;
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_OK("SetKeyProperty LENGTH=4096 before FinalizeKey → OK", ss);

    /* Verify the modification */
    dwVal = 0;
    ss = KSP_GetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&dwVal, sizeof dwVal, &cbResult, 0);
    ASSERT_OK("GetKeyProperty after Set → OK", ss);
    ASSERT_EQ("Length = 4096 after Set", dwVal, 4096U);

    /* Length 3072 */
    newBits = 3072;
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_OK("SetKeyProperty LENGTH=3072 → OK", ss);

    /* Invalid length */
    newBits = 1024;
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_EQ("LENGTH=1024 (invalid) → NTE_BAD_LEN",
        ss, (SECURITY_STATUS)NTE_BAD_LEN);

    newBits = 512;
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_EQ("LENGTH=512 → NTE_BAD_LEN", ss, (SECURITY_STATUS)NTE_BAD_LEN);

    /* Buffer too short */
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, 1, 0);
    ASSERT_EQ("Short buffer → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* pbInput NULL */
    ss = KSP_SetKeyProperty(hProv, hPre, NCRYPT_LENGTH_PROPERTY,
        NULL, sizeof newBits, 0);
    ASSERT_EQ("pbInput=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_Free((void *)(ULONG_PTR)hPre);

    /* Modify after FinalizeKey → forbidden */
    NCRYPT_KEY_HANDLE hPost = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);
    newBits = 4096;
    ss = KSP_SetKeyProperty(hProv, hPost, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_EQ("SetKeyProperty after Finalize → NTE_INVALID_HANDLE",
        ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);
    KSP_Free((void *)(ULONG_PTR)hPost);

    /* Non-modifiable property */
    NCRYPT_KEY_HANDLE hAny = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, FALSE);
    ss = KSP_SetKeyProperty(hProv, hAny, NCRYPT_ALGORITHM_PROPERTY,
        (PBYTE)L"EC", 6, 0);
    ASSERT_EQ("Set ALGORITHM → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* Invalid handle */
    ss = KSP_SetKeyProperty(hProv, 0, NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&newBits, sizeof newBits, 0);
    ASSERT_EQ("Invalid hKey → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    KSP_Free((void *)(ULONG_PTR)hAny);

    /* ── RSA length range (KSP_RSA_MIN_BITS..KSP_RSA_MAX_BITS, step 64) ──── */
    TEST_SUITE("SetKeyProperty — RSA length range");
    {
        static const DWORD accepted[] = { 2048, 2112, 3072, 4096, 7680,
                                          8192, 15360, 16384 };
        static const DWORD rejected[] = { 0, 512, 1024, 2047, 2049, 3000,
                                          16448, 32768 };
        size_t i;

        for (i = 0; i < sizeof accepted / sizeof accepted[0]; i++) {
            NCRYPT_KEY_HANDLE h = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, FALSE);
            DWORD bits = accepted[i];
            char  name[80];
            ss = KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                (PBYTE)&bits, sizeof bits, 0);
            sprintf(name, "RSA %u bits accepted", (unsigned)bits);
            ASSERT_EQ(name, ss, (SECURITY_STATUS)ERROR_SUCCESS);
            ASSERT_EQ("  ...and stored on the key",
                ((KSP_KEY *)(ULONG_PTR)h)->dwKeyBitLen, bits);
            KSP_Free((void *)(ULONG_PTR)h);
        }

        for (i = 0; i < sizeof rejected / sizeof rejected[0]; i++) {
            NCRYPT_KEY_HANDLE h = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, FALSE);
            DWORD bits = rejected[i];
            char  name[80];
            ss = KSP_SetKeyProperty(hProv, h, NCRYPT_LENGTH_PROPERTY,
                (PBYTE)&bits, sizeof bits, 0);
            sprintf(name, "RSA %u bits rejected → NTE_BAD_LEN", (unsigned)bits);
            ASSERT_EQ(name, ss, (SECURITY_STATUS)NTE_BAD_LEN);
            ASSERT_EQ("  ...and the key is unchanged",
                ((KSP_KEY *)(ULONG_PTR)h)->dwKeyBitLen, 2048U);
            KSP_Free((void *)(ULONG_PTR)h);
        }
    }

    /* ── RSA public exponent property ──────────────────────────────────── */
    TEST_SUITE("Get/SetKeyProperty — RSA public exponent");
    {
        NCRYPT_KEY_HANDLE h = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, FALSE);
        DWORD exp = 0;
        DWORD cb  = 0;

        /* The default must remain F4 so existing callers are unaffected. */
        ((KSP_KEY *)(ULONG_PTR)h)->dwPublicExponent = RSA_DEFAULT_PUBEXP;
        ss = KSP_GetKeyProperty(hProv, h, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, sizeof exp, &cb, 0);
        ASSERT_OK("Get public exponent → OK", ss);
        ASSERT_EQ("Default exponent is 65537", exp, (DWORD)RSA_DEFAULT_PUBEXP);
        ASSERT_EQ("cbResult = 4", cb, (DWORD)sizeof(DWORD));

        /* Size query */
        cb = 0;
        ss = KSP_GetKeyProperty(hProv, h, KSP_PUBLIC_EXPONENT_PROPERTY,
            NULL, 0, &cb, 0);
        ASSERT_OK("Size query → OK", ss);
        ASSERT_EQ("Size query returns 4", cb, (DWORD)sizeof(DWORD));

        exp = 3;
        ss = KSP_SetKeyProperty(hProv, h, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, sizeof exp, 0);
        ASSERT_OK("Set exponent 3 → OK", ss);
        ASSERT_EQ("Stored exponent is 3",
            ((KSP_KEY *)(ULONG_PTR)h)->dwPublicExponent, 3U);

        exp = 17;
        ss = KSP_SetKeyProperty(hProv, h, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, sizeof exp, 0);
        ASSERT_OK("Set exponent 17 → OK", ss);

        /* Even exponents and values below 3 are not valid RSA exponents. */
        exp = 4;
        ss = KSP_SetKeyProperty(hProv, h, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, sizeof exp, 0);
        ASSERT_EQ("Even exponent → NTE_INVALID_PARAMETER",
            ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        exp = 1;
        ss = KSP_SetKeyProperty(hProv, h, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, sizeof exp, 0);
        ASSERT_EQ("Exponent 1 → NTE_INVALID_PARAMETER",
            ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        exp = 0;
        ss = KSP_SetKeyProperty(hProv, h, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, sizeof exp, 0);
        ASSERT_EQ("Exponent 0 → NTE_INVALID_PARAMETER",
            ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        ASSERT_EQ("Rejected values left the key untouched",
            ((KSP_KEY *)(ULONG_PTR)h)->dwPublicExponent, 17U);

        exp = 65537;
        ss = KSP_SetKeyProperty(hProv, h, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, 2, 0);
        ASSERT_EQ("Short buffer → NTE_INVALID_PARAMETER",
            ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);
        KSP_Free((void *)(ULONG_PTR)h);
    }
    {
        /* The exponent is meaningless on a non-RSA key, and cannot be
         * changed once the key material exists on the token. */
        NCRYPT_KEY_HANDLE hEc = make_test_key(ALG_ECDSA_P256, 256,
                                              AT_SIGNATURE, FALSE);
        DWORD exp = 3;
        ss = KSP_SetKeyProperty(hProv, hEc, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, sizeof exp, 0);
        ASSERT_EQ("Exponent on EC key → NTE_NOT_SUPPORTED",
            ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        KSP_Free((void *)(ULONG_PTR)hEc);

        NCRYPT_KEY_HANDLE hFin = make_test_key(ALG_RSA, 2048,
                                               AT_SIGNATURE, TRUE);
        ss = KSP_SetKeyProperty(hProv, hFin, KSP_PUBLIC_EXPONENT_PROPERTY,
            (PBYTE)&exp, sizeof exp, 0);
        ASSERT_EQ("Exponent after Finalize → NTE_INVALID_HANDLE",
            ss, (SECURITY_STATUS)NTE_INVALID_HANDLE);
        KSP_Free((void *)(ULONG_PTR)hFin);
    }

    /* ── BCRYPT_ECC_CURVE_NAME: the standard CNG route to a curve ─────── */
    TEST_SUITE("SetKeyProperty — BCRYPT_ECC_CURVE_NAME");
    {
        /* A portable application creates a key with the generic ECDSA or
         * ECDH identifier and names the curve here, never mentioning
         * anything provider-specific. */
        struct { const WCHAR *generic; const WCHAR *curve;
                 const WCHAR *expect;  DWORD bits; } ok[] = {
            { BCRYPT_ECDSA_ALGORITHM, BCRYPT_ECC_CURVE_NISTP256,
              ALG_ECDSA_P256, 256 },
            { BCRYPT_ECDSA_ALGORITHM, BCRYPT_ECC_CURVE_NISTP521,
              ALG_ECDSA_P521, 521 },
            { BCRYPT_ECDH_ALGORITHM,  BCRYPT_ECC_CURVE_NISTP384,
              ALG_ECDH_P384,  384 },
            { BCRYPT_ECDSA_ALGORITHM, BCRYPT_ECC_CURVE_SECP256K1,
              ALG_ECDSA_SECP256K1, 256 },
            { BCRYPT_ECDSA_ALGORITHM, BCRYPT_ECC_CURVE_BRAINPOOLP256R1,
              ALG_ECDSA_BP256, 256 },
            { BCRYPT_ECDSA_ALGORITHM, BCRYPT_ECC_CURVE_BRAINPOOLP512R1,
              ALG_ECDSA_BP512, 512 },
            { BCRYPT_ECDH_ALGORITHM,  BCRYPT_ECC_CURVE_25519,
              ALG_ECDH_X25519, 255 },
        };
        size_t i;

        for (i = 0; i < sizeof ok / sizeof ok[0]; i++) {
            NCRYPT_KEY_HANDLE h =
                make_test_key(ok[i].generic, 0, AT_SIGNATURE, FALSE);
            KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
            char name[96];

            k->bCurvePending = TRUE;
            ss = KSP_SetKeyProperty(hProv, h, BCRYPT_ECC_CURVE_NAME,
                    (PBYTE)ok[i].curve,
                    (DWORD)(wcslen(ok[i].curve) * sizeof(WCHAR)), 0);
            sprintf(name, "%ls resolves", ok[i].curve);
            ASSERT_EQ(name, ss, (SECURITY_STATUS)ERROR_SUCCESS);
            ASSERT_WSTR("  ...to the right algorithm", k->szAlgId, ok[i].expect);
            ASSERT_EQ("  ...with the right length", k->dwKeyBitLen, ok[i].bits);
            ASSERT("  ...and the curve is no longer pending",
                   !k->bCurvePending);
            KSP_Free((void *)(ULONG_PTR)h);
        }
    }
    {
        /* Curve names are compared case-insensitively. CNG spells one of
         * them "secP256k1", so an exact match would be fragile. */
        NCRYPT_KEY_HANDLE h =
            make_test_key(BCRYPT_ECDSA_ALGORITHM, 0, AT_SIGNATURE, FALSE);
        KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)h;
        k->bCurvePending = TRUE;
        ss = KSP_SetKeyProperty(hProv, h, BCRYPT_ECC_CURVE_NAME,
                (PBYTE)L"SECP256K1", (DWORD)(9 * sizeof(WCHAR)), 0);
        ASSERT_OK("Curve name is case-insensitive", ss);
        ASSERT_WSTR("  still resolves", k->szAlgId, ALG_ECDSA_SECP256K1);
        KSP_Free((void *)(ULONG_PTR)h);
    }
    {
        /* A curve that cannot do what the generic algorithm asks must be
         * refused, not quietly reinterpreted: X25519 cannot sign, and no
         * ECDH form of secp256k1 is wired here. */
        NCRYPT_KEY_HANDLE h =
            make_test_key(BCRYPT_ECDSA_ALGORITHM, 0, AT_SIGNATURE, FALSE);
        ASSERT_EQ("X25519 under generic ECDSA → NTE_NOT_SUPPORTED",
            KSP_SetKeyProperty(hProv, h, BCRYPT_ECC_CURVE_NAME,
                (PBYTE)BCRYPT_ECC_CURVE_25519,
                (DWORD)(wcslen(BCRYPT_ECC_CURVE_25519) * sizeof(WCHAR)), 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        KSP_Free((void *)(ULONG_PTR)h);

        h = make_test_key(BCRYPT_ECDH_ALGORITHM, 0, AT_KEYEXCHANGE, FALSE);
        ASSERT_EQ("secp256k1 under generic ECDH → NTE_NOT_SUPPORTED",
            KSP_SetKeyProperty(hProv, h, BCRYPT_ECC_CURVE_NAME,
                (PBYTE)BCRYPT_ECC_CURVE_SECP256K1,
                (DWORD)(wcslen(BCRYPT_ECC_CURVE_SECP256K1) * sizeof(WCHAR)), 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        KSP_Free((void *)(ULONG_PTR)h);

        h = make_test_key(BCRYPT_ECDSA_ALGORITHM, 0, AT_SIGNATURE, FALSE);
        ASSERT_EQ("Unknown curve → NTE_NOT_SUPPORTED",
            KSP_SetKeyProperty(hProv, h, BCRYPT_ECC_CURVE_NAME,
                (PBYTE)L"nistP192", (DWORD)(8 * sizeof(WCHAR)), 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        ASSERT_EQ("Empty buffer → NTE_INVALID_PARAMETER",
            KSP_SetKeyProperty(hProv, h, BCRYPT_ECC_CURVE_NAME,
                (PBYTE)L"", 0, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);
        KSP_Free((void *)(ULONG_PTR)h);

        /* The curve cannot change after the key exists on the token. */
        h = make_test_key(ALG_ECDSA_P256, 256, AT_SIGNATURE, TRUE);
        ASSERT_EQ("After Finalize → NTE_INVALID_HANDLE",
            KSP_SetKeyProperty(hProv, h, BCRYPT_ECC_CURVE_NAME,
                (PBYTE)BCRYPT_ECC_CURVE_NISTP384,
                (DWORD)(wcslen(BCRYPT_ECC_CURVE_NISTP384) * sizeof(WCHAR)), 0),
            (SECURITY_STATUS)NTE_INVALID_HANDLE);
        KSP_Free((void *)(ULONG_PTR)h);
    }

    /* ── Suite : AuthTagLength and MessageBlockLength (phase 6) ────────── */
    TEST_SUITE("AuthTagLength and MessageBlockLength");

    /* Both arrived in phase 6 and were exercised only against the live
     * token, so the mock suite had no opinion on them at all. */
    {
        NCRYPT_KEY_HANDLE hAes = make_test_key(ALG_AES, 256, 0, TRUE);
        KSP_KEY          *k    = (KSP_KEY *)(ULONG_PTR)hAes;
        NCRYPT_KEY_HANDLE hRsaK = make_test_key(ALG_RSA, 2048, AT_SIGNATURE, TRUE);
        BCRYPT_AUTH_TAG_LENGTHS_STRUCT tags;
        DWORD cb = 0;
        DWORD dwBlock;
        BYTE  abJunk[4] = { 1, 2, 3, 4 };

        k->dwKeyClass = KSP_KEY_CLASS_SYMMETRIC;

        /* AuthTagLength is a read-only ALGORITHM property. Setting it used
         * to copy the caller's bytes into the key's AAD buffer. */
        ASSERT_EQ("Setting AuthTagLength is refused",
            KSP_SetKeyProperty(hProv, hAes, NCRYPT_AUTH_TAG_LENGTH,
                               abJunk, sizeof(abJunk), 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);

        /* An unauthenticated mode has no tag, so there is no range. */
        wcscpy_s(k->szChainingMode, MAX_ALG_ID_LEN, BCRYPT_CHAIN_MODE_CBC);
        ASSERT_EQ("CBC reports no tag range",
            KSP_GetKeyProperty(hProv, hAes, NCRYPT_AUTH_TAG_LENGTH,
                               (PBYTE)&tags, sizeof(tags), &cb, 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);

        wcscpy_s(k->szChainingMode, MAX_ALG_ID_LEN, BCRYPT_CHAIN_MODE_GCM);
        memset(&tags, 0, sizeof(tags));
        ASSERT_OK("GCM reports a tag range",
            KSP_GetKeyProperty(hProv, hAes, NCRYPT_AUTH_TAG_LENGTH,
                               (PBYTE)&tags, sizeof(tags), &cb, 0));
        ASSERT_EQ("of the documented struct size", cb, (DWORD)sizeof(tags));
        ASSERT("12..16 in steps of 1",
               tags.dwMinLength == 12 && tags.dwMaxLength == 16 &&
               tags.dwIncrement == 1);

        wcscpy_s(k->szChainingMode, MAX_ALG_ID_LEN, BCRYPT_CHAIN_MODE_CCM);
        memset(&tags, 0, sizeof(tags));
        ASSERT_OK("CCM reports a tag range",
            KSP_GetKeyProperty(hProv, hAes, NCRYPT_AUTH_TAG_LENGTH,
                               (PBYTE)&tags, sizeof(tags), &cb, 0));
        ASSERT("4..16 in steps of 2 — CCM does not take GCM's set",
               tags.dwMinLength == 4 && tags.dwMaxLength == 16 &&
               tags.dwIncrement == 2);

        ASSERT_EQ("An RSA key has no tag range at all",
            KSP_GetKeyProperty(hProv, hRsaK, NCRYPT_AUTH_TAG_LENGTH,
                               (PBYTE)&tags, sizeof(tags), &cb, 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);

        /* MessageBlockLength: the CFB feedback size. */
        dwBlock = 0;
        ASSERT_OK("Unset MessageBlockLength reads back",
            KSP_GetKeyProperty(hProv, hAes, BCRYPT_MESSAGE_BLOCK_LENGTH,
                               (PBYTE)&dwBlock, sizeof(dwBlock), &cb, 0));
        ASSERT_EQ("as 1 — CNG's default is 8-bit CFB, not the full block",
                  dwBlock, 1U);

        dwBlock = AES_BLOCK_SIZE;
        ASSERT_OK("The block size is accepted",
            KSP_SetKeyProperty(hProv, hAes, BCRYPT_MESSAGE_BLOCK_LENGTH,
                               (PBYTE)&dwBlock, sizeof(dwBlock), 0));
        dwBlock = 0;
        ASSERT_OK("and reads back",
            KSP_GetKeyProperty(hProv, hAes, BCRYPT_MESSAGE_BLOCK_LENGTH,
                               (PBYTE)&dwBlock, sizeof(dwBlock), &cb, 0));
        ASSERT_EQ("as the block size", dwBlock, (DWORD)AES_BLOCK_SIZE);

        dwBlock = 1;
        ASSERT_OK("1 is accepted",
            KSP_SetKeyProperty(hProv, hAes, BCRYPT_MESSAGE_BLOCK_LENGTH,
                               (PBYTE)&dwBlock, sizeof(dwBlock), 0));

        /* PKCS#11 has mechanisms for 1, 8, 64 and 128-bit feedback; this
         * provider wires the two CNG reaches. Anything else is refused
         * rather than rounded to a different cipher. */
        dwBlock = 8;
        ASSERT_OK("64-bit feedback (8 bytes) is accepted",
            KSP_SetKeyProperty(hProv, hAes, BCRYPT_MESSAGE_BLOCK_LENGTH,
                               (PBYTE)&dwBlock, sizeof(dwBlock), 0));

        /* 4 bytes is a size CNG permits and PKCS#11 names no mechanism
         * for, so it is refused rather than rounded. */
        dwBlock = 4;
        ASSERT_EQ("A feedback size with no PKCS#11 mechanism is refused",
            KSP_SetKeyProperty(hProv, hAes, BCRYPT_MESSAGE_BLOCK_LENGTH,
                               (PBYTE)&dwBlock, sizeof(dwBlock), 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);

        ASSERT_EQ("A wrong-sized value is refused",
            KSP_SetKeyProperty(hProv, hAes, BCRYPT_MESSAGE_BLOCK_LENGTH,
                               (PBYTE)&dwBlock, 2, 0),
            (SECURITY_STATUS)NTE_INVALID_PARAMETER);

        ASSERT_EQ("and an asymmetric key has no feedback size",
            KSP_SetKeyProperty(hProv, hRsaK, BCRYPT_MESSAGE_BLOCK_LENGTH,
                               (PBYTE)&dwBlock, sizeof(dwBlock), 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);

        KSP_Free((void *)(ULONG_PTR)hAes);
        KSP_Free((void *)(ULONG_PTR)hRsaK);
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
