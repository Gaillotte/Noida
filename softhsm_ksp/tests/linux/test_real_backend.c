/* test_real_backend.c — the provider against a PKCS#11 module nobody here wrote.
 *
 * Everything else this project knows about itself comes from
 * tests/mock/p11_mock.c, which I wrote to behave the way I believed a token
 * behaves. That is fine for pinning down the provider's own logic and
 * worthless for the one claim the architecture rests on: that any PKCS#11
 * v2.40+ module can back this provider, and that the capability probe
 * narrows what it advertises to what that module actually implements.
 *
 * A mock cannot test that claim. It can only agree with it.
 *
 * So this runs the real p11_context.c, p11_caps.c, p11_session.c and the
 * KSP layer — the same source the Windows DLL compiles — against Kryoptic,
 * a PKCS#11 token written in Rust by people who have never heard of this
 * repository. The only thing swapped in is the loader: LoadLibraryW becomes
 * dlopen (tests/linux/p11_real_loader.c) instead of the mock's fake handle.
 *
 * The Kryoptic build this runs against is deliberately NOT the full one.
 * It is configured without eddsa and without the post-quantum mechanisms,
 * so its mechanism list differs from SoftHSM2's in ways the provider must
 * notice. A probe that reported the same answers for both tokens would be
 * reporting the compiled-in list, which is the bug phase 4 existed to fix.
 *
 *   KSP_PKCS11_LIB   path to the module      (set by the caller)
 *   SOFTHSM2_PIN     user PIN for the token  (historic name, any module)
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/pkcs11/p11_session.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_properties.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/common/config.h"
#include "../../src/common/memory.h"
#include "../unit/test_framework.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

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
    NCryptAlgorithmName *pList = NULL;
    DWORD                cAlgs = 0;
    const char          *pszModule = getenv("KSP_PKCS11_LIB");

    if (!pszModule || !*pszModule) {
        fprintf(stderr,
            "KSP_PKCS11_LIB is not set — this suite needs a real module.\n");
        return 2;
    }
    printf("module under test: %s\n\n", pszModule);

    /* ── Suite 1 : the provider loads a module it has never seen ────────── */
    TEST_SUITE("Initialisation against a second backend");

    /* No mock anywhere in this process. P11_Initialize does what it does on
     * Windows: read the path, load the module, C_Initialize, pick a slot,
     * probe the token. */
    ss = P11_Initialize();
    ASSERT_OK("P11_Initialize against a real module", ss);
    ASSERT("A function list was obtained",
        P11_GetContext()->pFunctionList != NULL);
    ASSERT("Context reports itself initialised",
        P11_GetContext()->bInitialized);

    ss = P11_SessionPool_Initialize();
    ASSERT_OK("Session pool initialised", ss);

    /* ── Suite 2 : the probe read THIS token ───────────────────────────── */
    TEST_SUITE("Capability probe");

    ASSERT("The token was probed", P11_CapsProbed());

    {
        CK_BYTE bMajor = 0, bMinor = 0;
        P11_GetCryptokiVersion(&bMajor, &bMinor);
        printf("  token reports Cryptoki %u.%u\n",
               (unsigned)bMajor, (unsigned)bMinor);
        ASSERT("Cryptoki version is at least 2.40",
            P11_CryptokiAtLeast(2, 40));
    }

    /* What this build of Kryoptic has. */
    ASSERT("RSA key pair generation present",
        P11_HasMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN));
    ASSERT("RSA PKCS#1 present", P11_HasMechanism(CKM_RSA_PKCS));
    ASSERT("EC key pair generation present",
        P11_HasMechanism(CKM_EC_KEY_PAIR_GEN));
    ASSERT("ECDSA present", P11_HasMechanism(CKM_ECDSA));
    ASSERT("AES key generation present", P11_HasMechanism(CKM_AES_KEY_GEN));

    /* And what it does not. These are the assertions that would be
     * meaningless against the mock: the provider is reporting a real
     * token's absences, not a list compiled into itself. SoftHSM2 has
     * CKM_EDDSA; this Kryoptic build is configured without it. */
    ASSERT("CKM_EDDSA absent — this build has no eddsa feature",
        !P11_HasMechanism(CKM_EDDSA));
    ASSERT("CKM_ML_DSA absent — no post-quantum in this build",
        !P11_HasMechanism(CKM_ML_DSA));

    /* ── Suite 3 : advertisement follows the token ──────────────────────── */
    TEST_SUITE("EnumAlgorithms reflects this token");

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_OK("Provider opened", ss);

    ss = KSP_EnumAlgorithms(hProv, 0, &cAlgs, &pList, 0);
    ASSERT_OK("EnumAlgorithms", ss);
    printf("  provider advertises %lu algorithms\n", (unsigned long)cAlgs);

    ASSERT("RSA advertised", Advertises(pList, cAlgs, ALG_RSA));
    ASSERT("ECDSA_P256 advertised", Advertises(pList, cAlgs, ALG_ECDSA_P256));
    ASSERT("AES advertised", Advertises(pList, cAlgs, ALG_AES));
    /* ML-DSA is wired into this provider and must stay dark here. */
    ASSERT("ML-DSA-65 NOT advertised",
        !Advertises(pList, cAlgs, ALG_MLDSA_65));
    KSP_FreeBuffer(pList);

    ASSERT_OK("IsAlgSupported(RSA)", KSP_IsAlgSupported(hProv, ALG_RSA, 0));
    ASSERT_EQ("IsAlgSupported(ML-DSA-65) → NTE_NOT_SUPPORTED",
        KSP_IsAlgSupported(hProv, ALG_MLDSA_65, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    /* ── Suite 4 : a real key, on a real token ─────────────────────────── */
    TEST_SUITE("RSA key generation and signing");

    /* Delete any leftover from a previous run so the suite is re-runnable. */
    {
        NCRYPT_KEY_HANDLE hOld = 0;
        if (KSP_OpenKey(hProv, &hOld, L"phase7-rsa", 0, 0) == ERROR_SUCCESS) {
            KSP_DeleteKey(hProv, hOld, 0);
        }
    }

    ss = KSP_CreatePersistedKey(hProv, &hKey, ALG_RSA, L"phase7-rsa", 0, 0);
    ASSERT_OK("RSA-2048 generated on the token", ss);
    ASSERT("Key handle returned", hKey != 0);

    {
        BYTE  abHash[32];
        BYTE  abSig[512];
        DWORD cbSig = 0;
        DWORD i;

        for (i = 0; i < sizeof(abHash); i++)
            abHash[i] = (BYTE)i;

        cbSig = 0;
        ss = KSP_SignHash(hProv, hKey, NULL, abHash, sizeof(abHash),
                          NULL, 0, &cbSig, NCRYPT_PAD_PKCS1_FLAG);
        ASSERT_OK("Signature size query", ss);
        ASSERT_EQ("RSA-2048 signature is 256 bytes", cbSig, 256U);

        memset(abSig, 0, sizeof(abSig));
        cbSig = 0;
        ss = KSP_SignHash(hProv, hKey, NULL, abHash, sizeof(abHash),
                          abSig, sizeof(abSig), &cbSig, NCRYPT_PAD_PKCS1_FLAG);
        ASSERT_OK("Signed by the token", ss);
        ASSERT_EQ("256 bytes returned", cbSig, 256U);

        /* A token that returned a zero-filled buffer would pass every
         * length check above. */
        {
            BOOL bAllZero = TRUE;
            for (i = 0; i < cbSig; i++)
                if (abSig[i] != 0) { bAllZero = FALSE; break; }
            ASSERT("The signature is not all zeroes", !bAllZero);
        }
    }

    /* ── Suite 5 : the public key comes back in CNG's shape ────────────── */
    TEST_SUITE("Public key export");

    {
        BYTE  abBlob[1024];
        DWORD cbBlob = 0;

        ss = KSP_ExportKey(hProv, hKey, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
                           NULL, 0, &cbBlob, 0);
        ASSERT_OK("Export size query", ss);
        ASSERT("A blob size was reported", cbBlob > 0);

        ss = KSP_ExportKey(hProv, hKey, 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
                           abBlob, sizeof(abBlob), &cbBlob, 0);
        ASSERT_OK("Exported", ss);

        {
            BCRYPT_RSAKEY_BLOB *p = (BCRYPT_RSAKEY_BLOB *)abBlob;
            ASSERT_EQ("Magic is BCRYPT_RSAPUBLIC_MAGIC",
                p->Magic, (ULONG)BCRYPT_RSAPUBLIC_MAGIC);
            ASSERT_EQ("2048-bit modulus", p->BitLength, 2048U);
            ASSERT("Modulus present", p->cbModulus == 256);
            ASSERT("Public exponent present", p->cbPublicExp > 0);
        }
    }

    /* ── Suite 6 : an EC key, to exercise a different mechanism ─────────── */
    TEST_SUITE("ECDSA P-256");

    {
        NCRYPT_KEY_HANDLE hEc = 0;
        BYTE  abHash[32];
        BYTE  abSig[256];
        DWORD cbSig = 0;

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-ec", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hEc, ALG_ECDSA_P256,
                                    L"phase7-ec", 0, 0);
        ASSERT_OK("P-256 key generated on the token", ss);

        memset(abHash, 0x7C, sizeof(abHash));
        cbSig = 0;
        ss = KSP_SignHash(hProv, hEc, NULL, abHash, sizeof(abHash),
                          abSig, sizeof(abSig), &cbSig, 0);
        ASSERT_OK("ECDSA signature produced", ss);
        /* The token returns DER; the provider converts to CNG's raw r||s.
         * This is the conversion that a mock can only ever confirm against
         * a DER blob the same test wrote. */
        ASSERT_EQ("Converted to 64-byte raw r||s", cbSig, 64U);

        ss = KSP_DeleteKey(hProv, hEc, 0);
        ASSERT_OK("EC key deleted from the token", ss);
    }

    /* ── Suite 7 : enumeration and cleanup ──────────────────────────────── */
    TEST_SUITE("EnumKeys and deletion");

    {
        NCryptKeyName *pName  = NULL;
        PVOID          pState = NULL;
        int            nFound = 0;
        BOOL           bFoundOurs = FALSE;

        while (KSP_EnumKeys(hProv, NULL, &pName, &pState, 0) == ERROR_SUCCESS
               && pName) {
            nFound++;
            if (pName->pszName && _wcsicmp(pName->pszName, L"phase7-rsa") == 0)
                bFoundOurs = TRUE;
            KSP_FreeBuffer(pName);
            pName = NULL;
        }
        if (pState) KSP_FreeBuffer(pState);

        ASSERT("Enumeration found at least one key", nFound > 0);
        ASSERT("and it found the key this suite created", bFoundOurs);
    }

    ss = KSP_DeleteKey(hProv, hKey, 0);
    ASSERT_OK("RSA key deleted from the token", ss);

    KSP_FreeProvider(hProv);
    P11_SessionPool_Finalize();
    P11_Finalize();

    TEST_REPORT();
    TEST_EXIT();
}
