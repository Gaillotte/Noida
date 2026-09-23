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


    /* ── Suite 8 : ECDH agreement and the KDFs ─────────────────────────────
     *
     * The most provider logic between CNG and the token of anything here:
     * the peer's public key arrives as a CNG blob, is imported as a PKCS#11
     * object, agreed with CKM_ECDH1_DERIVE, and the raw Z is then run
     * through whichever KDF the caller named. None of it had ever met a
     * real token. */
    TEST_SUITE("ECDH agreement");

    {
        NCRYPT_KEY_HANDLE    hAlice = 0, hBob = 0, hPeer = 0;
        NCRYPT_SECRET_HANDLE hSecret = 0;
        BYTE   abPeerBlob[512];
        DWORD  cbPeerBlob = 0;

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-dh-a", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
            hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-dh-b", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hAlice, ALG_ECDH_P256,
                                    L"phase7-dh-a", 0, 0);
        ASSERT_OK("ECDH P-256 key A generated", ss);
        ss = KSP_CreatePersistedKey(hProv, &hBob, ALG_ECDH_P256,
                                    L"phase7-dh-b", 0, 0);
        ASSERT_OK("ECDH P-256 key B generated", ss);

        /* B's public half, in CNG's blob format, then back in as a peer. */
        cbPeerBlob = 0;
        ss = KSP_ExportKey(hProv, hBob, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
                           abPeerBlob, sizeof(abPeerBlob), &cbPeerBlob, 0);
        ASSERT_OK("B's public key exported", ss);
        ASSERT("Blob is not empty", cbPeerBlob > 0);

        ss = KSP_ImportKey(hProv, 0, BCRYPT_ECCPUBLIC_BLOB, NULL,
                           &hPeer, abPeerBlob, cbPeerBlob, 0);
        ASSERT_OK("and imported as a peer public key", ss);

        ss = KSP_SecretAgreement(hProv, hAlice, hPeer, &hSecret, 0);
        ASSERT_OK("Secret agreement on the token", ss);
        ASSERT("A secret handle came back", hSecret != 0);

        if (ss == ERROR_SUCCESS) {
            BYTE  abZ[64], abZ2[64], abHash[64], abHkdf[32];
            DWORD cbZ = 0, cbZ2 = 0, cbHash = 0, cbHkdf = 0;
            DWORD i;

            ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                               abZ, sizeof(abZ), &cbZ, 0);
            ASSERT_OK("Raw Z derived", ss);
            ASSERT_EQ("P-256 shared secret is 32 bytes", cbZ, 32U);

            {
                BOOL bZero = TRUE;
                for (i = 0; i < cbZ; i++)
                    if (abZ[i] != 0) { bZero = FALSE; break; }
                ASSERT("The shared secret is not all zeroes", !bZero);
            }

            /* Deriving twice from the same secret must be stable. */
            ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_RAW_SECRET, NULL,
                               abZ2, sizeof(abZ2), &cbZ2, 0);
            ASSERT_OK("Raw Z derived again", ss);
            ASSERT_EQ("same length", cbZ2, cbZ);
            ASSERT("and the same bytes", memcmp(abZ, abZ2, cbZ) == 0);

            ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HASH, NULL,
                               abHash, sizeof(abHash), &cbHash, 0);
            ASSERT_OK("Hash KDF", ss);
            ASSERT("produced output", cbHash > 0);

            ss = KSP_DeriveKey(hProv, hSecret, BCRYPT_KDF_HKDF, NULL,
                               abHkdf, sizeof(abHkdf), &cbHkdf, 0);
            ASSERT_OK("HKDF", ss);
            ASSERT_EQ("filled the requested length", cbHkdf, 32U);

            /* A KDF the provider refuses on purpose. */
            {
                BYTE  abTls[48];
                DWORD cbTls = 0;
                ss = KSP_DeriveKey(hProv, hSecret, L"TLS_PRF_1_1", NULL,
                                   abTls, sizeof(abTls), &cbTls, 0);
                ASSERT_ERR("An unknown KDF is refused", ss);
            }

            KSP_FreeSecret(hProv, hSecret);
        }

        if (hPeer) KSP_FreeKey(hProv, hPeer);
        ss = KSP_DeleteKey(hProv, hAlice, 0);
        ASSERT_OK("ECDH key A deleted", ss);
        ss = KSP_DeleteKey(hProv, hBob, 0);
        ASSERT_OK("ECDH key B deleted", ss);
    }

    /* ── Suite 9 : AES through a KSP ───────────────────────────────────── */
    TEST_SUITE("AES encryption");

    {
        NCRYPT_KEY_HANDLE hAes = 0;
        BYTE  abPlain[32];
        BYTE  abCipher[128];
        BYTE  abBack[128];
        BYTE  abIv[AES_BLOCK_SIZE];
        DWORD cbCipher = 0, cbBack = 0;
        DWORD i;

        for (i = 0; i < sizeof(abPlain); i++) abPlain[i] = (BYTE)(i * 3);
        memset(abIv, 0x5A, sizeof(abIv));

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-aes", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hAes, ALG_AES, L"phase7-aes", 0, 0);
        ASSERT_OK("AES-256 key generated on the token", ss);

        ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_CHAINING_MODE_PROPERTY,
                                (PBYTE)BCRYPT_CHAIN_MODE_CBC,
                                (DWORD)((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1)
                                        * sizeof(WCHAR)), 0);
        ASSERT_OK("CBC chaining mode set", ss);
        ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_INITIALIZATION_VECTOR,
                                abIv, sizeof(abIv), 0);
        ASSERT_OK("IV set", ss);

        cbCipher = 0;
        ss = KSP_Encrypt(hProv, hAes, abPlain, sizeof(abPlain), NULL,
                         abCipher, sizeof(abCipher), &cbCipher, 0);
        ASSERT_OK("AES-CBC encryption on the token", ss);
        ASSERT_EQ("two blocks in, two blocks out", cbCipher, 32U);
        ASSERT("The ciphertext differs from the plaintext",
               memcmp(abCipher, abPlain, sizeof(abPlain)) != 0);

        /* The round trip is the assertion that matters — a mock can return
         * any bytes and call them ciphertext. */
        ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_INITIALIZATION_VECTOR,
                                abIv, sizeof(abIv), 0);
        ASSERT_OK("IV reset for decryption", ss);

        cbBack = 0;
        ss = KSP_Decrypt(hProv, hAes, abCipher, cbCipher, NULL,
                         abBack, sizeof(abBack), &cbBack, 0);
        ASSERT_OK("AES-CBC decryption", ss);
        ASSERT_EQ("plaintext length restored", cbBack, (DWORD)sizeof(abPlain));
        ASSERT("and the plaintext round-trips",
               memcmp(abBack, abPlain, sizeof(abPlain)) == 0);

        ss = KSP_DeleteKey(hProv, hAes, 0);
        ASSERT_OK("AES key deleted", ss);
    }

    /* ── Suite 10 : the certificate property, on a real token ──────────── */
    TEST_SUITE("Certificate storage");

    {
        NCRYPT_KEY_HANDLE hCertKey = 0;
        BYTE  abRead[2048];
        DWORD cbRead = 0;

        /* A real certificate, not a shaped blob. Kryoptic requires
         * CKA_SUBJECT — it answers CKR_TEMPLATE_INCONSISTENT without one —
         * so this is what exercises P11_ExtractCertSubject end to end. A
         * fake blob would take the empty-Name fallback and prove nothing
         * about the parser. The bytes and the expected subject offset are
         * pinned in tests/unit/test_cert_subject.c. */
        extern const BYTE g_realCert[];
        extern const DWORD g_cbRealCert;
        const BYTE *abCert = g_realCert;
        const DWORD cbCert = g_cbRealCert;

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-cert", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hCertKey, ALG_RSA,
                                    L"phase7-cert", 0, 0);
        ASSERT_OK("Key for enrolment generated", ss);

        /* Before enrolment there is no certificate, and that is not an
         * error — it is the normal state of a freshly generated key. */
        cbRead = 0;
        ss = KSP_GetKeyProperty(hProv, hCertKey, NCRYPT_CERTIFICATE_PROPERTY,
                                NULL, 0, &cbRead, 0);
        ASSERT_EQ("No certificate yet → NTE_NOT_FOUND",
                  ss, (SECURITY_STATUS)NTE_NOT_FOUND);

        ss = KSP_SetKeyProperty(hProv, hCertKey, NCRYPT_CERTIFICATE_PROPERTY,
                                (PBYTE)abCert, cbCert, 0);
        /* This is the assertion that failed before CKA_SUBJECT was set:
         * Kryoptic refused the object outright. */
        ASSERT_OK("Certificate stored on a token that requires CKA_SUBJECT",
                  ss);

        cbRead = 0;
        ss = KSP_GetKeyProperty(hProv, hCertKey, NCRYPT_CERTIFICATE_PROPERTY,
                                abRead, sizeof(abRead), &cbRead, 0);
        ASSERT_OK("Certificate read back", ss);
        ASSERT_EQ("same length", cbRead, cbCert);
        ASSERT("and the same bytes", memcmp(abRead, abCert, cbCert) == 0);

        ss = KSP_DeleteKey(hProv, hCertKey, 0);
        ASSERT_OK("Key deleted", ss);
    }


    /* ── Suite 11 : AES-CMAC (AES-10, phase 5) ──────────────────────────── */
    TEST_SUITE("AES-CMAC");

    {
        NCRYPT_KEY_HANDLE hCmac = 0;
        BYTE  abData[32];
        BYTE  abMac[64];
        DWORD cbMac = 0;

        memset(abData, 0x4D, sizeof(abData));

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-cmac", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ASSERT("The token implements CKM_AES_CMAC",
               P11_HasMechanism(CKM_AES_CMAC));

        ss = KSP_CreatePersistedKey(hProv, &hCmac, BCRYPT_AES_CMAC_ALGORITHM,
                                    L"phase7-cmac", 0, 0);
        ASSERT_OK("CMAC key generated on the token", ss);

        cbMac = 0;
        ss = KSP_SignHash(hProv, hCmac, NULL, abData, sizeof(abData),
                          NULL, 0, &cbMac, 0);
        ASSERT_OK("MAC size query", ss);
        ASSERT_EQ("CMAC is one AES block", cbMac, (DWORD)AES_BLOCK_SIZE);

        memset(abMac, 0, sizeof(abMac));
        cbMac = 0;
        ss = KSP_SignHash(hProv, hCmac, NULL, abData, sizeof(abData),
                          abMac, sizeof(abMac), &cbMac, 0);
        ASSERT_OK("MAC produced by the token", ss);
        ASSERT_EQ("16 bytes returned", cbMac, (DWORD)AES_BLOCK_SIZE);

        {
            BOOL bZero = TRUE;
            DWORD i;
            for (i = 0; i < cbMac; i++)
                if (abMac[i] != 0) { bZero = FALSE; break; }
            ASSERT("and it is not all zeroes", !bZero);
        }

        ss = KSP_DeleteKey(hProv, hCmac, 0);
        ASSERT_OK("CMAC key deleted", ss);
    }

    /* ── Suite 12 : HMAC ────────────────────────────────────────────────── */
    TEST_SUITE("HMAC");

    {
        NCRYPT_KEY_HANDLE hMac = 0;
        BYTE  abData[32];
        BYTE  abMac[128];
        DWORD cbMac = 0;

        memset(abData, 0x68, sizeof(abData));

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-hmac", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hMac, ALG_HMAC_SHA256,
                                    L"phase7-hmac", 0, 0);
        ASSERT_OK("HMAC-SHA256 key generated on the token", ss);

        cbMac = 0;
        ss = KSP_SignHash(hProv, hMac, NULL, abData, sizeof(abData),
                          abMac, sizeof(abMac), &cbMac, 0);
        ASSERT_OK("HMAC produced by the token", ss);
        ASSERT_EQ("SHA-256 HMAC is 32 bytes", cbMac, 32U);

        ss = KSP_DeleteKey(hProv, hMac, 0);
        ASSERT_OK("HMAC key deleted", ss);
    }

    /* ── Suite 13 : AES key wrap (AES-09, phase 5) ──────────────────────── */
    TEST_SUITE("AES key wrap");

    {
        NCRYPT_KEY_HANDLE hKek = 0;
        NCRYPT_KEY_HANDLE hTarget = 0;

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-kek", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
            hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-wrapped", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ASSERT("The token implements CKM_AES_KEY_WRAP",
               P11_HasMechanism(CKM_AES_KEY_WRAP));

        ss = KSP_CreatePersistedKey(hProv, &hKek, ALG_AES, L"phase7-kek", 0, 0);
        ASSERT_OK("Key-encryption key generated", ss);
        ss = KSP_CreatePersistedKey(hProv, &hTarget, ALG_AES,
                                    L"phase7-wrapped", 0, 0);
        ASSERT_OK("Target key generated", ss);

        /* Wrapping a key this provider created must fail, and the token is
         * what refuses it: every key here is CKA_EXTRACTABLE=FALSE. This is
         * the posture working, not a defect. */
        {
            BYTE  abWrapped[128];
            DWORD cbWrapped = 0;

            ss = KSP_ExportKey(hProv, hTarget, hKek, BCRYPT_AES_WRAP_KEY_BLOB,
                               NULL, abWrapped, sizeof(abWrapped),
                               &cbWrapped, 0);
            ASSERT_EQ("Wrapping a non-extractable key → NTE_NOT_SUPPORTED",
                      ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);
        }

        /* Unwrap is the direction that works anywhere. A genuinely wrapped
         * blob is needed, and only the token can make one — so an
         * extractable key is created directly through the function list,
         * wrapped by the token, and the blob handed to the provider. */
        {
            P11_CONTEXT      *pCtx = P11_GetContext();
            CK_SESSION_HANDLE hSess = CK_INVALID_HANDLE;
            CK_OBJECT_HANDLE  hPlain = CK_INVALID_HANDLE;
            KSP_KEY          *pKek = (KSP_KEY *)(ULONG_PTR)hKek;
            BYTE   abBlob[128];
            CK_ULONG cbBlob = sizeof(abBlob);
            CK_RV  rv = CKR_OK;

            if (P11_AcquireSession(&hSess) == ERROR_SUCCESS) {
                CK_MECHANISM    gen  = { CKM_AES_KEY_GEN, NULL, 0 };
                CK_MECHANISM    wrap = { CKM_AES_KEY_WRAP, NULL, 0 };
                CK_OBJECT_CLASS cls  = CKO_SECRET_KEY;
                CK_KEY_TYPE     kt   = CKK_AES;
                CK_ULONG        len  = 32;
                CK_BBOOL        T = CK_TRUE, F = CK_FALSE;
                CK_ATTRIBUTE    t[] = {
                    { CKA_CLASS,       &cls, sizeof(cls) },
                    { CKA_KEY_TYPE,    &kt,  sizeof(kt)  },
                    { CKA_TOKEN,       &F,   sizeof(F)   },
                    { CKA_VALUE_LEN,   &len, sizeof(len) },
                    { CKA_SENSITIVE,   &F,   sizeof(F)   },
                    { CKA_EXTRACTABLE, &T,   sizeof(T)   },
                };

                rv = pCtx->pFunctionList->C_GenerateKey(hSess, &gen, t, 6,
                                                        &hPlain);
                ASSERT_EQ("An extractable key made directly on the token",
                          (DWORD)rv, (DWORD)CKR_OK);

                if (rv == CKR_OK) {
                    rv = pCtx->pFunctionList->C_WrapKey(hSess, &wrap,
                                                        pKek->hSecretKey,
                                                        hPlain,
                                                        abBlob, &cbBlob);
                    ASSERT_EQ("and wrapped by the token", (DWORD)rv,
                              (DWORD)CKR_OK);
                    pCtx->pFunctionList->C_DestroyObject(hSess, hPlain);
                }
                P11_ReleaseSession(hSess);
            }

            if (rv == CKR_OK) {
                NCRYPT_KEY_HANDLE hUnwrapped = 0;

                ss = KSP_ImportKey(hProv, hKek, BCRYPT_AES_WRAP_KEY_BLOB,
                                   NULL, &hUnwrapped, abBlob,
                                   (DWORD)cbBlob, 0);
                ASSERT_OK("A genuinely wrapped key unwraps through the KSP",
                          ss);
                ASSERT("and a handle comes back", hUnwrapped != 0);

                if (hUnwrapped) {
                    KSP_KEY *pNew = (KSP_KEY *)(ULONG_PTR)hUnwrapped;
                    ASSERT("holding a real token object",
                           pNew->hSecretKey != CK_INVALID_HANDLE);
                    KSP_FreeKey(hProv, hUnwrapped);
                }
            }
        }

        ss = KSP_DeleteKey(hProv, hTarget, 0);
        ASSERT_OK("Target key deleted", ss);
        ss = KSP_DeleteKey(hProv, hKek, 0);
        ASSERT_OK("KEK deleted", ss);
    }

    /* ── Suite 14 : per-key PIN (PROP-13, phase 5) ──────────────────────── */
    TEST_SUITE("Per-key PIN");

    {
        NCRYPT_KEY_HANDLE hPinKey = 0;
        BYTE  abHash[32];
        BYTE  abSig[512];
        DWORD cbSig = 0;

        memset(abHash, 0x9A, sizeof(abHash));

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-pin", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hPinKey, ALG_RSA,
                                    L"phase7-pin", 0, 0);
        ASSERT_OK("Key generated", ss);

        ss = KSP_SetKeyProperty(hProv, hPinKey, NCRYPT_PIN_PROPERTY,
                                (PBYTE)L"1234", 4 * sizeof(WCHAR), 0);
        ASSERT_OK("Per-key PIN accepted", ss);

        /* This key is not CKA_ALWAYS_AUTHENTICATE, so the token has no
         * re-authentication to perform and answers
         * CKR_OPERATION_NOT_INITIALIZED. Tolerating that is what keeps a
         * caller from being punished for supplying a credential the key
         * never needed — and this is the first time that tolerance has been
         * exercised against a token rather than a mock. */
        cbSig = 0;
        ss = KSP_SignHash(hProv, hPinKey, NULL, abHash, sizeof(abHash),
                          abSig, sizeof(abSig), &cbSig, NCRYPT_PAD_PKCS1_FLAG);
        ASSERT_OK("Signing still works with a PIN the key does not need", ss);
        ASSERT_EQ("and produces a full signature", cbSig, 256U);

        ss = KSP_DeleteKey(hProv, hPinKey, 0);
        ASSERT_OK("Key deleted", ss);
    }


    /* ── Suite 15 : RSA decryption, both paddings ───────────────────────── */
    TEST_SUITE("RSA decryption");

    {
        NCRYPT_KEY_HANDLE hDec = 0;
        P11_CONTEXT      *pCtx = P11_GetContext();
        BYTE   abPlain[32];
        BYTE   abCipher[512];
        BYTE   abBack[512];
        DWORD  cbBack = 0;
        DWORD  i;

        for (i = 0; i < sizeof(abPlain); i++) abPlain[i] = (BYTE)(0xE0 ^ i);

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-dec", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        /* AT_KEYEXCHANGE, so the public half carries CKA_ENCRYPT and the
         * token can produce its own ciphertext — no second crypto library
         * in the test, and the bytes under test come from the same
         * implementation that must undo them. */
        ss = KSP_CreatePersistedKey(hProv, &hDec, ALG_RSA, L"phase7-dec",
                                    AT_KEYEXCHANGE, 0);
        ASSERT_OK("RSA key-exchange key generated", ss);

        /* ---- PKCS#1 v1.5 ---- */
        {
            KSP_KEY          *pDec = (KSP_KEY *)(ULONG_PTR)hDec;
            CK_SESSION_HANDLE hSess = CK_INVALID_HANDLE;
            CK_MECHANISM      mech = { CKM_RSA_PKCS, NULL, 0 };
            CK_ULONG          cbCipher = sizeof(abCipher);
            CK_RV             rv = CKR_GENERAL_ERROR;

            if (P11_AcquireSession(&hSess) == ERROR_SUCCESS) {
                rv = pCtx->pFunctionList->C_EncryptInit(hSess, &mech,
                                                        pDec->hPubKey);
                if (rv == CKR_OK)
                    rv = pCtx->pFunctionList->C_Encrypt(hSess, abPlain,
                            (CK_ULONG)sizeof(abPlain), abCipher, &cbCipher);
                P11_ReleaseSession(hSess);
            }
            ASSERT_EQ("Token encrypted with PKCS#1 v1.5",
                      (DWORD)rv, (DWORD)CKR_OK);

            if (rv == CKR_OK) {
                cbBack = 0;
                ss = KSP_Decrypt(hProv, hDec, abCipher, (DWORD)cbCipher, NULL,
                                 abBack, sizeof(abBack), &cbBack,
                                 NCRYPT_PAD_PKCS1_FLAG);
                ASSERT_OK("PKCS#1 decryption through the KSP", ss);
                ASSERT_EQ("plaintext length restored", cbBack,
                          (DWORD)sizeof(abPlain));
                ASSERT("and the plaintext round-trips",
                       memcmp(abBack, abPlain, sizeof(abPlain)) == 0);
            }
        }

        /* ---- OAEP, SHA-256 ---- */
        {
            KSP_KEY          *pDec = (KSP_KEY *)(ULONG_PTR)hDec;
            CK_SESSION_HANDLE hSess = CK_INVALID_HANDLE;
            CK_RSA_PKCS_OAEP_PARAMS oaep;
            CK_MECHANISM      mech;
            CK_ULONG          cbCipher = sizeof(abCipher);
            CK_RV             rv = CKR_GENERAL_ERROR;
            BCRYPT_OAEP_PADDING_INFO oaepInfo;

            memset(&oaep, 0, sizeof(oaep));
            oaep.hashAlg    = CKM_SHA256;
            oaep.mgf        = CKG_MGF1_SHA256;
            oaep.source     = 0;
            oaep.pSourceData = NULL;
            oaep.ulSourceDataLen = 0;

            mech.mechanism      = CKM_RSA_PKCS_OAEP;
            mech.pParameter     = &oaep;
            mech.ulParameterLen = sizeof(oaep);

            if (P11_AcquireSession(&hSess) == ERROR_SUCCESS) {
                rv = pCtx->pFunctionList->C_EncryptInit(hSess, &mech,
                                                        pDec->hPubKey);
                if (rv == CKR_OK)
                    rv = pCtx->pFunctionList->C_Encrypt(hSess, abPlain,
                            (CK_ULONG)sizeof(abPlain), abCipher, &cbCipher);
                P11_ReleaseSession(hSess);
            }
            ASSERT_EQ("Token encrypted with OAEP-SHA256",
                      (DWORD)rv, (DWORD)CKR_OK);

            if (rv == CKR_OK) {
                oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
                oaepInfo.pbLabel  = NULL;
                oaepInfo.cbLabel  = 0;

                cbBack = 0;
                ss = KSP_Decrypt(hProv, hDec, abCipher, (DWORD)cbCipher,
                                 &oaepInfo, abBack, sizeof(abBack), &cbBack,
                                 NCRYPT_PAD_OAEP_FLAG);
                ASSERT_OK("OAEP decryption through the KSP", ss);
                ASSERT_EQ("plaintext length restored", cbBack,
                          (DWORD)sizeof(abPlain));
                ASSERT("and the plaintext round-trips",
                       memcmp(abBack, abPlain, sizeof(abPlain)) == 0);
            }
        }

        ss = KSP_DeleteKey(hProv, hDec, 0);
        ASSERT_OK("Key-exchange key deleted", ss);
    }

    /* ── Suite 16 : RSA-PSS signing ─────────────────────────────────────── */
    TEST_SUITE("RSA-PSS");

    {
        NCRYPT_KEY_HANDLE hPss = 0;
        BCRYPT_PSS_PADDING_INFO pssInfo;
        BYTE  abHash[32];
        BYTE  abSig[512];
        DWORD cbSig = 0;

        memset(abHash, 0x2B, sizeof(abHash));
        pssInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        pssInfo.cbSalt   = 32;

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-pss", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hPss, ALG_RSA, L"phase7-pss", 0, 0);
        ASSERT_OK("RSA signing key generated", ss);

        cbSig = 0;
        ss = KSP_SignHash(hProv, hPss, &pssInfo, abHash, sizeof(abHash),
                          abSig, sizeof(abSig), &cbSig, NCRYPT_PAD_PSS_FLAG);
        ASSERT_OK("PSS signature produced by the token", ss);
        ASSERT_EQ("and is the modulus length", cbSig, 256U);

        /* PSS is randomised: two signatures over the same hash must differ,
         * which also proves the salt reached the token. */
        {
            BYTE  abSig2[512];
            DWORD cbSig2 = 0;
            ss = KSP_SignHash(hProv, hPss, &pssInfo, abHash, sizeof(abHash),
                              abSig2, sizeof(abSig2), &cbSig2,
                              NCRYPT_PAD_PSS_FLAG);
            ASSERT_OK("A second PSS signature", ss);
            ASSERT("differs from the first — PSS is randomised",
                   memcmp(abSig, abSig2, cbSig) != 0);
        }

        ss = KSP_DeleteKey(hProv, hPss, 0);
        ASSERT_OK("PSS key deleted", ss);
    }

    /* ── Suite 17 : the other AES chaining modes ────────────────────────── */
    TEST_SUITE("AES chaining modes");

    {
        NCRYPT_KEY_HANDLE hAes = 0;
        BYTE  abPlain[32];
        BYTE  abCipher[128];
        BYTE  abBack[128];
        DWORD cbCipher = 0, cbBack = 0;
        DWORD i;

        for (i = 0; i < sizeof(abPlain); i++) abPlain[i] = (BYTE)(i + 1);

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-modes", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hAes, ALG_AES, L"phase7-modes",
                                    0, 0);
        ASSERT_OK("AES key generated", ss);

        /* ECB takes no IV. */
        ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_CHAINING_MODE_PROPERTY,
                                (PBYTE)BCRYPT_CHAIN_MODE_ECB,
                                (DWORD)((wcslen(BCRYPT_CHAIN_MODE_ECB) + 1)
                                        * sizeof(WCHAR)), 0);
        ASSERT_OK("ECB selected", ss);
        cbCipher = 0;
        ss = KSP_Encrypt(hProv, hAes, abPlain, sizeof(abPlain), NULL,
                         abCipher, sizeof(abCipher), &cbCipher, 0);
        ASSERT_OK("ECB encryption", ss);
        cbBack = 0;
        ss = KSP_Decrypt(hProv, hAes, abCipher, cbCipher, NULL,
                         abBack, sizeof(abBack), &cbBack, 0);
        ASSERT_OK("ECB decryption", ss);
        ASSERT("ECB round-trips", cbBack == sizeof(abPlain) &&
               memcmp(abBack, abPlain, sizeof(abPlain)) == 0);

        /* CTR — this provider's own chaining-mode name, so nothing but a
         * caller written against this KSP can reach it. */
        {
            BYTE abCtr[AES_BLOCK_SIZE];
            memset(abCtr, 0x01, sizeof(abCtr));

            ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_CHAINING_MODE_PROPERTY,
                                    (PBYTE)KSP_CHAIN_MODE_CTR,
                                    (DWORD)((wcslen(KSP_CHAIN_MODE_CTR) + 1)
                                            * sizeof(WCHAR)), 0);
            ASSERT_OK("CTR selected", ss);
            ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_INITIALIZATION_VECTOR,
                                    abCtr, sizeof(abCtr), 0);
            ASSERT_OK("counter block set", ss);

            cbCipher = 0;
            ss = KSP_Encrypt(hProv, hAes, abPlain, sizeof(abPlain), NULL,
                             abCipher, sizeof(abCipher), &cbCipher, 0);
            ASSERT_OK("CTR encryption", ss);

            ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_INITIALIZATION_VECTOR,
                                    abCtr, sizeof(abCtr), 0);
            ASSERT_OK("counter block reset", ss);
            cbBack = 0;
            ss = KSP_Decrypt(hProv, hAes, abCipher, cbCipher, NULL,
                             abBack, sizeof(abBack), &cbBack, 0);
            ASSERT_OK("CTR decryption", ss);
            ASSERT("CTR round-trips", cbBack == sizeof(abPlain) &&
                   memcmp(abBack, abPlain, sizeof(abPlain)) == 0);
        }

        /* GCM — 12-byte nonce, and the tag rides in the ciphertext. */
        {
            BYTE abNonce[12];
            memset(abNonce, 0x77, sizeof(abNonce));

            ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_CHAINING_MODE_PROPERTY,
                                    (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                                    (DWORD)((wcslen(BCRYPT_CHAIN_MODE_GCM) + 1)
                                            * sizeof(WCHAR)), 0);
            ASSERT_OK("GCM selected", ss);
            ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_INITIALIZATION_VECTOR,
                                    abNonce, sizeof(abNonce), 0);
            ASSERT_OK("nonce set", ss);

            cbCipher = 0;
            ss = KSP_Encrypt(hProv, hAes, abPlain, sizeof(abPlain), NULL,
                             abCipher, sizeof(abCipher), &cbCipher, 0);
            ASSERT_OK("GCM encryption", ss);
            ASSERT("ciphertext carries the 16-byte tag",
                   cbCipher == sizeof(abPlain) + 16);

            ss = KSP_SetKeyProperty(hProv, hAes, NCRYPT_INITIALIZATION_VECTOR,
                                    abNonce, sizeof(abNonce), 0);
            ASSERT_OK("nonce reset", ss);
            cbBack = 0;
            ss = KSP_Decrypt(hProv, hAes, abCipher, cbCipher, NULL,
                             abBack, sizeof(abBack), &cbBack, 0);
            ASSERT_OK("GCM decryption", ss);
            ASSERT("GCM round-trips", cbBack == sizeof(abPlain) &&
                   memcmp(abBack, abPlain, sizeof(abPlain)) == 0);
        }

        ss = KSP_DeleteKey(hProv, hAes, 0);
        ASSERT_OK("AES key deleted", ss);
    }

    /* ── Suite 18 : the standard curve-name route ───────────────────────── */
    TEST_SUITE("Generic ECDSA plus BCRYPT_ECC_CURVE_NAME");

    {
        NCRYPT_KEY_HANDLE hGen = 0;
        BYTE  abHash[48];
        BYTE  abSig[256];
        DWORD cbSig = 0;

        memset(abHash, 0x3C, sizeof(abHash));

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-generic", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        /* How a portable application reaches a curve: the generic algorithm
         * plus a curve name, with nothing provider-specific anywhere. */
        ss = KSP_CreatePersistedKey(hProv, &hGen, BCRYPT_ECDSA_ALGORITHM,
                                    L"phase7-generic", 0,
                                    NCRYPT_PERSIST_ONLY_FLAG);
        ASSERT_OK("Generic ECDSA key created", ss);

        ss = KSP_SetKeyProperty(hProv, hGen, BCRYPT_ECC_CURVE_NAME,
                                (PBYTE)BCRYPT_ECC_CURVE_NISTP384,
                                (DWORD)((wcslen(BCRYPT_ECC_CURVE_NISTP384) + 1)
                                        * sizeof(WCHAR)), 0);
        ASSERT_OK("Curve named as nistP384", ss);

        ss = KSP_FinalizeKey(hProv, hGen, 0);
        ASSERT_OK("Finalised on the token", ss);

        cbSig = 0;
        ss = KSP_SignHash(hProv, hGen, NULL, abHash, sizeof(abHash),
                          abSig, sizeof(abSig), &cbSig, 0);
        ASSERT_OK("Signed", ss);
        ASSERT_EQ("P-384 signature is 96 bytes", cbSig, 96U);

        ss = KSP_DeleteKey(hProv, hGen, 0);
        ASSERT_OK("Generic key deleted", ss);
    }

    /* ── Suite 19 : machine and user scopes are distinct objects ────────── */
    TEST_SUITE("Machine and user key scoping");

    {
        NCRYPT_KEY_HANDLE hUser = 0, hMachine = 0, hReopen = 0;

        {
            NCRYPT_KEY_HANDLE hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-scope", 0, 0) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
            hOld = 0;
            if (KSP_OpenKey(hProv, &hOld, L"phase7-scope", 0,
                            NCRYPT_MACHINE_KEY_FLAG) == ERROR_SUCCESS)
                KSP_DeleteKey(hProv, hOld, 0);
        }

        ss = KSP_CreatePersistedKey(hProv, &hUser, ALG_ECDSA_P256,
                                    L"phase7-scope", 0, 0);
        ASSERT_OK("User-scoped key created", ss);
        ss = KSP_CreatePersistedKey(hProv, &hMachine, ALG_ECDSA_P256,
                                    L"phase7-scope", 0,
                                    NCRYPT_MACHINE_KEY_FLAG);
        ASSERT_OK("Machine-scoped key of the SAME name created", ss);

        /* Before scoping existed these aliased each other. Both must now be
         * openable independently and be different objects on the token. */
        ss = KSP_OpenKey(hProv, &hReopen, L"phase7-scope", 0, 0);
        ASSERT_OK("The user key reopens", ss);
        if (ss == ERROR_SUCCESS) {
            KSP_KEY *pA = (KSP_KEY *)(ULONG_PTR)hReopen;
            KSP_KEY *pB = (KSP_KEY *)(ULONG_PTR)hMachine;
            ASSERT("and is not the machine key's object",
                   pA->hPrivKey != pB->hPrivKey);
            KSP_FreeKey(hProv, hReopen);
            hReopen = 0;
        }

        ss = KSP_OpenKey(hProv, &hReopen, L"phase7-scope", 0,
                         NCRYPT_MACHINE_KEY_FLAG);
        ASSERT_OK("The machine key reopens", ss);
        if (hReopen) KSP_FreeKey(hProv, hReopen);

        ss = KSP_DeleteKey(hProv, hMachine, 0);
        ASSERT_OK("Machine key deleted", ss);
        ss = KSP_DeleteKey(hProv, hUser, 0);
        ASSERT_OK("User key deleted", ss);
    }

    /* ── Suite 20 : enumeration and cleanup ─────────────────────────────── */
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
