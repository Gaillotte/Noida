/* test_adcs_lifecycle.c — the CA-shaped flow, against a real token.
 *
 * Phase A step 3 of docs/16-adcs-readiness.md. The provider is targeted at
 * an Active Directory Certificate Services CA whose key lives on an HSM,
 * and three pieces of that path were changed without a real token ever
 * seeing them: NCRYPT_LENGTHS_PROPERTY (A1), the NTE_EXISTS / overwrite
 * contract (A2), and the removal of the default PIN (A5).
 *
 * This runs the sequence a CA actually performs, in order, against a
 * PKCS#11 token nobody here wrote. It exists because the unit suite can
 * only confirm the provider agrees with a mock we built from our own
 * beliefs, and this project's record on that is unambiguous: every sweep
 * against a real token has found defects the mock passed, including three
 * in code that was days old with 1434 assertions behind it.
 *
 * The assertion that carries the most weight is the duplicate count.
 * "Create twice is refused" can pass while the token quietly holds two
 * objects, because a refusal and a clean token are different facts. After
 * a deliberate overwrite this suite counts what is actually on the token
 * and requires exactly one — which is the property the original defect
 * violated and the one a CA depends on, since a second object with the
 * same label means NCryptOpenKey may return either generation of the key.
 *
 * Run per case, one process each, because the PKCS#11 context is a
 * per-process singleton and the no-PIN case needs an environment the
 * others must not see.
 *
 *   KSP_PKCS11_LIB   path to the module
 *   SOFTHSM2_PIN     user PIN (absent on purpose for the no-pin case)
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_session.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_properties.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/common/config.h"
#include "../unit/test_framework.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

extern const BYTE  g_realCert[];
extern const DWORD g_cbRealCert;

/* The CA's key container name. One name throughout, because reusing it is
 * the whole point: renewal is what makes a duplicate possible. */
#define CA_KEY_NAME  L"adcs-test-ca"

/* Count objects on the token carrying this key's scoped label.
 *
 * Goes under the KSP layer to C_FindObjects deliberately. Asking the
 * provider "does this key exist" cannot distinguish one object from two —
 * it answers from the first match either way, which is exactly how the
 * duplicate defect stayed invisible. Counting is the only way to see it.
 */
static int CountObjectsNamed(LPCWSTR pszName, BOOL bMachine,
                             CK_OBJECT_CLASS ulClass)
{
    P11_CONTEXT      *pCtx = P11_GetContext();
    CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE  aObj[32];
    CK_ULONG          ulFound = 0;
    CK_ATTRIBUTE      tmpl[2];
    char              szLabel[MAX_KEY_LABEL_LEN + KSP_SCOPE_PREFIX_LEN + 1];
    int               n, i;
    CK_RV             rv;

    /* Build the scoped label the provider would have written. */
    n = snprintf(szLabel, sizeof(szLabel), "%s",
                 bMachine ? KSP_SCOPE_PREFIX_MACHINE : KSP_SCOPE_PREFIX_USER);
    for (i = 0; pszName[i] && n < (int)sizeof(szLabel) - 1; i++)
        szLabel[n++] = (char)pszName[i];
    szLabel[n] = '\0';

    if (P11_AcquireSession(bMachine ? P11_SCOPE_MACHINE : P11_SCOPE_USER,
                           &hSession) != ERROR_SUCCESS)
        return -1;

    tmpl[0].type       = CKA_CLASS;
    tmpl[0].pValue     = &ulClass;
    tmpl[0].ulValueLen = sizeof(ulClass);
    tmpl[1].type       = CKA_LABEL;
    tmpl[1].pValue     = szLabel;
    tmpl[1].ulValueLen = (CK_ULONG)strlen(szLabel);

    rv = pCtx->pFunctionList->C_FindObjectsInit(hSession, tmpl, 2);
    if (rv != CKR_OK) {
        P11_ReleaseSession(hSession);
        return -1;
    }
    rv = pCtx->pFunctionList->C_FindObjects(hSession, aObj, 32, &ulFound);
    pCtx->pFunctionList->C_FindObjectsFinal(hSession);
    P11_ReleaseSession(hSession);

    return (rv == CKR_OK) ? (int)ulFound : -1;
}

/* Delete the CA key if it is there, so the suite starts from a known
 * state and can run twice. */
static void CleanUp(NCRYPT_PROV_HANDLE hProv)
{
    NCRYPT_KEY_HANDLE hKey = 0;
    if (KSP_OpenKey(hProv, &hKey, CA_KEY_NAME, AT_SIGNATURE,
                    NCRYPT_MACHINE_KEY_FLAG) == ERROR_SUCCESS)
        KSP_DeleteKey(hProv, hKey, 0);
}

int main(int argc, char **argv)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS    ss;
    const char        *szCase;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <lifecycle|no-pin>\n", argv[0]);
        return 2;
    }
    szCase = argv[1];
    printf("\n═══ ADCS lifecycle: case '%s' ═══\n", szCase);

    /* ── A CA that cannot authenticate must refuse to start ──────────────
     *
     * certsrv is headless and never sets NCRYPT_PIN_PROPERTY, so the PIN
     * comes from the environment. There used to be a compiled-in "1234"
     * fallback; this case is what proves it is gone against a real token
     * rather than only against the mock. */
    if (strcmp(szCase, "no-pin") == 0) {
        NCRYPT_KEY_HANDLE hKey = 0;

        TEST_SUITE("No PIN configured — the CA cannot start");

        ASSERT_OK("OpenProvider still succeeds — it needs no token",
                  KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0));

        ss = KSP_CreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM,
                                    L"adcs-nopin", AT_SIGNATURE,
                                    NCRYPT_MACHINE_KEY_FLAG);
        ASSERT_ERR("but the first operation needing the token fails", ss);
        ASSERT_EQ("with NTE_PERM, not a login failure from the token",
                  ss, (SECURITY_STATUS)NTE_PERM);
        ASSERT_EQ("and no key handle was returned", (int)(hKey == 0), 1);

        KSP_FreeProvider(hProv);
        TEST_REPORT();
        TEST_EXIT();
    }

    if (strcmp(szCase, "lifecycle") != 0) {
        fprintf(stderr, "unknown case '%s'\n", szCase);
        return 2;
    }

    ASSERT_OK("OpenProvider", KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0));
    CleanUp(hProv);

    /* ── 1. The CA setup wizard asks what key sizes are available ────────
     *
     * NCRYPT_LENGTHS_PROPERTY, read on a key handle before it is
     * finalised, which is the sequence a wizard uses to populate its
     * list. Nothing here had ever answered it. */
    TEST_SUITE("1. Key sizes offered to the wizard");
    {
        NCRYPT_KEY_HANDLE        hProbe = 0;
        NCRYPT_SUPPORTED_LENGTHS lens;
        DWORD                    cb = 0;

        ASSERT_OK("Create a deferred RSA key to ask about",
            KSP_CreatePersistedKey(hProv, &hProbe, BCRYPT_RSA_ALGORITHM,
                                   NULL, AT_SIGNATURE,
                                   NCRYPT_PERSIST_ONLY_FLAG));

        memset(&lens, 0xAA, sizeof(lens));
        ASSERT_OK("NCRYPT_LENGTHS_PROPERTY answers",
            KSP_GetKeyProperty(hProv, hProbe, NCRYPT_LENGTHS_PROPERTY,
                               (PBYTE)&lens, sizeof(lens), &cb, 0));
        ASSERT_EQ("with the whole struct", cb,
                  (DWORD)sizeof(NCRYPT_SUPPORTED_LENGTHS));
        ASSERT("4096 is inside the advertised range",
               lens.dwMinLength <= 4096 && lens.dwMaxLength >= 4096);
        ASSERT("the preselected default is at least 2048",
               lens.dwDefaultLength >= 2048);
        ASSERT("and 4096 is reachable from the minimum by the increment",
               lens.dwIncrement > 0 &&
               ((4096 - lens.dwMinLength) % lens.dwIncrement) == 0);

        KSP_FreeKey(hProv, hProbe);
    }

    /* ── 2. Install the CA: a machine-scoped RSA-4096 signing key ────────*/
    TEST_SUITE("2. CA key creation");
    {
        NCRYPT_KEY_HANDLE hKey = 0;
        DWORD             dwBits = 4096;

        ASSERT_OK("Create the CA key, deferred so the size can be set",
            KSP_CreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM,
                                   CA_KEY_NAME, AT_SIGNATURE,
                                   NCRYPT_MACHINE_KEY_FLAG |
                                   NCRYPT_PERSIST_ONLY_FLAG));
        ASSERT_OK("Set 4096 bits",
            KSP_SetKeyProperty(hProv, hKey, NCRYPT_LENGTH_PROPERTY,
                               (PBYTE)&dwBits, sizeof(dwBits), 0));
        ASSERT_OK("Finalize — the token generates",
                  KSP_FinalizeKey(hProv, hKey, 0));

        ASSERT_EQ("exactly one private key object on the token",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_PRIVATE_KEY), 1);

        KSP_FreeKey(hProv, hKey);
    }

    /* ── 3. The CA signs, and stores its own certificate ─────────────────*/
    TEST_SUITE("3. Signing and the CA certificate");
    {
        NCRYPT_KEY_HANDLE hKey = 0;
        BCRYPT_PKCS1_PADDING_INFO pad;
        BYTE   abHash[32];
        BYTE   abSig[1024];
        DWORD  cbSig = 0;
        DWORD  i;

        ASSERT_OK("Open the CA key by name",
            KSP_OpenKey(hProv, &hKey, CA_KEY_NAME, AT_SIGNATURE,
                        NCRYPT_MACHINE_KEY_FLAG));

        for (i = 0; i < sizeof(abHash); i++)
            abHash[i] = (BYTE)i;
        pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;

        ASSERT_OK("Size query for the signature",
            KSP_SignHash(hProv, hKey, &pad, abHash, sizeof(abHash),
                         NULL, 0, &cbSig, NCRYPT_PAD_PKCS1_FLAG));
        ASSERT_EQ("a 4096-bit RSA signature is 512 bytes", cbSig, 512U);

        ASSERT_OK("Sign — this is a certificate being issued",
            KSP_SignHash(hProv, hKey, &pad, abHash, sizeof(abHash),
                         abSig, sizeof(abSig), &cbSig,
                         NCRYPT_PAD_PKCS1_FLAG));
        ASSERT_EQ("and the signature is the full modulus width",
                  cbSig, 512U);

        ASSERT_OK("Store the CA's own certificate beside the key",
            KSP_SetKeyProperty(hProv, hKey, NCRYPT_CERTIFICATE_PROPERTY,
                               (PBYTE)g_realCert, g_cbRealCert, 0));
        ASSERT_EQ("one certificate object now",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_CERTIFICATE), 1);

        KSP_FreeKey(hProv, hKey);
    }

    /* ── 4. Re-running CA setup with the same name must be refused ───────
     *
     * The refusal, and then the thing the refusal is FOR: the token must
     * still hold exactly one key. A provider that returned NTE_EXISTS
     * after creating a second object would pass a status-only check. */
    TEST_SUITE("4. The name is already in use");
    {
        NCRYPT_KEY_HANDLE hKey = 0;

        ASSERT_EQ("Creating over the CA key → NTE_EXISTS",
            KSP_CreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM,
                                   CA_KEY_NAME, AT_SIGNATURE,
                                   NCRYPT_MACHINE_KEY_FLAG),
            (SECURITY_STATUS)NTE_EXISTS);
        ASSERT_EQ("no handle returned", (int)(hKey == 0), 1);
        ASSERT_EQ("and the token still holds exactly one private key",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_PRIVATE_KEY), 1);
    }

    /* ── 5. CA certificate renewal with a new key ────────────────────────
     *
     * The operation this whole step exists for. The count afterwards is
     * the assertion: before the fix a renewal left TWO objects sharing a
     * label, and which one signed afterwards was whichever the token's
     * search returned first. */
    TEST_SUITE("5. Renewal — deliberate overwrite");
    {
        NCRYPT_KEY_HANDLE hKey = 0;
        DWORD             dwBits = 4096;
        BYTE              abRead[4096];
        DWORD             cbRead = 0;

        ASSERT_OK("Renew with NCRYPT_OVERWRITE_KEY_FLAG",
            KSP_CreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM,
                                   CA_KEY_NAME, AT_SIGNATURE,
                                   NCRYPT_MACHINE_KEY_FLAG |
                                   NCRYPT_OVERWRITE_KEY_FLAG |
                                   NCRYPT_PERSIST_ONLY_FLAG));
        ASSERT_OK("Set the size",
            KSP_SetKeyProperty(hProv, hKey, NCRYPT_LENGTH_PROPERTY,
                               (PBYTE)&dwBits, sizeof(dwBits), 0));

        ASSERT_EQ("before finalize the OLD key is still the only one — a "
                  "caller who never finalises must lose nothing",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_PRIVATE_KEY), 1);

        ASSERT_OK("Finalize the renewed key",
                  KSP_FinalizeKey(hProv, hKey, 0));

        ASSERT_EQ("STILL exactly one private key — not two",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_PRIVATE_KEY), 1);
        ASSERT_EQ("and exactly one public key",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_PUBLIC_KEY), 1);
        ASSERT_EQ("the replaced key's certificate went with it",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_CERTIFICATE), 0);

        /* The renewed key must be the one that signs. Reading the
         * certificate back would return the OLD certificate if the old
         * objects had survived. */
        ASSERT_EQ("and no stale certificate is readable",
            KSP_GetKeyProperty(hProv, hKey, NCRYPT_CERTIFICATE_PROPERTY,
                               NULL, 0, &cbRead, 0),
            (SECURITY_STATUS)NTE_NOT_FOUND);
        (void)abRead;

        KSP_FreeKey(hProv, hKey);
    }

    /* ── 6. The renewed key works ────────────────────────────────────────*/
    TEST_SUITE("6. The renewed CA key signs");
    {
        NCRYPT_KEY_HANDLE hKey = 0;
        BCRYPT_PKCS1_PADDING_INFO pad;
        BYTE   abHash[32] = {0};
        BYTE   abSig[1024];
        DWORD  cbSig = 0;

        ASSERT_OK("Open it by name",
            KSP_OpenKey(hProv, &hKey, CA_KEY_NAME, AT_SIGNATURE,
                        NCRYPT_MACHINE_KEY_FLAG));
        pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;
        ASSERT_OK("and it signs",
            KSP_SignHash(hProv, hKey, &pad, abHash, sizeof(abHash),
                         abSig, sizeof(abSig), &cbSig,
                         NCRYPT_PAD_PKCS1_FLAG));
        ASSERT_EQ("at the renewed size", cbSig, 512U);
        KSP_FreeKey(hProv, hKey);
    }

    /* ── 7. Decommission ─────────────────────────────────────────────────*/
    TEST_SUITE("7. Delete leaves nothing behind");
    {
        NCRYPT_KEY_HANDLE hKey = 0;
        ASSERT_OK("Open",
            KSP_OpenKey(hProv, &hKey, CA_KEY_NAME, AT_SIGNATURE,
                        NCRYPT_MACHINE_KEY_FLAG));
        ASSERT_OK("Delete", KSP_DeleteKey(hProv, hKey, 0));

        ASSERT_EQ("no private key left",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_PRIVATE_KEY), 0);
        ASSERT_EQ("no public key left",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_PUBLIC_KEY), 0);
        ASSERT_EQ("no certificate left",
                  CountObjectsNamed(CA_KEY_NAME, TRUE, CKO_CERTIFICATE), 0);

        /* And the name is free again, which is what makes this suite
         * repeatable over one token. */
        ASSERT_OK("the name can be reused",
            KSP_CreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM,
                                   CA_KEY_NAME, AT_SIGNATURE,
                                   NCRYPT_MACHINE_KEY_FLAG |
                                   NCRYPT_PERSIST_ONLY_FLAG));
        KSP_FreeKey(hProv, hKey);
        CleanUp(hProv);
    }

    KSP_FreeProvider(hProv);
    TEST_REPORT();
    TEST_EXIT();
}
