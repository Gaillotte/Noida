/* test_two_tokens.c — choosing a token, against two real tokens.
 *
 * This suite exists because a test with ONE token cannot tell a working
 * selection from an ignored one. Every selection "succeeds" by landing on
 * the slot the default would have chosen anyway, so the assertions pass
 * whether the provider reads the caller's choice or throws it away. That is
 * the shape of a test that proves nothing, and this project has written it
 * before: the unit suites called P11_ExportEddsaPublicKey directly and
 * declared six assertions' worth of coverage over a function the provider
 * could not reach.
 *
 * So Kryoptic is configured with two slots, each with its own SQLite
 * database, its own CKA_LABEL and — deliberately — its own user PIN. Then:
 *
 *   - the default must pick the first token, as it always has;
 *   - a label or slot named through NCryptSetProperty must pick the OTHER
 *     one, which is observable because the two tokens hold different keys;
 *   - a key created on one token must NOT be visible from the other, which
 *     is the only assertion that actually distinguishes two tokens from one
 *     token addressed twice;
 *   - a selection made after the slot is bound must be refused, not
 *     accepted and ignored;
 *   - a selection naming no present token must be an error and never a
 *     fallback to slot 0, because a fallback signs with the wrong key and
 *     reports success.
 *
 * Two facts force the structure. The PKCS#11 context is a per-process
 * singleton, and C_Initialize is not idempotent, so each case needs a
 * process that has never touched the module: the binary therefore takes the
 * case name as argv[1] and the Makefile runs it once per case. And the PINs
 * differ, so a case that reaches the second token must also be told the
 * second token's PIN — a provider that quietly bound the first token would
 * fail to log in, which is a second, independent way for the wrong
 * selection to be caught.
 *
 *   KSP_PKCS11_LIB   path to the module
 *   SOFTHSM2_PIN     user PIN for the token this case expects to reach
 *   KSP_TOKEN_A      label of the token in the first slot
 *   KSP_TOKEN_B      label of the token in the second slot
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/pkcs11/p11_session.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/ksp/ksp_properties.h"
#include "../../src/common/config.h"
#include "../../src/common/memory.h"
#include "../unit/test_framework.h"
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* The two token labels, from the environment so the Makefile owns them. */
static const char *LabelA(void)
{
    const char *p = getenv("KSP_TOKEN_A");
    return p ? p : "ksp-phase7";
}
static const char *LabelB(void)
{
    const char *p = getenv("KSP_TOKEN_B");
    return p ? p : "ksp-second";
}

/* Narrow to wide, for handing a label to NCryptSetProperty the way CNG
 * would. The property is a counted buffer of WCHARs; the count here
 * deliberately EXCLUDES the terminator, because the other convention is
 * covered in the unit suite. */
static DWORD ToWide(const char *sz, WCHAR *pwsz, size_t cchMax)
{
    size_t i, n = strlen(sz);
    if (n > cchMax - 1) n = cchMax - 1;
    for (i = 0; i < n; i++)
        pwsz[i] = (WCHAR)(unsigned char)sz[i];
    pwsz[n] = L'\0';
    return (DWORD)(n * sizeof(WCHAR));
}

/* A key name unique to a token, so "visible from the other token" is a
 * question with a definite answer. */
static LPCWSTR KeyNameFor(const char *szWhich)
{
    static WCHAR wsz[64];
    swprintf(wsz, 64, L"two-token-%hs", szWhich);
    return wsz;
}

/* Generate a key in a named scope. NCRYPT_MACHINE_KEY_FLAG is what CNG
 * gives a provider to say "machine", and with per-scope tokens it chooses
 * the token rather than a label prefix. */
static SECURITY_STATUS MakeScopedKey(NCRYPT_PROV_HANDLE hProv,
                                     LPCWSTR pszName, BOOL bMachine)
{
    NCRYPT_KEY_HANDLE hKey  = 0;
    DWORD             dwF   = bMachine ? NCRYPT_MACHINE_KEY_FLAG : 0;
    SECURITY_STATUS   ss;

    ss = KSP_CreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, pszName,
                                AT_SIGNATURE, dwF);
    if (ss != ERROR_SUCCESS)
        return ss;
    ss = KSP_FinalizeKey(hProv, hKey, 0);
    KSP_FreeKey(hProv, hKey);
    return ss;
}

/* Does a key of this name exist in this scope? */
static BOOL KeyExistsScoped(NCRYPT_PROV_HANDLE hProv, LPCWSTR pszName,
                            BOOL bMachine)
{
    NCRYPT_KEY_HANDLE hKey = 0;
    DWORD             dwF  = bMachine ? NCRYPT_MACHINE_KEY_FLAG : 0;

    if (KSP_OpenKey(hProv, &hKey, pszName, AT_SIGNATURE, dwF)
            != ERROR_SUCCESS)
        return FALSE;
    KSP_FreeKey(hProv, hKey);
    return TRUE;
}

/* Delete a key in a named scope. */
static SECURITY_STATUS DeleteScopedKey(NCRYPT_PROV_HANDLE hProv,
                                       LPCWSTR pszName, BOOL bMachine)
{
    NCRYPT_KEY_HANDLE hKey = 0;
    DWORD             dwF  = bMachine ? NCRYPT_MACHINE_KEY_FLAG : 0;
    SECURITY_STATUS   ss;

    ss = KSP_OpenKey(hProv, &hKey, pszName, AT_SIGNATURE, dwF);
    if (ss != ERROR_SUCCESS)
        return ss;
    return KSP_DeleteKey(hProv, hKey, 0);
}

/* Generate, finalise and close an RSA key of the given name. */
static SECURITY_STATUS MakeKey(NCRYPT_PROV_HANDLE hProv, LPCWSTR pszName)
{
    NCRYPT_KEY_HANDLE hKey = 0;
    SECURITY_STATUS   ss;

    ss = KSP_CreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, pszName,
                                AT_SIGNATURE, 0);
    if (ss != ERROR_SUCCESS)
        return ss;
    ss = KSP_FinalizeKey(hProv, hKey, 0);
    KSP_FreeKey(hProv, hKey);
    return ss;
}

/* Does a key of this name exist on whichever token is bound? */
static BOOL KeyExists(NCRYPT_PROV_HANDLE hProv, LPCWSTR pszName)
{
    NCRYPT_KEY_HANDLE hKey = 0;
    if (KSP_OpenKey(hProv, &hKey, pszName, AT_SIGNATURE, 0) != ERROR_SUCCESS)
        return FALSE;
    KSP_FreeKey(hProv, hKey);
    return TRUE;
}

int main(int argc, char **argv)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    SECURITY_STATUS    ss;
    WCHAR              wszLabel[64];
    DWORD              cbLabel;
    const char        *szCase;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <case>\n", argv[0]);
        fprintf(stderr, "cases: default, by-label, by-slot, isolated, "
                        "cleanup, too-late, no-such-label, no-such-slot,\n"
                        "       scope-setup, scope-isolated, "
                        "scope-no-machine-pin, scope-cleanup,\n"
                        "       scope-half-configured, scope-same-token\n");
        return 2;
    }
    szCase = argv[1];

    printf("\n═══ two tokens: case '%s' ═══\n", szCase);

    /* ── The default is unchanged ────────────────────────────────────────
     *
     * Deferring the binding must not change what a caller that names
     * nothing gets. The first slot reporting a token, as since session 3. */
    if (strcmp(szCase, "default") == 0) {
        TEST_SUITE("No selection — the first token, as before");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);
        ASSERT("and it binds nothing yet — there is no token to read",
               !P11_IsSlotBound());

        ASSERT_OK("Creating a key binds the slot",
                  MakeKey(hProv, KeyNameFor("A")));
        ASSERT("the slot is now bound", P11_IsSlotBound());
        ASSERT_EQ("and it is the first slot",
                  (int)P11_GetContext()->slotId, 0);

        KSP_FreeProvider(hProv);
    }

    /* ── By label ────────────────────────────────────────────────────────
     *
     * The caller names the SECOND token. The PIN in the environment is the
     * second token's, so a provider that bound the first would fail to log
     * in — the wrong selection is caught twice over. */
    else if (strcmp(szCase, "by-label") == 0) {
        TEST_SUITE("Select the second token by label");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        cbLabel = ToWide(LabelB(), wszLabel, 64);
        ASSERT_OK("Set the token label through NCryptSetProperty",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                                    (PBYTE)wszLabel, cbLabel, 0));
        ASSERT("still nothing bound — a property is not an operation",
               !P11_IsSlotBound());

        ASSERT_OK("Creating a key on the named token",
                  MakeKey(hProv, KeyNameFor("B")));
        ASSERT("the slot is bound", P11_IsSlotBound());
        ASSERT_EQ("and it is the SECOND slot, not the default",
                  (int)P11_GetContext()->slotId, 1);

        KSP_FreeProvider(hProv);
    }

    /* ── By slot ID ──────────────────────────────────────────────────────*/
    else if (strcmp(szCase, "by-slot") == 0) {
        TEST_SUITE("Select the second token by slot ID");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        {
            DWORD dwSlot = 1;
            ASSERT_OK("Set the slot through NCryptSetProperty",
                KSP_SetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                                        (PBYTE)&dwSlot, sizeof dwSlot, 0));
        }

        ASSERT_OK("A key operation reaches that token",
                  MakeKey(hProv, KeyNameFor("B2")));
        ASSERT_EQ("on the named slot", (int)P11_GetContext()->slotId, 1);

        /* Read it back: OPS-04 says the selected slot is reportable, and
         * after a selection the report must be of the NEW slot. A getter
         * still answering 0 would make the property look ignored even
         * though it was not. */
        {
            DWORD dwRead = 0xFFFFFFFF, cb = 0;
            ASSERT_OK("Read the slot back",
                KSP_GetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                                        (PBYTE)&dwRead, sizeof dwRead,
                                        &cb, 0));
            ASSERT_EQ("and it reports the selected slot", (int)dwRead, 1);
        }

        KSP_FreeProvider(hProv);
    }

    /* ── The assertion that proves there are two tokens ──────────────────
     *
     * Runs LAST, after the two cases above have each left a key behind on
     * their own token. If selection were ignored, both keys would be on
     * slot 0 and both would be visible from here. The scoped CKA_LABEL is
     * per key name, not per token, so nothing but a different token can
     * account for one being absent. */
    else if (strcmp(szCase, "isolated") == 0) {
        TEST_SUITE("A key on one token is invisible from the other");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        cbLabel = ToWide(LabelA(), wszLabel, 64);
        ASSERT_OK("Select the first token by label",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                                    (PBYTE)wszLabel, cbLabel, 0));

        ASSERT("the key made on the first token is there",
               KeyExists(hProv, KeyNameFor("A")));
        ASSERT("and the key made on the SECOND token is not",
               !KeyExists(hProv, KeyNameFor("B")));
        ASSERT_EQ("bound to the first slot",
                  (int)P11_GetContext()->slotId, 0);

        /* Clean up this token's key, so the suite can be run again. */
        {
            NCRYPT_KEY_HANDLE hKey = 0;
            if (KSP_OpenKey(hProv, &hKey, KeyNameFor("A"),
                            AT_SIGNATURE, 0) == ERROR_SUCCESS)
                ASSERT_OK("Delete it", KSP_DeleteKey(hProv, hKey, 0));
        }

        KSP_FreeProvider(hProv);
    }

    /* ── The other half of the isolation proof, and the cleanup ──────────
     *
     * 'isolated' shows the second token's keys are ABSENT from the first.
     * On its own that is weak: a key that was never created anywhere is
     * absent too, and the assertion would pass for the wrong reason. So
     * this case selects the second token and requires the same keys to be
     * PRESENT there. Absent from A and present on B is the pair of facts
     * that distinguishes two tokens from one.
     *
     * It then deletes them, which is what makes the suite repeatable
     * against the same pair of tokens — the property that found the
     * orphaned-certificate bug in session 10. */
    else if (strcmp(szCase, "cleanup") == 0) {
        TEST_SUITE("The same keys ARE present on the second token");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        cbLabel = ToWide(LabelB(), wszLabel, 64);
        ASSERT_OK("Select the second token by label",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                                    (PBYTE)wszLabel, cbLabel, 0));

        ASSERT("the key made by the by-label case is here",
               KeyExists(hProv, KeyNameFor("B")));
        ASSERT("so is the one made by the by-slot case",
               KeyExists(hProv, KeyNameFor("B2")));
        ASSERT("and the first token's key is NOT",
               !KeyExists(hProv, KeyNameFor("A")));
        ASSERT_EQ("bound to the second slot",
                  (int)P11_GetContext()->slotId, 1);

        {
            NCRYPT_KEY_HANDLE hKey = 0;
            if (KSP_OpenKey(hProv, &hKey, KeyNameFor("B"),
                            AT_SIGNATURE, 0) == ERROR_SUCCESS)
                ASSERT_OK("Delete the first", KSP_DeleteKey(hProv, hKey, 0));
            hKey = 0;
            if (KSP_OpenKey(hProv, &hKey, KeyNameFor("B2"),
                            AT_SIGNATURE, 0) == ERROR_SUCCESS)
                ASSERT_OK("Delete the second", KSP_DeleteKey(hProv, hKey, 0));
        }
        ASSERT("nothing of ours is left on this token",
               !KeyExists(hProv, KeyNameFor("B")) &&
               !KeyExists(hProv, KeyNameFor("B2")));

        KSP_FreeProvider(hProv);
    }

    /* ── Too late ────────────────────────────────────────────────────────
     *
     * Once a session exists the slot cannot move: PKCS#11 has no operation
     * for it. The only honest answers are "refuse" and "lie", and this
     * provider has shipped the lie before — KSP_NotifyChangeKey returned
     * ERROR_SUCCESS without writing the handle its caller would wait on. */
    else if (strcmp(szCase, "too-late") == 0) {
        TEST_SUITE("Selection after the slot is bound is refused");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        ASSERT_OK("An operation binds the first token",
                  MakeKey(hProv, KeyNameFor("late")));
        ASSERT_EQ("slot 0", (int)P11_GetContext()->slotId, 0);

        cbLabel = ToWide(LabelB(), wszLabel, 64);
        ASSERT_EQ("Selecting the other token now → NTE_INVALID_HANDLE",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                                    (PBYTE)wszLabel, cbLabel, 0),
            (SECURITY_STATUS)NTE_INVALID_HANDLE);
        ASSERT_EQ("and the slot did not move",
                  (int)P11_GetContext()->slotId, 0);

        {
            DWORD dwSlot = 1;
            ASSERT_EQ("By slot ID either → NTE_INVALID_HANDLE",
                KSP_SetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                                        (PBYTE)&dwSlot, sizeof dwSlot, 0),
                (SECURITY_STATUS)NTE_INVALID_HANDLE);
            ASSERT_EQ("still slot 0", (int)P11_GetContext()->slotId, 0);
        }

        /* The key is still usable — a refused selection must not have
         * disturbed anything. */
        ASSERT("the key made before the refusal still opens",
               KeyExists(hProv, KeyNameFor("late")));
        {
            NCRYPT_KEY_HANDLE hKey = 0;
            if (KSP_OpenKey(hProv, &hKey, KeyNameFor("late"),
                            AT_SIGNATURE, 0) == ERROR_SUCCESS)
                ASSERT_OK("Delete it", KSP_DeleteKey(hProv, hKey, 0));
        }

        KSP_FreeProvider(hProv);
    }

    /* ── Never a fallback ────────────────────────────────────────────────
     *
     * A label or slot naming no present token must fail. With two tokens
     * present this is a real test: a fallback would silently land on slot 0,
     * which holds working keys and a valid PIN, so every subsequent
     * operation would succeed against the wrong token. */
    else if (strcmp(szCase, "no-such-label") == 0) {
        TEST_SUITE("A label no token carries is an error, not slot 0");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        cbLabel = ToWide("no-token-has-this-label", wszLabel, 64);
        ASSERT_OK("The selection itself is accepted — it names a label, and "
                  "whether a token carries it is not yet known",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                                    (PBYTE)wszLabel, cbLabel, 0));

        ASSERT_ERR("A key operation then fails rather than using slot 0",
                   MakeKey(hProv, KeyNameFor("nope")));
        ASSERT("and nothing is bound", !P11_IsSlotBound());

        /* Correctable in the same process: the window is still open,
         * because nothing was bound. */
        cbLabel = ToWide(LabelB(), wszLabel, 64);
        ASSERT_OK("Correcting the label",
            KSP_SetProviderProperty(hProv, KSP_TOKEN_LABEL_PROPERTY,
                                    (PBYTE)wszLabel, cbLabel, 0));
        ASSERT_OK("and the operation then succeeds",
                  MakeKey(hProv, KeyNameFor("recovered")));
        ASSERT_EQ("on the corrected token",
                  (int)P11_GetContext()->slotId, 1);

        {
            NCRYPT_KEY_HANDLE hKey = 0;
            if (KSP_OpenKey(hProv, &hKey, KeyNameFor("recovered"),
                            AT_SIGNATURE, 0) == ERROR_SUCCESS)
                ASSERT_OK("Delete it", KSP_DeleteKey(hProv, hKey, 0));
        }

        KSP_FreeProvider(hProv);
    }

    else if (strcmp(szCase, "no-such-slot") == 0) {
        TEST_SUITE("A slot ID no token occupies is an error, not slot 0");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        {
            DWORD dwSlot = 99;
            ASSERT_OK("The selection is accepted",
                KSP_SetProviderProperty(hProv, KSP_SLOT_PROPERTY,
                                        (PBYTE)&dwSlot, sizeof dwSlot, 0));
        }
        ASSERT_ERR("A key operation then fails",
                   MakeKey(hProv, KeyNameFor("nope2")));
        ASSERT("and nothing is bound", !P11_IsSlotBound());

        KSP_FreeProvider(hProv);
    }

    /* ── Per-scope tokens: isolation, not namespacing (LIFE-08) ───────────
     *
     * With KSP_MACHINE_TOKEN_LABEL and KSP_USER_TOKEN_LABEL set, the machine
     * and user scopes are on different tokens with different PINs. The claim
     * is that a caller holding the user credential cannot reach machine
     * keys, and the only way to demonstrate it is to try.
     *
     * The old behaviour — one token, an "m/" or "u/" label prefix — kept
     * distinct keys distinct and isolated nothing: anyone logged in read
     * both prefixes. These cases are the difference, and the assertion that
     * matters is the one that must FAIL to find something. */
    else if (strcmp(szCase, "scope-setup") == 0) {
        TEST_SUITE("Per-scope tokens resolve to two different tokens");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        /* A machine key. The scope decides the token, so this one is
         * created on the machine token with the machine PIN. */
        ASSERT_OK("Create a MACHINE key",
                  MakeScopedKey(hProv, KeyNameFor("mach"), TRUE));
        ASSERT("per-scope tokens are in effect", P11_HasPerScopeTokens());
        ASSERT("and the two scopes are on DIFFERENT slots",
               P11_GetScopeSlot(P11_SCOPE_MACHINE) !=
               P11_GetScopeSlot(P11_SCOPE_USER));

        /* A user key of the SAME name. Under the old scheme these differed
         * only by label prefix in one token; now they are on two tokens. */
        ASSERT_OK("Create a USER key of the same name",
                  MakeScopedKey(hProv, KeyNameFor("mach"), FALSE));

        KSP_FreeProvider(hProv);
    }

    /* The isolation assertion itself. */
    else if (strcmp(szCase, "scope-isolated") == 0) {
        TEST_SUITE("A user-scope caller cannot reach machine keys");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        /* The user scope sees its own key. */
        ASSERT("the user-scope key opens in the user scope",
               KeyExistsScoped(hProv, KeyNameFor("mach"), FALSE));

        /* And the machine scope sees its own. Both halves are needed: if
         * the machine key were simply absent, the isolation assertion below
         * would pass for the wrong reason. */
        ASSERT("the machine-scope key opens in the machine scope",
               KeyExistsScoped(hProv, KeyNameFor("mach"), TRUE));

        /* The keys are genuinely different objects on different tokens.
         * They carry the same CNG name, so under the old one-token scheme
         * this would be two labels in one place; here it is two tokens, and
         * the slots prove it. */
        ASSERT_EQ("the machine scope's slot is the machine token",
                  (int)P11_GetScopeSlot(P11_SCOPE_MACHINE), 0);
        ASSERT_EQ("the user scope's slot is the user token",
                  (int)P11_GetScopeSlot(P11_SCOPE_USER), 1);

        /* Enumeration is scoped too. NCryptEnumKeys passes its flags on the
         * first call only, so a scope not carried into the continuation
         * would list the user token from the second key onwards. */
        {
            NCryptKeyName *pName  = NULL;
            PVOID          pEnum  = NULL;
            int            nUser  = 0, nMach = 0;

            while (KSP_EnumKeys(hProv, NULL, &pName, &pEnum, 0)
                       == ERROR_SUCCESS && pName) {
                nUser++;
                KSP_FreeBuffer(pName);
                pName = NULL;
            }
            if (pEnum) KSP_FreeBuffer(pEnum);
            pEnum = NULL;

            while (KSP_EnumKeys(hProv, NULL, &pName, &pEnum,
                                NCRYPT_MACHINE_KEY_FLAG)
                       == ERROR_SUCCESS && pName) {
                nMach++;
                KSP_FreeBuffer(pName);
                pName = NULL;
            }
            if (pEnum) KSP_FreeBuffer(pEnum);

            printf("  user scope enumerated %d key(s), "
                   "machine scope %d\n", nUser, nMach);
            ASSERT("each scope enumerates at least its own key",
                   nUser >= 1 && nMach >= 1);
        }

        KSP_FreeProvider(hProv);
    }

    /* The credential boundary. This is the case that separates isolation
     * from namespacing, and it is run WITHOUT the machine PIN in the
     * environment: reaching the machine token then requires a credential
     * this process does not have, so the operation must fail at C_Login
     * rather than succeed on the wrong token.
     *
     * Under the old label-prefix scheme it would have succeeded, because
     * there was one token and one PIN. */
    else if (strcmp(szCase, "scope-no-machine-pin") == 0) {
        TEST_SUITE("Without the machine PIN, machine keys are unreachable");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);

        ASSERT("the user scope still works — it has its own PIN",
               KeyExistsScoped(hProv, KeyNameFor("mach"), FALSE));
        ASSERT("but the machine scope cannot be reached at all",
               !KeyExistsScoped(hProv, KeyNameFor("mach"), TRUE));
        ASSERT_ERR("and creating a machine key fails",
                   MakeScopedKey(hProv, KeyNameFor("denied"), TRUE));

        KSP_FreeProvider(hProv);
    }

    /* Cleanup for the per-scope cases, with both PINs present. */
    else if (strcmp(szCase, "scope-cleanup") == 0) {
        TEST_SUITE("Per-scope cleanup");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);
        ASSERT_OK("Delete the machine key",
                  DeleteScopedKey(hProv, KeyNameFor("mach"), TRUE));
        ASSERT_OK("Delete the user key",
                  DeleteScopedKey(hProv, KeyNameFor("mach"), FALSE));
        ASSERT("nothing of ours is left in either scope",
               !KeyExistsScoped(hProv, KeyNameFor("mach"), TRUE) &&
               !KeyExistsScoped(hProv, KeyNameFor("mach"), FALSE));
        KSP_FreeProvider(hProv);
    }

    /* Setting only one of the pair must be refused, not half-applied. A
     * deployment naming a machine token and forgetting the user one would
     * otherwise put user keys on the machine token and report success —
     * isolation that does not isolate and that nobody re-checks. */
    else if (strcmp(szCase, "scope-half-configured") == 0) {
        TEST_SUITE("One scope configured alone is refused");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);
        ASSERT_ERR("Any operation fails rather than guessing the other token",
                   MakeScopedKey(hProv, KeyNameFor("half"), FALSE));
        ASSERT("and nothing is bound", !P11_IsSlotBound());
        KSP_FreeProvider(hProv);
    }

    /* Both names resolving to the SAME token is refused for the same
     * reason: it reads as isolation and is not. */
    else if (strcmp(szCase, "scope-same-token") == 0) {
        TEST_SUITE("Two scopes on one token is refused");

        ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
        ASSERT_OK("OpenProvider", ss);
        ASSERT_ERR("Any operation fails",
                   MakeScopedKey(hProv, KeyNameFor("same"), FALSE));
        ASSERT("and nothing is bound", !P11_IsSlotBound());
        KSP_FreeProvider(hProv);
    }

    else {
        fprintf(stderr, "unknown case '%s'\n", szCase);
        return 2;
    }

    TEST_REPORT();
    TEST_EXIT();
}
