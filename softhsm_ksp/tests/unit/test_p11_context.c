/* test_p11_context.c — OPS-08, and the first coverage of p11_context.c
 *
 * p11_context.c had no unit tests at all. It could not have: it reaches the
 * token through LoadLibrary and GetProcAddress, and the stand-ins for those
 * in windows_compat.h were inline stubs that always failed. So the module
 * that loads the backend, initialises Cryptoki and chooses the slot was the
 * one module nothing exercised. Making the loader controllable fixed that.
 *
 * The gap being closed here is OPS-08. P11_Initialize used to be a bare
 * InitOnceExecuteOnce, which runs its callback exactly once per process
 * whether it succeeds or not. One bad module path therefore poisoned the
 * provider for the lifetime of the host: correcting KSP_PKCS11_LIB changed
 * nothing, and the only cure was restarting the application.
 *
 * The distinction that matters, and that these tests pin down, is between
 * retrying a FAILED initialisation — which must happen — and repeating a
 * SUCCESSFUL one, which must not, because C_Initialize is not idempotent.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/common/config.h"
#include "test_framework.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* p11_context.c calls into the session pool's PIN store and the utility
 * module; neither is under test here. */
SECURITY_STATUS P11_SetPin(const char *p) { (void)p; return ERROR_SUCCESS; }
void            P11_ClearPin(void) {}

static void Reset(void)
{
    P11_Finalize();          /* returns the guard to not-initialised */
    P11Mock_Reset();
}

int main(void)
{
    SECURITY_STATUS ss;

    /* ── Suite 1 : a module that will not load ──────────────────────────── */
    TEST_SUITE("Initialisation failure");

    Reset();
    P11Mock_GetConfig()->bModuleLoads = FALSE;

    ss = P11_Initialize();
    ASSERT_EQ("No module → NTE_PROVIDER_DLL_FAIL",
        ss, (SECURITY_STATUS)NTE_PROVIDER_DLL_FAIL);
    ASSERT_EQ("LoadLibrary was attempted",
        P11Mock_GetCalls()->nLoadLibrary, 1);
    ASSERT_EQ("and Cryptoki was never initialised",
        P11Mock_GetCalls()->nInitialize, 0);

    /* ── Suite 2 : the failure is retried, not remembered (OPS-08) ──────── */
    TEST_SUITE("Recovery without a restart");

    /* A second attempt while still broken must actually try again rather
     * than replay a cached answer. */
    ss = P11_Initialize();
    ASSERT_EQ("Second attempt still fails",
        ss, (SECURITY_STATUS)NTE_PROVIDER_DLL_FAIL);
    ASSERT_EQ("and it really re-tried the load",
        P11Mock_GetCalls()->nLoadLibrary, 2);

    /* Now the operator fixes the path. Under InitOnceExecuteOnce this was
     * the moment nothing could be done but restart the host. */
    P11Mock_GetConfig()->bModuleLoads = TRUE;

    ss = P11_Initialize();
    ASSERT_OK("Initialisation succeeds once the module is there", ss);
    ASSERT_EQ("Cryptoki initialised", P11Mock_GetCalls()->nInitialize, 1);
    ASSERT("A function list was obtained",
        P11_GetContext()->pFunctionList != NULL);
    ASSERT("and the context reports itself initialised",
        P11_GetContext()->bInitialized);

    /* ── Suite 3 : success is not repeated ──────────────────────────────── */
    TEST_SUITE("Success stays one-shot");

    P11Mock_ResetCalls();

    ss = P11_Initialize();
    ASSERT_OK("A further call succeeds", ss);
    /* C_Initialize is not idempotent, and re-loading the module would leak
     * a handle per call. Retrying a failure must not become retrying
     * everything. */
    ASSERT_EQ("C_Initialize was NOT called again",
        P11Mock_GetCalls()->nInitialize, 0);
    ASSERT_EQ("and the module was not loaded again",
        P11Mock_GetCalls()->nLoadLibrary, 0);

    ss = P11_Initialize();
    ASSERT_OK("and again", ss);
    ASSERT_EQ("still no repeat", P11Mock_GetCalls()->nInitialize, 0);

    /* ── Suite 4 : the other ways initialisation fails ──────────────────── */
    TEST_SUITE("Failure modes");

    /* A module that loads but exports nothing useful. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads       = TRUE;
    P11Mock_GetConfig()->bNoGetFunctionList = TRUE;
    ss = P11_Initialize();
    ASSERT_ERR("No C_GetFunctionList → failure", ss);
    ASSERT_EQ("and the module was released",
        P11Mock_GetCalls()->nFreeLibrary > 0, 1);

    /* C_Initialize refusing. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads  = TRUE;
    P11Mock_GetConfig()->rv_Initialize = CKR_DEVICE_ERROR;
    ss = P11_Initialize();
    ASSERT_ERR("C_Initialize failure propagates", ss);

    /* A token already initialised by another library in the same process is
     * not an error — this provider may not be the only PKCS#11 consumer. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads  = TRUE;
    P11Mock_GetConfig()->rv_Initialize = CKR_CRYPTOKI_ALREADY_INITIALIZED;
    ss = P11_Initialize();
    ASSERT_OK("CKR_CRYPTOKI_ALREADY_INITIALIZED is tolerated", ss);

    /* No slot with a token present.
     *
     * The slot is bound lazily now, so this is P11_EnsureSlotSelected's
     * answer rather than P11_Initialize's: loading the module and calling
     * C_Initialize genuinely did succeed, and nothing about them depends on
     * a token being present. Reporting failure from P11_Initialize would
     * blame the wrong step. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 0;
    ASSERT_OK("Initialising with no token present still succeeds",
              P11_Initialize());
    ss = P11_EnsureSlotSelected();
    ASSERT_EQ("but binding a slot → NTE_NO_KEY", ss,
              (SECURITY_STATUS)NTE_NO_KEY);
    ASSERT("and nothing is bound", !P11_IsSlotBound());

    /* And that failure is retryable too — a token inserted later must work
     * without restarting the host, which is the whole point of OPS-08. */
    P11Mock_GetConfig()->nSlots = 1;
    ss = P11_EnsureSlotSelected();
    ASSERT_OK("A token appearing later is picked up", ss);
    ASSERT("and the slot is now bound", P11_IsSlotBound());

    /* ── Suite 5 : the probe runs when the slot is bound ───────────────── */
    TEST_SUITE("Probe on slot binding");

    /* The probe reads the token's mechanism list, so it cannot run before
     * there is a token to read. It moved out of P11_Initialize with the
     * slot selection, and anything that asks a capability question binds
     * the slot first. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    ss = P11_Initialize();
    ASSERT_OK("Initialised", ss);
    ASSERT("but nothing is probed yet — there is no token chosen",
           !P11_CapsProbed());

    ss = P11_EnsureSlotSelected();
    ASSERT_OK("Slot bound", ss);
    ASSERT("The token was probed", P11_CapsProbed());
    ASSERT("and its mechanisms are known",
        P11_HasMechanism(CKM_RSA_PKCS_KEY_PAIR_GEN));
    ASSERT("including ones it does not have",
        !P11_HasMechanism(CKM_ML_DSA));

    /* A token that refuses the probe still initialises: the mechanism list
     * is a capability hint, not a precondition. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads        = TRUE;
    P11Mock_GetConfig()->rv_GetMechanismList = CKR_FUNCTION_NOT_SUPPORTED;
    ss = P11_Initialize();
    ASSERT_OK("A refused probe does not fail initialisation", ss);
    ASSERT("and nothing was probed", !P11_CapsProbed());

    /* ── Suite 6 : choosing the token after initialisation (IFACE-04) ─────
     *
     * The point of deferring the binding. P11_Initialize loads the module
     * and calls C_Initialize, neither of which needs a token; the slot is
     * chosen on the first call that does. That leaves a window in which
     * NCryptSetProperty can name the token, which is what IFACE-04 asked
     * for and what the old code could not offer.
     *
     * The mock presents several slots with distinct labels so these
     * assertions can tell a working selection from an ignored one. With one
     * token they could not: every selection would "succeed" by landing on
     * the slot the default would have chosen anyway. */
    TEST_SUITE("Token selection through the property (IFACE-04)");

    /* By label. Slot 2 is deliberately not the default, which is slot 0. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    snprintf(P11Mock_GetConfig()->szSlotLabels[2],
             sizeof(P11Mock_GetConfig()->szSlotLabels[2]), "Chosen");
    ASSERT_OK("Initialised with four tokens present", P11_Initialize());
    ASSERT("Nothing bound yet", !P11_IsSlotBound());

    ASSERT_OK("Select by label before binding",
              P11_SetTokenSelection("Chosen", NULL));
    ASSERT_OK("Binding then succeeds", P11_EnsureSlotSelected());
    ASSERT("and the slot is bound", P11_IsSlotBound());
    ASSERT_EQ("the chosen token's slot was taken, not the first",
              (int)P11_GetContext()->slotId, 2);

    /* Too late. PKCS#11 cannot move a session between tokens, so the only
     * honest answers are "refuse" and "lie". */
    ASSERT_EQ("Selecting after binding → NTE_INVALID_HANDLE",
              P11_SetTokenSelection("MockToken1", NULL),
              (SECURITY_STATUS)NTE_INVALID_HANDLE);
    ASSERT_EQ("and the slot did not move",
              (int)P11_GetContext()->slotId, 2);

    /* By slot ID. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    ASSERT_OK("Initialised", P11_Initialize());
    {
        CK_SLOT_ID want = 3;
        ASSERT_OK("Select by slot", P11_SetTokenSelection(NULL, &want));
        ASSERT_OK("Binding succeeds", P11_EnsureSlotSelected());
        ASSERT_EQ("the named slot was taken",
                  (int)P11_GetContext()->slotId, 3);
    }

    /* An explicit selection that matches nothing is an error, never a
     * fallback to slot 0. A fallback would sign with the wrong key and
     * report success — the same failure the environment-variable path has
     * refused since session 3. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_OK("Select a label no token carries",
              P11_SetTokenSelection("NoSuchToken", NULL));
    ASSERT_EQ("Binding → NTE_NO_KEY, not slot 0",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);
    ASSERT("and nothing is bound", !P11_IsSlotBound());

    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 2;
    ASSERT_OK("Initialised", P11_Initialize());
    {
        CK_SLOT_ID absent = 9;
        ASSERT_OK("Select an absent slot",
                  P11_SetTokenSelection(NULL, &absent));
        ASSERT_EQ("Binding → NTE_NO_KEY, not slot 0",
                  P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);
        ASSERT("and nothing is bound", !P11_IsSlotBound());

        /* Correctable without a restart, like every other failure here. */
        absent = 1;
        ASSERT_OK("Correcting the selection",
                  P11_SetTokenSelection(NULL, &absent));
        ASSERT_OK("Binding then succeeds", P11_EnsureSlotSelected());
        ASSERT_EQ("on the corrected slot",
                  (int)P11_GetContext()->slotId, 1);
    }

    /* One selection at a time: a label and a slot ID can disagree, so the
     * later call must replace the earlier rather than both being consulted
     * in some order the caller cannot see. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    snprintf(P11Mock_GetConfig()->szSlotLabels[1],
             sizeof(P11Mock_GetConfig()->szSlotLabels[1]), "ByLabel");
    ASSERT_OK("Initialised", P11_Initialize());
    {
        CK_SLOT_ID want = 3;
        ASSERT_OK("Select by label", P11_SetTokenSelection("ByLabel", NULL));
        ASSERT_OK("then by slot",     P11_SetTokenSelection(NULL, &want));
        ASSERT_OK("Binding succeeds", P11_EnsureSlotSelected());
        ASSERT_EQ("the later selection won",
                  (int)P11_GetContext()->slotId, 3);

        /* And the other way round. */
        Reset();
        P11Mock_GetConfig()->bModuleLoads = TRUE;
        P11Mock_GetConfig()->nSlots       = 4;
        snprintf(P11Mock_GetConfig()->szSlotLabels[1],
                 sizeof(P11Mock_GetConfig()->szSlotLabels[1]), "ByLabel");
        ASSERT_OK("Initialised", P11_Initialize());
        want = 3;
        ASSERT_OK("Select by slot",  P11_SetTokenSelection(NULL, &want));
        ASSERT_OK("then by label",   P11_SetTokenSelection("ByLabel", NULL));
        ASSERT_OK("Binding succeeds", P11_EnsureSlotSelected());
        ASSERT_EQ("the later selection won again",
                  (int)P11_GetContext()->slotId, 1);
    }

    /* Argument validation: exactly one of the two. Both or neither is a
     * caller error, not a silent preference for one of them. */
    ASSERT_EQ("Neither label nor slot → NTE_INVALID_PARAMETER",
              P11_SetTokenSelection(NULL, NULL),
              (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    {
        CK_SLOT_ID both = 0;
        ASSERT_EQ("Both → NTE_INVALID_PARAMETER",
                  P11_SetTokenSelection("X", &both),
                  (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }

    /* A label longer than CKA_LABEL cannot match any token. Refused rather
     * than truncated: a truncated label selects a DIFFERENT token. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    {
        char szLong[P11_TOKEN_LABEL_LEN + 4];
        memset(szLong, 'x', sizeof(szLong) - 1);
        szLong[sizeof(szLong) - 1] = '\0';
        ASSERT_EQ("Over-long label → NTE_INVALID_PARAMETER",
                  P11_SetTokenSelection(szLong, NULL),
                  (SECURITY_STATUS)NTE_INVALID_PARAMETER);
        ASSERT_EQ("Empty label → NTE_INVALID_PARAMETER",
                  P11_SetTokenSelection("", NULL),
                  (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }

    /* A label exactly P11_TOKEN_LABEL_LEN long must be accepted: CKA_LABEL
     * is 32 bytes blank-padded and NOT NUL-terminated, so a full-width
     * label is legal and an off-by-one here would reject it. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 2;
    {
        char szFull[P11_TOKEN_LABEL_LEN + 1];
        memset(szFull, 'y', P11_TOKEN_LABEL_LEN);
        szFull[P11_TOKEN_LABEL_LEN] = '\0';
        snprintf(P11Mock_GetConfig()->szSlotLabels[1],
                 sizeof(P11Mock_GetConfig()->szSlotLabels[1]), "%s", szFull);
        ASSERT_OK("Initialised", P11_Initialize());
        ASSERT_OK("A full-width 32-byte label is accepted",
                  P11_SetTokenSelection(szFull, NULL));
        ASSERT_OK("and matches the token carrying it",
                  P11_EnsureSlotSelected());
        ASSERT_EQ("on the right slot", (int)P11_GetContext()->slotId, 1);
    }

    /* The binding is idempotent, and a second call must not re-probe or
     * re-select: C_Initialize is not idempotent and neither is this. */
    {
        int nBefore = P11Mock_GetCalls()->nGetSlotList;
        ASSERT_OK("Second EnsureSlotSelected → OK", P11_EnsureSlotSelected());
        ASSERT_EQ("and it did not look at the slots again",
                  P11Mock_GetCalls()->nGetSlotList, nBefore);
    }

    /* P11_Finalize drops the binding. Leaving it set would make a later
     * EnsureSlotSelected answer "already done" against a context with no
     * module loaded. */
    P11_Finalize();
    ASSERT("Finalise clears the binding", !P11_IsSlotBound());

    /* ── Suite 7 : per-scope tokens (LIFE-08) ─────────────────────────────
     *
     * The live suite in tests/linux proves the ISOLATION — that a caller
     * holding the user PIN cannot read machine keys — because only a real
     * token has a PIN to withhold. What it cannot cover cheaply is the
     * resolution logic's refusals, and those are the part that decides
     * whether a misconfigured deployment fails closed or silently puts one
     * scope's keys on the other scope's token.
     *
     * The mock gives each slot a distinct CKA_LABEL, so selecting between
     * them is a real question here too. GetEnvironmentVariableA in the mock
     * reads the process environment, so setenv/unsetenv drive it. */
    TEST_SUITE("Per-scope tokens (LIFE-08)");

    /* Unconfigured: one token, both scopes on it, nothing changes. This is
     * the assertion that matters most, because every existing deployment is
     * this one. */
    unsetenv(KSP_MACHINE_TOKEN_LABEL_ENV);
    unsetenv(KSP_USER_TOKEN_LABEL_ENV);
    unsetenv(KSP_MACHINE_SLOT_ENV);
    unsetenv(KSP_USER_SLOT_ENV);
    Reset();
    /* Suite 6 left a token selection behind, and that persistence is
     * deliberate: P11_Finalize keeps the caller's choice so a re-initialise
     * honours it. P11_ClearTokenSelection is how a caller takes it back,
     * and it is what makes these two suites independent. */
    ASSERT_OK("Clearing the selection suite 6 left",
              P11_ClearTokenSelection());
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_OK("Binding succeeds with no per-scope configuration",
              P11_EnsureSlotSelected());
    ASSERT("per-scope tokens are NOT in effect", !P11_HasPerScopeTokens());
    ASSERT_EQ("the user scope is the bound slot",
              (int)P11_GetScopeSlot(P11_SCOPE_USER),
              (int)P11_GetContext()->slotId);
    ASSERT_EQ("and so is the machine scope — one token, as before",
              (int)P11_GetScopeSlot(P11_SCOPE_MACHINE),
              (int)P11_GetContext()->slotId);

    /* An out-of-range scope answers the user scope rather than reading off
     * the end of the array. */
    ASSERT_EQ("A scope outside the range falls back to USER",
              (int)P11_GetScopeSlot(99),
              (int)P11_GetScopeSlot(P11_SCOPE_USER));
    ASSERT_EQ("and so does a negative one",
              (int)P11_GetScopeSlot(-1),
              (int)P11_GetScopeSlot(P11_SCOPE_USER));

    /* Configured by label. Slot 3 for machine and slot 1 for user — neither
     * is the default, so a resolution that quietly used the bound slot for
     * either scope is visible. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    snprintf(P11Mock_GetConfig()->szSlotLabels[3],
             sizeof(P11Mock_GetConfig()->szSlotLabels[3]), "MachTok");
    snprintf(P11Mock_GetConfig()->szSlotLabels[1],
             sizeof(P11Mock_GetConfig()->szSlotLabels[1]), "UserTok");
    setenv(KSP_MACHINE_TOKEN_LABEL_ENV, "MachTok", 1);
    setenv(KSP_USER_TOKEN_LABEL_ENV,    "UserTok", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_OK("Binding succeeds with two labels", P11_EnsureSlotSelected());
    ASSERT("per-scope tokens ARE in effect", P11_HasPerScopeTokens());
    ASSERT_EQ("the machine scope resolved to its token",
              (int)P11_GetScopeSlot(P11_SCOPE_MACHINE), 3);
    ASSERT_EQ("the user scope resolved to its own",
              (int)P11_GetScopeSlot(P11_SCOPE_USER), 1);
    ASSERT_EQ("and the context reports the USER slot, which is what "
              "KSP_SLOT_PROPERTY returns and what the probe read",
              (int)P11_GetContext()->slotId, 1);

    /* One label alone. The outcome is a refusal either way — the absent
     * label is the empty string and matches no token — so this covers the
     * path rather than proving the explicit guard. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    snprintf(P11Mock_GetConfig()->szSlotLabels[3],
             sizeof(P11Mock_GetConfig()->szSlotLabels[3]), "MachTok");
    setenv(KSP_MACHINE_TOKEN_LABEL_ENV, "MachTok", 1);
    unsetenv(KSP_USER_TOKEN_LABEL_ENV);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_EQ("One label alone → NTE_NO_KEY, not a guessed second token",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);
    ASSERT("and nothing is bound", !P11_IsSlotBound());

    /* A label no token carries. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    snprintf(P11Mock_GetConfig()->szSlotLabels[1],
             sizeof(P11Mock_GetConfig()->szSlotLabels[1]), "UserTok");
    setenv(KSP_MACHINE_TOKEN_LABEL_ENV, "NoSuchMachineToken", 1);
    setenv(KSP_USER_TOKEN_LABEL_ENV,    "UserTok", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_EQ("A machine label no token carries → NTE_NO_KEY",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);

    /* The other way round, so neither lookup is the only one tested. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    snprintf(P11Mock_GetConfig()->szSlotLabels[3],
             sizeof(P11Mock_GetConfig()->szSlotLabels[3]), "MachTok");
    setenv(KSP_MACHINE_TOKEN_LABEL_ENV, "MachTok", 1);
    setenv(KSP_USER_TOKEN_LABEL_ENV,    "NoSuchUserToken", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_EQ("A user label no token carries → NTE_NO_KEY",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);

    /* Both labels naming the SAME token. Refused: it reads as isolation and
     * is not, and a deployment that believes its scopes are separated when
     * they share a token and a PIN is worse off than one that knows. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    snprintf(P11Mock_GetConfig()->szSlotLabels[2],
             sizeof(P11Mock_GetConfig()->szSlotLabels[2]), "OneTok");
    setenv(KSP_MACHINE_TOKEN_LABEL_ENV, "OneTok", 1);
    setenv(KSP_USER_TOKEN_LABEL_ENV,    "OneTok", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_EQ("Two scopes on one token → NTE_NO_KEY",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);
    ASSERT("and nothing is bound", !P11_IsSlotBound());
    unsetenv(KSP_MACHINE_TOKEN_LABEL_ENV);
    unsetenv(KSP_USER_TOKEN_LABEL_ENV);

    /* Configured by slot ID. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    setenv(KSP_MACHINE_SLOT_ENV, "2", 1);
    setenv(KSP_USER_SLOT_ENV,    "3", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_OK("Binding succeeds with two slot IDs",
              P11_EnsureSlotSelected());
    ASSERT("per-scope tokens are in effect", P11_HasPerScopeTokens());
    ASSERT_EQ("machine slot", (int)P11_GetScopeSlot(P11_SCOPE_MACHINE), 2);
    ASSERT_EQ("user slot",    (int)P11_GetScopeSlot(P11_SCOPE_USER),    3);

    /* One slot alone. THIS one is load-bearing: an unset variable leaves
     * the other scope at slot 0, which is a perfectly valid slot, so
     * without the guard a deployment naming only KSP_MACHINE_SLOT=2 would
     * silently put every user key on slot 0 and report success. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    setenv(KSP_MACHINE_SLOT_ENV, "2", 1);
    unsetenv(KSP_USER_SLOT_ENV);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_EQ("One slot alone → NTE_NO_KEY, not slot 0 for the other scope",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);
    ASSERT("and nothing is bound", !P11_IsSlotBound());

    /* A slot ID no token occupies, and a non-numeric one. Both are a
     * refusal rather than a fallback. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 2;
    setenv(KSP_MACHINE_SLOT_ENV, "9", 1);
    setenv(KSP_USER_SLOT_ENV,    "1", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_EQ("An absent machine slot → NTE_NO_KEY",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);

    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 2;
    setenv(KSP_MACHINE_SLOT_ENV, "not-a-number", 1);
    setenv(KSP_USER_SLOT_ENV,    "1", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_EQ("A non-numeric slot → NTE_NO_KEY, never slot 0",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);

    /* Two slot IDs naming the same token. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    setenv(KSP_MACHINE_SLOT_ENV, "2", 1);
    setenv(KSP_USER_SLOT_ENV,    "2", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_EQ("Two scopes on one slot → NTE_NO_KEY",
              P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);

    /* A label pair outranks a slot pair: a label names a token wherever the
     * module happens to enumerate it, which is the more specific statement
     * of intent, and the single-token path orders them the same way. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    snprintf(P11Mock_GetConfig()->szSlotLabels[3],
             sizeof(P11Mock_GetConfig()->szSlotLabels[3]), "MachTok");
    snprintf(P11Mock_GetConfig()->szSlotLabels[1],
             sizeof(P11Mock_GetConfig()->szSlotLabels[1]), "UserTok");
    setenv(KSP_MACHINE_TOKEN_LABEL_ENV, "MachTok", 1);
    setenv(KSP_USER_TOKEN_LABEL_ENV,    "UserTok", 1);
    setenv(KSP_MACHINE_SLOT_ENV, "0", 1);
    setenv(KSP_USER_SLOT_ENV,    "2", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_OK("Binding succeeds", P11_EnsureSlotSelected());
    ASSERT_EQ("the LABELS won for the machine scope",
              (int)P11_GetScopeSlot(P11_SCOPE_MACHINE), 3);
    ASSERT_EQ("and for the user scope",
              (int)P11_GetScopeSlot(P11_SCOPE_USER), 1);

    unsetenv(KSP_MACHINE_TOKEN_LABEL_ENV);
    unsetenv(KSP_USER_TOKEN_LABEL_ENV);
    unsetenv(KSP_MACHINE_SLOT_ENV);
    unsetenv(KSP_USER_SLOT_ENV);

    /* A caller selection and per-scope tokens are contradictory: one names
     * a single token, the other names two. Refused rather than resolved by
     * precedence, because letting the configuration win would leave the
     * caller's NCryptSetProperty accepted and ignored — and the caller is
     * the party least able to notice, having asked and been told yes. */
    Reset();
    ASSERT_OK("Start from no selection", P11_ClearTokenSelection());
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    setenv(KSP_MACHINE_SLOT_ENV, "2", 1);
    setenv(KSP_USER_SLOT_ENV,    "3", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    {
        CK_SLOT_ID want = 1;
        ASSERT_OK("A caller selects a single token",
                  P11_SetTokenSelection(NULL, &want));
        ASSERT_EQ("Binding → NTE_NO_KEY: the two cannot both be honoured",
                  P11_EnsureSlotSelected(), (SECURITY_STATUS)NTE_NO_KEY);
        ASSERT("and nothing is bound", !P11_IsSlotBound());

        /* Clearing the selection resolves it, and the configuration then
         * applies — the refusal is about the conflict, not about either
         * mechanism being broken. */
        ASSERT_OK("Clearing the selection", P11_ClearTokenSelection());
        ASSERT_OK("Binding then succeeds", P11_EnsureSlotSelected());
        ASSERT_EQ("on the configured machine token",
                  (int)P11_GetScopeSlot(P11_SCOPE_MACHINE), 2);

        /* And once bound, clearing is refused like setting. */
        ASSERT_EQ("Clearing after binding → NTE_INVALID_HANDLE",
                  P11_ClearTokenSelection(),
                  (SECURITY_STATUS)NTE_INVALID_HANDLE);
    }
    unsetenv(KSP_MACHINE_SLOT_ENV);
    unsetenv(KSP_USER_SLOT_ENV);

    /* P11_Finalize drops the per-scope resolution with the binding. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 4;
    setenv(KSP_MACHINE_SLOT_ENV, "2", 1);
    setenv(KSP_USER_SLOT_ENV,    "3", 1);
    ASSERT_OK("Initialised", P11_Initialize());
    ASSERT_OK("Bound", P11_EnsureSlotSelected());
    ASSERT("per-scope in effect", P11_HasPerScopeTokens());
    P11_Finalize();
    ASSERT("Finalise drops the per-scope resolution too",
           !P11_HasPerScopeTokens());
    unsetenv(KSP_MACHINE_SLOT_ENV);
    unsetenv(KSP_USER_SLOT_ENV);

    P11_Finalize();

    TEST_REPORT();
    TEST_EXIT();
}
