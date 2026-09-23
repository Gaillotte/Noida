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

    /* No slot with a token present. */
    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    P11Mock_GetConfig()->nSlots       = 0;
    ss = P11_Initialize();
    ASSERT_EQ("No token present → NTE_NO_KEY", ss, (SECURITY_STATUS)NTE_NO_KEY);

    /* And that failure is retryable too — a token inserted later must work
     * without restarting the host, which is the whole point of OPS-08. */
    P11Mock_GetConfig()->nSlots = 1;
    ss = P11_Initialize();
    ASSERT_OK("A token appearing later is picked up", ss);

    /* ── Suite 5 : the capability probe runs as part of initialisation ─── */
    TEST_SUITE("Probe on initialisation");

    Reset();
    P11Mock_GetConfig()->bModuleLoads = TRUE;
    ss = P11_Initialize();
    ASSERT_OK("Initialised", ss);
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

    P11_Finalize();

    TEST_REPORT();
    TEST_EXIT();
}
