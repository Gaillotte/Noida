/* test_p11_session.c — Coverage of p11_session.c
 *
 * The session pool had no tests at all: it was not compiled into any suite,
 * so none of its code appeared in the coverage report. That is the module
 * holding the token credential and every PKCS#11 session the provider uses.
 *
 * These cover the parts that can be exercised without a real token: the
 * PIN override and its precedence over the environment, lazy opening,
 * pool exhaustion, and the recovery path that reopens a session the token
 * has logged out or closed underneath us.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "../../src/pkcs11/p11_session.h"
#include "test_framework.h"
#include <string.h>

/* ── Context stub ───────────────────────────────────────────────────────── */
typedef struct { void *hModule; CK_FUNCTION_LIST_PTR pFunctionList;
                 CK_SLOT_ID slotId; BOOL bInitialized; } P11_CONTEXT;
static P11_CONTEXT g_testCtx;
P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }

void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }

/* p11_session.c reaches P11RvToSecStatus in p11_utils.c, which drags in the
 * whole utility module. Only the mapping is needed here. */
SECURITY_STATUS P11RvToSecStatus(CK_RV rv)
{
    return (rv == CKR_OK) ? ERROR_SUCCESS : (SECURITY_STATUS)NTE_FAIL;
}

static void reset_pool(void)
{
    P11_SessionPool_Finalize();
    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    g_testCtx.slotId        = 0;
    P11_SessionPool_Initialize();
}

int main(void)
{
    SECURITY_STATUS   ss;
    CK_SESSION_HANDLE h1 = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE h2 = CK_INVALID_HANDLE;

    /* ── Suite 1 : the PIN override ─────────────────────────────────────── */
    TEST_SUITE("P11_SetPin / P11_ClearPin");

    reset_pool();

    ASSERT_OK("Set a PIN → OK", P11_SetPin("1234"));
    ASSERT_OK("Replace it → OK", P11_SetPin("5678"));
    ASSERT_OK("Clear with NULL → OK", P11_SetPin(NULL));

    {
        /* Exactly at the limit is accepted; one past it is refused. A PIN
         * that is silently truncated fails to log in for no visible
         * reason, which is far harder to diagnose than an error here. */
        char szMax[P11_MAX_PIN_LEN + 2];
        memset(szMax, 'p', P11_MAX_PIN_LEN);
        szMax[P11_MAX_PIN_LEN] = '\0';
        ASSERT_OK("PIN of exactly P11_MAX_PIN_LEN → OK", P11_SetPin(szMax));

        szMax[P11_MAX_PIN_LEN]     = 'p';
        szMax[P11_MAX_PIN_LEN + 1] = '\0';
        ASSERT_EQ("One character longer → NTE_INVALID_PARAMETER",
            P11_SetPin(szMax), (SECURITY_STATUS)NTE_INVALID_PARAMETER);
    }

    ASSERT_OK("Empty PIN is accepted (a token may have none)",
        P11_SetPin(""));
    P11_ClearPin();

    /* ── Suite 2 : sessions open lazily ─────────────────────────────────── */
    TEST_SUITE("P11_AcquireSession — lazy open");

    reset_pool();

    ASSERT_EQ("No session opened before the first acquire",
        P11Mock_GetCalls()->nOpenSession, 0);

    ss = P11_AcquireSession(&h1);
    ASSERT_OK("First acquire → OK", ss);
    ASSERT_NEQ("Returns a session handle", h1, (CK_SESSION_HANDLE)CK_INVALID_HANDLE);
    ASSERT_EQ("Opened exactly one session",
        P11Mock_GetCalls()->nOpenSession, 1);
    ASSERT_EQ("And logged it in", P11Mock_GetCalls()->nLogin, 1);

    P11_ReleaseSession(h1);

    /* Releasing does not close: the pool keeps the session for reuse. */
    ss = P11_AcquireSession(&h2);
    ASSERT_OK("Second acquire → OK", ss);
    ASSERT_EQ("Reused the pooled session, no second open",
        P11Mock_GetCalls()->nOpenSession, 1);
    ASSERT_EQ("And did not log in again", P11Mock_GetCalls()->nLogin, 1);
    P11_ReleaseSession(h2);

    /* ── Suite 3 : login already done is not an error ───────────────────── */
    TEST_SUITE("P11_AcquireSession — login states");

    reset_pool();
    P11Mock_GetConfig()->rv_Login = CKR_USER_ALREADY_LOGGED_IN;
    ss = P11_AcquireSession(&h1);
    ASSERT_OK("CKR_USER_ALREADY_LOGGED_IN tolerated", ss);
    P11_ReleaseSession(h1);

    reset_pool();
    P11Mock_GetConfig()->rv_Login = CKR_PIN_INCORRECT;
    ss = P11_AcquireSession(&h1);
    ASSERT_ERR("A wrong PIN fails the acquire", ss);
    ASSERT_EQ("And the failed session was closed",
        P11Mock_GetCalls()->nCloseSession, 1);

    /* The semaphore slot must be returned, or a failed login would leak a
     * pool entry and the sixteenth failure would deadlock. */
    P11Mock_GetConfig()->rv_Login = CKR_OK;
    ss = P11_AcquireSession(&h1);
    ASSERT_OK("A later acquire still succeeds (slot not leaked)", ss);
    P11_ReleaseSession(h1);

    reset_pool();
    P11Mock_GetConfig()->rv_OpenSession = CKR_DEVICE_ERROR;
    ss = P11_AcquireSession(&h1);
    ASSERT_ERR("C_OpenSession failure propagates", ss);

    /* ── Suite 4 : recovery after the token logs out (OPS-09) ───────────── */
    TEST_SUITE("P11_AcquireSession — session recovery");

    reset_pool();

    ss = P11_AcquireSession(&h1);
    ASSERT_OK("Acquire a session", ss);
    P11_ReleaseSession(h1);
    ASSERT_EQ("One open so far", P11Mock_GetCalls()->nOpenSession, 1);

    /* The token logged out underneath the pool. The handle is still
     * numerically valid, so only C_GetSessionInfo reveals it. */
    P11Mock_GetConfig()->sessionState = CKS_RW_PUBLIC_SESSION;

    ss = P11_AcquireSession(&h2);
    ASSERT_OK("Acquire after logout → OK", ss);
    ASSERT_EQ("Session state was checked",
        P11Mock_GetCalls()->nGetSessionInfo > 0, 1);
    ASSERT_EQ("Stale session was closed",
        P11Mock_GetCalls()->nCloseSession, 1);
    ASSERT_EQ("A fresh session was opened",
        P11Mock_GetCalls()->nOpenSession, 2);
    ASSERT_EQ("And logged in again", P11Mock_GetCalls()->nLogin, 2);
    P11_ReleaseSession(h2);

    /* A read-only user session is still logged in and must be kept. */
    reset_pool();
    ss = P11_AcquireSession(&h1);
    ASSERT_OK("Acquire", ss);
    P11_ReleaseSession(h1);
    P11Mock_GetConfig()->sessionState = CKS_RO_USER_FUNCTIONS;
    ss = P11_AcquireSession(&h2);
    ASSERT_OK("Acquire again", ss);
    ASSERT_EQ("Read-only user session is not discarded",
        P11Mock_GetCalls()->nOpenSession, 1);
    P11_ReleaseSession(h2);

    /* A handle the token no longer recognises must also be replaced. */
    reset_pool();
    ss = P11_AcquireSession(&h1);
    ASSERT_OK("Acquire", ss);
    P11_ReleaseSession(h1);
    P11Mock_GetConfig()->rv_GetSessionInfo = CKR_SESSION_HANDLE_INVALID;
    ss = P11_AcquireSession(&h2);
    ASSERT_OK("Acquire after the handle went invalid → OK", ss);
    ASSERT_EQ("Reopened", P11Mock_GetCalls()->nOpenSession, 2);
    P11_ReleaseSession(h2);

    /* A healthy session must not be reopened — recovery that fires every
     * time would quietly cost a login per operation. */
    reset_pool();
    ss = P11_AcquireSession(&h1);
    P11_ReleaseSession(h1);
    ss = P11_AcquireSession(&h2);
    ASSERT_OK("Acquire a healthy session", ss);
    ASSERT_EQ("Healthy session reused, not reopened",
        P11Mock_GetCalls()->nOpenSession, 1);
    ASSERT_EQ("No redundant login", P11Mock_GetCalls()->nLogin, 1);
    P11_ReleaseSession(h2);

    /* ── Suite 5 : parameter and lifecycle handling ─────────────────────── */
    TEST_SUITE("Pool lifecycle");

    reset_pool();
    ASSERT_EQ("phSession=NULL → NTE_INVALID_PARAMETER",
        P11_AcquireSession(NULL), (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* Releasing a handle the pool does not hold must be harmless. */
    P11_ReleaseSession((CK_SESSION_HANDLE)0xDEAD);
    ASSERT_OK("Release of an unknown handle is a no-op",
        P11_AcquireSession(&h1));
    P11_ReleaseSession(h1);

    ASSERT_OK("Re-initialising an initialised pool is a no-op",
        P11_SessionPool_Initialize());

    P11_SessionPool_Finalize();
    /* Finalise twice: the second must not fault on freed locks. */
    P11_SessionPool_Finalize();
    ASSERT("Double finalise survived", 1);

    TEST_REPORT();
    TEST_EXIT();
}
