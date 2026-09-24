/* p11_pure_stubs.c — Minimal stubs for pure-function tests
 * Used by test_p11rv_mapping, test_ecdsa_decode, test_mechanism_resolve
 * which link p11_utils.c but do not call PKCS#11 functions directly.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"

typedef struct {
    void                *hModule;
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_ULONG             slotId;
    int                  bInitialized;
} P11_CONTEXT;

static P11_CONTEXT g_dummyCtx;

P11_CONTEXT *P11_GetContext(void) { return &g_dummyCtx; }

void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }

/* The capability probe. p11_utils.c consults it for raw RSA, which is
 * gated on the token advertising CKM_RSA_X_509 the same way ML-DSA is.
 *
 * TRUE here matches the real P11_HasMechanism's behaviour when no probe
 * has run: permissive, so a token that refuses C_GetMechanismList keeps
 * working exactly as it did before the probe existed. These suites test
 * pure mapping functions and have no token to ask.
 *
 * test_mldsa.c links the real p11_caps.c and is where the gate itself is
 * exercised, in both directions. */
BOOL P11_HasMechanism(CK_MECHANISM_TYPE mech) { (void)mech; return TRUE; }
