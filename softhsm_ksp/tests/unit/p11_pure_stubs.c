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
