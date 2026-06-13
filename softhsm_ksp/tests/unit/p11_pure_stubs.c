/* p11_pure_stubs.c — Stubs minimaux pour les tests de fonctions pures
 * Utilisé avec test_p11rv_mapping, test_ecdsa_decode, test_mechanism_resolve
 * qui linkent p11_utils.c mais n'appellent pas les fonctions PKCS#11 directes.
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
