/* p11_context.h — PKCS#11 context singleton
 * Dynamically loads softhsm2.dll, initialises the library,
 * and selects the first available slot.
 */
#ifndef P11_CONTEXT_H
#define P11_CONTEXT_H

#include <windows.h>
#include "pkcs11.h"

/* Global PKCS#11 context (singleton) */
typedef struct _P11_CONTEXT {
    HMODULE              hModule;        /* softhsm2.dll handle */
    CK_FUNCTION_LIST_PTR pFunctionList;  /* Cryptoki function table */
    CK_SLOT_ID           slotId;         /* First slot with a token present */
    BOOL                 bInitialized;   /* Library initialised? */
} P11_CONTEXT;

/* Initialise the PKCS#11 context (thread-safe, idempotent).
 * Loads softhsm2.dll from SOFTHSM2_LIB or the default path.
 * Returns ERROR_SUCCESS or a SECURITY_STATUS code. */
SECURITY_STATUS P11_Initialize(void);

/* Free the PKCS#11 context (called from DllMain PROCESS_DETACH) */
void P11_Finalize(void);

/* Return a pointer to the global context (valid after P11_Initialize) */
P11_CONTEXT *P11_GetContext(void);

#endif /* P11_CONTEXT_H */
