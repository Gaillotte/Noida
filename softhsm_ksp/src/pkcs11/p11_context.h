/* p11_context.h — PKCS#11 context singleton
 * Dynamically loads softhsm2.dll, initialises the library,
 * and selects the first available slot.
 */
#ifndef P11_CONTEXT_H
#define P11_CONTEXT_H

#include "../common/ksp_windows.h"
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

/* Bind the slot and probe the token, on first use.
 *
 * Called by anything that needs a token: acquiring a session, or answering
 * a capability question. Idempotent and cheap once bound. Separate from
 * P11_Initialize so that a caller has a window between opening the
 * provider and the first operation in which to choose the token. */
SECURITY_STATUS P11_EnsureSlotSelected(void);

/* Choose the token. Exactly one of szLabel / pSlot must be non-NULL.
 * Refused with NTE_INVALID_HANDLE once the slot is bound. */
SECURITY_STATUS P11_SetTokenSelection(const char *szLabel,
                                      const CK_SLOT_ID *pSlot);

/* Forget a token selection, reverting to the environment and then the
 * default. Refused with NTE_INVALID_HANDLE once the slot is bound. */
SECURITY_STATUS P11_ClearTokenSelection(void);

/* TRUE once the slot can no longer change. */
BOOL P11_IsSlotBound(void);

/* The slot a scope's keys live in (LIFE-08).
 *
 * With per-scope tokens configured, the machine and user scopes are on
 * different tokens with different PINs, so isolation is as strong as the
 * token boundary instead of being a label prefix anyone logged in can read.
 * Without them, both scopes answer the one bound slot and nothing changes.
 *
 * Valid after P11_EnsureSlotSelected. nScope is P11_SCOPE_USER or
 * P11_SCOPE_MACHINE; anything else is treated as the user scope. */
CK_SLOT_ID P11_GetScopeSlot(int nScope);

/* TRUE when the two scopes are on different tokens, so a caller can say
 * whether a deployment is isolated or merely namespaced. */
BOOL P11_HasPerScopeTokens(void);

/* Free the PKCS#11 context (called from DllMain PROCESS_DETACH) */
void P11_Finalize(void);

/* Return a pointer to the global context (valid after P11_Initialize) */
P11_CONTEXT *P11_GetContext(void);

#endif /* P11_CONTEXT_H */
