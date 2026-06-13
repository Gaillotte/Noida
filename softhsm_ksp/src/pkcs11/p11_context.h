/* p11_context.h — Singleton de contexte PKCS#11
 * Charge softhsm2.dll dynamiquement, initialise la bibliothèque
 * et sélectionne le premier slot disponible.
 */
#ifndef P11_CONTEXT_H
#define P11_CONTEXT_H

#include <windows.h>
#include "pkcs11.h"

/* Contexte global PKCS#11 (singleton) */
typedef struct _P11_CONTEXT {
    HMODULE              hModule;        /* Handle softhsm2.dll */
    CK_FUNCTION_LIST_PTR pFunctionList;  /* Table des fonctions Cryptoki */
    CK_SLOT_ID           slotId;         /* Premier slot avec token présent */
    BOOL                 bInitialized;   /* Bibliothèque initialisée ? */
} P11_CONTEXT;

/* Initialise le contexte PKCS#11 (thread-safe, idempotent).
 * Charge softhsm2.dll depuis SOFTHSM2_LIB ou chemin par défaut.
 * Retourne ERROR_SUCCESS ou un code SECURITY_STATUS. */
SECURITY_STATUS P11_Initialize(void);

/* Libère le contexte PKCS#11 (appelé depuis DllMain PROCESS_DETACH) */
void P11_Finalize(void);

/* Retourne le pointeur vers le contexte global (valide après P11_Initialize) */
P11_CONTEXT *P11_GetContext(void);

#endif /* P11_CONTEXT_H */
