/* p11_session.h — Pool de sessions PKCS#11
 * Gère jusqu'à P11_SESSION_POOL_SIZE sessions concurrentes.
 * Acquisition via sémaphore, login automatique à la première ouverture.
 */
#ifndef P11_SESSION_H
#define P11_SESSION_H

#include <windows.h>
#include "pkcs11.h"

/* Entrée du pool de sessions */
typedef struct _P11_SESSION_ENTRY {
    CK_SESSION_HANDLE hSession;    /* Handle PKCS#11 */
    BOOL              bInUse;      /* En cours d'utilisation ? */
    BOOL              bLoggedIn;   /* Session authentifiée ? */
    CRITICAL_SECTION  cs;          /* Protection per-session */
} P11_SESSION_ENTRY;

/* Acquiert une session du pool (bloque si toutes occupées).
 * Effectue le login si nécessaire.
 * Retourne ERROR_SUCCESS ou un code SECURITY_STATUS. */
SECURITY_STATUS P11_AcquireSession(CK_SESSION_HANDLE *phSession);

/* Remet la session dans le pool sans la fermer */
void P11_ReleaseSession(CK_SESSION_HANDLE hSession);

/* Initialise le pool de sessions (appelé par P11_Initialize) */
SECURITY_STATUS P11_SessionPool_Initialize(void);

/* Détruit le pool de sessions (appelé par P11_Finalize) */
void P11_SessionPool_Finalize(void);

#endif /* P11_SESSION_H */
