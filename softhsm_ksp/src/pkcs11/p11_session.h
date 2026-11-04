/* p11_session.h — PKCS#11 session pool
 * Manages up to P11_SESSION_POOL_SIZE concurrent sessions.
 * Acquisition via semaphore, automatic login on first open.
 */
#ifndef P11_SESSION_H
#define P11_SESSION_H

#include "../common/ksp_windows.h"
#include "pkcs11.h"

/* Session pool entry */
typedef struct _P11_SESSION_ENTRY {
    CK_SESSION_HANDLE hSession;    /* PKCS#11 handle */
    BOOL              bInUse;      /* Currently in use? */
    BOOL              bLoggedIn;   /* Session authenticated? */
    CRITICAL_SECTION  cs;          /* Per-session protection */
} P11_SESSION_ENTRY;

/* Acquire a session from the scope's pool (blocks if all are busy).
 * Performs login if necessary.
 *
 * nScope is P11_SCOPE_USER or P11_SCOPE_MACHINE. With per-scope tokens
 * configured (LIFE-08) the two scopes have separate pools on separate
 * tokens with separate PINs, so the scope decides which token the returned
 * session can see. Without them both scopes share pool 0 and the parameter
 * changes nothing.
 *
 * The parameter is mandatory rather than defaulted on purpose: a call site
 * that forgot it would silently operate on the wrong token under a
 * successful status, and the compiler is a better reviewer than a comment.
 *
 * Returns ERROR_SUCCESS or a SECURITY_STATUS code. */
SECURITY_STATUS P11_AcquireSession(int nScope, CK_SESSION_HANDLE *phSession);

/* Return a session to the pool without closing it */
void P11_ReleaseSession(CK_SESSION_HANDLE hSession);

/* Initialise the session pool (called by P11_Initialize) */
SECURITY_STATUS P11_SessionPool_Initialize(void);

/* Destroy the session pool (called by P11_Finalize) */
void P11_SessionPool_Finalize(void);

/* Set the user PIN used for C_Login, overriding SOFTHSM2_PIN.
 *
 * With per-scope tokens configured, KSP_MACHINE_PIN / KSP_USER_PIN outrank
 * this value — see GetEffectivePin. One PIN cannot name two tokens, and
 * sending the user PIN to the machine token is the failure per-scope tokens
 * exist to prevent.
 *
 * Sessions open lazily on first use, so a PIN set between
 * NCryptOpenStorageProvider and the first cryptographic call is the one
 * that will be used. Sessions already open keep their login; PKCS#11 has
 * no way to change credentials on a live session.
 *
 * szPin is copied and the caller's buffer is not retained. Pass NULL to
 * clear the override and fall back to the environment variable.
 *
 * Returns NTE_INVALID_PARAMETER if the PIN is longer than the token
 * accepts. */
SECURITY_STATUS P11_SetPin(const char *szPin);

/* Zero the stored PIN. Called by P11_SessionPool_Finalize; exposed so a
 * caller that is done authenticating can drop the credential early. */
void P11_ClearPin(void);

#endif /* P11_SESSION_H */
