/* p11_credential.h — the PIN as a DPAPI-protected blob (ADCS plan, C-b).
 *
 * A headless certsrv never calls NCryptSetProperty(NCRYPT_PIN_PROPERTY), so
 * without this the only credential route for a service is a machine-wide
 * environment variable readable by every process on the host. For a CA that
 * inverts the model the HSM was bought for: the key cannot be extracted,
 * but anyone on the box can ask the token to sign, and signing IS the asset.
 *
 * The blob is produced by tools/set_ksp_pin.ps1 with CryptProtectData at
 * CRYPTPROTECT_LOCAL_MACHINE scope and stored as a REG_BINARY value under
 * HKLM. Machine scope rather than user scope because the CA service account
 * is not the account an administrator provisions from; the ACL on the
 * registry value, not the DPAPI scope, is what restricts who can read it.
 *
 * WHAT IS AND IS NOT TESTED HERE
 *
 * KspAcceptPinBytes is pure and is covered by tests/unit/test_credential.c
 * on Linux. It is deliberately a separate function because it is where this
 * project's recurring defect lives: a counted buffer whose terminator is
 * mishandled. That exact off-by-one has already appeared twice, in the PIN
 * path and in a counted wide-string property, written independently.
 *
 * P11_ReadProtectedPin is Windows-only — a registry read and one
 * CryptUnprotectData call. It cannot be RUN here. It is compile-checked
 * against the real mingw-w64 dpapi.h and wincrypt.h by the cross-compile
 * job, which is more than "written blind" and less than "tested". Treat it
 * as unproven until Phase B runs it on Windows.
 */
#ifndef P11_CREDENTIAL_H
#define P11_CREDENTIAL_H

#include "../common/config.h"

#ifdef _WIN32
#  include "../common/ksp_windows.h"
#else
#  include "../../tests/mock/windows_compat.h"
#endif

/* Validate decrypted bytes and copy them out as a NUL-terminated PIN.
 *
 * Returns TRUE only when the whole value fits. A value too long is
 * REJECTED, never truncated: a silently shortened PIN fails the login with
 * no indication that the credential was the problem, which is the same
 * reasoning that makes P11_MAX_PIN_LEN a refusal elsewhere.
 *
 * `cb` is a byte count and the bytes are NOT required to be terminated —
 * DPAPI returns exactly what was protected. A terminator that IS present is
 * accepted and not counted twice.
 */
BOOL KspAcceptPinBytes(const BYTE *pbIn, DWORD cbIn,
                       char *pszOut, size_t cbOut);

/* Read the scope's protected PIN from the registry, if one is provisioned.
 *
 * TRUE  pszOut holds the PIN.
 * FALSE no blob is provisioned, or it could not be unprotected. The caller
 *       falls through to its other sources; a blob that EXISTS and fails to
 *       unprotect is logged, because that is a provisioning fault an
 *       administrator needs to see rather than a quiet fallback.
 */
BOOL P11_ReadProtectedPin(int nScope, char *pszOut, size_t cbOut);

#endif /* P11_CREDENTIAL_H */
