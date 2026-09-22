/* p11_caps.h — what the token behind this provider can actually do.
 *
 * Until now the KSP answered NCryptEnumAlgorithms and NCryptIsAlgSupported
 * from a list compiled into the DLL. That list describes SoftHSM2 2.7.0 and
 * nothing else: point the provider at a different PKCS#11 module — which
 * SOFTHSM2_LIB has always allowed — and it would still claim AES, ECDH and
 * P-521 whether or not the token had ever heard of them. The failure would
 * surface as a key-generation error long after the application had chosen
 * the algorithm on the provider's word.
 *
 * C_GetMechanismList is the answer PKCS#11 already provides. This module
 * asks the token once, at initialisation, and keeps the reply. Algorithm
 * advertisement then becomes the intersection of what the KSP can map and
 * what the token implements.
 *
 * That intersection is also the only honest way to reach post-quantum:
 * ML-DSA is unreachable on SoftHSM2 2.7.0 and reachable on a PKCS#11 v3.2
 * token, and the difference is visible only at runtime.
 *
 * Threading: the probe runs inside the InitOnceExecuteOnce callback in
 * p11_context.c, before any other thread can hold a provider handle, and the
 * stored answer is read-only afterwards. No lock is needed and none is taken.
 */
#ifndef P11_CAPS_H
#define P11_CAPS_H

#include "../common/ksp_windows.h"
#include "pkcs11.h"

/* Ask the token what it implements and remember the answer.
 *
 * Returns ERROR_SUCCESS when the token answered. A token that refuses
 * C_GetMechanismList is not a fatal error: the provider falls back to
 * advertising its full compiled-in list, which is exactly the behaviour
 * that existed before this module. Failing closed would break a working
 * deployment on the day this shipped, for no security benefit — the
 * mechanism list is a capability hint, not an access control. */
SECURITY_STATUS P11_ProbeCapabilities(void);

/* Release the probe result. Called from P11_Finalize. */
void P11_ReleaseCapabilities(void);

/* TRUE once a probe has succeeded. While FALSE, P11_HasMechanism answers
 * TRUE for everything, so callers filtering on it degrade to the old
 * unfiltered behaviour rather than to an empty provider. */
BOOL P11_CapsProbed(void);

/* TRUE if the token advertises this mechanism — or if no probe succeeded. */
BOOL P11_HasMechanism(CK_MECHANISM_TYPE mech);

/* The token's CKF_* flags for a mechanism, or 0 if it has none.
 *
 * Kept for diagnostics and for a future refinement; nothing filters on it
 * today. Flags are reliable, but the key-size range that comes with them is
 * not comparable across mechanisms: PKCS#11 leaves the unit to each one, so
 * SoftHSM2 reports RSA in bits (2048..16384) and AES in bytes (16..32) from
 * the same two fields. Filtering on those numbers without a per-mechanism
 * unit table would silently drop AES. Curve support is not expressible as a
 * range at all — a token may implement P-256 and P-384 but not P-521 while
 * reporting 256..521. */
CK_FLAGS P11_MechanismFlags(CK_MECHANISM_TYPE mech);

/* The Cryptoki version the module reports through C_GetInfo. Zero if the
 * probe has not run or C_GetInfo failed. */
void P11_GetCryptokiVersion(CK_BYTE *pbMajor, CK_BYTE *pbMinor);

/* TRUE if the module reports at least this Cryptoki version.
 *
 * The PQC mechanisms are PKCS#11 v3.2 additions, and their numeric values
 * fall in a range that v2.40 assigned to nothing. A v2.40 module answering
 * a question about CKM_ML_DSA is being asked about a mechanism its own
 * header does not define, so the version is checked as well as the list. */
BOOL P11_CryptokiAtLeast(CK_BYTE bMajor, CK_BYTE bMinor);

/* Upper bound on the mechanism count this provider will accept from
 * C_GetMechanismList. SoftHSM2 2.7.0 reports about 70.
 *
 * A token reporting more than this abandons the probe rather than having
 * its list truncated: a partial capability view would make the provider
 * refuse algorithms the token really has, whereas no view at all is
 * answered permissively and costs nothing. */
#define P11_MAX_MECHANISMS  512

#endif /* P11_CAPS_H */
