/* ksp_windows.h — the project's Windows include policy, in one place.
 *
 * Every KSP and PKCS#11 header includes this rather than <windows.h>
 * directly, because <windows.h> alone is not enough:
 *
 *   - WIN32_LEAN_AND_MEAN (set by CMakeLists.txt) excludes <wincrypt.h>,
 *     which is where AT_SIGNATURE and AT_KEYEXCHANGE live.
 *   - SECURITY_STATUS is declared by <ncrypt.h>, not by <windows.h>.
 *   - The BCRYPT_* algorithm identifiers and blob structures come from
 *     <bcrypt.h>.
 *
 * Relying on one of these to pull in another is what let the project reach
 * a state where seven of ten source files could not compile for Windows at
 * all. Include this header and the question does not arise.
 *
 * On Linux, tests/mock/ supplies shims for each of these names so the unit
 * suite resolves them to windows_compat.h.
 */
#ifndef KSP_WINDOWS_H
#define KSP_WINDOWS_H

#include <windows.h>
#include <wincrypt.h>   /* AT_SIGNATURE, AT_KEYEXCHANGE */
#include <bcrypt.h>     /* BCRYPT_* identifiers, BCRYPT_*_BLOB structures */
#include <ncrypt.h>     /* SECURITY_STATUS, NCRYPT_* properties and flags */

#endif /* KSP_WINDOWS_H */
