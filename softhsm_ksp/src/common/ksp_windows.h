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

/* Target Windows version.
 *
 * Large parts of bcrypt.h are gated on NTDDI_VERSION, and without setting
 * it the build silently takes whatever the toolchain defaults to — which
 * is how BCRYPT_KDF_HKDF, KDF_HKDF_SALT and KDF_HKDF_INFO came to be
 * invisible even though the header declares them. They need
 * NTDDI_WIN10_RS4 (Windows 10 1803).
 *
 * This project already states Windows 10/11 as its target, so declaring it
 * here makes that real rather than implied. Set before <windows.h>, which
 * is why it lives in the include-policy header. */
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT   0x0A00        /* _WIN32_WINNT_WIN10 */
#endif
#ifndef NTDDI_VERSION
#  define NTDDI_VERSION  0x0A000005    /* NTDDI_WIN10_RS4 */
#endif

#include <windows.h>
#include <wincrypt.h>   /* AT_SIGNATURE, AT_KEYEXCHANGE */
#include <bcrypt.h>     /* BCRYPT_* identifiers, BCRYPT_*_BLOB structures */
#include <ncrypt.h>     /* SECURITY_STATUS, NCRYPT_* properties and flags */

#endif /* KSP_WINDOWS_H */
