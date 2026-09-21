/* p11_pin_stub.c — session-layer PIN storage, for suites that link
 * ksp_provider.c without p11_session.c.
 *
 * KSP_SetProviderProperty(NCRYPT_PIN_PROPERTY) hands the PIN to the session
 * layer, which creates a link dependency from the KSP layer onto the
 * PKCS#11 session pool. Suites exercising key or crypto behaviour do not
 * want the real pool, so they link this instead.
 *
 * test_ksp_provider.c defines its own recording version and must NOT link
 * this file, or the two definitions collide.
 */
#include "../mock/windows_compat.h"

SECURITY_STATUS P11_SetPin(const char *szPin) { (void)szPin; return ERROR_SUCCESS; }
void            P11_ClearPin(void)            {}
