/* p11_prov_stub.c — the PKCS#11-layer calls ksp_provider.c makes, for
 * suites that link it without p11_context.c or p11_session.c.
 *
 * KSP_SetProviderProperty hands the PIN to the session layer and the token
 * selection to the context layer, and both capability entry points bind the
 * slot before answering. Each of those is a link dependency from the KSP
 * layer onto a PKCS#11 module these suites deliberately do not build.
 *
 * The stubs succeed and record nothing: a suite exercising key or crypto
 * behaviour has nothing to say about slot binding. The suite that does —
 * test_ksp_provider.c — defines its own recording versions and must NOT
 * link this file, or the definitions collide.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"

SECURITY_STATUS P11_SetPin(const char *szPin) { (void)szPin; return ERROR_SUCCESS; }
void            P11_ClearPin(void)            {}

SECURITY_STATUS P11_EnsureSlotSelected(void)  { return ERROR_SUCCESS; }
BOOL            P11_IsSlotBound(void)         { return FALSE; }
SECURITY_STATUS P11_SetTokenSelection(const char *szLabel,
                                      const CK_SLOT_ID *pSlot)
{ (void)szLabel; (void)pSlot; return ERROR_SUCCESS; }
