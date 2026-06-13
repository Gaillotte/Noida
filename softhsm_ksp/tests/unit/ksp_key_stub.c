/* ksp_key_stub.c — Stub minimal pour KSP_IsValidKey
 * Utilisé par test_ksp_key_props quand ksp_key.c n'est pas lié.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "../../src/ksp/ksp_key.h"

BOOL KSP_IsValidKey(NCRYPT_KEY_HANDLE hKey)
{
    KSP_KEY *k = (KSP_KEY *)(ULONG_PTR)hKey;
    return (k && k->dwMagic == KSP_KEY_MAGIC);
}
