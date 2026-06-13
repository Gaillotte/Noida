/* ksp_key_stub.c — Minimal stub for KSP_IsValidKey
 * Used by test_ksp_key_props when ksp_key.c is not linked.
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
