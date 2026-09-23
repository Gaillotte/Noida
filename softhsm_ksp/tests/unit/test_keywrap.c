/* test_keywrap.c — AES-09: RFC 3394 / 5649 key wrap
 *
 * Every key this provider creates is CKA_EXTRACTABLE=FALSE, so key material
 * has had no way in or out except the public half of an asymmetric pair.
 * Key wrap is the standard CNG answer: the caller supplies a key-encryption
 * key already on the token, and the target key crosses the boundary
 * encrypted under it. The plaintext key never exists outside the token.
 *
 * The two directions are not symmetric, and the asymmetry is the point:
 *
 *   unwrap  works on any token. A key arrives wrapped and is decrypted
 *           inside the token, into an object that is itself sensitive and
 *           non-extractable. This is the migration path.
 *   wrap    works only on a key the TOKEN considers extractable. This
 *           provider never creates such a key, so C_WrapKey answers
 *           CKR_KEY_UNEXTRACTABLE for anything it generated. That is the
 *           token enforcing the posture, not the KSP refusing, and the
 *           tests below assert the error is passed through rather than
 *           swallowed.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/common/config.h"
#include "../../src/common/memory.h"
#include "test_framework.h"
#include <wchar.h>
#include <string.h>

/* ── PKCS#11 context / session stubs ────────────────────────────────────── */
static P11_CONTEXT g_testCtx;

P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }
SECURITY_STATUS P11_Initialize(void)             { return ERROR_SUCCESS; }
SECURITY_STATUS P11_SessionPool_Initialize(void) { return ERROR_SUCCESS; }

SECURITY_STATUS P11_AcquireSession(CK_SESSION_HANDLE *ph)
{
    *ph = (CK_SESSION_HANDLE)1;
    return ERROR_SUCCESS;
}
void P11_ReleaseSession(CK_SESSION_HANDLE h) { (void)h; }

/* A token that implements key wrap, and one that does not. */
static const CK_MECHANISM_TYPE g_wrapToken[] = {
    CKM_AES_KEY_GEN, CKM_AES_CBC, CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS,
};
static const CK_MECHANISM_TYPE g_noWrapToken[] = {
    CKM_AES_KEY_GEN, CKM_AES_CBC,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS,
};

static NCRYPT_KEY_HANDLE MakeAesKey(NCRYPT_PROV_HANDLE hProv, LPCWSTR pszName)
{
    NCRYPT_KEY_HANDLE hKey = 0;
    if (KSP_CreatePersistedKey(hProv, &hKey, ALG_AES, pszName, 0,
                               NCRYPT_PERSIST_ONLY_FLAG) != ERROR_SUCCESS)
        return 0;
    if (KSP_FinalizeKey(hProv, hKey, 0) != ERROR_SUCCESS)
        return 0;
    return hKey;
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE  hKek  = 0;
    NCRYPT_KEY_HANDLE  hTarget = 0;
    NCRYPT_KEY_HANDLE  hNew  = 0;
    SECURITY_STATUS    ss;
    DWORD              cbResult = 0;
    BYTE               abWrapped[256];

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    g_testCtx.slotId        = 0;

    P11Mock_SetMechanisms(g_wrapToken,
                          sizeof(g_wrapToken) / sizeof(g_wrapToken[0]));
    P11_ProbeCapabilities();

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_OK("Provider opened", ss);

    hKek = MakeAesKey(hProv, L"kek");
    ASSERT("KEK created", hKek != 0);
    hTarget = MakeAesKey(hProv, L"payload");
    ASSERT("Target key created", hTarget != 0);

    /* ── Suite 1 : wrapping ─────────────────────────────────────────────── */
    TEST_SUITE("ExportKey — BCRYPT_AES_WRAP_KEY_BLOB");

    P11Mock_ResetCalls();

    /* Two-call convention: NULL buffer reports the wrapped length. */
    cbResult = 0;
    ss = KSP_ExportKey(hProv, hTarget, hKek, BCRYPT_AES_WRAP_KEY_BLOB,
                       NULL, NULL, 0, &cbResult, 0);
    ASSERT_OK("Size query succeeds", ss);
    ASSERT_EQ("Reports the wrapped length", cbResult,
        (DWORD)P11Mock_GetConfig()->cbWrapped);
    ASSERT_EQ("C_WrapKey was called once", P11Mock_GetCalls()->nWrapKey, 1);
    ASSERT_EQ("with CKM_AES_KEY_WRAP",
        P11Mock_GetConfig()->lastWrapMech,
        (CK_MECHANISM_TYPE)CKM_AES_KEY_WRAP);

    /* Both C_WrapKey calls are checked, not just the second. Asserting
     * only after the call that fills the buffer leaves the size query
     * unexamined — a fault injected there alone passed every assertion
     * in an earlier version of this suite. */
    {
        KSP_KEY *pKek = (KSP_KEY *)(ULONG_PTR)hKek;
        KSP_KEY *pTgt = (KSP_KEY *)(ULONG_PTR)hTarget;

        ASSERT_EQ("Size query used the KEK as the wrapping key",
            P11Mock_GetConfig()->lastWrappingKey, pKek->hSecretKey);
        ASSERT_EQ("and the target as the key being wrapped",
            P11Mock_GetConfig()->lastWrappedKey, pTgt->hSecretKey);
    }

    memset(abWrapped, 0, sizeof(abWrapped));
    cbResult = 0;
    ss = KSP_ExportKey(hProv, hTarget, hKek, BCRYPT_AES_WRAP_KEY_BLOB,
                       NULL, abWrapped, sizeof(abWrapped), &cbResult, 0);
    ASSERT_OK("Wrap succeeds", ss);
    ASSERT_EQ("Length is the wrapped length", cbResult,
        (DWORD)P11Mock_GetConfig()->cbWrapped);
    ASSERT("Something was written", abWrapped[0] == 0x5A);

    /* The KEK must be the wrapping key and the target the wrapped one.
     * Swapping the two arguments still produces a blob, so asserting only
     * that they differ would not catch it — each is checked against the
     * object handle it must be. */
    {
        KSP_KEY *pKek = (KSP_KEY *)(ULONG_PTR)hKek;
        KSP_KEY *pTgt = (KSP_KEY *)(ULONG_PTR)hTarget;

        ASSERT_EQ("The KEK is the wrapping key",
            P11Mock_GetConfig()->lastWrappingKey, pKek->hSecretKey);
        ASSERT_EQ("The target is the key being wrapped",
            P11Mock_GetConfig()->lastWrappedKey, pTgt->hSecretKey);
        ASSERT_NEQ("and they are genuinely different objects",
            pKek->hSecretKey, pTgt->hSecretKey);
    }

    cbResult = 0;
    ss = KSP_ExportKey(hProv, hTarget, hKek, BCRYPT_AES_WRAP_KEY_BLOB,
                       NULL, abWrapped, 4, &cbResult, 0);
    ASSERT_EQ("Short buffer → NTE_BUFFER_TOO_SMALL",
        ss, (SECURITY_STATUS)NTE_BUFFER_TOO_SMALL);
    ASSERT_EQ("and the needed size is reported", cbResult,
        (DWORD)P11Mock_GetConfig()->cbWrapped);

    /* ── Suite 2 : the wrapping key must be one ─────────────────────────── */
    TEST_SUITE("Wrapping key validation");

    cbResult = 0;
    ASSERT_EQ("No hExportKey → NTE_INVALID_PARAMETER",
        KSP_ExportKey(hProv, hTarget, 0, BCRYPT_AES_WRAP_KEY_BLOB,
                      NULL, NULL, 0, &cbResult, 0),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    {
        /* An RSA key cannot wrap under CKM_AES_KEY_WRAP. Catching it here
         * gives a clear answer instead of a mechanism error from the
         * token several layers down. */
        NCRYPT_KEY_HANDLE hRsa = 0;
        ss = KSP_CreatePersistedKey(hProv, &hRsa, ALG_RSA, L"not-a-kek", 0,
                                    NCRYPT_PERSIST_ONLY_FLAG);
        ASSERT_OK("RSA key created", ss);
        ss = KSP_FinalizeKey(hProv, hRsa, 0);
        ASSERT_OK("RSA key finalised", ss);

        cbResult = 0;
        ASSERT_EQ("An RSA wrapping key → NTE_BAD_KEY",
            KSP_ExportKey(hProv, hTarget, hRsa, BCRYPT_AES_WRAP_KEY_BLOB,
                          NULL, NULL, 0, &cbResult, 0),
            (SECURITY_STATUS)NTE_BAD_KEY);

        KSP_FreeKey(hProv, hRsa);
    }

    /* ── Suite 3 : the token decides what may leave ─────────────────────── */
    TEST_SUITE("Non-extractable keys stay put");

    P11Mock_GetConfig()->rv_WrapKey = CKR_KEY_UNEXTRACTABLE;
    cbResult = 0;
    ss = KSP_ExportKey(hProv, hTarget, hKek, BCRYPT_AES_WRAP_KEY_BLOB,
                       NULL, NULL, 0, &cbResult, 0);
    /* This is the answer for every key this provider generates, and it is
     * the token enforcing CKA_EXTRACTABLE=FALSE, not the KSP refusing.
     * P11RvToSecStatus maps it to NTE_NOT_SUPPORTED. */
    ASSERT_EQ("CKR_KEY_UNEXTRACTABLE → NTE_NOT_SUPPORTED",
        ss, (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    P11Mock_GetConfig()->rv_WrapKey = CKR_OK;

    /* ── Suite 4 : unwrapping ───────────────────────────────────────────── */
    TEST_SUITE("ImportKey — BCRYPT_AES_WRAP_KEY_BLOB");

    P11Mock_ResetCalls();
    memset(abWrapped, 0xC3, 40);

    hNew = 0;
    ss = KSP_ImportKey(hProv, hKek, BCRYPT_AES_WRAP_KEY_BLOB, NULL,
                       &hNew, abWrapped, 40, 0);
    ASSERT_OK("Unwrap succeeds", ss);
    ASSERT("A key handle came back", hNew != 0);
    ASSERT_EQ("C_UnwrapKey was called once", P11Mock_GetCalls()->nUnwrapKey, 1);
    ASSERT_EQ("with CKM_AES_KEY_WRAP",
        P11Mock_GetConfig()->lastUnwrapMech,
        (CK_MECHANISM_TYPE)CKM_AES_KEY_WRAP);
    ASSERT_EQ("The whole blob was handed to the token",
        P11Mock_GetConfig()->cbLastUnwrapInput, (CK_ULONG)40);
    ASSERT("and unaltered",
        memcmp(P11Mock_GetConfig()->lastUnwrapInput, abWrapped, 40) == 0);

    /* The decisive assertion. A key that arrives wrapped and is then
     * created extractable could be exported in the clear immediately
     * afterwards, which would make wrapping it pointless. */
    ASSERT_EQ("Unwrapped key is not extractable",
        (DWORD)P11Mock_GetConfig()->lastUnwrapExtractable, (DWORD)CK_FALSE);
    ASSERT_EQ("and is sensitive",
        (DWORD)P11Mock_GetConfig()->lastUnwrapSensitive, (DWORD)CK_TRUE);

    {
        KSP_KEY *pNew = (KSP_KEY *)(ULONG_PTR)hNew;
        ASSERT("Imported as a symmetric key",
            pNew->dwKeyClass == KSP_KEY_CLASS_SYMMETRIC);
        ASSERT("named AES", _wcsicmp(pNew->szAlgId, ALG_AES) == 0);
        ASSERT("and finalised", pNew->bFinalized);
        ASSERT("holding the unwrapped object",
            pNew->hSecretKey != CK_INVALID_HANDLE);
    }
    KSP_FreeKey(hProv, hNew);

    ASSERT_EQ("No unwrapping key → NTE_INVALID_PARAMETER",
        KSP_ImportKey(hProv, 0, BCRYPT_AES_WRAP_KEY_BLOB, NULL,
                      &hNew, abWrapped, 40, 0),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    P11Mock_GetConfig()->rv_UnwrapKey = CKR_WRAPPED_KEY_INVALID;
    hNew = 0;
    ss = KSP_ImportKey(hProv, hKek, BCRYPT_AES_WRAP_KEY_BLOB, NULL,
                       &hNew, abWrapped, 40, 0);
    ASSERT_ERR("A corrupt blob is refused by the token", ss);
    ASSERT("and no handle is returned", hNew == 0);
    P11Mock_GetConfig()->rv_UnwrapKey = CKR_OK;

    /* ── Suite 5 : gated on the token, like every other mechanism ───────── */
    TEST_SUITE("Capability gating");

    P11Mock_SetMechanisms(g_noWrapToken,
                          sizeof(g_noWrapToken) / sizeof(g_noWrapToken[0]));
    P11_ProbeCapabilities();

    cbResult = 0;
    ASSERT_EQ("Wrap on a token without CKM_AES_KEY_WRAP → NTE_NOT_SUPPORTED",
        KSP_ExportKey(hProv, hTarget, hKek, BCRYPT_AES_WRAP_KEY_BLOB,
                      NULL, NULL, 0, &cbResult, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    hNew = 0;
    ASSERT_EQ("Unwrap likewise → NTE_NOT_SUPPORTED",
        KSP_ImportKey(hProv, hKek, BCRYPT_AES_WRAP_KEY_BLOB, NULL,
                      &hNew, abWrapped, 40, 0),
        (SECURITY_STATUS)NTE_NOT_SUPPORTED);

    P11Mock_ResetCalls();
    (void)KSP_ExportKey(hProv, hTarget, hKek, BCRYPT_AES_WRAP_KEY_BLOB,
                        NULL, NULL, 0, &cbResult, 0);
    ASSERT_EQ("and the token was never asked",
        P11Mock_GetCalls()->nWrapKey, 0);

    /* Restore the capable token so the teardown is representative. */
    P11Mock_SetMechanisms(g_wrapToken,
                          sizeof(g_wrapToken) / sizeof(g_wrapToken[0]));
    P11_ProbeCapabilities();

    KSP_FreeKey(hProv, hTarget);
    KSP_FreeKey(hProv, hKek);
    P11_ReleaseCapabilities();
    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
