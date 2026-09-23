/* test_key_pin.c — PROP-13: per-key PIN
 *
 * A "per-key PIN" is a smart-card idea, and PKCS#11 has no second user
 * within a slot to hang it on. What it does have is CKA_ALWAYS_AUTHENTICATE:
 * a key that requires re-authentication before each private-key operation,
 * supplied by C_Login(CKU_CONTEXT_SPECIFIC) between the operation's Init
 * call and the operation itself.
 *
 * That is what this implements, and it is why the credential is replayed on
 * every operation rather than cached as a one-time unlock. SoftHSM2
 * implements both halves — verified in the submodule, not assumed from the
 * constants being present in a header.
 *
 * The provider-wide NCRYPT_PIN_PROPERTY still exists and is a different
 * thing: it supplies the token's user PIN for C_Login(CKU_USER). The mock
 * counts the two logins separately so a test cannot mistake one for the
 * other.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_properties.h"
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

static NCRYPT_KEY_HANDLE MakeRsaKey(void)
{
    KSP_KEY *k = (KSP_KEY *)KSP_AllocZero(sizeof(KSP_KEY));
    if (!k) return 0;
    k->dwMagic     = KSP_KEY_MAGIC;
    k->hPrivKey    = 0x11;
    k->hPubKey     = 0x12;
    k->hSecretKey  = CK_INVALID_HANDLE;
    k->bFinalized  = TRUE;
    k->dwKeyBitLen = 2048;
    k->dwKeySpec   = AT_SIGNATURE;
    k->dwKeyClass  = KSP_KEY_CLASS_ASYMMETRIC;
    wcscpy_s(k->szKeyName, MAX_KEY_LABEL_LEN, L"pin-key");
    wcscpy_s(k->szAlgId,   MAX_ALG_ID_LEN,    ALG_RSA);
    return (NCRYPT_KEY_HANDLE)(ULONG_PTR)k;
}

static SECURITY_STATUS SignOnce(NCRYPT_PROV_HANDLE hProv,
                                NCRYPT_KEY_HANDLE hKey)
{
    BYTE  abHash[32];
    BYTE  abSig[256];
    DWORD cb = 0;
    memset(abHash, 0x5E, sizeof(abHash));
    return KSP_SignHash(hProv, hKey, NULL, abHash, sizeof(abHash),
                        abSig, sizeof(abSig), &cb, NCRYPT_PAD_PKCS1_FLAG);
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    NCRYPT_KEY_HANDLE  hKey  = 0;
    SECURITY_STATUS    ss;

    P11Mock_Reset();
    g_testCtx.pFunctionList = P11Mock_GetFunctionList();
    g_testCtx.bInitialized  = TRUE;
    g_testCtx.slotId        = 0;
    P11Mock_GetConfig()->cbSignature = 256;
    P11_ProbeCapabilities();

    ss = KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_OK("Provider opened", ss);

    hKey = MakeRsaKey();
    ASSERT("Key created", hKey != 0);

    /* ── Suite 1 : no PIN, no re-authentication ─────────────────────────── */
    TEST_SUITE("Without a per-key PIN");

    P11Mock_ResetCalls();
    ss = SignOnce(hProv, hKey);
    ASSERT_OK("Sign succeeds", ss);
    ASSERT_EQ("No re-authentication attempted",
        P11Mock_GetCalls()->nContextLogin, 0);

    /* ── Suite 2 : setting one ──────────────────────────────────────────── */
    TEST_SUITE("Setting a per-key PIN");

    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_PIN_PROPERTY,
                            (PBYTE)L"9876", 4 * sizeof(WCHAR), 0);
    ASSERT_OK("Per-key PIN accepted", ss);

    P11Mock_ResetCalls();
    ss = SignOnce(hProv, hKey);
    ASSERT_OK("Sign with a per-key PIN", ss);
    ASSERT_EQ("Re-authenticated once",
        P11Mock_GetCalls()->nContextLogin, 1);
    ASSERT("with the PIN that was set",
        strcmp(P11Mock_GetConfig()->lastContextPin, "9876") == 0);
    /* The ordinary session login is a different thing and must not be
     * confused with this one. */
    ASSERT_EQ("and not as an ordinary session login",
        P11Mock_GetCalls()->nLogin, 0);

    /* Replayed every time. A credential cached as a one-time unlock would
     * leave the key usable by whatever ran next on the same session. */
    P11Mock_ResetCalls();
    (void)SignOnce(hProv, hKey);
    ASSERT_EQ("Replayed on the next operation too",
        P11Mock_GetCalls()->nContextLogin, 1);

    /* Decryption takes the same path. */
    {
        KSP_KEY *pKey = (KSP_KEY *)(ULONG_PTR)hKey;
        BYTE     abIn[256], abOut[256];
        DWORD    cb = 0;

        pKey->dwKeySpec = AT_KEYEXCHANGE;
        memset(abIn, 0x33, sizeof(abIn));
        P11Mock_GetConfig()->cbPlaintext = 32;

        P11Mock_ResetCalls();
        ss = KSP_Decrypt(hProv, hKey, abIn, sizeof(abIn), NULL,
                         abOut, sizeof(abOut), &cb, NCRYPT_PAD_PKCS1_FLAG);
        ASSERT_OK("Decrypt with a per-key PIN", ss);
        ASSERT_EQ("also re-authenticates",
            P11Mock_GetCalls()->nContextLogin, 1);

        pKey->dwKeySpec = AT_SIGNATURE;
    }

    /* ── Suite 3 : what the token says back ─────────────────────────────── */
    TEST_SUITE("Token responses");

    /* A key the token does not actually mark always-authenticate answers
     * CKR_OPERATION_NOT_INITIALIZED. Failing the operation for that would
     * punish a caller for supplying a credential that was not needed. */
    P11Mock_GetConfig()->rv_ContextLogin = CKR_OPERATION_NOT_INITIALIZED;
    ss = SignOnce(hProv, hKey);
    ASSERT_OK("A key needing no re-auth still signs", ss);

    P11Mock_GetConfig()->rv_ContextLogin = CKR_USER_ALREADY_LOGGED_IN;
    ss = SignOnce(hProv, hKey);
    ASSERT_OK("Already re-authenticated is tolerated", ss);

    /* A wrong PIN must stop the operation. Signing anyway would make the
     * whole property decorative. */
    P11Mock_GetConfig()->rv_ContextLogin = CKR_PIN_INCORRECT;
    P11Mock_ResetCalls();
    ss = SignOnce(hProv, hKey);
    ASSERT_ERR("A wrong per-key PIN fails the signature", ss);
    ASSERT_EQ("and C_Sign was never reached", P11Mock_GetCalls()->nSign, 0);

    P11Mock_GetConfig()->rv_ContextLogin = CKR_PIN_LOCKED;
    ss = SignOnce(hProv, hKey);
    ASSERT_ERR("A locked PIN fails the signature", ss);
    P11Mock_GetConfig()->rv_ContextLogin = CKR_OK;

    /* ── Suite 4 : clearing, and never reading back ─────────────────────── */
    TEST_SUITE("Lifecycle");

    ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_PIN_PROPERTY, NULL, 0, 0);
    ASSERT_OK("Per-key PIN cleared", ss);

    P11Mock_ResetCalls();
    (void)SignOnce(hProv, hKey);
    ASSERT_EQ("No re-authentication after clearing",
        P11Mock_GetCalls()->nContextLogin, 0);

    {
        BYTE  abOut[64];
        DWORD cb = 0;
        /* A caller that set it already has it; one that did not has no
         * business reading it off the handle. */
        ASSERT_EQ("Reading the PIN back is refused",
            KSP_GetKeyProperty(hProv, hKey, NCRYPT_PIN_PROPERTY,
                               abOut, sizeof(abOut), &cb, 0),
            (SECURITY_STATUS)NTE_NOT_SUPPORTED);
    }

    ASSERT_EQ("An over-long PIN is refused",
        KSP_SetKeyProperty(hProv, hKey, NCRYPT_PIN_PROPERTY,
                           (PBYTE)L"x", (P11_MAX_PIN_LEN + 2) * sizeof(WCHAR), 0),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    ASSERT_EQ("A zero-length PIN is refused",
        KSP_SetKeyProperty(hProv, hKey, NCRYPT_PIN_PROPERTY,
                           (PBYTE)L"", 0, 0),
        (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* Freeing the key must not leave the credential in the freed block. */
    {
        KSP_KEY *pKey = (KSP_KEY *)(ULONG_PTR)hKey;
        ss = KSP_SetKeyProperty(hProv, hKey, NCRYPT_PIN_PROPERTY,
                                (PBYTE)L"secret", 6 * sizeof(WCHAR), 0);
        ASSERT_OK("PIN set again before free", ss);
        ASSERT("and is held on the key", pKey->szKeyPin[0] != '\0');

        ASSERT_OK("Key freed", KSP_FreeKey(hProv, hKey));
        hKey = 0;

        /* KSP_FreeKey zeroes szKeyPin before releasing the block. That is
         * deliberately NOT asserted here: reading the block afterwards is
         * undefined behaviour, and an assertion that happens to pass on
         * this allocator would be measuring the allocator, not the code.
         * The zeroing is visible in ksp_key.c and is the kind of thing a
         * reviewer checks by reading, not by testing. */
    }

    P11_ReleaseCapabilities();
    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
