/* ksp_provider.c — Provider management function implementation */
#include "ksp_provider.h"
#include "../pkcs11/p11_context.h"
#include "../pkcs11/p11_caps.h"
#include "../pkcs11/p11_session.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/memory.h"
#include <string.h>
#include <wchar.h>

/* Validate a provider handle */
BOOL KSP_IsValidProvider(NCRYPT_PROV_HANDLE hProvider)
{
    KSP_PROVIDER *pProv = (KSP_PROVIDER *)(ULONG_PTR)hProvider;
    return (pProv && pProv->dwMagic == KSP_PROVIDER_MAGIC);
}

/* Open the provider and initialise the PKCS#11 layer */
SECURITY_STATUS WINAPI KSP_OpenProvider(
    NCRYPT_PROV_HANDLE *phProvider,
    LPCWSTR             pszProviderName,
    DWORD               dwFlags)
{
    KSP_PROVIDER   *pProv;
    SECURITY_STATUS ss;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_OpenProvider");

    if (!phProvider) {
        LOG_LEAVE("KSP_OpenProvider", NTE_INVALID_PARAMETER);
        return NTE_INVALID_PARAMETER;
    }

    /* Initialise the PKCS#11 layer (idempotent) */
    ss = P11_Initialize();
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_OpenProvider", ss);
        return ss;
    }

    /* Initialise the session pool */
    ss = P11_SessionPool_Initialize();
    if (ss != ERROR_SUCCESS) {
        LOG_LEAVE("KSP_OpenProvider", ss);
        return ss;
    }

    pProv = (KSP_PROVIDER *)KSP_AllocZero(sizeof(KSP_PROVIDER));
    if (!pProv) {
        LOG_LEAVE("KSP_OpenProvider", NTE_NO_MEMORY);
        return NTE_NO_MEMORY;
    }

    pProv->dwMagic = KSP_PROVIDER_MAGIC;
    wcscpy_s(pProv->szName, 256,
             pszProviderName ? pszProviderName : KSP_PROVIDER_NAME);

    *phProvider = (NCRYPT_PROV_HANDLE)(ULONG_PTR)pProv;

    LOG_LEAVE("KSP_OpenProvider", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Free the provider */
SECURITY_STATUS WINAPI KSP_FreeProvider(NCRYPT_PROV_HANDLE hProvider)
{
    KSP_PROVIDER *pProv;

    LOG_ENTER("KSP_FreeProvider");

    if (!KSP_IsValidProvider(hProvider)) {
        LOG_LEAVE("KSP_FreeProvider", NTE_INVALID_HANDLE);
        return NTE_INVALID_HANDLE;
    }

    pProv = (KSP_PROVIDER *)(ULONG_PTR)hProvider;
    pProv->dwMagic = 0;
    KSP_Free(pProv);

    LOG_LEAVE("KSP_FreeProvider", ERROR_SUCCESS);
    return ERROR_SUCCESS;
}

/* Return a provider property */
SECURITY_STATUS WINAPI KSP_GetProviderProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszProperty,
    PBYTE               pbOutput,
    DWORD               cbOutput,
    DWORD              *pcbResult,
    DWORD               dwFlags)
{
    SECURITY_STATUS ss = ERROR_SUCCESS;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_GetProviderProperty");

    if (!KSP_IsValidProvider(hProvider) || !pszProperty || !pcbResult) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_GetProviderProperty", ss);
        return ss;
    }

    if (_wcsicmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0) {
        DWORD cbNeeded = (DWORD)((wcslen(KSP_PROVIDER_NAME) + 1) * sizeof(WCHAR));
        *pcbResult = cbNeeded;
        if (pbOutput) {
            if (cbOutput < cbNeeded) {
                ss = NTE_BUFFER_TOO_SMALL;
            } else {
                memcpy(pbOutput, KSP_PROVIDER_NAME, cbNeeded);
            }
        }
    } else if (_wcsicmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0) {
        DWORD dwVersion = KSP_VERSION;
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                ss = NTE_BUFFER_TOO_SMALL;
            } else {
                memcpy(pbOutput, &dwVersion, sizeof(DWORD));
            }
        }
    } else if (_wcsicmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0) {
        /* SoftHSM2 is a software token: keys live in an encrypted SQLite
         * file, not in tamper-resistant hardware. Report that honestly.
         * This emits the same value the provider has always emitted —
         * NCRYPT_IMPL_HARDWARE_FLAG was previously mis-defined as 0x2,
         * which is NCRYPT_IMPL_SOFTWARE_FLAG — so only the name changes. */
        DWORD dwImpl = NCRYPT_IMPL_SOFTWARE_FLAG;
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                ss = NTE_BUFFER_TOO_SMALL;
            } else {
                memcpy(pbOutput, &dwImpl, sizeof(DWORD));
            }
        }
    } else if (_wcsicmp(pszProperty, KSP_SLOT_PROPERTY) == 0) {
        /* Which token this process actually selected. Read-only: the slot
         * is fixed when the PKCS#11 context initialises, and sessions are
         * bound to it. Useful for a caller that set SOFTHSM2_TOKEN_LABEL
         * and wants to confirm what it got. */
        DWORD dwSlot = (DWORD)P11_GetContext()->slotId;
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD)) {
                ss = NTE_BUFFER_TOO_SMALL;
            } else {
                memcpy(pbOutput, &dwSlot, sizeof(DWORD));
            }
        }
    } else {
        ss = NTE_NOT_SUPPORTED;
    }

    LOG_LEAVE("KSP_GetProviderProperty", ss);
    return ss;
}

/* Set a provider property */
/* Copy a counted CNG wide-string property into a bounded buffer, returning
 * its length in characters or 0 if it cannot be one.
 *
 * cbInput is a byte count that MAY OR MAY NOT include the terminator —
 * CNG callers differ, and Microsoft documents the parameter as the size of
 * the buffer rather than the length of the string. The consequence is that
 * the terminator has to be stripped BEFORE the length is bounded, not
 * after: a value of exactly cchMax characters passed WITH its terminator
 * occupies cchMax+1 characters, so a bound applied first refuses something
 * entirely legal. Both this function's callers made that mistake
 * independently, which is why there is now one function.
 *
 * pwszOut must hold cchMax + 2 characters: cchMax of value, one for a
 * terminator the caller may have counted, and one written here.
 *
 * An embedded NUL truncates, which is the correct reading of a C string and
 * not a silent acceptance: the result is bounded and terminated either way.
 */
static DWORD CopyWideProperty(LPWSTR pwszOut, DWORD cchMax,
                              const BYTE *pbInput, DWORD cbInput)
{
    DWORD cch;

    if (!pwszOut || !pbInput)
        return 0;

    /* A wide string cannot occupy an odd number of bytes. */
    if (cbInput == 0 || (cbInput % sizeof(WCHAR)) != 0)
        return 0;

    cch = cbInput / sizeof(WCHAR);
    if (cch > cchMax + 1)
        return 0;

    memcpy(pwszOut, pbInput, cch * sizeof(WCHAR));
    pwszOut[cch] = L'\0';

    cch = (DWORD)wcslen(pwszOut);
    if (cch == 0 || cch > cchMax)
        return 0;

    return cch;
}

SECURITY_STATUS WINAPI KSP_SetProviderProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    LPCWSTR             pszProperty,
    PBYTE               pbInput,
    DWORD               cbInput,
    DWORD               dwFlags)
{
    UNREFERENCED_PARAMETER(dwFlags);

    if (!KSP_IsValidProvider(hProvider))
        return NTE_INVALID_HANDLE;

    if (!pszProperty || !pbInput)
        return NTE_INVALID_PARAMETER;

    /* NCRYPT_PIN_PROPERTY — the standard CNG way to hand a provider a PIN,
     * and the reason this function exists at all. CNG passes it as a
     * NUL-terminated wide string; PKCS#11 C_Login wants bytes, so it is
     * narrowed here.
     *
     * Sessions open lazily, so a PIN set before the first cryptographic
     * call is the one used to log in. Both the wide copy and the narrow
     * copy are zeroed before returning. */
    if (_wcsicmp(pszProperty, NCRYPT_PIN_PROPERTY) == 0) {
        WCHAR  wszPin[P11_MAX_PIN_LEN + 2];
        char   szPin[P11_MAX_PIN_LEN + 1];
        DWORD  cchPin;
        int    cb;
        SECURITY_STATUS ss;

        cchPin = CopyWideProperty(wszPin, P11_MAX_PIN_LEN, pbInput, cbInput);
        if (cchPin == 0) {
            SecureZeroMemory(wszPin, sizeof(wszPin));
            return NTE_INVALID_PARAMETER;
        }

        cb = WideCharToMultiByte(CP_UTF8, 0, wszPin, (int)cchPin,
                                 szPin, sizeof(szPin) - 1, NULL, NULL);
        SecureZeroMemory(wszPin, sizeof(wszPin));

        if (cb <= 0)
            return NTE_INVALID_PARAMETER;

        szPin[cb] = '\0';
        ss = P11_SetPin(szPin);
        SecureZeroMemory(szPin, sizeof(szPin));
        return ss;
    }

    /* Token selection, writable until the slot is bound.
     *
     * This used to be refused outright, on the reasoning that the session
     * pool is already bound to a slot by the time a caller holds a provider
     * handle. That was true of the old code and not a law: the slot is now
     * chosen on the first operation that needs a token, exactly as the PIN
     * has always worked, so there is a window between
     * NCryptOpenStorageProvider and the first call in which the choice can
     * still be made.
     *
     * After that window it is refused with NTE_INVALID_HANDLE rather than
     * accepted: PKCS#11 cannot move a session between tokens, and a caller
     * told its selection succeeded would go on using the previous token
     * believing it had switched. An explicit selection naming no present
     * token remains an error when the slot is bound — never a fallback. */
    if (_wcsicmp(pszProperty, KSP_TOKEN_LABEL_PROPERTY) == 0) {
        WCHAR wszLabel[P11_TOKEN_LABEL_LEN + 2];
        char  szLabel[P11_TOKEN_LABEL_LEN * 4 + 1];
        DWORD cchLabel;
        int   cb;

        cchLabel = CopyWideProperty(wszLabel, P11_TOKEN_LABEL_LEN,
                                    pbInput, cbInput);
        if (cchLabel == 0)
            return NTE_INVALID_PARAMETER;

        cb = WideCharToMultiByte(CP_UTF8, 0, wszLabel, (int)cchLabel,
                                 szLabel, sizeof(szLabel) - 1, NULL, NULL);
        if (cb <= 0)
            return NTE_INVALID_PARAMETER;
        szLabel[cb] = '\0';

        return P11_SetTokenSelection(szLabel, NULL);
    }

    if (_wcsicmp(pszProperty, KSP_SLOT_PROPERTY) == 0) {
        DWORD      dwSlot;
        CK_SLOT_ID slot;

        if (cbInput != sizeof(DWORD))
            return NTE_INVALID_PARAMETER;
        memcpy(&dwSlot, pbInput, sizeof(DWORD));
        slot = (CK_SLOT_ID)dwSlot;

        return P11_SetTokenSelection(NULL, &slot);
    }

    return NTE_NOT_SUPPORTED;
}

/* Free a buffer allocated by the KSP */
SECURITY_STATUS WINAPI KSP_FreeBuffer(PVOID pvInput)
{
    KSP_Free(pvInput);
    return ERROR_SUCCESS;
}

/* Free an opaque object */
SECURITY_STATUS WINAPI KSP_FreeObject(PVOID pvInput)
{
    KSP_Free(pvInput);
    return ERROR_SUCCESS;
}

/* Register or remove a key change notification.
 *
 * The second parameter is NOT a key handle. Microsoft documents
 * NCryptNotifyChangeKey(hProvider, HANDLE *phEvent, dwFlags) with phEvent
 * as [in, out]: "the address of a HANDLE variable that either receives or
 * contains the key change notification event handle", and the caller then
 * passes that handle to the wait functions.
 *
 * This took NCRYPT_KEY_HANDLE and returned ERROR_SUCCESS. Both halves were
 * wrong and the second is the dangerous one: a caller registering for
 * notification was told it had succeeded and never had its HANDLE written,
 * so it went on to wait on whatever was in that variable. Success with an
 * untouched out-parameter is the worst answer available — worse than the
 * refusal below, which at least tells the truth.
 *
 * The honest answer is a refusal. Key change notification is a property of
 * a key store that can announce changes; a PKCS#11 token has no such
 * channel. There is no C_WaitForSlotEvent equivalent for objects, and
 * polling C_FindObjects on a timer would be a fabrication rather than a
 * notification. *phEvent is cleared first so a caller that ignores the
 * return value waits on nothing rather than on a stale value.
 *
 * Both halves of this are unverifiable on Linux: the mock's function table
 * types every slot as void *, so a wrong parameter TYPE is not a build
 * error here, and the MSVC job that would catch it cannot compile
 * ksp_main.c without ncrypt_provider.h. That is how this survived.
 */
SECURITY_STATUS WINAPI KSP_NotifyChangeKey(
    NCRYPT_PROV_HANDLE hProvider,
    HANDLE            *phEvent,
    DWORD              dwFlags)
{
    if (!KSP_IsValidProvider(hProvider))
        return NTE_INVALID_HANDLE;

    if (dwFlags & ~(NCRYPT_REGISTER_NOTIFY_FLAG |
                    NCRYPT_UNREGISTER_NOTIFY_FLAG))
        return NTE_BAD_FLAGS;

    /* Unregistering something that was never registered is not an error
     * worth raising: there is nothing to tear down. */
    if (dwFlags & NCRYPT_UNREGISTER_NOTIFY_FLAG)
        return ERROR_SUCCESS;

    if (!phEvent)
        return NTE_INVALID_PARAMETER;

    *phEvent = NULL;
    return NTE_NOT_SUPPORTED;
}

/* Prompt the user (not supported) */
SECURITY_STATUS WINAPI KSP_PromptUser(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    LPCWSTR            pszOperation,
    DWORD              dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszOperation);
    UNREFERENCED_PARAMETER(dwFlags);

    return NTE_NOT_SUPPORTED;
}

/* Return an operation property (not supported) */
SECURITY_STATUS WINAPI KSP_GetOperationProperty(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    LPCWSTR            pszProperty,
    PBYTE              pbOutput,
    DWORD              cbOutput,
    DWORD             *pcbResult,
    DWORD              dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszProperty);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);

    return NTE_NOT_SUPPORTED;
}

/* ── Algorithm discovery ──────────────────────────────────────────────────
 *
 * IsAlgSupported and EnumAlgorithms are slots in
 * NCRYPT_KEY_STORAGE_FUNCTION_TABLE, which is how ncrypt.dll answers
 * NCryptIsAlgSupported and NCryptEnumAlgorithms. They are not served from
 * the registry — an earlier version of the gap analysis said otherwise and
 * was wrong.
 *
 * Only algorithms with a real CNG identifier are published. The provider
 * also accepts EDDSA_ED25519, EDDSA_ED448, ECDSA_SECP256K1 and HMAC_SHA*,
 * but CNG has no identifiers for those, so no standard caller could act on
 * them if they were listed here. They stay reachable by name for an
 * application coded against this KSP directly.
 *
 * The list below is what this provider knows how to map. What it publishes
 * is that list intersected with what the token actually implements, which
 * p11_caps.c learns from C_GetMechanismList at startup. Before that
 * intersection existed, pointing KSP_PKCS11_LIB at a different module left
 * the provider claiming AES and P-521 on a token that might have neither,
 * and the lie only surfaced when key generation failed — long after the
 * application had committed to the algorithm on the provider's word.
 *
 * Each entry names the mechanisms the operation needs. Generation and use
 * are listed separately because a token can have one without the other:
 * CKM_EC_KEY_PAIR_GEN without CKM_ECDH1_DERIVE is a signing-only EC token,
 * and it should not be advertising key agreement.
 */

typedef struct _KSP_ALG_ENTRY {
    LPCWSTR           pszName;
    DWORD             dwOperations;
    CK_MECHANISM_TYPE genMech;   /* key generation */
    CK_MECHANISM_TYPE useMech;   /* sign / derive / encrypt */
} KSP_ALG_ENTRY;

static const KSP_ALG_ENTRY g_KspAlgorithms[] = {
    { ALG_RSA,        NCRYPT_SIGNATURE_OPERATION |
                      NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION,
                      CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS },
    { ALG_ECDSA_P256, NCRYPT_SIGNATURE_OPERATION,
                      CKM_EC_KEY_PAIR_GEN, CKM_ECDSA },
    { ALG_ECDSA_P384, NCRYPT_SIGNATURE_OPERATION,
                      CKM_EC_KEY_PAIR_GEN, CKM_ECDSA },
    { ALG_ECDSA_P521, NCRYPT_SIGNATURE_OPERATION,
                      CKM_EC_KEY_PAIR_GEN, CKM_ECDSA },
    { ALG_ECDH_P256,  NCRYPT_SECRET_AGREEMENT_OPERATION,
                      CKM_EC_KEY_PAIR_GEN, CKM_ECDH1_DERIVE },
    { ALG_ECDH_P384,  NCRYPT_SECRET_AGREEMENT_OPERATION,
                      CKM_EC_KEY_PAIR_GEN, CKM_ECDH1_DERIVE },
    { ALG_ECDH_P521,  NCRYPT_SECRET_AGREEMENT_OPERATION,
                      CKM_EC_KEY_PAIR_GEN, CKM_ECDH1_DERIVE },
    { ALG_AES,        NCRYPT_CIPHER_OPERATION,
                      CKM_AES_KEY_GEN, CKM_AES_CBC },
    /* AES-CMAC is a standard CNG identifier, unlike this provider's HMAC
     * names, so it is published rather than left reachable by name only. */
    { BCRYPT_AES_CMAC_ALGORITHM, NCRYPT_SIGNATURE_OPERATION,
                      CKM_AES_KEY_GEN, CKM_AES_CMAC },

    /* Post-quantum. Unreachable on SoftHSM2 2.7.0, which defines these
     * mechanisms and implements none of them, and therefore never lists
     * them. A PKCS#11 v3.2 token that does implement them makes these
     * entries appear with no change to this provider. */
    { ALG_MLDSA_44,   NCRYPT_SIGNATURE_OPERATION,
                      CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA },
    { ALG_MLDSA_65,   NCRYPT_SIGNATURE_OPERATION,
                      CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA },
    { ALG_MLDSA_87,   NCRYPT_SIGNATURE_OPERATION,
                      CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA },
};

#define KSP_ALG_COUNT (sizeof(g_KspAlgorithms) / sizeof(g_KspAlgorithms[0]))

/* TRUE when the token can actually do what this entry promises.
 *
 * With no successful probe, P11_HasMechanism answers TRUE for everything
 * and this degrades to the unfiltered list the provider published before —
 * a token that refuses C_GetMechanismList loses no functionality. */
static BOOL KspAlgAvailable(const KSP_ALG_ENTRY *pEntry)
{
    if (!P11_HasMechanism(pEntry->genMech))
        return FALSE;
    if (pEntry->useMech != 0 && !P11_HasMechanism(pEntry->useMech))
        return FALSE;
    return TRUE;
}

/* The single predicate EnumAlgorithms filters on. It is one function
 * because the answer is needed three times — to count, to size the name
 * block, and to fill the array — and three copies of the same condition is
 * how the count and the contents drift apart. */
static BOOL KspAlgMatches(const KSP_ALG_ENTRY *pEntry, DWORD dwAlgOperations)
{
    /* dwAlgOperations == 0 means "every operation class". */
    if (dwAlgOperations != 0 &&
        (pEntry->dwOperations & dwAlgOperations) == 0)
        return FALSE;
    return KspAlgAvailable(pEntry);
}

SECURITY_STATUS WINAPI KSP_IsAlgSupported(
    NCRYPT_PROV_HANDLE hProvider,
    LPCWSTR            pszAlgId,
    DWORD              dwFlags)
{
    size_t i;

    UNREFERENCED_PARAMETER(dwFlags);

    if (!KSP_IsValidProvider(hProvider))
        return NTE_INVALID_HANDLE;

    /* Bind the slot and probe, if nothing has yet. A capability answer is
     * about a particular token, so it cannot be given before one is chosen.
     * A failure here is deliberately NOT propagated: a provider that cannot
     * reach a token should answer from the mapped list rather than refuse
     * to describe itself, which is what P11_HasMechanism does when
     * unprobed. */
    (void)P11_EnsureSlotSelected();


    if (!pszAlgId)
        return NTE_INVALID_PARAMETER;

    for (i = 0; i < KSP_ALG_COUNT; i++) {
        if (_wcsicmp(pszAlgId, g_KspAlgorithms[i].pszName) == 0 &&
            KspAlgAvailable(&g_KspAlgorithms[i]))
            return ERROR_SUCCESS;
    }

    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI KSP_EnumAlgorithms(
    NCRYPT_PROV_HANDLE    hProvider,
    DWORD                 dwAlgOperations,
    DWORD                *pdwAlgCount,
    NCryptAlgorithmName **ppAlgList,
    DWORD                 dwFlags)
{
    NCryptAlgorithmName *pList   = NULL;
    DWORD                cMatch  = 0;
    size_t               i;

    UNREFERENCED_PARAMETER(dwFlags);

    if (!KSP_IsValidProvider(hProvider))
        return NTE_INVALID_HANDLE;

    /* Bind the slot and probe, if nothing has yet. A capability answer is
     * about a particular token, so it cannot be given before one is chosen.
     * A failure here is deliberately NOT propagated: a provider that cannot
     * reach a token should answer from the mapped list rather than refuse
     * to describe itself, which is what P11_HasMechanism does when
     * unprobed. */
    (void)P11_EnsureSlotSelected();

    if (!pdwAlgCount || !ppAlgList)
        return NTE_INVALID_PARAMETER;

    for (i = 0; i < KSP_ALG_COUNT; i++) {
        if (KspAlgMatches(&g_KspAlgorithms[i], dwAlgOperations))
            cMatch++;
    }

    *pdwAlgCount = 0;
    *ppAlgList   = NULL;

    if (cMatch == 0)
        return ERROR_SUCCESS;

    /* One allocation holds the array and the names it points at, so the
     * caller releases the whole thing with a single NCryptFreeBuffer. */
    {
        size_t cbNames = 0;
        BYTE  *pbName;

        for (i = 0; i < KSP_ALG_COUNT; i++) {
            if (KspAlgMatches(&g_KspAlgorithms[i], dwAlgOperations))
                cbNames += (wcslen(g_KspAlgorithms[i].pszName) + 1) *
                           sizeof(WCHAR);
        }

        pList = (NCryptAlgorithmName *)KSP_AllocZero(
                    cMatch * sizeof(NCryptAlgorithmName) + cbNames);
        if (!pList)
            return NTE_NO_MEMORY;

        pbName = (BYTE *)pList + cMatch * sizeof(NCryptAlgorithmName);
        cMatch = 0;

        for (i = 0; i < KSP_ALG_COUNT; i++) {
            size_t cb;

            if (!KspAlgMatches(&g_KspAlgorithms[i], dwAlgOperations))
                continue;

            cb = (wcslen(g_KspAlgorithms[i].pszName) + 1) * sizeof(WCHAR);
            memcpy(pbName, g_KspAlgorithms[i].pszName, cb);

            pList[cMatch].pszName         = (LPWSTR)pbName;
            pList[cMatch].dwClass         = NCRYPT_KEY_STORAGE_INTERFACE;
            pList[cMatch].dwAlgOperations = g_KspAlgorithms[i].dwOperations;
            pList[cMatch].dwFlags         = 0;

            pbName += cb;
            cMatch++;
        }
    }

    *pdwAlgCount = cMatch;
    *ppAlgList   = pList;
    return ERROR_SUCCESS;
}

/* KSP_VerifySignature now lives in ksp_crypto.c, beside KSP_SignHash:
 * it is the same mechanism resolution and the same three format rules. */
