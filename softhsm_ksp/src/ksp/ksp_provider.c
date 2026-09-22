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
        WCHAR  wszPin[P11_MAX_PIN_LEN + 1];
        char   szPin[P11_MAX_PIN_LEN + 1];
        DWORD  cchPin;
        int    cb;
        SECURITY_STATUS ss;

        /* cbInput is a byte count and may or may not include the
         * terminator, so bound it and terminate ourselves. */
        cchPin = cbInput / sizeof(WCHAR);
        if (cchPin == 0 || cchPin > P11_MAX_PIN_LEN)
            return NTE_INVALID_PARAMETER;

        memcpy(wszPin, pbInput, cchPin * sizeof(WCHAR));
        wszPin[cchPin] = L'\0';
        /* Tolerate a caller that already included the terminator. */
        cchPin = (DWORD)wcslen(wszPin);
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

    /* Token selection is read-only here, and deliberately so. By the time
     * a caller holds a provider handle the PKCS#11 context has initialised
     * and the session pool is bound to a slot; PKCS#11 offers no way to
     * move a session between tokens. Accepting the value and continuing to
     * use the old token would be worse than refusing it — the caller would
     * believe it had switched.
     *
     * Choose the token before the provider opens, with SOFTHSM2_SLOT or
     * SOFTHSM2_TOKEN_LABEL, and read KSP_SLOT_PROPERTY back to confirm. */
    if (_wcsicmp(pszProperty, KSP_TOKEN_LABEL_PROPERTY) == 0 ||
        _wcsicmp(pszProperty, KSP_SLOT_PROPERTY) == 0) {
        LOG_ERROR("KSP_SetProviderProperty - token selection is read-only; "
                  "use " SOFTHSM2_TOKEN_LABEL_ENV " or " SOFTHSM2_SLOT_ENV,
                  NTE_NOT_SUPPORTED);
        return NTE_NOT_SUPPORTED;
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

/* Notify a key change (stub) */
SECURITY_STATUS WINAPI KSP_NotifyChangeKey(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    DWORD              dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(dwFlags);

    return ERROR_SUCCESS;
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

/* Verify a signature.
 *
 * Not supported: SoftHSM2 can verify through C_Verify, but the public key
 * is exportable and callers verify far more cheaply in software with
 * BCryptVerifySignature. Returning NTE_NOT_SUPPORTED is the honest answer
 * rather than a slot left NULL, which ncrypt.dll would call anyway. */
SECURITY_STATUS WINAPI KSP_VerifySignature(
    NCRYPT_PROV_HANDLE hProvider,
    NCRYPT_KEY_HANDLE  hKey,
    VOID              *pPaddingInfo,
    PBYTE              pbHashValue,
    DWORD              cbHashValue,
    PBYTE              pbSignature,
    DWORD              cbSignature,
    DWORD              dwFlags)
{
    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(pbHashValue);
    UNREFERENCED_PARAMETER(cbHashValue);
    UNREFERENCED_PARAMETER(pbSignature);
    UNREFERENCED_PARAMETER(cbSignature);
    UNREFERENCED_PARAMETER(dwFlags);

    return NTE_NOT_SUPPORTED;
}
