/* ksp_properties.c — CNG key property implementation */
#include "ksp_properties.h"
#include "ksp_key.h"
#include "ksp_provider.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <string.h>
#include <wchar.h>

/* Return a key property */
SECURITY_STATUS WINAPI KSP_GetKeyProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hKey,
    LPCWSTR             pszProperty,
    PBYTE               pbOutput,
    DWORD               cbOutput,
    DWORD              *pcbResult,
    DWORD               dwFlags)
{
    KSP_KEY        *pKey;
    SECURITY_STATUS ss = ERROR_SUCCESS;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_GetKeyProperty");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pszProperty || !pcbResult) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_GetKeyProperty", ss);
        return ss;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    if (_wcsicmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0) {
        DWORD cbNeeded = (DWORD)((wcslen(pKey->szAlgId) + 1) * sizeof(WCHAR));
        *pcbResult = cbNeeded;
        if (pbOutput) {
            if (cbOutput < cbNeeded)
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, pKey->szAlgId, cbNeeded);
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD))
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, &pKey->dwKeyBitLen, sizeof(DWORD));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0) {
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD))
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, &pKey->dwKeySpec, sizeof(DWORD));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0 ||
               _wcsicmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0) {
        DWORD cbNeeded = (DWORD)((wcslen(pKey->szKeyName) + 1) * sizeof(WCHAR));
        *pcbResult = cbNeeded;
        if (pbOutput) {
            if (cbOutput < cbNeeded)
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, pKey->szKeyName, cbNeeded);
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0) {
        /* Not exportable from the HSM */
        DWORD dwPolicy = 0;
        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD))
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, &dwPolicy, sizeof(DWORD));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0) {
        DWORD dwUsage;

        if (KSP_IsEcdhAlg(pKey->szAlgId))
            dwUsage = NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
        else if (_wcsicmp(pKey->szAlgId, ALG_AES) == 0)
            dwUsage = NCRYPT_ALLOW_DECRYPT_FLAG;
        else if (pKey->dwKeySpec == AT_SIGNATURE)
            dwUsage = NCRYPT_ALLOW_SIGNING_FLAG;
        else
            dwUsage = NCRYPT_ALLOW_DECRYPT_FLAG;

        *pcbResult = sizeof(DWORD);
        if (pbOutput) {
            if (cbOutput < sizeof(DWORD))
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, &dwUsage, sizeof(DWORD));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0) {
        LPCWSTR pszGroup;
        DWORD   cbNeeded;

        if (_wcsicmp(pKey->szAlgId, ALG_RSA) == 0)
            pszGroup = ALG_GROUP_RSA;
        else if (KSP_IsEcdhAlg(pKey->szAlgId))
            pszGroup = ALG_GROUP_ECDH;
        else if (KSP_IsEddsaAlg(pKey->szAlgId))
            pszGroup = ALG_GROUP_EDDSA;
        else if (_wcsicmp(pKey->szAlgId, ALG_AES) == 0)
            pszGroup = ALG_GROUP_AES;
        else if (KSP_IsSymmetricAlg(pKey->szAlgId))
            pszGroup = ALG_GROUP_HMAC;
        else
            pszGroup = ALG_GROUP_ECDSA;

        cbNeeded   = (DWORD)((wcslen(pszGroup) + 1) * sizeof(WCHAR));
        *pcbResult = cbNeeded;
        if (pbOutput) {
            if (cbOutput < cbNeeded)
                ss = NTE_BUFFER_TOO_SMALL;
            else
                memcpy(pbOutput, pszGroup, cbNeeded);
        }

    } else if (_wcsicmp(pszProperty, KSP_PUBLIC_EXPONENT_PROPERTY) == 0) {
        if (_wcsicmp(pKey->szAlgId, ALG_RSA) != 0) {
            ss = NTE_NOT_SUPPORTED;
        } else {
            DWORD dwExp = pKey->dwPublicExponent
                          ? pKey->dwPublicExponent : (DWORD)RSA_DEFAULT_PUBEXP;
            *pcbResult = sizeof(DWORD);
            if (pbOutput) {
                if (cbOutput < sizeof(DWORD))
                    ss = NTE_BUFFER_TOO_SMALL;
                else
                    memcpy(pbOutput, &dwExp, sizeof(DWORD));
            }
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_CHAINING_MODE_PROPERTY) == 0) {
        /* Symmetric keys only */
        if (pKey->dwKeyClass != KSP_KEY_CLASS_SYMMETRIC) {
            ss = NTE_NOT_SUPPORTED;
        } else {
            LPCWSTR pszMode = (pKey->szChainingMode[0] != L'\0')
                              ? pKey->szChainingMode
                              : BCRYPT_CHAIN_MODE_CBC;
            DWORD cbNeeded = (DWORD)((wcslen(pszMode) + 1) * sizeof(WCHAR));
            *pcbResult = cbNeeded;
            if (pbOutput) {
                if (cbOutput < cbNeeded)
                    ss = NTE_BUFFER_TOO_SMALL;
                else
                    memcpy(pbOutput, pszMode, cbNeeded);
            }
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_INITIALIZATION_VECTOR) == 0) {
        if (pKey->dwKeyClass != KSP_KEY_CLASS_SYMMETRIC) {
            ss = NTE_NOT_SUPPORTED;
        } else {
            *pcbResult = pKey->cbIV;
            if (pbOutput) {
                if (cbOutput < pKey->cbIV)
                    ss = NTE_BUFFER_TOO_SMALL;
                else
                    memcpy(pbOutput, pKey->pbIV, pKey->cbIV);
            }
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_BLOCK_LENGTH_PROPERTY) == 0) {
        /* AES block size; meaningless for asymmetric keys */
        if (_wcsicmp(pKey->szAlgId, ALG_AES) != 0) {
            ss = NTE_NOT_SUPPORTED;
        } else {
            DWORD dwBlock = AES_BLOCK_SIZE;
            *pcbResult = sizeof(DWORD);
            if (pbOutput) {
                if (cbOutput < sizeof(DWORD))
                    ss = NTE_BUFFER_TOO_SMALL;
                else
                    memcpy(pbOutput, &dwBlock, sizeof(DWORD));
            }
        }

    } else {
        ss = NTE_NOT_SUPPORTED;
    }

    LOG_LEAVE("KSP_GetKeyProperty", ss);
    return ss;
}

/* Set a key property */
SECURITY_STATUS WINAPI KSP_SetKeyProperty(
    NCRYPT_PROV_HANDLE  hProvider,
    NCRYPT_KEY_HANDLE   hKey,
    LPCWSTR             pszProperty,
    PBYTE               pbInput,
    DWORD               cbInput,
    DWORD               dwFlags)
{
    KSP_KEY        *pKey;
    SECURITY_STATUS ss = NTE_NOT_SUPPORTED;

    UNREFERENCED_PARAMETER(dwFlags);
    LOG_ENTER("KSP_SetKeyProperty");

    if (!KSP_IsValidProvider(hProvider) || !KSP_IsValidKey(hKey) ||
        !pszProperty) {
        ss = NTE_INVALID_PARAMETER;
        LOG_LEAVE("KSP_SetKeyProperty", ss);
        return ss;
    }

    pKey = (KSP_KEY *)(ULONG_PTR)hKey;

    /* Key length — settable before FinalizeKey only */
    if (_wcsicmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
        if (!pbInput || cbInput < sizeof(DWORD)) {
            ss = NTE_INVALID_PARAMETER;
        } else if (pKey->bFinalized) {
            ss = NTE_INVALID_HANDLE;
        } else {
            DWORD dwBits;
            memcpy(&dwBits, pbInput, sizeof(DWORD));

            if (_wcsicmp(pKey->szAlgId, ALG_RSA) == 0) {
                /* RSA: any multiple of 64 within the configured range.
                 * The floor defaults to 2048 — see KSP_RSA_MIN_BITS. */
                if (dwBits >= KSP_RSA_MIN_BITS &&
                    dwBits <= KSP_RSA_MAX_BITS &&
                    (dwBits % KSP_RSA_BITS_STEP) == 0) {
                    pKey->dwKeyBitLen = dwBits;
                    ss = ERROR_SUCCESS;
                } else {
                    ss = NTE_BAD_LEN;
                }
            } else if (_wcsicmp(pKey->szAlgId, ALG_AES) == 0) {
                /* AES: 128, 192 and 256 only */
                if (dwBits == 128 || dwBits == 192 || dwBits == 256) {
                    pKey->dwKeyBitLen = dwBits;
                    ss = ERROR_SUCCESS;
                } else {
                    ss = NTE_BAD_LEN;
                }
            } else if (KSP_IsSymmetricAlg(pKey->szAlgId)) {
                /* HMAC: any whole-byte length from 128 bits up */
                if (dwBits >= 128 && (dwBits % 8) == 0) {
                    pKey->dwKeyBitLen = dwBits;
                    ss = ERROR_SUCCESS;
                } else {
                    ss = NTE_BAD_LEN;
                }
            } else {
                /* EC and EdDSA curves have a fixed length: accept only
                 * the value already implied by the algorithm name. */
                ss = (dwBits == pKey->dwKeyBitLen) ? ERROR_SUCCESS : NTE_BAD_LEN;
            }
        }

    } else if (_wcsicmp(pszProperty, KSP_PUBLIC_EXPONENT_PROPERTY) == 0) {
        /* RSA only, and only before the pair is generated */
        if (_wcsicmp(pKey->szAlgId, ALG_RSA) != 0) {
            ss = NTE_NOT_SUPPORTED;
        } else if (!pbInput || cbInput < sizeof(DWORD)) {
            ss = NTE_INVALID_PARAMETER;
        } else if (pKey->bFinalized) {
            ss = NTE_INVALID_HANDLE;
        } else {
            DWORD dwExp;
            memcpy(&dwExp, pbInput, sizeof(DWORD));
            /* Must be odd and at least 3: an even exponent is not coprime
             * with phi(n), and 1 provides no encryption at all. */
            if (dwExp >= 3 && (dwExp & 1) != 0) {
                pKey->dwPublicExponent = dwExp;
                ss = ERROR_SUCCESS;
            } else {
                ss = NTE_INVALID_PARAMETER;
            }
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_CHAINING_MODE_PROPERTY) == 0) {
        if (pKey->dwKeyClass != KSP_KEY_CLASS_SYMMETRIC) {
            ss = NTE_NOT_SUPPORTED;
        } else if (!pbInput || cbInput < sizeof(WCHAR)) {
            ss = NTE_INVALID_PARAMETER;
        } else {
            LPCWSTR pszMode = (LPCWSTR)pbInput;

            if (_wcsicmp(pszMode, BCRYPT_CHAIN_MODE_ECB) == 0 ||
                _wcsicmp(pszMode, BCRYPT_CHAIN_MODE_CBC) == 0 ||
                _wcsicmp(pszMode, BCRYPT_CHAIN_MODE_GCM) == 0 ||
                _wcsicmp(pszMode, KSP_CHAIN_MODE_CTR)    == 0) {
                wcscpy_s(pKey->szChainingMode, MAX_ALG_ID_LEN, pszMode);
                ss = ERROR_SUCCESS;
            } else {
                /* CCM / CFB are not wired to a SoftHSM2 mechanism */
                ss = NTE_NOT_SUPPORTED;
            }
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_INITIALIZATION_VECTOR) == 0) {
        if (pKey->dwKeyClass != KSP_KEY_CLASS_SYMMETRIC) {
            ss = NTE_NOT_SUPPORTED;
        } else if (!pbInput || cbInput == 0 || cbInput > AES_BLOCK_SIZE) {
            ss = NTE_INVALID_PARAMETER;
        } else {
            memcpy(pKey->pbIV, pbInput, cbInput);
            pKey->cbIV = cbInput;
            ss = ERROR_SUCCESS;
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_AUTH_TAG_LENGTH) == 0) {
        /* GCM additional authenticated data */
        if (pKey->dwKeyClass != KSP_KEY_CLASS_SYMMETRIC) {
            ss = NTE_NOT_SUPPORTED;
        } else if (!pbInput || cbInput > MAX_AUTH_DATA_LEN) {
            ss = NTE_INVALID_PARAMETER;
        } else {
            memcpy(pKey->pbAuthData, pbInput, cbInput);
            pKey->cbAuthData = cbInput;
            ss = ERROR_SUCCESS;
        }
    }

    LOG_LEAVE("KSP_SetKeyProperty", ss);
    return ss;
}
