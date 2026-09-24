/* ksp_properties.c — CNG key property implementation */
#include "ksp_properties.h"
#include "ksp_key.h"
#include "ksp_provider.h"
#include "../pkcs11/p11_utils.h"
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
        else if (KSP_IsMlDsaAlg(pKey->szAlgId))
            pszGroup = ALG_GROUP_MLDSA;
        else if (_wcsicmp(pKey->szAlgId, ALG_AES) == 0 ||
                 _wcsicmp(pKey->szAlgId, BCRYPT_AES_CMAC_ALGORITHM) == 0)
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

    } else if (_wcsicmp(pszProperty, NCRYPT_AUTH_TAG_LENGTH) == 0) {
        /* What the property is actually for: the tag lengths the algorithm
         * supports, as a BCRYPT_AUTH_TAG_LENGTHS_STRUCT. Reported per
         * chaining mode because GCM and CCM do not accept the same set —
         * GCM takes 12..16 in steps of 1, CCM 4..16 in steps of 2. */
        if (_wcsicmp(pKey->szAlgId, ALG_AES) != 0) {
            ss = NTE_NOT_SUPPORTED;
        } else {
            BOOL bCcm = (_wcsicmp(pKey->szChainingMode,
                                  BCRYPT_CHAIN_MODE_CCM) == 0);
            BOOL bGcm = (_wcsicmp(pKey->szChainingMode,
                                  BCRYPT_CHAIN_MODE_GCM) == 0);
            if (!bCcm && !bGcm) {
                /* An unauthenticated mode has no tag at all. */
                ss = NTE_NOT_SUPPORTED;
            } else {
                BCRYPT_AUTH_TAG_LENGTHS_STRUCT tags;
                tags.dwMinLength = bCcm ? AES_CCM_TAG_MIN : AES_GCM_TAG_MIN;
                tags.dwMaxLength = bCcm ? AES_CCM_TAG_MAX : AES_GCM_TAG_MAX;
                tags.dwIncrement = bCcm ? 2 : 1;

                *pcbResult = sizeof(tags);
                if (pbOutput) {
                    if (cbOutput < sizeof(tags))
                        ss = NTE_BUFFER_TOO_SMALL;
                    else
                        memcpy(pbOutput, &tags, sizeof(tags));
                }
            }
        }

    } else if (_wcsicmp(pszProperty, BCRYPT_MESSAGE_BLOCK_LENGTH) == 0) {
        /* CFB feedback size. Unset reads back as CNG's default of 1. */
        if (pKey->dwKeyClass != KSP_KEY_CLASS_SYMMETRIC) {
            ss = NTE_NOT_SUPPORTED;
        } else {
            DWORD cbBlock = pKey->cbMessageBlockLen
                            ? pKey->cbMessageBlockLen : 1;
            *pcbResult = sizeof(DWORD);
            if (pbOutput) {
                if (cbOutput < sizeof(DWORD))
                    ss = NTE_BUFFER_TOO_SMALL;
                else
                    memcpy(pbOutput, &cbBlock, sizeof(DWORD));
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

    } else if (_wcsicmp(pszProperty, NCRYPT_PIN_PROPERTY) == 0) {
        /* Never hand a credential back. A caller that set it has it; a
         * caller that did not has no business reading it. */
        ss = NTE_NOT_SUPPORTED;

    } else if (_wcsicmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0) {
        /* The certificate issued for this key, as stored by
         * NCryptSetProperty after enrolment. NTE_NOT_FOUND means the key
         * exists but has not been enrolled yet. */
        ss = KSP_LoadCertificate(pKey, pbOutput, cbOutput, pcbResult);

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
    /* BCRYPT_ECC_CURVE_NAME — the standard CNG way to pick a curve.
     *
     * The caller creates the key with the generic BCRYPT_ECDSA_ALGORITHM or
     * BCRYPT_ECDH_ALGORITHM and names the curve here, before finalising.
     * Resolving it rewrites the key's algorithm to this provider's specific
     * identifier, after which every existing path — key generation, OID
     * lookup, coordinate size, signature length — works unchanged. */
    if (_wcsicmp(pszProperty, BCRYPT_ECC_CURVE_NAME) == 0) {
        WCHAR   wszCurve[64];
        DWORD   cchCurve;
        LPCWSTR pszResolved;
        BOOL    bAgreement;

        if (pKey->bFinalized) {
            ss = NTE_INVALID_HANDLE;
        } else if (!pbInput || cbInput < sizeof(WCHAR)) {
            ss = NTE_INVALID_PARAMETER;
        } else {
            cchCurve = cbInput / sizeof(WCHAR);
            if (cchCurve >= (sizeof(wszCurve) / sizeof(wszCurve[0]))) {
                ss = NTE_INVALID_PARAMETER;
            } else {
                memcpy(wszCurve, pbInput, cchCurve * sizeof(WCHAR));
                wszCurve[cchCurve] = L'\0';

                /* Which generic algorithm the key was created with decides
                 * whether a NIST curve becomes ECDSA or ECDH. */
                bAgreement =
                    (_wcsicmp(pKey->szAlgId, BCRYPT_ECDH_ALGORITHM) == 0) ||
                    KSP_IsEcdhAlg(pKey->szAlgId);

                pszResolved = P11_CurveNameToAlgId(wszCurve, bAgreement);
                if (!pszResolved) {
                    /* Either an unknown curve, or one that cannot do what
                     * the chosen generic algorithm asks — X25519 cannot
                     * sign, secp256k1 has no ECDH form here. */
                    ss = NTE_NOT_SUPPORTED;
                } else {
                    wcscpy_s(pKey->szAlgId, MAX_ALG_ID_LEN, pszResolved);
                    pKey->dwKeyBitLen   = KSP_DefaultKeyBits(pszResolved);
                    pKey->bCurvePending = FALSE;
                    ss = ERROR_SUCCESS;
                }
            }
        }
    } else if (_wcsicmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0) {
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

            /* CCM and CFB are accepted here and gated at the point of
             * use, where the capability probe can be asked. Refusing them
             * outright was right while no token could do them and wrong
             * once the probe existed: the mode a caller may select is a
             * property of the TOKEN, not of a list compiled into this
             * provider — the same correctness bug phase 4 fixed for
             * algorithm advertisement.
             *
             * A caller that sets a mode the token cannot do learns so from
             * the operation, which is where PKCS#11 reports it. */
            if (_wcsicmp(pszMode, BCRYPT_CHAIN_MODE_ECB) == 0 ||
                _wcsicmp(pszMode, BCRYPT_CHAIN_MODE_CBC) == 0 ||
                _wcsicmp(pszMode, BCRYPT_CHAIN_MODE_GCM) == 0 ||
                _wcsicmp(pszMode, BCRYPT_CHAIN_MODE_CCM) == 0 ||
                _wcsicmp(pszMode, BCRYPT_CHAIN_MODE_CFB) == 0 ||
                _wcsicmp(pszMode, KSP_CHAIN_MODE_CTR)    == 0) {
                wcscpy_s(pKey->szChainingMode, MAX_ALG_ID_LEN, pszMode);
                ss = ERROR_SUCCESS;
            } else {
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
        /* Read-only, and it never meant what this provider used it for.
         *
         * Microsoft's property documentation: "The authentication tag
         * lengths that are supported by the algorithm. This property is a
         * BCRYPT_AUTH_TAG_LENGTHS_STRUCT structure. This property only
         * applies to algorithms." It reports a RANGE the algorithm
         * supports; it is not a setter and it is not per-key.
         *
         * This branch used to treat a set of it as "here is my additional
         * authenticated data" and copy the bytes into pbAuthData. Two
         * consequences: an application that legitimately wrote a tag
         * length would have those four bytes silently become GCM AAD and
         * fail authentication, and AAD had no correct route at all — it is
         * carried in BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO through
         * pPaddingInfo, which KSP_Encrypt and KSP_Decrypt now read. No
         * test ever exercised this, which is why it survived. */
        ss = NTE_NOT_SUPPORTED;

    } else if (_wcsicmp(pszProperty, BCRYPT_MESSAGE_BLOCK_LENGTH) == 0) {
        /* CFB feedback size in bytes. 1 is 8-bit CFB (CNG's default) and
         * the block size is full-block CFB; nothing else is wired. */
        if (pKey->dwKeyClass != KSP_KEY_CLASS_SYMMETRIC) {
            ss = NTE_NOT_SUPPORTED;
        } else if (!pbInput || cbInput != sizeof(DWORD)) {
            ss = NTE_INVALID_PARAMETER;
        } else {
            DWORD cbBlock;
            memcpy(&cbBlock, pbInput, sizeof(DWORD));
            if (cbBlock != 1 && cbBlock != AES_BLOCK_SIZE) {
                ss = NTE_NOT_SUPPORTED;
            } else {
                pKey->cbMessageBlockLen = cbBlock;
                ss = ERROR_SUCCESS;
            }
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_PIN_PROPERTY) == 0) {
        /* Per-key PIN (PROP-13).
         *
         * PKCS#11 has no second user within a slot, so this is not a login
         * as a different identity. It is CKA_ALWAYS_AUTHENTICATE: a key can
         * require re-authentication before each private-key operation, and
         * C_Login(CKU_CONTEXT_SPECIFIC) supplies it. The credential is kept
         * on the key handle and replayed by KSP_SignHash and KSP_Decrypt.
         *
         * Setting it on the PROVIDER handle remains the way to supply the
         * token's user PIN; the two are different things and both exist. */
        WCHAR wszPin[P11_MAX_PIN_LEN + 1];
        DWORD cchPin;
        int   cb;

        if (!pbInput) {
            /* An explicit clear. */
            SecureZeroMemory(pKey->szKeyPin, sizeof(pKey->szKeyPin));
            ss = ERROR_SUCCESS;
        } else {
            cchPin = cbInput / sizeof(WCHAR);
            if (cchPin == 0 || cchPin > P11_MAX_PIN_LEN) {
                ss = NTE_INVALID_PARAMETER;
            } else {
                memcpy(wszPin, pbInput, cchPin * sizeof(WCHAR));
                wszPin[cchPin] = L'\0';
                cchPin = (DWORD)wcslen(wszPin);

                if (cchPin == 0) {
                    ss = NTE_INVALID_PARAMETER;
                } else {
                    cb = WideCharToMultiByte(CP_UTF8, 0, wszPin, (int)cchPin,
                                             pKey->szKeyPin,
                                             sizeof(pKey->szKeyPin) - 1,
                                             NULL, NULL);
                    if (cb <= 0) {
                        SecureZeroMemory(pKey->szKeyPin,
                                         sizeof(pKey->szKeyPin));
                        ss = NTE_INVALID_PARAMETER;
                    } else {
                        pKey->szKeyPin[cb] = '\0';
                        ss = ERROR_SUCCESS;
                    }
                }
            }
            SecureZeroMemory(wszPin, sizeof(wszPin));
        }

    } else if (_wcsicmp(pszProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0) {
        /* The issued certificate, handed back after enrolment. Stored on
         * the token as a CKO_CERTIFICATE sharing the key's scoped label.
         *
         * The key must exist on the token first: a certificate attached to
         * a key that was never generated would outlive nothing and be found
         * by a later key of the same name. */
        if (!pKey->bFinalized) {
            LOG_ERROR("SetKeyProperty - certificate set on an unfinalised key",
                      NTE_INVALID_HANDLE);
            ss = NTE_INVALID_HANDLE;
        } else if (!pbInput || cbInput == 0) {
            ss = NTE_INVALID_PARAMETER;
        } else {
            ss = KSP_StoreCertificate(pKey, pbInput, cbInput);
        }
    }

    LOG_LEAVE("KSP_SetKeyProperty", ss);
    return ss;
}
