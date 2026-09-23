/* p11_mock.c — PKCS#11 mock implementation */
#include "p11_mock.h"
#include <string.h>
#include <stdlib.h>

/* OID P-256 */
static const char g_oidP256[] = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
/* Simulated uncompressed P-256 EC point (1 + 32 + 32 = 65 bytes), DER-wrapped */
static const char g_ecPoint256[] =
    "\x04\x41"             /* DER OCTET STRING wrapper */
    "\x04"                 /* uncompressed point */
    "\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00"
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10" /* Qx 32 */
    "\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC"
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10" /* Qy 32 */
    ;

/* Simulated RSA-2048 modulus (256 bytes) and exponent */
static BYTE g_modulus[256];
static const BYTE g_exponent[] = { 0x01, 0x00, 0x01 };

static P11_MOCK_CONFIG g_cfg;
static P11_MOCK_CALLS  g_calls;

/* ── Mock functions ────────────────────────────────────────────────────── */

static CK_RV mock_Initialize(CK_VOID_PTR p) {
    (void)p;
    g_calls.nInitialize++;
    return g_cfg.rv_Initialize;
}

static CK_RV mock_Finalize(CK_VOID_PTR p) {
    (void)p;
    g_calls.nFinalize++;
    return CKR_OK;
}

static CK_RV mock_GetInfo(CK_INFO CK_PTR p) {
    g_calls.nGetInfo++;
    if (g_cfg.rv_GetInfo != CKR_OK) return g_cfg.rv_GetInfo;
    if (!p) return CKR_ARGUMENTS_BAD;
    /* This used to return CKR_OK and fill nothing, which let a caller read
     * an uninitialised cryptokiVersion and believe it. */
    memset(p, 0, sizeof(*p));
    p->cryptokiVersion.major = g_cfg.ckMajor;
    p->cryptokiVersion.minor = g_cfg.ckMinor;
    return CKR_OK;
}

static CK_RV mock_GetFunctionList(CK_FUNCTION_LIST_PTR CK_PTR pp) {
    (void)pp; return CKR_OK;
}

static CK_RV mock_GetSlotList(CK_BBOOL present, CK_SLOT_ID_PTR pSlots,
                               CK_ULONG_PTR pulCount) {
    (void)present;
    g_calls.nGetSlotList++;
    if (g_cfg.rv_GetSlotList != CKR_OK) return g_cfg.rv_GetSlotList;

    if (!pSlots) {
        *pulCount = (CK_ULONG)g_cfg.nSlots;
        return CKR_OK;
    }
    for (int i = 0; i < g_cfg.nSlots; i++) pSlots[i] = (CK_SLOT_ID)i;
    *pulCount = (CK_ULONG)g_cfg.nSlots;
    return CKR_OK;
}

static CK_RV mock_GetSlotInfo(CK_SLOT_ID id, CK_SLOT_INFO CK_PTR p) {
    (void)id; (void)p; return CKR_OK;
}
static CK_RV mock_GetTokenInfo(CK_SLOT_ID id, CK_TOKEN_INFO CK_PTR p) {
    (void)id; (void)p; return CKR_OK;
}
/* The mechanism list the token claims. Configured per test so a suite can
 * present a v2.40 SoftHSM2, a v3.2 token with ML-DSA, or a token that
 * refuses to answer at all. */
static CK_RV mock_GetMechanismList(CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR p,
                                    CK_ULONG_PTR n) {
    CK_ULONG i;
    (void)id;
    g_calls.nGetMechanismList++;
    if (g_cfg.rv_GetMechanismList != CKR_OK) return g_cfg.rv_GetMechanismList;
    if (!n) return CKR_ARGUMENTS_BAD;

    /* Two-call idiom: a NULL buffer asks for the count only. */
    if (!p) { *n = g_cfg.nMechs; return CKR_OK; }

    if (*n < g_cfg.nMechs) { *n = g_cfg.nMechs; return CKR_BUFFER_TOO_SMALL; }

    for (i = 0; i < g_cfg.nMechs; i++) p[i] = g_cfg.mechList[i];
    *n = g_cfg.nMechs;
    return CKR_OK;
}

static CK_RV mock_GetMechanismInfo(CK_SLOT_ID id, CK_MECHANISM_TYPE t,
                                    CK_MECHANISM_INFO CK_PTR p) {
    CK_ULONG i;
    (void)id;
    g_calls.nGetMechanismInfo++;
    if (g_cfg.rv_GetMechanismInfo != CKR_OK) return g_cfg.rv_GetMechanismInfo;
    if (!p) return CKR_ARGUMENTS_BAD;

    for (i = 0; i < g_cfg.nMechs; i++) {
        if (g_cfg.mechList[i] == t) {
            p->ulMinKeySize = 0;
            p->ulMaxKeySize = 0;
            p->flags        = g_cfg.mechFlags;
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_INVALID;
}
static CK_RV mock_InitToken(CK_SLOT_ID id, CK_UTF8CHAR_PTR pin, CK_ULONG n,
                              CK_UTF8CHAR_PTR label) {
    (void)id; (void)pin; (void)n; (void)label; return CKR_OK;
}
static CK_RV mock_InitPIN(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR pin, CK_ULONG n) {
    (void)h; (void)pin; (void)n; return CKR_OK;
}
static CK_RV mock_SetPIN(CK_SESSION_HANDLE h, CK_UTF8CHAR_PTR op, CK_ULONG ol,
                          CK_UTF8CHAR_PTR np, CK_ULONG nl) {
    (void)h; (void)op; (void)ol; (void)np; (void)nl; return CKR_OK;
}

static CK_RV mock_OpenSession(CK_SLOT_ID id, CK_FLAGS f, CK_VOID_PTR app,
                               CK_VOID_PTR notify, CK_SESSION_HANDLE_PTR ph) {
    (void)id; (void)f; (void)app; (void)notify;
    g_calls.nOpenSession++;
    if (g_cfg.rv_OpenSession != CKR_OK) return g_cfg.rv_OpenSession;
    *ph = 0xBEEF;
    return CKR_OK;
}

static CK_RV mock_CloseSession(CK_SESSION_HANDLE h) {
    (void)h;
    g_calls.nCloseSession++;
    return CKR_OK;
}
static CK_RV mock_CloseAllSessions(CK_SLOT_ID id) { (void)id; return CKR_OK; }
static CK_RV mock_GetSessionInfo(CK_SESSION_HANDLE h, CK_SESSION_INFO CK_PTR p) {
    (void)h;
    g_calls.nGetSessionInfo++;
    if (g_cfg.rv_GetSessionInfo != CKR_OK)
        return g_cfg.rv_GetSessionInfo;
    if (p) {
        memset(p, 0, sizeof(*p));
        p->state = g_cfg.sessionState;
    }
    return CKR_OK;
}
static CK_RV mock_GetOperationState(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
                                     CK_ULONG_PTR n) {
    (void)h; (void)p; (void)n; return CKR_OK;
}
static CK_RV mock_SetOperationState(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
    CK_ULONG n, CK_OBJECT_HANDLE ek, CK_OBJECT_HANDLE ak) {
    (void)h; (void)p; (void)n; (void)ek; (void)ak; return CKR_OK;
}

static CK_RV mock_Login(CK_SESSION_HANDLE h, CK_USER_TYPE t,
                         CK_UTF8CHAR_PTR pin, CK_ULONG n) {
    (void)h;
    /* CKU_CONTEXT_SPECIFIC is per-key re-authentication and is counted
     * separately: a test asserting "the key's PIN was replayed" must not be
     * satisfied by the ordinary session login. */
    if (t == CKU_CONTEXT_SPECIFIC) {
        g_calls.nContextLogin++;
        g_cfg.cbLastContextPin = 0;
        if (pin && n < sizeof(g_cfg.lastContextPin)) {
            memcpy(g_cfg.lastContextPin, pin, n);
            g_cfg.lastContextPin[n] = '\0';
            g_cfg.cbLastContextPin = n;
        }
        return g_cfg.rv_ContextLogin;
    }
    g_calls.nLogin++;
    return g_cfg.rv_Login;
}

static CK_RV mock_Logout(CK_SESSION_HANDLE h) { (void)h; return CKR_OK; }

static CK_RV mock_CreateObject(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR tmpl,
                                CK_ULONG n, CK_OBJECT_HANDLE_PTR phObj) {
    CK_ULONG i;
    (void)h;
    g_calls.nCreateObject++;
    g_cfg.lastCreateClass    = (CK_OBJECT_CLASS)~0UL;
    g_cfg.lastCreateCertType = (CK_ULONG)~0UL;
    for (i = 0; tmpl && i < n; i++) {
        if (tmpl[i].type == CKA_VALUE && tmpl[i].pValue &&
            tmpl[i].ulValueLen <= sizeof(g_cfg.lastCreateValue)) {
            memcpy(g_cfg.lastCreateValue, tmpl[i].pValue, tmpl[i].ulValueLen);
            g_cfg.cbLastCreateValue = tmpl[i].ulValueLen;
        } else if (tmpl[i].type == CKA_CLASS && tmpl[i].pValue &&
                   tmpl[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            g_cfg.lastCreateClass = *(CK_OBJECT_CLASS *)tmpl[i].pValue;
        } else if (tmpl[i].type == CKA_CERTIFICATE_TYPE && tmpl[i].pValue &&
                   tmpl[i].ulValueLen == sizeof(CK_ULONG)) {
            g_cfg.lastCreateCertType = *(CK_ULONG *)tmpl[i].pValue;
        } else if (tmpl[i].type == CKA_LABEL && tmpl[i].pValue &&
                   tmpl[i].ulValueLen < sizeof(g_cfg.lastLabel)) {
            memcpy(g_cfg.lastLabel, tmpl[i].pValue, tmpl[i].ulValueLen);
            g_cfg.lastLabel[tmpl[i].ulValueLen] = '\0';
        }
    }
    if (g_cfg.rv_CreateObject != CKR_OK) return g_cfg.rv_CreateObject;
    *phObj = 0x100;
    return CKR_OK;
}

static CK_RV mock_CopyObject(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR ph) {
    (void)h; (void)o; (void)t; (void)n; (void)ph; return CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV mock_DestroyObject(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o) {
    (void)h; (void)o;
    g_calls.nDestroyObject++;
    return g_cfg.rv_DestroyObject;
}

static CK_RV mock_GetObjectSize(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
                                 CK_ULONG_PTR n) {
    (void)h; (void)o; if (n) *n = 0; return CKR_OK;
}

/* FindObjects state */
static int g_findCallCount = 0;

static CK_RV mock_GetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
                                     CK_ATTRIBUTE_PTR tmpl, CK_ULONG n) {
    (void)h; (void)o;
    g_calls.nGetAttributeValue++;
    if (g_cfg.rv_GetAttributeValue != CKR_OK) return g_cfg.rv_GetAttributeValue;

    for (CK_ULONG i = 0; i < n; i++) {
        switch (tmpl[i].type) {
        case CKA_KEY_TYPE:
            if (tmpl[i].pValue && tmpl[i].ulValueLen >= sizeof(CK_ULONG))
                *(CK_ULONG*)tmpl[i].pValue = g_cfg.ulKeyType;
            tmpl[i].ulValueLen = sizeof(CK_ULONG);
            break;
        case CKA_MODULUS_BITS:
            if (tmpl[i].pValue && tmpl[i].ulValueLen >= sizeof(CK_ULONG))
                *(CK_ULONG*)tmpl[i].pValue = g_cfg.ulModBits;
            tmpl[i].ulValueLen = sizeof(CK_ULONG);
            break;
        case CKA_VALUE_LEN:
            if (tmpl[i].pValue && tmpl[i].ulValueLen >= sizeof(CK_ULONG))
                *(CK_ULONG*)tmpl[i].pValue = g_cfg.ulValueLen;
            tmpl[i].ulValueLen = sizeof(CK_ULONG);
            break;
        case CKA_DERIVE:
            if (tmpl[i].pValue && tmpl[i].ulValueLen >= sizeof(CK_ULONG))
                *(CK_ULONG*)tmpl[i].pValue = g_cfg.ulDerive;
            tmpl[i].ulValueLen = sizeof(CK_ULONG);
            break;
        case CKA_VALUE:
            if (!g_cfg.pbSecretValue) return CKR_ATTRIBUTE_TYPE_INVALID;
            if (!tmpl[i].pValue) {
                tmpl[i].ulValueLen = g_cfg.cbSecretValue;
            } else {
                memcpy(tmpl[i].pValue, g_cfg.pbSecretValue,
                       g_cfg.cbSecretValue);
                tmpl[i].ulValueLen = g_cfg.cbSecretValue;
            }
            break;
        case CKA_MODULUS:
            if (!tmpl[i].pValue) {
                tmpl[i].ulValueLen = g_cfg.cbModulus;
            } else {
                memcpy(tmpl[i].pValue, g_cfg.pbModulus, g_cfg.cbModulus);
                tmpl[i].ulValueLen = g_cfg.cbModulus;
            }
            break;
        case CKA_PUBLIC_EXPONENT:
            if (!tmpl[i].pValue) {
                tmpl[i].ulValueLen = g_cfg.cbExponent;
            } else {
                memcpy(tmpl[i].pValue, g_cfg.pbExponent, g_cfg.cbExponent);
                tmpl[i].ulValueLen = g_cfg.cbExponent;
            }
            break;
        case CKA_EC_PARAMS:
            if (!tmpl[i].pValue) {
                tmpl[i].ulValueLen = g_cfg.cbEcParams;
            } else {
                memcpy(tmpl[i].pValue, g_cfg.pbEcParams, g_cfg.cbEcParams);
                tmpl[i].ulValueLen = g_cfg.cbEcParams;
            }
            break;
        case CKA_EC_POINT:
            if (!tmpl[i].pValue) {
                tmpl[i].ulValueLen = g_cfg.cbEcPoint;
            } else {
                memcpy(tmpl[i].pValue, g_cfg.pbEcPoint, g_cfg.cbEcPoint);
                tmpl[i].ulValueLen = g_cfg.cbEcPoint;
            }
            break;
        case CKA_LABEL:
            if (!tmpl[i].pValue) {
                tmpl[i].ulValueLen = (CK_ULONG)strlen(g_cfg.szKeyLabel);
            } else {
                size_t llen = strlen(g_cfg.szKeyLabel);
                memcpy(tmpl[i].pValue, g_cfg.szKeyLabel, llen);
                tmpl[i].ulValueLen = (CK_ULONG)llen;
            }
            break;
        default:
            tmpl[i].ulValueLen = (CK_ULONG)-1;
            break;
        }
    }
    return CKR_OK;
}

static CK_RV mock_SetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
    CK_ATTRIBUTE_PTR t, CK_ULONG n) {
    (void)h; (void)o; (void)t; (void)n; return CKR_OK;
}

/* The search template used to be ignored entirely, so a search for a
 * certificate came back with key handles. The class is now honoured, which
 * is what lets a test say "this key has no certificate yet". */
static CK_RV mock_FindObjectsInit(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR t,
                                   CK_ULONG n) {
    CK_ULONG i;
    (void)h;
    g_calls.nFindObjectsInit++;
    g_findCallCount = 0;

    /* CKO_DATA is 0, so "no class in the template" needs its own marker. */
    g_cfg.lastFindClass    = (CK_OBJECT_CLASS)~0UL;
    g_cfg.lastFindLabel[0] = '\0';

    for (i = 0; t && i < n; i++) {
        if (t[i].type == CKA_CLASS && t[i].pValue &&
            t[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            g_cfg.lastFindClass = *(CK_OBJECT_CLASS *)t[i].pValue;
        } else if (t[i].type == CKA_LABEL && t[i].pValue &&
                   t[i].ulValueLen < sizeof(g_cfg.lastFindLabel)) {
            memcpy(g_cfg.lastFindLabel, t[i].pValue, t[i].ulValueLen);
            g_cfg.lastFindLabel[t[i].ulValueLen] = '\0';
        }
    }
    return g_cfg.rv_FindObjectsInit;
}

static CK_RV mock_FindObjects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE_PTR phObj,
                               CK_ULONG max, CK_ULONG_PTR pulFound) {
    CK_ULONG n;
    CK_OBJECT_HANDLE base;
    (void)h;
    g_calls.nFindObjects++;
    if (g_cfg.rv_FindObjects != CKR_OK) { *pulFound = 0; return g_cfg.rv_FindObjects; }

    if (g_cfg.lastFindClass == CKO_CERTIFICATE) {
        n    = (CK_ULONG)g_cfg.nCertObjects;
        base = 0x40;
    } else {
        n    = (CK_ULONG)g_cfg.nKeyObjects;
        base = 0x10;
    }

    if (g_findCallCount > 0 || n == 0) {
        *pulFound = 0;
        return CKR_OK;
    }

    if (n > max) n = max;
    for (CK_ULONG i = 0; i < n; i++) phObj[i] = (CK_OBJECT_HANDLE)(base + i);
    *pulFound = n;
    g_findCallCount++;
    return CKR_OK;
}

static CK_RV mock_FindObjectsFinal(CK_SESSION_HANDLE h) {
    (void)h;
    g_calls.nFindObjectsFinal++;
    return CKR_OK;
}

static CK_RV mock_EncryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                               CK_OBJECT_HANDLE k) {
    (void)h; (void)k;
    g_calls.nEncryptInit++;
    if (m) g_cfg.lastEncryptMech = m->mechanism;
    return g_cfg.rv_EncryptInit;
}
static CK_RV mock_Encrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl,
    CK_BYTE_PTR e, CK_ULONG_PTR el) {
    CK_ULONG need;
    (void)h; (void)d;
    g_calls.nEncrypt++;

    if (g_cfg.rv_Encrypt != CKR_OK) return g_cfg.rv_Encrypt;
    if (!el) return CKR_ARGUMENTS_BAD;

    /* Default: ciphertext same length as plaintext (stream-like) */
    need = g_cfg.cbCiphertext ? g_cfg.cbCiphertext : dl;

    if (e == NULL) { *el = need; return CKR_OK; }
    if (*el < need) { *el = need; return CKR_BUFFER_TOO_SMALL; }

    memset(e, 0xE1, need);
    *el = need;
    return CKR_OK;
}
static CK_RV mock_EncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
    CK_ULONG pl, CK_BYTE_PTR ep, CK_ULONG_PTR epl) {
    (void)h; (void)p; (void)pl; (void)ep; (void)epl; return CKR_OK;
}
static CK_RV mock_EncryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR lep,
    CK_ULONG_PTR lepl) {
    (void)h; (void)lep; (void)lepl; return CKR_OK;
}

static CK_RV mock_DecryptInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                               CK_OBJECT_HANDLE k) {
    (void)h; (void)k;
    g_calls.nDecryptInit++;
    if (m) g_cfg.lastDecryptMech = m->mechanism;
    return g_cfg.rv_DecryptInit;
}

static CK_RV mock_Decrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR cipher,
    CK_ULONG clen, CK_BYTE_PTR plain, CK_ULONG_PTR plen) {
    (void)h; (void)cipher; (void)clen;
    g_calls.nDecrypt++;
    if (g_cfg.rv_Decrypt != CKR_OK) return g_cfg.rv_Decrypt;
    if (!plain) { *plen = 32; return CKR_OK; }
    if (*plen < 32) { *plen = 32; return CKR_BUFFER_TOO_SMALL; }
    memset(plain, 0x42, 32);
    *plen = 32;
    return CKR_OK;
}

static CK_RV mock_DecryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR ep,
    CK_ULONG el, CK_BYTE_PTR p, CK_ULONG_PTR pl) {
    (void)h; (void)ep; (void)el; (void)p; (void)pl; return CKR_OK;
}
static CK_RV mock_DecryptFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR lp,
    CK_ULONG_PTR lpl) {
    (void)h; (void)lp; (void)lpl; return CKR_OK;
}

static CK_RV mock_DigestInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m) {
    (void)h;
    g_calls.nDigestInit++;
    if (m) g_cfg.lastDigestMech = m->mechanism;
    g_cfg.cbDigestFed = 0;            /* a new chain */
    return CKR_OK;
}
static CK_RV mock_Digest(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl,
    CK_BYTE_PTR dg, CK_ULONG_PTR dgl) {
    (void)h; (void)d; (void)dl; (void)dg; (void)dgl; return CKR_OK;
}
static CK_RV mock_DigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
    CK_ULONG pl) {
    (void)h;
    g_calls.nDigestUpdate++;
    if (p && pl && g_cfg.cbDigestFed + pl <= sizeof(g_cfg.digestFed)) {
        memcpy(g_cfg.digestFed + g_cfg.cbDigestFed, p, pl);
        g_cfg.cbDigestFed += pl;
    }
    return CKR_OK;
}
static CK_RV mock_DigestKey(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE k) {
    (void)h; (void)k; return CKR_OK;
}
static CK_RV mock_DigestFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR dg,
    CK_ULONG_PTR dgl) {
    CK_ULONG n = g_cfg.cbDigestOut;
    (void)h;
    g_calls.nDigestFinal++;
    /* Not a real hash: returns the first n bytes of what was fed, which is
     * enough to prove the KSP assembled prepend || Z || append correctly
     * and asked for the right digest length. */
    if (n > g_cfg.cbDigestFed) n = g_cfg.cbDigestFed;
    if (dg) memcpy(dg, g_cfg.digestFed, n);
    if (dgl) *dgl = g_cfg.cbDigestOut;
    return CKR_OK;
}

static CK_RV mock_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                            CK_OBJECT_HANDLE k) {
    (void)h; (void)k;
    g_calls.nSignInit++;
    if (m) {
        g_cfg.lastSignMech = m->mechanism;
        if (m->mechanism == CKM_RSA_PKCS_PSS &&
            m->pParameter != NULL &&
            m->ulParameterLen == sizeof(CK_RSA_PKCS_PSS_PARAMS)) {
            memcpy(&g_cfg.lastSignPss, m->pParameter,
                   sizeof(CK_RSA_PKCS_PSS_PARAMS));
            g_cfg.lastSignPssValid = 1;
        }
    }
    return g_cfg.rv_SignInit;
}

static CK_RV mock_Sign(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG dlen,
                        CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {
    (void)h;
    g_calls.nSign++;
    if (data && dlen && dlen <= sizeof(g_cfg.lastSignData)) {
        memcpy(g_cfg.lastSignData, data, dlen);
        g_cfg.cbLastSignData = dlen;
    }
    if (g_cfg.rv_Sign != CKR_OK) return g_cfg.rv_Sign;
    if (!sig) { *siglen = g_cfg.cbSignature; return CKR_OK; }
    if (*siglen < g_cfg.cbSignature) {
        *siglen = g_cfg.cbSignature;
        return CKR_BUFFER_TOO_SMALL;
    }
    if (g_cfg.pbSignature)
        memcpy(sig, g_cfg.pbSignature, g_cfg.cbSignature);
    else
        memset(sig, 0xAB, g_cfg.cbSignature);
    *siglen = g_cfg.cbSignature;
    return CKR_OK;
}

static CK_RV mock_SignUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG pl) {
    (void)h; (void)p; (void)pl; return CKR_OK;
}
static CK_RV mock_SignFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR s, CK_ULONG_PTR sl) {
    (void)h; (void)s; (void)sl; return CKR_OK;
}
static CK_RV mock_SignRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE k) { (void)h; (void)m; (void)k; return CKR_OK; }
static CK_RV mock_SignRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl,
    CK_BYTE_PTR s, CK_ULONG_PTR sl) {
    (void)h; (void)d; (void)dl; (void)s; (void)sl; return CKR_OK;
}
static CK_RV mock_VerifyInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE k) { (void)h; (void)m; (void)k; return CKR_OK; }
static CK_RV mock_Verify(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl,
    CK_BYTE_PTR s, CK_ULONG sl) {
    (void)h; (void)d; (void)dl; (void)s; (void)sl; return CKR_OK;
}
static CK_RV mock_VerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG pl) {
    (void)h; (void)p; (void)pl; return CKR_OK;
}
static CK_RV mock_VerifyFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR s, CK_ULONG sl) {
    (void)h; (void)s; (void)sl; return CKR_OK;
}
static CK_RV mock_VerifyRecoverInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE k) { (void)h; (void)m; (void)k; return CKR_OK; }
static CK_RV mock_VerifyRecover(CK_SESSION_HANDLE h, CK_BYTE_PTR s, CK_ULONG sl,
    CK_BYTE_PTR d, CK_ULONG_PTR dl) {
    (void)h; (void)s; (void)sl; (void)d; (void)dl; return CKR_OK;
}

static CK_RV mock_DigestEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
    CK_ULONG pl, CK_BYTE_PTR ep, CK_ULONG_PTR epl) {
    (void)h; (void)p; (void)pl; (void)ep; (void)epl; return CKR_OK;
}
static CK_RV mock_DecryptDigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR ep,
    CK_ULONG el, CK_BYTE_PTR p, CK_ULONG_PTR pl) {
    (void)h; (void)ep; (void)el; (void)p; (void)pl; return CKR_OK;
}
static CK_RV mock_SignEncryptUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
    CK_ULONG pl, CK_BYTE_PTR ep, CK_ULONG_PTR epl) {
    (void)h; (void)p; (void)pl; (void)ep; (void)epl; return CKR_OK;
}
static CK_RV mock_DecryptVerifyUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR ep,
    CK_ULONG el, CK_BYTE_PTR p, CK_ULONG_PTR pl) {
    (void)h; (void)ep; (void)el; (void)p; (void)pl; return CKR_OK;
}

/* Record CKA_LABEL from a creation template. */
static void capture_label(CK_ATTRIBUTE_PTR t, CK_ULONG n)
{
    CK_ULONG i;
    if (!t) return;
    for (i = 0; i < n; i++) {
        if (t[i].type == CKA_LABEL && t[i].pValue && t[i].ulValueLen > 0) {
            size_t cb = t[i].ulValueLen;
            if (cb >= sizeof(g_cfg.lastLabel))
                cb = sizeof(g_cfg.lastLabel) - 1;
            memcpy(g_cfg.lastLabel, t[i].pValue, cb);
            g_cfg.lastLabel[cb] = '\0';
            return;
        }
    }
}

static CK_RV mock_GenerateKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR ph) {
    (void)h;
    g_calls.nGenerateKey++;
    capture_label(t, n);
    if (m) g_cfg.lastGenerateMech = m->mechanism;
    if (g_cfg.rv_GenerateKey != CKR_OK) return g_cfg.rv_GenerateKey;
    /* Distinct handles per key. Handing every generated key the same
     * object handle made two different keys indistinguishable, so a test
     * could not tell a wrapping key from the key being wrapped. */
    if (ph) *ph = (CK_OBJECT_HANDLE)(0xFF + g_calls.nGenerateKey - 1);
    return CKR_OK;
}

static CK_RV mock_GenerateKeyPair(
    CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_ATTRIBUTE_PTR pubT, CK_ULONG nPub,
    CK_ATTRIBUTE_PTR privT, CK_ULONG nPriv,
    CK_OBJECT_HANDLE_PTR phPub, CK_OBJECT_HANDLE_PTR phPriv)
{
    (void)h;
    g_calls.nGenerateKeyPair++;
    capture_label(privT, nPriv);
    if (g_cfg.lastLabel[0] == '\0') capture_label(pubT, nPub);
    if (m) g_cfg.lastGenerateKeyPairMech = m->mechanism;
    if (g_cfg.rv_GenerateKeyPair != CKR_OK) return g_cfg.rv_GenerateKeyPair;
    *phPub  = 0x20;
    *phPriv = 0x21;
    return CKR_OK;
}

static CK_RV mock_WrapKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE wk, CK_OBJECT_HANDLE k, CK_BYTE_PTR wkb,
    CK_ULONG_PTR wkbl) {
    (void)h;
    g_calls.nWrapKey++;
    if (m) g_cfg.lastWrapMech = m->mechanism;
    g_cfg.lastWrappingKey = wk;
    g_cfg.lastWrappedKey  = k;
    if (g_cfg.rv_WrapKey != CKR_OK) return g_cfg.rv_WrapKey;
    if (!wkbl) return CKR_ARGUMENTS_BAD;

    /* Two-call idiom, as a real token does it. */
    if (!wkb) { *wkbl = g_cfg.cbWrapped; return CKR_OK; }
    if (*wkbl < g_cfg.cbWrapped) { *wkbl = g_cfg.cbWrapped; return CKR_BUFFER_TOO_SMALL; }

    memset(wkb, 0x5A, g_cfg.cbWrapped);
    *wkbl = g_cfg.cbWrapped;
    return CKR_OK;
}

static CK_RV mock_UnwrapKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE uwk, CK_BYTE_PTR wkb, CK_ULONG wkbl,
    CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR ph) {
    CK_ULONG i;
    (void)h;
    g_calls.nUnwrapKey++;
    if (m) g_cfg.lastUnwrapMech = m->mechanism;
    g_cfg.lastWrappingKey = uwk;
    g_cfg.cbLastUnwrapInput = wkbl;
    if (wkb && wkbl <= sizeof(g_cfg.lastUnwrapInput))
        memcpy(g_cfg.lastUnwrapInput, wkb, wkbl);

    /* Record the template the provider asked for, so a test can assert the
     * unwrapped key is sensitive and non-extractable rather than assuming
     * it. A key that arrives wrapped and leaves in the clear would defeat
     * the point of wrapping it. */
    g_cfg.lastUnwrapExtractable = 0xFF;
    g_cfg.lastUnwrapSensitive   = 0xFF;
    for (i = 0; t && i < n; i++) {
        if (t[i].type == CKA_EXTRACTABLE && t[i].pValue)
            g_cfg.lastUnwrapExtractable = *(CK_BBOOL *)t[i].pValue;
        else if (t[i].type == CKA_SENSITIVE && t[i].pValue)
            g_cfg.lastUnwrapSensitive = *(CK_BBOOL *)t[i].pValue;
    }

    if (g_cfg.rv_UnwrapKey != CKR_OK) return g_cfg.rv_UnwrapKey;
    if (ph) *ph = 0x200;
    return CKR_OK;
}
static CK_RV mock_DeriveKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE bk, CK_ATTRIBUTE_PTR t, CK_ULONG n,
    CK_OBJECT_HANDLE_PTR ph) {
    (void)h; (void)bk; (void)t; (void)n;
    g_calls.nDeriveKey++;

    if (m) {
        g_cfg.lastDeriveMech = m->mechanism;
        /* Capture the peer public data length for ECDH assertions */
        if (m->mechanism == CKM_ECDH1_DERIVE && m->pParameter &&
            m->ulParameterLen >= sizeof(CK_ECDH1_DERIVE_PARAMS)) {
            CK_ECDH1_DERIVE_PARAMS *p =
                (CK_ECDH1_DERIVE_PARAMS *)m->pParameter;
            g_cfg.lastEcdhPublicDataLen = p->ulPublicDataLen;
        }
    }

    if (g_cfg.rv_DeriveKey != CKR_OK) return g_cfg.rv_DeriveKey;
    if (ph) *ph = 0xD5;
    return CKR_OK;
}
static CK_RV mock_SeedRandom(CK_SESSION_HANDLE h, CK_BYTE_PTR s, CK_ULONG sl) {
    (void)h; (void)s; (void)sl; return CKR_OK;
}
static CK_RV mock_GenerateRandom(CK_SESSION_HANDLE h, CK_BYTE_PTR r,
    CK_ULONG rl) {
    (void)h; memset(r, 0x5A, rl); return CKR_OK;
}
static CK_RV mock_GetFunctionStatus(CK_SESSION_HANDLE h) {
    (void)h; return CKR_FUNCTION_NOT_PARALLEL;
}
static CK_RV mock_CancelFunction(CK_SESSION_HANDLE h) {
    (void)h; return CKR_FUNCTION_NOT_PARALLEL;
}
static CK_RV mock_WaitForSlotEvent(CK_FLAGS f, CK_SLOT_ID_PTR p,
    CK_VOID_PTR r) {
    (void)f; (void)p; (void)r; return CKR_NO_EVENT;
}

static CK_FUNCTION_LIST g_fnList = {
    {2, 40},
    mock_Initialize, mock_Finalize, mock_GetInfo, mock_GetFunctionList,
    mock_GetSlotList, mock_GetSlotInfo, mock_GetTokenInfo,
    mock_GetMechanismList, mock_GetMechanismInfo, mock_InitToken,
    mock_InitPIN, mock_SetPIN, mock_OpenSession, mock_CloseSession,
    mock_CloseAllSessions, mock_GetSessionInfo, mock_GetOperationState,
    mock_SetOperationState, mock_Login, mock_Logout, mock_CreateObject,
    mock_CopyObject, mock_DestroyObject, mock_GetObjectSize,
    mock_GetAttributeValue, mock_SetAttributeValue,
    mock_FindObjectsInit, mock_FindObjects, mock_FindObjectsFinal,
    mock_EncryptInit, mock_Encrypt, mock_EncryptUpdate, mock_EncryptFinal,
    mock_DecryptInit, mock_Decrypt, mock_DecryptUpdate, mock_DecryptFinal,
    mock_DigestInit, mock_Digest, mock_DigestUpdate, mock_DigestKey,
    mock_DigestFinal, mock_SignInit, mock_Sign, mock_SignUpdate,
    mock_SignFinal, mock_SignRecoverInit, mock_SignRecover,
    mock_VerifyInit, mock_Verify, mock_VerifyUpdate, mock_VerifyFinal,
    mock_VerifyRecoverInit, mock_VerifyRecover,
    mock_DigestEncryptUpdate, mock_DecryptDigestUpdate,
    mock_SignEncryptUpdate, mock_DecryptVerifyUpdate,
    mock_GenerateKey, mock_GenerateKeyPair,
    mock_WrapKey, mock_UnwrapKey, mock_DeriveKey,
    mock_SeedRandom, mock_GenerateRandom,
    mock_GetFunctionStatus, mock_CancelFunction, mock_WaitForSlotEvent
};

/* ── Module loading ──────────────────────────────────────────────────────
 *
 * p11_context.c reaches the token through LoadLibrary + GetProcAddress.
 * Driving those from here is what lets a test exercise the failure path and
 * the recovery from it; while they were inline stubs in windows_compat.h
 * that always returned NULL, p11_context.c could not be tested at all.
 *
 * bModuleLoads is FALSE by default, so a suite that does not care keeps the
 * old behaviour: no module, initialisation fails. */
static CK_RV mock_C_GetFunctionList_entry(CK_FUNCTION_LIST_PTR CK_PTR pp)
{
    if (!pp) return CKR_ARGUMENTS_BAD;
    *pp = &g_fnList;
    return CKR_OK;
}

HMODULE LoadLibraryW(const wchar_t *path)
{
    (void)path;
    g_calls.nLoadLibrary++;
    if (!g_cfg.bModuleLoads) return NULL;
    /* Any non-NULL value; the provider only ever passes it back to us. */
    return (HMODULE)(ULONG_PTR)0xD11;
}

void *GetProcAddress(HMODULE m, const char *n)
{
    (void)m;
    g_calls.nGetProcAddress++;
    if (!g_cfg.bModuleLoads || g_cfg.bNoGetFunctionList) return NULL;
    if (n && strcmp(n, "C_GetFunctionList") == 0)
        return (void *)mock_C_GetFunctionList_entry;
    return NULL;
}

int FreeLibrary(HMODULE m)
{
    (void)m;
    g_calls.nFreeLibrary++;
    return 1;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void P11Mock_ResetCalls(void)
{
    memset(&g_calls, 0, sizeof(g_calls));
    g_cfg.cbLastSignData    = 0;
    g_cfg.cbLastCreateValue = 0;
    g_cfg.cbDigestFed       = 0;
    g_findCallCount         = 0;
}

void P11Mock_Reset(void)
{
    memset(&g_cfg, 0, sizeof g_cfg);
    memset(&g_calls, 0, sizeof g_calls);
    g_cfg.rv_Initialize      = CKR_OK;
    g_cfg.rv_GetSlotList     = CKR_OK;
    g_cfg.rv_OpenSession     = CKR_OK;
    g_cfg.rv_Login           = CKR_OK;
    g_cfg.rv_GenerateKeyPair = CKR_OK;
    g_cfg.rv_FindObjectsInit = CKR_OK;
    g_cfg.rv_FindObjects     = CKR_OK;
    g_cfg.rv_GetAttributeValue = CKR_OK;
    g_cfg.rv_SignInit        = CKR_OK;
    g_cfg.rv_GetSessionInfo  = CKR_OK;
    g_cfg.lastLabel[0]       = '\0';
    g_cfg.cbDigestFed        = 0;
    g_cfg.cbLastSignData     = 0;
    g_cfg.cbLastCreateValue  = 0;
    g_cfg.cbDigestOut        = 20;
    g_cfg.sessionState       = CKS_RW_USER_FUNCTIONS;
    g_cfg.rv_Sign            = CKR_OK;
    g_cfg.rv_DecryptInit     = CKR_OK;
    g_cfg.rv_Decrypt         = CKR_OK;
    g_cfg.rv_DestroyObject   = CKR_OK;
    g_cfg.rv_CreateObject    = CKR_OK;
    g_cfg.rv_GenerateKey     = CKR_OK;
    g_cfg.rv_DeriveKey       = CKR_OK;
    g_cfg.rv_EncryptInit     = CKR_OK;
    g_cfg.rv_Encrypt         = CKR_OK;

    g_cfg.nSlots       = 1;
    g_cfg.nKeyObjects  = 0;
    g_cfg.nCertObjects = 0;
    g_cfg.lastFindClass    = (CK_OBJECT_CLASS)~0UL;
    g_cfg.lastFindLabel[0] = '\0';
    g_cfg.ulKeyType   = CKK_RSA;
    g_cfg.ulModBits   = 2048;
    g_cfg.cbSignature = 256;
    strcpy(g_cfg.szKeyLabel, "TestKey");

    /* Initialise the dummy modulus */
    memset(g_modulus, 0xCC, sizeof g_modulus);
    g_modulus[0] = 0x00; g_modulus[1] = 0xBF; /* Avoid sign bit */

    g_cfg.pbModulus  = g_modulus;
    g_cfg.cbModulus  = 256;
    g_cfg.pbExponent = g_exponent;
    g_cfg.cbExponent = 3;

    g_cfg.pbEcParams = g_oidP256;
    g_cfg.cbEcParams = 10;
    g_cfg.pbEcPoint  = g_ecPoint256;
    g_cfg.cbEcPoint  = 67;

    g_cfg.rv_GetInfo           = CKR_OK;
    g_cfg.rv_GetMechanismList  = CKR_OK;
    g_cfg.rv_GetMechanismInfo  = CKR_OK;
    g_cfg.rv_WrapKey           = CKR_OK;
    g_cfg.rv_UnwrapKey         = CKR_OK;
    g_cfg.rv_ContextLogin      = CKR_OK;
    g_cfg.cbWrapped            = 40;   /* 32-byte AES key + RFC 3394 overhead */

    /* Default token: SoftHSM2 2.7.0 as this provider sees it — every
     * mechanism the KSP maps, and no post-quantum one, because SoftHSM2
     * defines those constants and implements none of them. A suite that
     * wants a different token calls P11Mock_SetMechanisms. */
    {
        static const CK_MECHANISM_TYPE softhsm[] = {
            CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS,
            CKM_RSA_PKCS_OAEP,
            CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDH1_DERIVE,
            CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EDDSA,
            CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD,
            CKM_AES_CTR, CKM_AES_GCM,
            CKM_GENERIC_SECRET_KEY_GEN,
            CKM_SHA_1_HMAC, CKM_SHA224_HMAC, CKM_SHA256_HMAC,
            CKM_SHA384_HMAC, CKM_SHA512_HMAC,
        };
        P11Mock_SetMechanisms(softhsm,
                              sizeof(softhsm) / sizeof(softhsm[0]));
    }
    g_cfg.mechFlags = CKF_SIGN | CKF_VERIFY | CKF_GENERATE_KEY_PAIR;
    g_cfg.ckMajor   = 2;
    g_cfg.ckMinor   = 40;

    g_findCallCount = 0;
}

void P11Mock_SetMechanisms(const CK_MECHANISM_TYPE *pMechs, CK_ULONG nMechs)
{
    CK_ULONG i;

    if (nMechs > P11_MOCK_MAX_MECHS)
        nMechs = P11_MOCK_MAX_MECHS;

    for (i = 0; i < nMechs; i++)
        g_cfg.mechList[i] = pMechs ? pMechs[i] : 0;

    g_cfg.nMechs = pMechs ? nMechs : 0;
}

void P11Mock_SetCryptokiVersion(CK_BYTE bMajor, CK_BYTE bMinor)
{
    g_cfg.ckMajor = bMajor;
    g_cfg.ckMinor = bMinor;
}

P11_MOCK_CONFIG *P11Mock_GetConfig(void) { return &g_cfg; }
P11_MOCK_CALLS  *P11Mock_GetCalls(void)  { return &g_calls; }
CK_FUNCTION_LIST *P11Mock_GetFunctionList(void) { return &g_fnList; }
