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
    (void)p; return CKR_OK;
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
static CK_RV mock_GetMechanismList(CK_SLOT_ID id, CK_MECHANISM_TYPE_PTR p,
                                    CK_ULONG_PTR n) {
    (void)id; (void)p; if (n) *n = 0; return CKR_OK;
}
static CK_RV mock_GetMechanismInfo(CK_SLOT_ID id, CK_MECHANISM_TYPE t,
                                    CK_MECHANISM_INFO CK_PTR p) {
    (void)id; (void)t; (void)p; return CKR_OK;
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
    (void)h; (void)p; return CKR_OK;
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
    (void)h; (void)t; (void)pin; (void)n;
    g_calls.nLogin++;
    return g_cfg.rv_Login;
}

static CK_RV mock_Logout(CK_SESSION_HANDLE h) { (void)h; return CKR_OK; }

static CK_RV mock_CreateObject(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR tmpl,
                                CK_ULONG n, CK_OBJECT_HANDLE_PTR phObj) {
    (void)h; (void)tmpl; (void)n;
    g_calls.nCreateObject++;
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

static CK_RV mock_FindObjectsInit(CK_SESSION_HANDLE h, CK_ATTRIBUTE_PTR t,
                                   CK_ULONG n) {
    (void)h; (void)t; (void)n;
    g_calls.nFindObjectsInit++;
    g_findCallCount = 0;
    return g_cfg.rv_FindObjectsInit;
}

static CK_RV mock_FindObjects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE_PTR phObj,
                               CK_ULONG max, CK_ULONG_PTR pulFound) {
    (void)h;
    g_calls.nFindObjects++;
    if (g_cfg.rv_FindObjects != CKR_OK) { *pulFound = 0; return g_cfg.rv_FindObjects; }
    if (g_findCallCount > 0 || g_cfg.nKeyObjects == 0) {
        *pulFound = 0;
        return CKR_OK;
    }
    CK_ULONG n = (CK_ULONG)g_cfg.nKeyObjects;
    if (n > max) n = max;
    for (CK_ULONG i = 0; i < n; i++) phObj[i] = (CK_OBJECT_HANDLE)(0x10 + i);
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
    (void)h; (void)m; (void)k; return CKR_OK;
}
static CK_RV mock_Encrypt(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl,
    CK_BYTE_PTR e, CK_ULONG_PTR el) {
    (void)h; (void)d; (void)dl; (void)e; (void)el; return CKR_OK;
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
    (void)h; (void)m; (void)k;
    g_calls.nDecryptInit++;
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
    (void)h; (void)m; return CKR_OK;
}
static CK_RV mock_Digest(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl,
    CK_BYTE_PTR dg, CK_ULONG_PTR dgl) {
    (void)h; (void)d; (void)dl; (void)dg; (void)dgl; return CKR_OK;
}
static CK_RV mock_DigestUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p,
    CK_ULONG pl) { (void)h; (void)p; (void)pl; return CKR_OK; }
static CK_RV mock_DigestKey(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE k) {
    (void)h; (void)k; return CKR_OK;
}
static CK_RV mock_DigestFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR dg,
    CK_ULONG_PTR dgl) { (void)h; (void)dg; (void)dgl; return CKR_OK; }

static CK_RV mock_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
                            CK_OBJECT_HANDLE k) {
    (void)h; (void)m; (void)k;
    g_calls.nSignInit++;
    return g_cfg.rv_SignInit;
}

static CK_RV mock_Sign(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG dlen,
                        CK_BYTE_PTR sig, CK_ULONG_PTR siglen) {
    (void)h; (void)data; (void)dlen;
    g_calls.nSign++;
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

static CK_RV mock_GenerateKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR ph) {
    (void)h; (void)m; (void)t; (void)n; *ph = 0xFF; return CKR_OK;
}

static CK_RV mock_GenerateKeyPair(
    CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_ATTRIBUTE_PTR pubT, CK_ULONG nPub,
    CK_ATTRIBUTE_PTR privT, CK_ULONG nPriv,
    CK_OBJECT_HANDLE_PTR phPub, CK_OBJECT_HANDLE_PTR phPriv)
{
    (void)h; (void)m; (void)pubT; (void)nPub; (void)privT; (void)nPriv;
    g_calls.nGenerateKeyPair++;
    if (g_cfg.rv_GenerateKeyPair != CKR_OK) return g_cfg.rv_GenerateKeyPair;
    *phPub  = 0x20;
    *phPriv = 0x21;
    return CKR_OK;
}

static CK_RV mock_WrapKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE wk, CK_OBJECT_HANDLE k, CK_BYTE_PTR wkb,
    CK_ULONG_PTR wkbl) {
    (void)h; (void)m; (void)wk; (void)k; (void)wkb; (void)wkbl;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
static CK_RV mock_UnwrapKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE uwk, CK_BYTE_PTR wkb, CK_ULONG wkbl,
    CK_ATTRIBUTE_PTR t, CK_ULONG n, CK_OBJECT_HANDLE_PTR ph) {
    (void)h; (void)m; (void)uwk; (void)wkb; (void)wkbl; (void)t; (void)n; (void)ph;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
static CK_RV mock_DeriveKey(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m,
    CK_OBJECT_HANDLE bk, CK_ATTRIBUTE_PTR t, CK_ULONG n,
    CK_OBJECT_HANDLE_PTR ph) {
    (void)h; (void)m; (void)bk; (void)t; (void)n; (void)ph;
    return CKR_FUNCTION_NOT_SUPPORTED;
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

/* ── Public API ─────────────────────────────────────────────────────────── */

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
    g_cfg.rv_Sign            = CKR_OK;
    g_cfg.rv_DecryptInit     = CKR_OK;
    g_cfg.rv_Decrypt         = CKR_OK;
    g_cfg.rv_DestroyObject   = CKR_OK;
    g_cfg.rv_CreateObject    = CKR_OK;

    g_cfg.nSlots      = 1;
    g_cfg.nKeyObjects = 0;
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

    g_findCallCount = 0;
}

P11_MOCK_CONFIG *P11Mock_GetConfig(void) { return &g_cfg; }
P11_MOCK_CALLS  *P11Mock_GetCalls(void)  { return &g_calls; }
CK_FUNCTION_LIST *P11Mock_GetFunctionList(void) { return &g_fnList; }
