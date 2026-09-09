/* p11_mock.h — Controllable PKCS#11 mock for unit tests
 * Simulates SoftHSM2 with error injection and call verification.
 */
#ifndef P11_MOCK_H
#define P11_MOCK_H

#include "windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"

/* ── Mock configuration ─────────────────────────────────────────────────── */

/* Injectable error codes (CKR_OK = normal behaviour) */
typedef struct _P11_MOCK_CONFIG {
    CK_RV rv_Initialize;
    CK_RV rv_GetSlotList;
    CK_RV rv_OpenSession;
    CK_RV rv_Login;
    CK_RV rv_GenerateKeyPair;
    CK_RV rv_FindObjectsInit;
    CK_RV rv_FindObjects;
    CK_RV rv_GetAttributeValue;
    CK_RV rv_SignInit;
    CK_RV rv_Sign;
    CK_RV rv_DecryptInit;
    CK_RV rv_Decrypt;
    CK_RV rv_DestroyObject;
    CK_RV rv_CreateObject;
    CK_RV rv_GenerateKey;
    CK_RV rv_DeriveKey;
    CK_RV rv_EncryptInit;
    CK_RV rv_Encrypt;

    /* Number of simulated slots */
    int nSlots;
    /* Number of simulated keys returned by FindObjects */
    int nKeyObjects;
    /* Label of the simulated keys */
    char szKeyLabel[256];
    /* Key type returned (CKK_RSA or CKK_EC) */
    CK_ULONG ulKeyType;
    /* Modulus size in bits (RSA) */
    CK_ULONG ulModBits;
    /* Signature length returned */
    CK_ULONG cbSignature;
    /* Signature data (filled with 0xAB if NULL) */
    CK_BYTE *pbSignature;
    /* CKA_EC_PARAMS to return */
    const char *pbEcParams;
    CK_ULONG   cbEcParams;
    /* CKA_EC_POINT to return */
    const char *pbEcPoint;
    CK_ULONG   cbEcPoint;
    /* RSA modulus to return */
    const BYTE *pbModulus;
    CK_ULONG   cbModulus;
    const BYTE *pbExponent;
    CK_ULONG   cbExponent;

    /* Ciphertext length returned by C_Encrypt */
    CK_ULONG   cbCiphertext;
    /* Plaintext length returned by C_Decrypt */
    CK_ULONG   cbPlaintext;
    /* CKA_VALUE returned for derived secrets / symmetric keys */
    const BYTE *pbSecretValue;
    CK_ULONG    cbSecretValue;
    /* CKA_VALUE_LEN returned for symmetric keys */
    CK_ULONG    ulValueLen;
    /* CKA_DERIVE returned for EC keys (distinguishes ECDH from ECDSA) */
    CK_ULONG    ulDerive;
    /* Mechanism captured by the last C_EncryptInit / C_DeriveKey call */
    CK_MECHANISM_TYPE lastEncryptMech;
    CK_MECHANISM_TYPE lastDecryptMech;
    CK_MECHANISM_TYPE lastDeriveMech;
    /* Set by C_GenerateKey (symmetric keys) only. */
    CK_MECHANISM_TYPE lastGenerateMech;
    /* Set by C_GenerateKeyPair (asymmetric keys) only. */
    CK_MECHANISM_TYPE lastGenerateKeyPairMech;
    CK_MECHANISM_TYPE lastSignMech;
    /* CK_RSA_PKCS_PSS_PARAMS captured by the last C_SignInit call. Valid
     * only when lastSignPssValid is non-zero. */
    CK_RSA_PKCS_PSS_PARAMS lastSignPss;
    int                    lastSignPssValid;
    /* ECDH peer public data captured from CK_ECDH1_DERIVE_PARAMS */
    CK_ULONG    lastEcdhPublicDataLen;
} P11_MOCK_CONFIG;

/* ── Call counters ───────────────────────────────────────────────────────── */
typedef struct _P11_MOCK_CALLS {
    int nInitialize;
    int nFinalize;
    int nGetSlotList;
    int nOpenSession;
    int nLogin;
    int nCloseSession;
    int nGenerateKeyPair;
    int nFindObjectsInit;
    int nFindObjects;
    int nFindObjectsFinal;
    int nGetAttributeValue;
    int nSignInit;
    int nSign;
    int nDecryptInit;
    int nDecrypt;
    int nDestroyObject;
    int nCreateObject;
    int nGenerateKey;
    int nDeriveKey;
    int nEncryptInit;
    int nEncrypt;
} P11_MOCK_CALLS;

/* Reset mock configuration (all CKR_OK, default behaviour) */
void P11Mock_Reset(void);

/* Return the mutable config */
P11_MOCK_CONFIG *P11Mock_GetConfig(void);

/* Return the call counters */
P11_MOCK_CALLS *P11Mock_GetCalls(void);

/* Return the PKCS#11 mock function list */
CK_FUNCTION_LIST *P11Mock_GetFunctionList(void);

#endif /* P11_MOCK_H */
