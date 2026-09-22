/* p11_mock.h — Controllable PKCS#11 mock for unit tests
 * Simulates SoftHSM2 with error injection and call verification.
 */
#ifndef P11_MOCK_H
#define P11_MOCK_H

#include "windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"

/* Room for a mechanism list larger than P11_MAX_MECHANISMS would allow, so
 * a test can present a token that overflows the provider's own bound. */
#define P11_MOCK_MAX_MECHS  600

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
    CK_RV rv_GetInfo;
    CK_RV rv_GetMechanismList;
    CK_RV rv_GetMechanismInfo;

    /* What the token claims to implement, for the capability probe.
     * P11Mock_SetMechanisms fills these; the default is the SoftHSM2 2.7.0
     * subset this provider maps, with no post-quantum mechanism. */
    CK_MECHANISM_TYPE mechList[P11_MOCK_MAX_MECHS];
    CK_ULONG          nMechs;
    /* Flags reported for every mechanism in the list. */
    CK_FLAGS          mechFlags;
    /* Cryptoki version reported by C_GetInfo. Default 2.40. */
    CK_BYTE           ckMajor;
    CK_BYTE           ckMinor;

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
    /* Session state reported by C_GetSessionInfo, and its return value.
     * Used to simulate a token that logged out under the provider. */
    /* CKA_LABEL of the last object created or generated, as a NUL
     * terminated UTF-8 string. Lets a test assert the scope prefix. */
    char       lastLabel[128];

    /* Digest chain: every byte passed to C_DigestUpdate is accumulated
     * here so a KDF test can assert exactly what was hashed and in what
     * order. C_DigestFinal returns the first cbDigestOut bytes of it. */
    unsigned char digestFed[512];
    CK_ULONG      cbDigestFed;
    CK_ULONG      cbDigestOut;
    CK_MECHANISM_TYPE lastDigestMech;

    /* Bytes handed to the last C_Sign, so an HKDF test can verify the
     * T(i-1) || info || counter block the KSP assembled. */
    unsigned char lastSignData[512];
    CK_ULONG      cbLastSignData;
    /* CKA_VALUE of the last object created — the HMAC key in each HKDF
     * step, so the salt and PRK can be checked. */
    unsigned char lastCreateValue[128];
    CK_ULONG      cbLastCreateValue;

    CK_ULONG   sessionState;
    CK_RV      rv_GetSessionInfo;

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
    int nGetSessionInfo;
    int nDigestInit;
    int nDigestUpdate;
    int nDigestFinal;
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
    int nGetInfo;
    int nGetMechanismList;
    int nGetMechanismInfo;
} P11_MOCK_CALLS;

/* Reset mock configuration (all CKR_OK, default behaviour) */
void P11Mock_Reset(void);

/* Zero the call counters and the captured buffers, leaving the configured
 * behaviour alone. A full reset would also clear pbSecretValue, cbSignature
 * and the rest, which a test in the middle of a scenario still needs. */
void P11Mock_ResetCalls(void);

/* Return the mutable config */
P11_MOCK_CONFIG *P11Mock_GetConfig(void);

/* Return the call counters */
P11_MOCK_CALLS *P11Mock_GetCalls(void);

/* Return the PKCS#11 mock function list */
CK_FUNCTION_LIST *P11Mock_GetFunctionList(void);

/* Replace the advertised mechanism list.
 *
 * Passing NULL/0 makes the token advertise nothing, which is how a test
 * checks that the provider stops claiming algorithms it cannot deliver. */
void P11Mock_SetMechanisms(const CK_MECHANISM_TYPE *pMechs, CK_ULONG nMechs);

/* Set the Cryptoki version reported by C_GetInfo. */
void P11Mock_SetCryptokiVersion(CK_BYTE bMajor, CK_BYTE bMinor);

#endif /* P11_MOCK_H */
