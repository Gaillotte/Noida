/* p11_mock.h — Mock PKCS#11 controllable pour les tests
 * Simule SoftHSM2 avec injection d'erreurs et vérification des appels.
 */
#ifndef P11_MOCK_H
#define P11_MOCK_H

#include "windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"

/* ── Configuration du mock ──────────────────────────────────────────────── */

/* Erreurs injectables */
typedef struct _P11_MOCK_CONFIG {
    CK_RV rv_Initialize;        /* CKR_OK = normal */
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

    /* Nombre de slots simulés */
    int nSlots;
    /* Nombre de clés simulées pour FindObjects */
    int nKeyObjects;
    /* Label des clés simulées */
    char szKeyLabel[256];
    /* Type de clé retourné (CKK_RSA ou CKK_EC) */
    CK_ULONG ulKeyType;
    /* Nombre de bits (RSA) */
    CK_ULONG ulModBits;
    /* Taille de signature retournée */
    CK_ULONG cbSignature;
    /* Données de signature (fill avec 0xAB si NULL) */
    CK_BYTE *pbSignature;
    /* CKA_EC_PARAMS à retourner */
    const char *pbEcParams;
    CK_ULONG   cbEcParams;
    /* CKA_EC_POINT à retourner */
    const char *pbEcPoint;
    CK_ULONG   cbEcPoint;
    /* Modules RSA à retourner */
    const BYTE *pbModulus;
    CK_ULONG   cbModulus;
    const BYTE *pbExponent;
    CK_ULONG   cbExponent;
} P11_MOCK_CONFIG;

/* ── Compteurs d'appels ──────────────────────────────────────────────────── */
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
} P11_MOCK_CALLS;

/* Réinitialise la configuration du mock (tout à CKR_OK, comportement par défaut) */
void P11Mock_Reset(void);

/* Retourne la config modifiable */
P11_MOCK_CONFIG *P11Mock_GetConfig(void);

/* Retourne les compteurs d'appels */
P11_MOCK_CALLS *P11Mock_GetCalls(void);

/* Retourne la liste des fonctions mock PKCS#11 */
CK_FUNCTION_LIST *P11Mock_GetFunctionList(void);

#endif /* P11_MOCK_H */
