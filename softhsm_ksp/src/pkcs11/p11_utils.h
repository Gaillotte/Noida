/* p11_utils.h — Utilitaires PKCS#11 : mécanismes, attributs, conversion d'erreurs */
#ifndef P11_UTILS_H
#define P11_UTILS_H

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include "pkcs11.h"

/* Convertit un code CK_RV en SECURITY_STATUS */
SECURITY_STATUS P11RvToSecStatus(CK_RV rv);

/* Résout le mécanisme PKCS#11 à partir de l'algorithme CNG et des flags */
SECURITY_STATUS P11_ResolveMechanism(
    LPCWSTR          pszAlgId,
    DWORD            dwFlags,
    CK_MECHANISM    *pMechanism,
    CK_RSA_PKCS_PSS_PARAMS *pPssParams);

/* Recherche un objet par son label (CKA_LABEL) et sa classe (CKO_*)
 * Retourne CK_INVALID_HANDLE si non trouvé */
CK_OBJECT_HANDLE P11_FindObjectByLabel(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_CLASS   ulClass,
    LPCWSTR           pszLabel);

/* Lit la valeur d'un attribut CK_ULONG */
CK_RV P11_GetUlongAttr(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE  hObject,
    CK_ATTRIBUTE_TYPE attrType,
    CK_ULONG         *pulValue);

/* Lit la valeur d'un attribut binaire (alloue avec KSP_Alloc) */
CK_RV P11_GetBinaryAttr(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hObject,
    CK_ATTRIBUTE_TYPE  attrType,
    BYTE             **ppData,
    DWORD             *pcbData);

/* Convertit une clé publique RSA PKCS#11 en BCRYPT_RSAKEY_BLOB */
SECURITY_STATUS P11_ExportRsaPublicKey(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hPubKey,
    BYTE             **ppBlob,
    DWORD             *pcbBlob);

/* Convertit une clé publique EC PKCS#11 en BCRYPT_ECCKEY_BLOB */
SECURITY_STATUS P11_ExportEcPublicKey(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hPubKey,
    BYTE             **ppBlob,
    DWORD             *pcbBlob);

/* Décode une signature ECDSA DER (SEQUENCE { INTEGER r, INTEGER s })
 * en format Windows (r||s, taille fixe selon la courbe).
 * pszAlgId : L"ECDSA_P256" ou L"ECDSA_P384" */
SECURITY_STATUS P11_DecodeDerEcdsaSignature(
    LPCWSTR  pszAlgId,
    BYTE    *pbDer,
    DWORD    cbDer,
    BYTE    *pbOut,
    DWORD   *pcbOut);

/* Retourne la taille en octets des coordonnées EC selon l'algorithme */
DWORD P11_EcCoordSize(LPCWSTR pszAlgId);

#endif /* P11_UTILS_H */
