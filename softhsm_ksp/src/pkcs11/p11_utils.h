/* p11_utils.h — PKCS#11 utilities: mechanisms, attributes, error conversion */
#ifndef P11_UTILS_H
#define P11_UTILS_H

#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include "pkcs11.h"

/* Convert a CK_RV code to SECURITY_STATUS */
SECURITY_STATUS P11RvToSecStatus(CK_RV rv);

/* Resolve the PKCS#11 mechanism from the CNG algorithm and flags */
SECURITY_STATUS P11_ResolveMechanism(
    LPCWSTR          pszAlgId,
    DWORD            dwFlags,
    CK_MECHANISM    *pMechanism,
    CK_RSA_PKCS_PSS_PARAMS *pPssParams);

/* Search for an object by its label (CKA_LABEL) and class (CKO_*)
 * Returns CK_INVALID_HANDLE if not found */
CK_OBJECT_HANDLE P11_FindObjectByLabel(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_CLASS   ulClass,
    LPCWSTR           pszLabel);

/* Read the value of a CK_ULONG attribute */
CK_RV P11_GetUlongAttr(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE  hObject,
    CK_ATTRIBUTE_TYPE attrType,
    CK_ULONG         *pulValue);

/* Read the value of a binary attribute (allocates with KSP_Alloc) */
CK_RV P11_GetBinaryAttr(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hObject,
    CK_ATTRIBUTE_TYPE  attrType,
    BYTE             **ppData,
    DWORD             *pcbData);

/* Export a PKCS#11 RSA public key as a BCRYPT_RSAKEY_BLOB */
SECURITY_STATUS P11_ExportRsaPublicKey(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hPubKey,
    BYTE             **ppBlob,
    DWORD             *pcbBlob);

/* Export a PKCS#11 EC public key as a BCRYPT_ECCKEY_BLOB */
SECURITY_STATUS P11_ExportEcPublicKey(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hPubKey,
    BYTE             **ppBlob,
    DWORD             *pcbBlob);

/* Export a PKCS#11 Edwards-curve public key as a BCRYPT_ECCKEY_BLOB.
 * EdDSA public keys are a single raw point (no X/Y split). */
SECURITY_STATUS P11_ExportEddsaPublicKey(
    CK_SESSION_HANDLE  hSession,
    CK_OBJECT_HANDLE   hPubKey,
    LPCWSTR            pszAlgId,
    BYTE             **ppBlob,
    DWORD             *pcbBlob);

/* Decode a DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
 * into Windows format (r||s, fixed size based on the curve).
 * pszAlgId: L"ECDSA_P256", L"ECDSA_P384" or L"ECDSA_P521" */
SECURITY_STATUS P11_DecodeDerEcdsaSignature(
    LPCWSTR  pszAlgId,
    BYTE    *pbDer,
    DWORD    cbDer,
    BYTE    *pbOut,
    DWORD   *pcbOut);

/* Return the EC coordinate size in bytes for the given algorithm */
DWORD P11_EcCoordSize(LPCWSTR pszAlgId);

/* Return the DER-encoded curve OID for an EC / EdDSA algorithm.
 * Returns NULL and leaves *pcbOid untouched for non-curve algorithms. */
const char *P11_GetCurveOid(LPCWSTR pszAlgId, CK_ULONG *pcbOid);

/* Map a CNG hash algorithm name (BCRYPT_*_ALGORITHM) to the matching
 * PKCS#11 digest mechanism and MGF1 identifier.
 * Returns NTE_NOT_SUPPORTED for an unrecognised hash. */
SECURITY_STATUS P11_MapHashAlg(
    LPCWSTR            pszHashAlg,
    CK_MECHANISM_TYPE *pHashMech,
    CK_ULONG          *pMgf);

/* Populate CK_RSA_PKCS_OAEP_PARAMS from BCRYPT_OAEP_PADDING_INFO.
 * Supports SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512. */
SECURITY_STATUS P11_BuildOaepParams(
    BCRYPT_OAEP_PADDING_INFO *pOaepInfo,
    CK_RSA_PKCS_OAEP_PARAMS  *pParams);

/* Build a PKCS#11 CKA_EC_POINT value (DER OCTET STRING wrapping
 * 0x04 || X || Y) from the X/Y coordinates of a BCRYPT_ECCKEY_BLOB.
 * The caller frees *ppDer with KSP_Free. */
SECURITY_STATUS P11_BuildEcPointDer(
    const BYTE *pbX,
    const BYTE *pbY,
    DWORD       cbCoord,
    BYTE      **ppDer,
    DWORD      *pcbDer);

#endif /* P11_UTILS_H */
