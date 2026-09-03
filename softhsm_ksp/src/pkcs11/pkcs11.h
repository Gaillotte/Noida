/* pkcs11.h — Standard PKCS#11 v2.40 header (OASIS)
 * Type definitions, constants, and function prototypes.
 * Source: OASIS PKCS#11 Cryptographic Token Interface Base Specification v2.40
 */
#ifndef PKCS11_H
#define PKCS11_H

#ifdef _WIN32
#  define CK_PTR *
#  define CK_DEFINE_FUNCTION(returnType, name) returnType __declspec(dllexport) name
#  define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#  define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (__cdecl CK_PTR name)
#  define CK_CALLBACK_FUNCTION(returnType, name) returnType (__cdecl CK_PTR name)
#  ifndef NULL_PTR
#    define NULL_PTR 0
#  endif
#  pragma pack(push, cryptoki, 1)
#endif

/* Basic types */
typedef unsigned char     CK_BYTE;
typedef CK_BYTE           CK_CHAR;
typedef CK_BYTE           CK_UTF8CHAR;
typedef CK_BYTE           CK_BBOOL;
typedef unsigned long int CK_ULONG;
typedef long int          CK_LONG;
typedef CK_ULONG          CK_FLAGS;

typedef CK_BYTE   CK_PTR CK_BYTE_PTR;
typedef CK_CHAR   CK_PTR CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR CK_UTF8CHAR_PTR;
typedef CK_ULONG  CK_PTR CK_ULONG_PTR;
typedef void      CK_PTR CK_VOID_PTR;
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;

#define CK_TRUE  1
#define CK_FALSE 0

/* Special values */
#define CK_UNAVAILABLE_INFORMATION  (~0UL)
#define CK_EFFECTIVELY_INFINITE     0UL

/* Handles */
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_STATE;
typedef CK_ULONG CK_USER_TYPE;
typedef CK_ULONG CK_NOTIFICATION;

typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;
typedef CK_OBJECT_HANDLE  CK_PTR CK_OBJECT_HANDLE_PTR;
typedef CK_SLOT_ID        CK_PTR CK_SLOT_ID_PTR;
typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;

#define CK_INVALID_HANDLE 0UL

/* Object classes */
#define CKO_DATA              0x00000000UL
#define CKO_CERTIFICATE       0x00000001UL
#define CKO_PUBLIC_KEY        0x00000002UL
#define CKO_PRIVATE_KEY       0x00000003UL
#define CKO_SECRET_KEY        0x00000004UL
#define CKO_HW_FEATURE        0x00000005UL
#define CKO_DOMAIN_PARAMETERS 0x00000006UL
#define CKO_MECHANISM         0x00000007UL

/* Key types */
#define CKK_RSA             0x00000000UL
#define CKK_DSA             0x00000001UL
#define CKK_DH              0x00000002UL
#define CKK_EC              0x00000003UL
#define CKK_GENERIC_SECRET  0x00000010UL
#define CKK_AES             0x0000001FUL
#define CKK_EC_EDWARDS      0x00000040UL

/* Attributs */
#define CKA_CLASS              0x00000000UL
#define CKA_TOKEN              0x00000001UL
#define CKA_PRIVATE            0x00000002UL
#define CKA_LABEL              0x00000003UL
#define CKA_APPLICATION        0x00000010UL
#define CKA_VALUE              0x00000011UL
#define CKA_OBJECT_ID          0x00000012UL
#define CKA_CERTIFICATE_TYPE   0x00000080UL
#define CKA_ISSUER             0x00000081UL
#define CKA_SERIAL_NUMBER      0x00000082UL
#define CKA_KEY_TYPE           0x00000100UL
#define CKA_SUBJECT            0x00000101UL
#define CKA_ID                 0x00000102UL
#define CKA_SENSITIVE          0x00000103UL
#define CKA_ENCRYPT            0x00000104UL
#define CKA_DECRYPT            0x00000105UL
#define CKA_WRAP               0x00000106UL
#define CKA_UNWRAP             0x00000107UL
#define CKA_SIGN               0x00000108UL
#define CKA_SIGN_RECOVER       0x00000109UL
#define CKA_VERIFY             0x0000010AUL
#define CKA_VERIFY_RECOVER     0x0000010BUL
#define CKA_DERIVE             0x0000010CUL
#define CKA_START_DATE         0x00000110UL
#define CKA_END_DATE           0x00000111UL
#define CKA_MODULUS            0x00000120UL
#define CKA_MODULUS_BITS       0x00000121UL
#define CKA_PUBLIC_EXPONENT    0x00000122UL
#define CKA_PRIVATE_EXPONENT   0x00000123UL
#define CKA_PRIME_1            0x00000124UL
#define CKA_PRIME_2            0x00000125UL
#define CKA_EXPONENT_1         0x00000126UL
#define CKA_EXPONENT_2         0x00000127UL
#define CKA_COEFFICIENT        0x00000128UL
#define CKA_VALUE_LEN          0x00000161UL
#define CKA_EC_PARAMS          0x00000180UL
#define CKA_EC_POINT           0x00000181UL
#define CKA_EXTRACTABLE        0x00000162UL
#define CKA_LOCAL              0x00000163UL
#define CKA_NEVER_EXTRACTABLE  0x00000164UL
#define CKA_ALWAYS_SENSITIVE   0x00000165UL
#define CKA_KEY_GEN_MECHANISM  0x00000166UL

/* Mechanisms */
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0x00000000UL
#define CKM_RSA_PKCS              0x00000001UL
#define CKM_RSA_9796              0x00000002UL
#define CKM_RSA_X_509             0x00000003UL
#define CKM_RSA_PKCS_OAEP         0x00000009UL
#define CKM_RSA_PKCS_PSS          0x0000000DUL
#define CKM_EC_KEY_PAIR_GEN       0x00001040UL
#define CKM_ECDSA                 0x00001041UL
#define CKM_ECDSA_SHA1            0x00001042UL
#define CKM_ECDSA_SHA256          0x00001043UL
#define CKM_ECDSA_SHA384          0x00001044UL
#define CKM_ECDSA_SHA512          0x00001045UL
#define CKM_SHA_1                 0x00000220UL
#define CKM_SHA256                0x00000250UL
#define CKM_SHA384                0x00000260UL
#define CKM_SHA512                0x00000270UL
#define CKM_SHA1_RSA_PKCS         0x00000006UL
#define CKM_SHA256_RSA_PKCS       0x00000040UL
#define CKM_SHA384_RSA_PKCS       0x00000041UL
#define CKM_SHA512_RSA_PKCS       0x00000042UL
#define CKM_SHA256_RSA_PKCS_PSS   0x00000043UL
#define CKM_SHA384_RSA_PKCS_PSS   0x00000044UL
#define CKM_SHA512_RSA_PKCS_PSS   0x00000045UL
#define CKM_SHA224                0x00000255UL

/* ECDH key agreement */
#define CKM_ECDH1_DERIVE          0x00001050UL

/* EdDSA (Edwards curves: Ed25519, Ed448) */
#define CKM_EC_EDWARDS_KEY_PAIR_GEN 0x00001055UL
#define CKM_EDDSA                 0x00001057UL

/* AES */
#define CKM_AES_KEY_GEN           0x00001080UL
#define CKM_AES_ECB               0x00001081UL
#define CKM_AES_CBC               0x00001082UL
#define CKM_AES_MAC               0x00001083UL
#define CKM_AES_CBC_PAD           0x00001085UL
#define CKM_AES_CTR               0x00001086UL
#define CKM_AES_GCM               0x00001087UL
#define CKM_AES_CMAC              0x0000108AUL
#define CKM_AES_KEY_WRAP          0x00002109UL
#define CKM_AES_KEY_WRAP_PAD      0x0000210AUL

/* HMAC */
#define CKM_SHA_1_HMAC            0x00000221UL
#define CKM_SHA224_HMAC           0x00000256UL
#define CKM_SHA256_HMAC           0x00000251UL
#define CKM_SHA384_HMAC           0x00000261UL
#define CKM_SHA512_HMAC           0x00000271UL

/* Generic secret */
#define CKM_GENERIC_SECRET_KEY_GEN 0x00000350UL

/* Return codes */
#define CKR_OK                          0x00000000UL
#define CKR_CANCEL                      0x00000001UL
#define CKR_HOST_MEMORY                 0x00000002UL
#define CKR_SLOT_ID_INVALID             0x00000003UL
#define CKR_GENERAL_ERROR               0x00000005UL
#define CKR_FUNCTION_FAILED             0x00000006UL
#define CKR_ARGUMENTS_BAD               0x00000007UL
#define CKR_NO_EVENT                    0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS      0x00000009UL
#define CKR_CANT_LOCK                   0x0000000AUL
#define CKR_ATTRIBUTE_READ_ONLY         0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE         0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID      0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID     0x00000013UL
#define CKR_DATA_INVALID                0x00000020UL
#define CKR_DATA_LEN_RANGE              0x00000021UL
#define CKR_DEVICE_ERROR                0x00000030UL
#define CKR_DEVICE_MEMORY               0x00000031UL
#define CKR_DEVICE_REMOVED              0x00000032UL
#define CKR_ENCRYPTED_DATA_INVALID      0x00000040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE    0x00000041UL
#define CKR_FUNCTION_CANCELED           0x00000050UL
#define CKR_FUNCTION_NOT_PARALLEL       0x00000051UL
#define CKR_FUNCTION_NOT_SUPPORTED      0x00000054UL
#define CKR_KEY_HANDLE_INVALID          0x00000060UL
#define CKR_KEY_SIZE_RANGE              0x00000062UL
#define CKR_KEY_TYPE_INCONSISTENT       0x00000063UL
#define CKR_KEY_NOT_NEEDED              0x00000064UL
#define CKR_KEY_CHANGED                 0x00000065UL
#define CKR_KEY_NEEDED                  0x00000066UL
#define CKR_KEY_INDIGESTIBLE            0x00000067UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED  0x00000068UL
#define CKR_KEY_NOT_WRAPPABLE           0x00000069UL
#define CKR_KEY_UNEXTRACTABLE           0x0000006AUL
#define CKR_MECHANISM_INVALID           0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID     0x00000071UL
#define CKR_OBJECT_HANDLE_INVALID       0x00000082UL
#define CKR_OPERATION_ACTIVE            0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED   0x00000091UL
#define CKR_PIN_INCORRECT               0x000000A0UL
#define CKR_PIN_INVALID                 0x000000A1UL
#define CKR_PIN_LEN_RANGE               0x000000A2UL
#define CKR_PIN_EXPIRED                 0x000000A3UL
#define CKR_PIN_LOCKED                  0x000000A4UL
#define CKR_SESSION_CLOSED              0x000000B0UL
#define CKR_SESSION_COUNT               0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID      0x000000B3UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED 0x000000B4UL
#define CKR_SESSION_READ_ONLY           0x000000B5UL
#define CKR_SESSION_EXISTS              0x000000B6UL
#define CKR_SESSION_READ_ONLY_EXISTS    0x000000B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS 0x000000B8UL
#define CKR_SIGNATURE_INVALID           0x000000C0UL
#define CKR_SIGNATURE_LEN_RANGE        0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE         0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT       0x000000D1UL
#define CKR_TOKEN_NOT_PRESENT           0x000000E0UL
#define CKR_TOKEN_NOT_RECOGNIZED        0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED       0x000000E2UL
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID 0x000000F0UL
#define CKR_UNWRAPPING_KEY_SIZE_RANGE   0x000000F1UL
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT 0x000000F2UL
#define CKR_USER_ALREADY_LOGGED_IN      0x00000100UL
#define CKR_USER_NOT_LOGGED_IN          0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED    0x00000102UL
#define CKR_USER_TYPE_INVALID           0x00000103UL
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN 0x00000104UL
#define CKR_USER_TOO_MANY_TYPES         0x00000105UL
#define CKR_WRAPPED_KEY_INVALID         0x00000110UL
#define CKR_WRAPPED_KEY_LEN_RANGE       0x00000112UL
#define CKR_WRAPPING_KEY_HANDLE_INVALID 0x00000113UL
#define CKR_WRAPPING_KEY_SIZE_RANGE     0x00000114UL
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT 0x00000115UL
#define CKR_RANDOM_SEED_NOT_SUPPORTED   0x00000120UL
#define CKR_RANDOM_NO_RNG               0x00000121UL
#define CKR_DOMAIN_PARAMS_INVALID       0x00000130UL
#define CKR_BUFFER_TOO_SMALL            0x00000150UL
#define CKR_SAVED_STATE_INVALID         0x00000160UL
#define CKR_INFORMATION_SENSITIVE       0x00000170UL
#define CKR_STATE_UNSAVEABLE            0x00000180UL
#define CKR_CRYPTOKI_NOT_INITIALIZED    0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191UL
#define CKR_MUTEX_BAD                   0x000001A0UL
#define CKR_MUTEX_NOT_LOCKED            0x000001A1UL
#define CKR_NEW_PIN_MODE                0x000001B0UL
#define CKR_NEXT_OTP                    0x000001B1UL
#define CKR_EXCEEDED_MAX_ITERATIONS     0x000001B5UL
#define CKR_FIPS_SELF_TEST_FAILED       0x000001B6UL
#define CKR_LIBRARY_LOAD_FAILED         0x000001B7UL
#define CKR_PIN_TOO_WEAK                0x000001B8UL
#define CKR_PUBLIC_KEY_INVALID          0x000001B9UL
#define CKR_FUNCTION_REJECTED           0x00000200UL
#define CKR_VENDOR_DEFINED              0x80000000UL

/* User types */
#define CKU_SO   0UL
#define CKU_USER 1UL

/* Initialisation flags */
#define CKF_TOKEN_PRESENT    0x00000001UL
#define CKF_REMOVABLE_DEVICE 0x00000002UL
#define CKF_HW_SLOT          0x00000004UL
#define CKF_OS_LOCKING_OK    0x00000002UL
#define CKF_RW_SESSION       0x00000002UL
#define CKF_SERIAL_SESSION   0x00000004UL

/* RSA MGF1 parameters */
#define CKG_MGF1_SHA1   0x00000001UL
#define CKG_MGF1_SHA256 0x00000002UL
#define CKG_MGF1_SHA384 0x00000003UL
#define CKG_MGF1_SHA512 0x00000004UL
#define CKG_MGF1_SHA224 0x00000005UL

#define CKZ_DATA_SPECIFIED 0x00000001UL

/* EC key derivation functions (CK_EC_KDF_TYPE) */
#define CKD_NULL        0x00000001UL
#define CKD_SHA1_KDF    0x00000002UL
#define CKD_SHA224_KDF  0x00000005UL
#define CKD_SHA256_KDF  0x00000006UL
#define CKD_SHA384_KDF  0x00000007UL
#define CKD_SHA512_KDF  0x00000008UL

/* Hash algorithms for PSS */
#define CKM_SHA_1_HMAC  0x00000221UL

/* Structures */
typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS   flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS    flags;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
} CK_SLOT_INFO;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR     serialNumber[16];
    CK_FLAGS    flags;
    CK_ULONG    ulMaxSessionCount;
    CK_ULONG    ulSessionCount;
    CK_ULONG    ulMaxRwSessionCount;
    CK_ULONG    ulRwSessionCount;
    CK_ULONG    ulMaxPinLen;
    CK_ULONG    ulMinPinLen;
    CK_ULONG    ulTotalPublicMemory;
    CK_ULONG    ulFreePublicMemory;
    CK_ULONG    ulTotalPrivateMemory;
    CK_ULONG    ulFreePrivateMemory;
    CK_VERSION  hardwareVersion;
    CK_VERSION  firmwareVersion;
    CK_CHAR     utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID  slotID;
    CK_STATE    state;
    CK_FLAGS    flags;
    CK_ULONG    ulDeviceError;
} CK_SESSION_INFO;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR       pValue;
    CK_ULONG          ulValueLen;
} CK_ATTRIBUTE;
typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR       pParameter;
    CK_ULONG          ulParameterLen;
} CK_MECHANISM;
typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;

/* RSA PSS parameters */
typedef struct CK_RSA_PKCS_PSS_PARAMS {
    CK_MECHANISM_TYPE hashAlg;
    CK_ULONG          mgf;
    CK_ULONG          sLen;
} CK_RSA_PKCS_PSS_PARAMS;
typedef CK_RSA_PKCS_PSS_PARAMS CK_PTR CK_RSA_PKCS_PSS_PARAMS_PTR;

/* RSA OAEP parameters */
typedef struct CK_RSA_PKCS_OAEP_PARAMS {
    CK_MECHANISM_TYPE hashAlg;
    CK_ULONG          mgf;
    CK_ULONG          source;
    CK_VOID_PTR       pSourceData;
    CK_ULONG          ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;
typedef CK_RSA_PKCS_OAEP_PARAMS CK_PTR CK_RSA_PKCS_OAEP_PARAMS_PTR;

/* ECDH1 key derivation parameters (CKM_ECDH1_DERIVE) */
typedef CK_ULONG CK_EC_KDF_TYPE;
typedef struct CK_ECDH1_DERIVE_PARAMS {
    CK_EC_KDF_TYPE kdf;              /* CKD_NULL, CKD_SHA256_KDF, ... */
    CK_ULONG       ulSharedDataLen;  /* Optional shared data length   */
    CK_BYTE_PTR    pSharedData;      /* Optional shared data          */
    CK_ULONG       ulPublicDataLen;  /* Peer public key length        */
    CK_BYTE_PTR    pPublicData;      /* Peer public key (04||X||Y)    */
} CK_ECDH1_DERIVE_PARAMS;
typedef CK_ECDH1_DERIVE_PARAMS CK_PTR CK_ECDH1_DERIVE_PARAMS_PTR;

/* AES-GCM parameters (CKM_AES_GCM) */
typedef struct CK_GCM_PARAMS {
    CK_BYTE_PTR pIv;
    CK_ULONG    ulIvLen;
    CK_ULONG    ulIvBits;
    CK_BYTE_PTR pAAD;
    CK_ULONG    ulAADLen;
    CK_ULONG    ulTagBits;
} CK_GCM_PARAMS;
typedef CK_GCM_PARAMS CK_PTR CK_GCM_PARAMS_PTR;

/* AES-CTR parameters (CKM_AES_CTR) */
typedef struct CK_AES_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE  cb[16];
} CK_AES_CTR_PARAMS;
typedef CK_AES_CTR_PARAMS CK_PTR CK_AES_CTR_PARAMS_PTR;

/* Cryptoki initialisation parameters */
typedef CK_VOID_PTR CK_CREATEMUTEX;
typedef CK_VOID_PTR CK_DESTROYMUTEX;
typedef CK_VOID_PTR CK_LOCKMUTEX;
typedef CK_VOID_PTR CK_UNLOCKMUTEX;

typedef struct CK_C_INITIALIZE_ARGS {
    CK_CREATEMUTEX  CreateMutex;
    CK_DESTROYMUTEX DestroyMutex;
    CK_LOCKMUTEX    LockMutex;
    CK_UNLOCKMUTEX  UnlockMutex;
    CK_FLAGS        flags;
    CK_VOID_PTR     pReserved;
} CK_C_INITIALIZE_ARGS;

/* Cryptoki function table */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

struct CK_FUNCTION_LIST {
    CK_VERSION version;

    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Finalize)(CK_VOID_PTR pReserved);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetInfo)(CK_INFO CK_PTR pInfo);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR CK_PTR ppFunctionList);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO CK_PTR pInfo);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO CK_PTR pInfo);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO CK_PTR pInfo);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_VOID_PTR Notify, CK_SESSION_HANDLE_PTR phSession);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO CK_PTR pInfo);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pCiphertext, CK_ULONG ulCiphertextLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession);
    CK_DECLARE_FUNCTION_POINTER(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);
};

/* Prototype of the main entry point */
CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR CK_PTR ppFunctionList);

typedef CK_RV (CK_PTR CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

#ifdef _WIN32
#  pragma pack(pop, cryptoki)
#endif

#endif /* PKCS11_H */
