/* windows_compat.h — Stubs for Windows types and APIs for Linux compilation
 * Allows compiling and testing pure functions (without hardware dependencies)
 * on Linux with gcc + gcov.
 */
#ifndef WINDOWS_COMPAT_H
#define WINDOWS_COMPAT_H

#ifdef _WIN32
#  error "This header is exclusively for Linux/gcov compilation"
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <semaphore.h>

/* ── PKCS#11 platform macros (replace the _WIN32 section of pkcs11.h) */
#ifndef CK_PTR
#  define CK_PTR *
#  define CK_DEFINE_FUNCTION(returnType, name)         returnType name
#  define CK_DECLARE_FUNCTION(returnType, name)        returnType name
#  define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#  define CK_CALLBACK_FUNCTION(returnType, name)       returnType (* name)
#endif

/* ── Basic Windows types ────────────────────────────────────────────────── */
typedef unsigned char      BYTE;
typedef unsigned char      BOOL;
typedef unsigned short     WORD;
typedef unsigned int       DWORD;
typedef unsigned long long QWORD;
typedef long               LONG;
typedef unsigned long long ULONG_PTR;
typedef unsigned int       UINT;
typedef size_t             SIZE_T;
typedef void              *HANDLE;
typedef void               VOID;
typedef void              *PVOID;
typedef void              *LPVOID;
typedef char              *LPSTR;
typedef const char        *LPCSTR;
typedef wchar_t            WCHAR;
typedef wchar_t           *LPWSTR;
typedef const wchar_t     *LPCWSTR;
typedef unsigned char     *PBYTE;

#define TRUE  1
#define FALSE 0
#define NULL_PTR 0

/* ── SECURITY_STATUS ─────────────────────────────────────────────────────── */
typedef long SECURITY_STATUS;

#define ERROR_SUCCESS             0x00000000L
#define NTE_BAD_UID               0x80090001L
#define NTE_BAD_HASH              0x80090002L
#define NTE_BAD_KEY               0x80090003L
#define NTE_BAD_LEN               0x80090004L
#define NTE_BAD_DATA              0x80090005L
#define NTE_BAD_SIGNATURE         0x80090006L
#define NTE_BAD_VER               0x80090007L
#define NTE_BAD_ALGID             0x80090008L
#define NTE_FAIL                  0x80090020L
#define NTE_BAD_FLAGS             0x80090009L
#define NTE_BAD_TYPE              0x8009000AL
#define NTE_BAD_KEY_STATE         0x8009000BL
#define NTE_BAD_HASH_STATE        0x8009000CL
#define NTE_NO_KEY                0x8009000DL
#define NTE_NO_MEMORY             0x8009000EL
#define NTE_EXISTS                0x8009000FL
#define NTE_PERM                  0x80090010L
#define NTE_NOT_FOUND             0x80090011L
#define NTE_DOUBLE_ENCRYPT        0x80090012L
#define NTE_BAD_PROVIDER          0x80090013L
#define NTE_BAD_PROV_TYPE         0x80090014L
#define NTE_BAD_PUBLIC_KEY        0x80090015L
#define NTE_BAD_KEYSET            0x80090016L
#define NTE_PROV_TYPE_NOT_DEF     0x80090017L
#define NTE_PROV_TYPE_ENTRY_BAD   0x80090018L
#define NTE_KEYSET_NOT_DEF        0x80090019L
#define NTE_KEYSET_ENTRY_BAD      0x8009001AL
#define NTE_PROV_TYPE_NO_MATCH    0x8009001BL
#define NTE_SIGNATURE_FILE_BAD    0x8009001CL
#define NTE_PROVIDER_DLL_FAIL     0x8009001DL
#define NTE_BAD_KEYSET_PARAM      0x8009001EL
#define NTE_BAD_KEYSET_ACCESS     0x8009001FL
#define NTE_NOT_SUPPORTED         0x80090029L
#define NTE_NO_MORE_ITEMS         0x8009002AL
#define NTE_BUFFER_TOO_SMALL      0x80090028L
#define NTE_INVALID_PARAMETER     0x80090027L
#define NTE_INVALID_HANDLE        0x80090026L
#define NTE_KEY_DOES_NOT_EXIST    0x80090026L

/* ── NCrypt flags ────────────────────────────────────────────────────────── */
#define NCRYPT_NO_PADDING_FLAG    0x00000001
#define NCRYPT_PAD_PKCS1_FLAG     0x00000002
#define NCRYPT_PAD_PSS_FLAG       0x00000008
#define NCRYPT_PAD_OAEP_FLAG      0x00000004
#define NCRYPT_PAD_CIPHER_FLAG    0x00000010

/* Symmetric cipher key properties */
#define NCRYPT_CHAINING_MODE_PROPERTY   L"Chaining Mode"
#define NCRYPT_INITIALIZATION_VECTOR    L"IV"
#define NCRYPT_AUTH_TAG_LENGTH          L"AuthTagLength"
#define NCRYPT_PERSIST_ONLY_FLAG  0x40000000

#define NCRYPT_ALLOW_SIGNING_FLAG       0x00000002
#define NCRYPT_ALLOW_DECRYPT_FLAG       0x00000001
#define NCRYPT_ALLOW_KEY_AGREEMENT_FLAG 0x00000004
#define NCRYPT_BLOCK_LENGTH_PROPERTY    L"Block Length"
#define NCRYPT_IMPL_HARDWARE_FLAG  0x00000002

/* AT_KEYEXCHANGE / AT_SIGNATURE */
#define AT_KEYEXCHANGE 1
#define AT_SIGNATURE   2

/* ── MAX_PATH ───────────────────────────────────────────────────────────── */
#define MAX_PATH 260

/* ── Wide string functions ──────────────────────────────────────────────── */
#ifndef _wcsicmp
#  define _wcsicmp wcscasecmp
#endif

static inline int wcscpy_s(wchar_t *dst, size_t n, const wchar_t *src) {
    if (!dst || n == 0) return 1;
    wcsncpy(dst, src, n - 1);
    dst[n - 1] = L'\0';
    return 0;
}

static inline int swprintf_s(wchar_t *buf, size_t n, const wchar_t *fmt, ...) {
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vswprintf(buf, n, fmt, ap);
    va_end(ap);
    return ret;
}

/* ── Heap (→ malloc/free) ────────────────────────────────────────────────── */
#define HEAP_ZERO_MEMORY 0x00000008

static inline void *HeapAlloc(void *heap, DWORD flags, SIZE_T n) {
    (void)heap;
    void *p = malloc(n);
    if (p && (flags & HEAP_ZERO_MEMORY)) memset(p, 0, n);
    return p;
}
static inline int HeapFree(void *heap, DWORD flags, void *p) {
    (void)heap; (void)flags;
    free(p);
    return 1;
}
static inline void *GetProcessHeap(void) { return (void*)1; }

/* ── SecureZeroMemory ────────────────────────────────────────────────────── */
static inline void SecureZeroMemory(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) *vp++ = 0;
}

/* ── OutputDebugString ───────────────────────────────────────────────────── */
static inline void OutputDebugStringA(const char *s) { (void)s; /* no-op */ }

/* ── GetEnvironmentVariable ──────────────────────────────────────────────── */
static inline DWORD GetEnvironmentVariableA(const char *name, char *buf, DWORD n) {
    const char *val = getenv(name);
    if (!val) return 0;
    size_t len = strlen(val);
    if (buf && n > len) { memcpy(buf, val, len + 1); return (DWORD)len; }
    return (DWORD)(len + 1);
}

/* ── MultiByteToWideChar / WideCharToMultiByte (simplified) ──────────────── */
#define CP_UTF8 65001
#define CP_ACP  0

static inline int MultiByteToWideChar(DWORD cp, DWORD flags,
    const char *src, int srcLen, wchar_t *dst, int dstLen) {
    (void)cp; (void)flags;
    if (srcLen == -1) srcLen = (int)strlen(src) + 1;
    int n = mbstowcs(dst, src, dstLen > 0 ? (size_t)dstLen : 0);
    return (n < 0) ? 0 : n;
}

static inline int WideCharToMultiByte(DWORD cp, DWORD flags,
    const wchar_t *src, int srcLen, char *dst, int dstLen,
    const char *def, int *used) {
    (void)cp; (void)flags; (void)def; (void)used;
    if (srcLen == -1) srcLen = (int)wcslen(src) + 1;
    size_t n = wcstombs(dst, src, dstLen > 0 ? (size_t)dstLen : 0);
    return (n == (size_t)-1) ? 0 : (int)n;
}

/* ── CRITICAL_SECTION (→ pthread_mutex_t) ────────────────────────────────── */
typedef pthread_mutex_t CRITICAL_SECTION;
static inline void InitializeCriticalSection(CRITICAL_SECTION *cs) {
    pthread_mutex_init(cs, NULL);
}
static inline void DeleteCriticalSection(CRITICAL_SECTION *cs) {
    pthread_mutex_destroy(cs);
}
static inline void EnterCriticalSection(CRITICAL_SECTION *cs) {
    pthread_mutex_lock(cs);
}
static inline void LeaveCriticalSection(CRITICAL_SECTION *cs) {
    pthread_mutex_unlock(cs);
}

/* ── Windows Semaphore (→ sem_t) ─────────────────────────────────────────── */
typedef sem_t* HSEMAPHORE;

static inline sem_t *CreateSemaphoreW(void *attr, long init, long max, void *name) {
    (void)attr; (void)max; (void)name;
    sem_t *s = (sem_t*)malloc(sizeof(sem_t));
    if (s) sem_init(s, 0, (unsigned)init);
    return s;
}
static inline int CloseHandle(sem_t *s) { sem_destroy(s); free(s); return 1; }

#define WAIT_OBJECT_0 0
#define INFINITE      0xFFFFFFFF

static inline DWORD WaitForSingleObject(sem_t *s, DWORD ms) {
    (void)ms;
    sem_wait(s);
    return WAIT_OBJECT_0;
}
static inline int ReleaseSemaphore(sem_t *s, long n, long *prev) {
    (void)prev;
    while (n-- > 0) sem_post(s);
    return 1;
}

/* ── INIT_ONCE (→ pthread_once_t) ────────────────────────────────────────── */
typedef pthread_once_t INIT_ONCE;
#define INIT_ONCE_STATIC_INIT PTHREAD_ONCE_INIT
typedef int (*PINIT_ONCE_FN)(INIT_ONCE*, void*, void**);

/* Simulated simply with pthread_once */
typedef struct { pthread_once_t once; PINIT_ONCE_FN fn; } _INIT_ONCE_CTX;
static _INIT_ONCE_CTX _g_once_ctx;
static void _once_runner(void) { _g_once_ctx.fn(NULL, NULL, NULL); }

static inline int InitOnceExecuteOnce(INIT_ONCE *o, PINIT_ONCE_FN fn,
                                      void *param, void **ctx) {
    (void)param; (void)ctx;
    _g_once_ctx.fn = fn;
    return pthread_once(o, _once_runner) == 0;
}

/* ── HMODULE (mock) ─────────────────────────────────────────────────────── */
typedef void* HMODULE;
typedef void* HINSTANCE;
static inline HMODULE LoadLibraryW(const wchar_t *path) { (void)path; return NULL; }
static inline void *GetProcAddress(HMODULE m, const char *n) { (void)m; (void)n; return NULL; }
static inline int FreeLibrary(HMODULE m) { (void)m; return 1; }
static inline DWORD GetLastError(void) { return 0; }
static inline int DisableThreadLibraryCalls(HINSTANCE h) { (void)h; return 1; }

/* ── UNREFERENCED_PARAMETER ─────────────────────────────────────────────── */
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define WINAPI
#define __cdecl

/* ── snprintf_s stubs ────────────────────────────────────────────────────── */
#define _TRUNCATE ((size_t)-1)
#define _vsnprintf_s(buf, sz, trunc, fmt, ap) vsnprintf(buf, sz, fmt, ap)
#define strncat_s(dst, dsz, src, cnt) strncat(dst, src, cnt)
#define strcpy_s(dst, n, src) strncpy(dst, src, n)

/* ── BCRYPT structures ───────────────────────────────────────────────────── */
typedef struct _BCRYPT_RSAKEY_BLOB {
    DWORD Magic;
    DWORD BitLength;
    DWORD cbPublicExp;
    DWORD cbModulus;
    DWORD cbPrime1;
    DWORD cbPrime2;
} BCRYPT_RSAKEY_BLOB;

typedef struct _BCRYPT_ECCKEY_BLOB {
    DWORD dwMagic;
    DWORD cbKey;
} BCRYPT_ECCKEY_BLOB;

/* Symmetric key blob (AES / HMAC raw key material) */
typedef struct _BCRYPT_KEY_DATA_BLOB_HEADER {
    DWORD dwMagic;
    DWORD dwVersion;
    DWORD cbKeyData;
} BCRYPT_KEY_DATA_BLOB_HEADER;

#define BCRYPT_RSAPUBLIC_MAGIC      0x31415352UL
#define BCRYPT_RSAPRIVATE_MAGIC     0x32415352UL
#define BCRYPT_RSAFULLPRIVATE_MAGIC 0x33415352UL
#define BCRYPT_ECDSA_PUBLIC_P256_MAGIC 0x31534345UL
#define BCRYPT_ECDSA_PUBLIC_P384_MAGIC 0x33534345UL
#define BCRYPT_ECDSA_PUBLIC_P521_MAGIC 0x35534345UL
#define BCRYPT_ECDSA_PRIVATE_P256_MAGIC 0x32534345UL
#define BCRYPT_ECDSA_PRIVATE_P384_MAGIC 0x34534345UL
#define BCRYPT_ECDSA_PRIVATE_P521_MAGIC 0x36534345UL
#define BCRYPT_ECDH_PUBLIC_P256_MAGIC  0x314B4345UL
#define BCRYPT_ECDH_PUBLIC_P384_MAGIC  0x334B4345UL
#define BCRYPT_ECDH_PUBLIC_P521_MAGIC  0x354B4345UL
/* Generic ECC magic used for Edwards curves (Windows 10 1903+) */
#define BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC 0x50444345UL
#define BCRYPT_KEY_DATA_BLOB_MAGIC   0x4D42444BUL
#define BCRYPT_KEY_DATA_BLOB_VERSION1 0x00000001UL

#define BCRYPT_RSAPUBLIC_BLOB       L"RSAPUBLICBLOB"
#define BCRYPT_RSAPRIVATE_BLOB      L"RSAPRIVATEBLOB"
#define BCRYPT_RSAFULLPRIVATE_BLOB  L"RSAFULLPRIVATEBLOB"
#define BCRYPT_ECCPUBLIC_BLOB       L"ECCPUBLICBLOB"
#define BCRYPT_ECCPRIVATE_BLOB      L"ECCPRIVATEBLOB"
#define BCRYPT_KEY_DATA_BLOB        L"KeyDataBlob"

#define BCRYPT_SHA1_ALGORITHM    L"SHA1"
#define BCRYPT_SHA224_ALGORITHM  L"SHA224"
#define BCRYPT_SHA256_ALGORITHM  L"SHA256"
#define BCRYPT_SHA384_ALGORITHM  L"SHA384"
#define BCRYPT_SHA512_ALGORITHM  L"SHA512"

/* Block cipher chaining modes */
#define BCRYPT_CHAIN_MODE_ECB    L"ChainingModeECB"
#define BCRYPT_CHAIN_MODE_CBC    L"ChainingModeCBC"
#define BCRYPT_CHAIN_MODE_GCM    L"ChainingModeGCM"
#define BCRYPT_CHAIN_MODE_CCM    L"ChainingModeCCM"
#define BCRYPT_CHAIN_MODE_CFB    L"ChainingModeCFB"

/* Key derivation function identifiers */
#define BCRYPT_KDF_RAW_SECRET    L"TRUNCATE"
#define BCRYPT_KDF_HASH          L"HASH"
#define BCRYPT_KDF_HMAC          L"HMAC"

typedef struct { LPCWSTR pszAlgId; DWORD cbSalt; } BCRYPT_PSS_PADDING_INFO;
typedef struct { LPCWSTR pszAlgId; PBYTE pbLabel; DWORD cbLabel; } BCRYPT_OAEP_PADDING_INFO;

/* ── NCrypt types ────────────────────────────────────────────────────────── */
typedef ULONG_PTR NCRYPT_PROV_HANDLE;
typedef ULONG_PTR NCRYPT_KEY_HANDLE;
typedef ULONG_PTR NCRYPT_SECRET_HANDLE;

#define NCRYPT_NAME_PROPERTY            L"Name"
#define NCRYPT_VERSION_PROPERTY         L"Version"
#define NCRYPT_IMPL_TYPE_PROPERTY       L"Impl Type"
#define NCRYPT_ALGORITHM_PROPERTY       L"Algorithm Name"
#define NCRYPT_LENGTH_PROPERTY          L"KeyLength"
#define NCRYPT_KEY_TYPE_PROPERTY        L"Key Type"
#define NCRYPT_UNIQUE_NAME_PROPERTY     L"Unique Name"
#define NCRYPT_EXPORT_POLICY_PROPERTY   L"Export Policy"
#define NCRYPT_KEY_USAGE_PROPERTY       L"Key Usage"
#define NCRYPT_ALGORITHM_GROUP_PROPERTY L"Algorithm Group"

#define NCRYPT_RSA_ALGORITHM_GROUP   L"RSA"
#define NCRYPT_ECDSA_ALGORITHM_GROUP L"ECDSA"

typedef struct _NCryptKeyName {
    LPWSTR pszName;
    LPWSTR pszAlgid;
    DWORD  dwLegacyKeySpec;
    DWORD  dwFlags;
} NCryptKeyName;

typedef struct _NCryptBufferDesc { DWORD ulVersion; DWORD cBuffers; void *pBuffers; }
    NCryptBufferDesc;

/* ── NCRYPT_KEY_STORAGE_FUNCTION_TABLE ───────────────────────────────────── */
#define NCRYPT_KEY_STORAGE_INTERFACE_VERSION 1

typedef struct _NCRYPT_KEY_STORAGE_FUNCTION_TABLE {
    DWORD  dwVersion;
    void  *OpenProvider;
    void  *OpenKey;
    void  *CreatePersistedKey;
    void  *GetProviderProperty;
    void  *GetKeyProperty;
    void  *SetProviderProperty;
    void  *SetKeyProperty;
    void  *FinalizeKey;
    void  *DeleteKey;
    void  *FreeProvider;
    void  *FreeKey;
    void  *FreeBuffer;
    void  *EnumKeys;
    void  *ImportKey;
    void  *ExportKey;
    void  *SignHash;
    void  *Decrypt;
    void  *NotifyChangeKey;
    void  *GetOperationProperty;
    void  *FreeObject;
    void  *PromptUser;
    /* Extended slots — symmetric encryption and ECDH key agreement */
    void  *Encrypt;
    void  *SecretAgreement;
    void  *DeriveKey;
    void  *FreeSecret;
} NCRYPT_KEY_STORAGE_FUNCTION_TABLE;

/* ── Tick count (mock) ───────────────────────────────────────────────────── */
#include <time.h>
static inline DWORD GetTickCount(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (DWORD)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

#endif /* WINDOWS_COMPAT_H */
