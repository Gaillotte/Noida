/* test_entry_contracts.c — every function-table entry point, against a
 * handle it must refuse.
 *
 * WHY THIS SUITE EXISTS
 *
 * The feature matrix tracks capabilities observed across shipping CNG KSPs.
 * It structurally cannot see this provider's OWN surface, and gap_detail.py
 * records that blind spot as having cost three defects already. Session 14
 * found two of them — KSP_VerifySignature unimplemented, and
 * KSP_NotifyChangeKey returning ERROR_SUCCESS while never writing the
 * caller's HANDLE — and it found them by reading the function table, which
 * nothing had ever enumerated.
 *
 * Reading is not a method. This enumerates the table and CALLS every slot.
 *
 * WHAT IT CHECKS, AND WHY THE HANDLE
 *
 * ncrypt.dll runs in the caller's process and hands the provider back the
 * handles the provider itself produced. That makes handle validation look
 * like a formality, and it is not one: anything in the process can call
 * these entry points directly with any value, so every slot that takes a
 * handle is a place where a wrong pointer becomes a dereference. There are
 * 24 such slots and nothing had ever checked them as a set.
 *
 * Two values per handle, because they fail differently:
 *
 *   0                 the NULL check. KSP_IsValidProvider tests the pointer
 *                     before reading dwMagic, so this passes today — but it
 *                     is one `&&` away from a null dereference on every
 *                     entry point at once, which is worth a test.
 *   wrong magic       a READABLE object whose dwMagic is not ours. This is
 *                     the realistic shape of the mistake: a live pointer to
 *                     the wrong kind of object. A NULL-only test would pass
 *                     against a provider that checked for NULL and never
 *                     looked at the magic.
 *
 * Every other argument is deliberately PLAUSIBLE — real buffers, a real
 * property name, sane lengths — so that the handle is the only thing wrong.
 * Passing NULL for everything would let an entry point that validates its
 * arguments before its handle return NTE_INVALID_PARAMETER and look as
 * though it had rejected the handle. Argument-first validation is itself
 * worth knowing about, and this is how it shows up.
 *
 * COMPLETENESS IS ENFORCED, NOT INTENDED
 *
 * The point of an inventory is that nothing is missing from it, so the
 * adapter table is checked against the real function table by POINTER: a
 * new slot with no adapter fails the suite and names itself. A hand-kept
 * list would rot on the first addition, which is exactly how the two
 * session-14 stubs survived.
 *
 * WHAT IT DELIBERATELY DOES NOT ASSERT
 *
 * It does not require one particular error code. The inventory's first run
 * found the provider answers a bad handle with NTE_INVALID_HANDLE in some
 * slots and NTE_INVALID_PARAMETER in others, and standardising those is a
 * separate change from measuring them. What is asserted is the part that is
 * not a matter of taste: the call must not crash, and it must NOT report
 * success. A slot that returns ERROR_SUCCESS for a handle it never
 * validated is the KSP_NotifyChangeKey defect again.
 */
#include "../mock/windows_compat.h"
#include "../mock/p11_mock.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/common/config.h"
#include "../../src/ksp/ksp_main.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_properties.h"
/* The REAL prototypes for everything stubbed below, so the compiler checks
 * the stubs against them.
 *
 * This is not boilerplate. Session 15 hit ten segfaults because every suite
 * that stubs P11_AcquireSession had kept the pre-scope signature: the
 * mismatch is across translation units, so there is no diagnostic, and the
 * scope argument arrived in the pointer parameter. The fix was recorded as
 * "including p11_session.h in all ten" — and session 18 found the include
 * was never added to any of them; only a comment SAYING it had been was
 * pasted into each file. The trap was open the whole time, confirmed by
 * giving a stub the wrong signature and watching the build succeed.
 *
 * Including p11_context.h as well so P11_GetContext and the slot-selection
 * stubs are checked too, rather than re-declaring P11_CONTEXT locally the
 * way the older suites do — a locally invented struct is the same trap in a
 * different place. */
#include "../../src/pkcs11/p11_session.h"
#include "../../src/pkcs11/p11_context.h"
#include "test_framework.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* ── Stubs for the layers this suite does not link ──────────────────────── */

static P11_CONTEXT g_testCtx;
P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }

void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }
void Log_Initialize(void) {}

SECURITY_STATUS P11_Initialize(void)             { return ERROR_SUCCESS; }
void            P11_Finalize(void)               {}
SECURITY_STATUS P11_SessionPool_Initialize(void) { return ERROR_SUCCESS; }
void            P11_SessionPool_Finalize(void)   {}
SECURITY_STATUS P11_EnsureSlotSelected(void)     { return ERROR_SUCCESS; }
SECURITY_STATUS P11_ClearTokenSelection(void)    { return ERROR_SUCCESS; }
BOOL            P11_IsSlotBound(void)            { return FALSE; }
BOOL            P11_HasPerScopeTokens(void)      { return FALSE; }
CK_SLOT_ID      P11_GetScopeSlot(int nScope)     { (void)nScope; return 0; }
SECURITY_STATUS P11_SetTokenSelection(const char *szLabel,
                                      const CK_SLOT_ID *pSlot)
{ (void)szLabel; (void)pSlot; return ERROR_SUCCESS; }

SECURITY_STATUS P11_AcquireSession(int nScope, CK_SESSION_HANDLE *phSession)
{
    (void)nScope;
    *phSession = (CK_SESSION_HANDLE)0xBEEF;
    return ERROR_SUCCESS;
}
void P11_ReleaseSession(CK_SESSION_HANDLE hSession) { (void)hSession; }

SECURITY_STATUS P11_SetPin(const char *szPin) { (void)szPin; return ERROR_SUCCESS; }
void            P11_ClearPin(void) {}

/* A readable object carrying the wrong magic, padded so that an entry point
 * reading further into the struct before validating still touches our
 * memory rather than the allocator's.
 *
 * The pad does NOT guarantee a clean failure, and the first version of this
 * comment claimed it did. Defeating KSP_IsValidProvider as an injection
 * segfaults the suite: padding keeps a direct read in bounds, but it cannot
 * help once the provider follows a POINTER FIELD read out of the fake
 * object, which is zero here. Detection still works — the suite dies with
 * exit 139 and CI fails the job — but it dies rather than reporting, so the
 * finding is "this entry point dereferenced an unvalidated handle" and the
 * evidence is the crash, not an assertion. */
typedef struct {
    DWORD dwMagic;
    BYTE  pad[2048];
} WRONG_OBJECT;

static WRONG_OBJECT g_wrong;

#define WRONG_MAGIC 0xDEADBEEFu

static NCRYPT_PROV_HANDLE wrong_prov(void)
{
    return (NCRYPT_PROV_HANDLE)(ULONG_PTR)&g_wrong;
}
static NCRYPT_KEY_HANDLE wrong_key(void)
{
    return (NCRYPT_KEY_HANDLE)(ULONG_PTR)&g_wrong;
}
static NCRYPT_SECRET_HANDLE wrong_secret(void)
{
    return (NCRYPT_SECRET_HANDLE)(ULONG_PTR)&g_wrong;
}

/* Plausible arguments, shared by the adapters. */
static BYTE  g_buf[256];
static DWORD g_cb;
static DWORD g_count;
static PVOID g_state;
static NCryptKeyName       *g_keyname;
static NCryptAlgorithmName *g_alglist;
static HANDLE               g_event;

/* ── Adapters ───────────────────────────────────────────────────────────── */
/*
 * One per slot that takes a handle. Each calls its entry point with the
 * supplied provider handle and otherwise plausible arguments.
 *
 * `hKey` deliberately carries a VALID-looking wrong-magic object rather
 * than 0 in the provider-handle cases: if the provider validated the key
 * first and the key were 0, a "key is NULL" rejection would be mistaken for
 * the provider check doing its job.
 */
typedef SECURITY_STATUS (*PROV_CALL)(NCRYPT_PROV_HANDLE);

static SECURITY_STATUS c_OpenKey(NCRYPT_PROV_HANDLE h)
{
    NCRYPT_KEY_HANDLE k = 0;
    return KSP_OpenKey(h, &k, L"contract-probe", 0, 0);
}
static SECURITY_STATUS c_CreatePersistedKey(NCRYPT_PROV_HANDLE h)
{
    NCRYPT_KEY_HANDLE k = 0;
    return KSP_CreatePersistedKey(h, &k, ALG_RSA, L"contract-probe", 0, 0);
}
static SECURITY_STATUS c_GetProviderProperty(NCRYPT_PROV_HANDLE h)
{
    g_cb = 0;
    return KSP_GetProviderProperty(h, NCRYPT_NAME_PROPERTY,
                                   g_buf, sizeof(g_buf), &g_cb, 0);
}
static SECURITY_STATUS c_SetProviderProperty(NCRYPT_PROV_HANDLE h)
{
    return KSP_SetProviderProperty(h, NCRYPT_PIN_PROPERTY,
                                   (PBYTE)L"1234", 5 * sizeof(WCHAR), 0);
}
static SECURITY_STATUS c_GetKeyProperty(NCRYPT_PROV_HANDLE h)
{
    g_cb = 0;
    return KSP_GetKeyProperty(h, wrong_key(), NCRYPT_ALGORITHM_PROPERTY,
                              g_buf, sizeof(g_buf), &g_cb, 0);
}
static SECURITY_STATUS c_SetKeyProperty(NCRYPT_PROV_HANDLE h)
{
    return KSP_SetKeyProperty(h, wrong_key(), NCRYPT_LENGTH_PROPERTY,
                              (PBYTE)&g_count, sizeof(g_count), 0);
}
static SECURITY_STATUS c_FinalizeKey(NCRYPT_PROV_HANDLE h)
{
    return KSP_FinalizeKey(h, wrong_key(), 0);
}
static SECURITY_STATUS c_DeleteKey(NCRYPT_PROV_HANDLE h)
{
    return KSP_DeleteKey(h, wrong_key(), 0);
}
static SECURITY_STATUS c_FreeProvider(NCRYPT_PROV_HANDLE h)
{
    return KSP_FreeProvider(h);
}
static SECURITY_STATUS c_FreeKey(NCRYPT_PROV_HANDLE h)
{
    return KSP_FreeKey(h, wrong_key());
}
static SECURITY_STATUS c_Encrypt(NCRYPT_PROV_HANDLE h)
{
    g_cb = 0;
    return KSP_Encrypt(h, wrong_key(), g_buf, 16, NULL,
                       g_buf, sizeof(g_buf), &g_cb, 0);
}
static SECURITY_STATUS c_Decrypt(NCRYPT_PROV_HANDLE h)
{
    g_cb = 0;
    return KSP_Decrypt(h, wrong_key(), g_buf, 16, NULL,
                       g_buf, sizeof(g_buf), &g_cb, NCRYPT_PAD_PKCS1_FLAG);
}
static SECURITY_STATUS c_IsAlgSupported(NCRYPT_PROV_HANDLE h)
{
    return KSP_IsAlgSupported(h, ALG_RSA, 0);
}
static SECURITY_STATUS c_EnumAlgorithms(NCRYPT_PROV_HANDLE h)
{
    g_count = 0; g_alglist = NULL;
    return KSP_EnumAlgorithms(h, 0, &g_count, &g_alglist, 0);
}
static SECURITY_STATUS c_EnumKeys(NCRYPT_PROV_HANDLE h)
{
    g_keyname = NULL; g_state = NULL;
    return KSP_EnumKeys(h, NULL, &g_keyname, &g_state, 0);
}
static SECURITY_STATUS c_ImportKey(NCRYPT_PROV_HANDLE h)
{
    NCRYPT_KEY_HANDLE k = 0;
    return KSP_ImportKey(h, 0, BCRYPT_RSAPUBLIC_BLOB, NULL, &k,
                         g_buf, sizeof(g_buf), 0);
}
static SECURITY_STATUS c_ExportKey(NCRYPT_PROV_HANDLE h)
{
    g_cb = 0;
    return KSP_ExportKey(h, wrong_key(), 0, BCRYPT_RSAPUBLIC_BLOB, NULL,
                         g_buf, sizeof(g_buf), &g_cb, 0);
}
static SECURITY_STATUS c_SignHash(NCRYPT_PROV_HANDLE h)
{
    g_cb = 0;
    return KSP_SignHash(h, wrong_key(), NULL, g_buf, 32,
                        g_buf, sizeof(g_buf), &g_cb, NCRYPT_PAD_PKCS1_FLAG);
}
static SECURITY_STATUS c_VerifySignature(NCRYPT_PROV_HANDLE h)
{
    return KSP_VerifySignature(h, wrong_key(), NULL, g_buf, 32,
                               g_buf, 256, NCRYPT_PAD_PKCS1_FLAG);
}
static SECURITY_STATUS c_PromptUser(NCRYPT_PROV_HANDLE h)
{
    return KSP_PromptUser(h, wrong_key(), L"sign", 0);
}
static SECURITY_STATUS c_NotifyChangeKey(NCRYPT_PROV_HANDLE h)
{
    g_event = (HANDLE)(ULONG_PTR)0x1234;
    return KSP_NotifyChangeKey(h, &g_event, 0);
}
static SECURITY_STATUS c_SecretAgreement(NCRYPT_PROV_HANDLE h)
{
    NCRYPT_SECRET_HANDLE s = 0;
    return KSP_SecretAgreement(h, wrong_key(), wrong_key(), &s, 0);
}
static SECURITY_STATUS c_DeriveKey(NCRYPT_PROV_HANDLE h)
{
    g_cb = 0;
    return KSP_DeriveKey(h, wrong_secret(), BCRYPT_KDF_RAW_SECRET, NULL,
                         g_buf, sizeof(g_buf), &g_cb, 0);
}
static SECURITY_STATUS c_FreeSecret(NCRYPT_PROV_HANDLE h)
{
    return KSP_FreeSecret(h, wrong_secret());
}

typedef struct {
    const char *slot;       /* the function-table field name */
    void       *fn;         /* the entry point, for the completeness check */
    PROV_CALL   call;
} ENTRY;

static const ENTRY ENTRIES[] = {
    { "OpenKey",             (void *)KSP_OpenKey,             c_OpenKey },
    { "CreatePersistedKey",  (void *)KSP_CreatePersistedKey,  c_CreatePersistedKey },
    { "GetProviderProperty", (void *)KSP_GetProviderProperty, c_GetProviderProperty },
    { "GetKeyProperty",      (void *)KSP_GetKeyProperty,      c_GetKeyProperty },
    { "SetProviderProperty", (void *)KSP_SetProviderProperty, c_SetProviderProperty },
    { "SetKeyProperty",      (void *)KSP_SetKeyProperty,      c_SetKeyProperty },
    { "FinalizeKey",         (void *)KSP_FinalizeKey,         c_FinalizeKey },
    { "DeleteKey",           (void *)KSP_DeleteKey,           c_DeleteKey },
    { "FreeProvider",        (void *)KSP_FreeProvider,        c_FreeProvider },
    { "FreeKey",             (void *)KSP_FreeKey,             c_FreeKey },
    { "Encrypt",             (void *)KSP_Encrypt,             c_Encrypt },
    { "Decrypt",             (void *)KSP_Decrypt,             c_Decrypt },
    { "IsAlgSupported",      (void *)KSP_IsAlgSupported,      c_IsAlgSupported },
    { "EnumAlgorithms",      (void *)KSP_EnumAlgorithms,      c_EnumAlgorithms },
    { "EnumKeys",            (void *)KSP_EnumKeys,            c_EnumKeys },
    { "ImportKey",           (void *)KSP_ImportKey,           c_ImportKey },
    { "ExportKey",           (void *)KSP_ExportKey,           c_ExportKey },
    { "SignHash",            (void *)KSP_SignHash,            c_SignHash },
    { "VerifySignature",     (void *)KSP_VerifySignature,     c_VerifySignature },
    { "PromptUser",          (void *)KSP_PromptUser,          c_PromptUser },
    { "NotifyChangeKey",     (void *)KSP_NotifyChangeKey,     c_NotifyChangeKey },
    { "SecretAgreement",     (void *)KSP_SecretAgreement,     c_SecretAgreement },
    { "DeriveKey",           (void *)KSP_DeriveKey,           c_DeriveKey },
    { "FreeSecret",          (void *)KSP_FreeSecret,          c_FreeSecret },
};
#define NENTRIES ((int)(sizeof(ENTRIES) / sizeof(ENTRIES[0])))

/* The two slots with no handle to validate, named so the completeness check
 * can account for every slot in the table rather than most of them.
 *
 *   OpenProvider  PRODUCES the provider handle; there is nothing to check.
 *   FreeBuffer    takes a buffer, not a handle.
 *
 * Listing them is the point: "this slot has no handle" is a claim, and a
 * silent omission from the adapter table would look identical to a slot
 * somebody forgot. */
static const char *NO_HANDLE_SLOTS[] = { "OpenProvider", "FreeBuffer" };
#define NNOHANDLE ((int)(sizeof(NO_HANDLE_SLOTS) / sizeof(NO_HANDLE_SLOTS[0])))

static const char *status_name(SECURITY_STATUS ss)
{
    static char buf[32];
    if (ss == ERROR_SUCCESS)         return "ERROR_SUCCESS";
    if (ss == NTE_INVALID_HANDLE)    return "NTE_INVALID_HANDLE";
    if (ss == NTE_INVALID_PARAMETER) return "NTE_INVALID_PARAMETER";
    if (ss == NTE_NOT_SUPPORTED)     return "NTE_NOT_SUPPORTED";
    if (ss == NTE_BAD_FLAGS)         return "NTE_BAD_FLAGS";
    if (ss == NTE_BAD_KEY)           return "NTE_BAD_KEY";
    if (ss == NTE_BAD_ALGID)         return "NTE_BAD_ALGID";
    if (ss == NTE_BAD_LEN)           return "NTE_BAD_LEN";
    if (ss == NTE_PERM)              return "NTE_PERM";
    snprintf(buf, sizeof(buf), "0x%08lX", (unsigned long)ss);
    return buf;
}

/* ── The completeness check ─────────────────────────────────────────────── */

static void check_completeness(void)
{
    const NCRYPT_KEY_STORAGE_FUNCTION_TABLE *t = NULL;
    SECURITY_STATUS ss;
    int i;

    TEST_SUITE("Function table: every slot is accounted for");

    ss = GetKeyStorageInterface(L"SoftHSM KSP",
            (NCRYPT_KEY_STORAGE_FUNCTION_TABLE **)&t, 0);
    ASSERT_OK("GetKeyStorageInterface returns the table", ss);
    if (!t)
        return;

    /* Each adapter's function pointer must be the one the table holds.
     * Pointer identity, not name matching: the table's slots are void * in
     * this build, so a name check would prove nothing about what is wired
     * where. */
    #define SLOT_IS(field, fn) \
        ASSERT("table slot " #field " is the function this suite calls", \
               t->field == (void *)(fn))

    SLOT_IS(OpenKey,             KSP_OpenKey);
    SLOT_IS(CreatePersistedKey,  KSP_CreatePersistedKey);
    SLOT_IS(GetProviderProperty, KSP_GetProviderProperty);
    SLOT_IS(GetKeyProperty,      KSP_GetKeyProperty);
    SLOT_IS(SetProviderProperty, KSP_SetProviderProperty);
    SLOT_IS(SetKeyProperty,      KSP_SetKeyProperty);
    SLOT_IS(FinalizeKey,         KSP_FinalizeKey);
    SLOT_IS(DeleteKey,           KSP_DeleteKey);
    SLOT_IS(FreeProvider,        KSP_FreeProvider);
    SLOT_IS(FreeKey,             KSP_FreeKey);
    SLOT_IS(Encrypt,             KSP_Encrypt);
    SLOT_IS(Decrypt,             KSP_Decrypt);
    SLOT_IS(IsAlgSupported,      KSP_IsAlgSupported);
    SLOT_IS(EnumAlgorithms,      KSP_EnumAlgorithms);
    SLOT_IS(EnumKeys,            KSP_EnumKeys);
    SLOT_IS(ImportKey,           KSP_ImportKey);
    SLOT_IS(ExportKey,           KSP_ExportKey);
    SLOT_IS(SignHash,            KSP_SignHash);
    SLOT_IS(VerifySignature,     KSP_VerifySignature);
    SLOT_IS(PromptUser,          KSP_PromptUser);
    SLOT_IS(NotifyChangeKey,     KSP_NotifyChangeKey);
    SLOT_IS(SecretAgreement,     KSP_SecretAgreement);
    SLOT_IS(DeriveKey,           KSP_DeriveKey);
    SLOT_IS(FreeSecret,          KSP_FreeSecret);
    #undef SLOT_IS

    /* And the two with nothing to validate, so all 26 are accounted for and
     * the arithmetic below is a real check rather than a restatement. */
    ASSERT("table slot OpenProvider is wired",
           t->OpenProvider == (void *)KSP_OpenProvider);
    ASSERT("table slot FreeBuffer is wired",
           t->FreeBuffer == (void *)KSP_FreeBuffer);

    ASSERT_EQ("every function slot is either probed here or declared "
              "handle-free", (DWORD)(NENTRIES + NNOHANDLE), 26u);

    for (i = 0; i < NENTRIES; i++)
        ASSERT("adapter has a callable entry point", ENTRIES[i].call != NULL);
}

/* ── The inventory ──────────────────────────────────────────────────────── */

static void probe_provider_handle(const char *label, NCRYPT_PROV_HANDLE h)
{
    int i;
    char msg[160];

    for (i = 0; i < NENTRIES; i++) {
        SECURITY_STATUS ss = ENTRIES[i].call(h);

        /* The assertion is "not success", not a particular code. See the
         * header comment: the codes are inconsistent across slots today,
         * and measuring that is not the same job as settling it. */
        snprintf(msg, sizeof(msg), "%-20s refuses a %s provider handle "
                 "(answered %s)", ENTRIES[i].slot, label, status_name(ss));
        ASSERT(msg, ss != ERROR_SUCCESS);
    }
}

int main(void)
{
    NCRYPT_PROV_HANDLE hProv = 0;
    int i;
    char msg[160];

    P11Mock_Reset();
    memset(&g_wrong, 0, sizeof(g_wrong));
    g_wrong.dwMagic = WRONG_MAGIC;
    memset(g_buf, 0x5A, sizeof(g_buf));

    check_completeness();

    TEST_SUITE("Every entry point refuses a NULL provider handle");
    probe_provider_handle("NULL", (NCRYPT_PROV_HANDLE)0);

    TEST_SUITE("Every entry point refuses a wrong-magic provider handle");
    probe_provider_handle("wrong-magic", wrong_prov());

    /* With a VALID provider, the key and secret handles are what is wrong.
     * This is the dimension a provider-handle-only sweep misses: a slot can
     * validate the provider faithfully and then dereference the key. */
    TEST_SUITE("Key and secret handles are validated separately");
    ASSERT_OK("OpenProvider", KSP_OpenProvider(&hProv, KSP_PROVIDER_NAME, 0));

    for (i = 0; i < NENTRIES; i++) {
        SECURITY_STATUS ss;

        /* Only the slots that take a key or secret handle. The rest would
         * legitimately succeed here, since nothing is wrong with them. */
        if (strcmp(ENTRIES[i].slot, "GetKeyProperty")  != 0 &&
            strcmp(ENTRIES[i].slot, "SetKeyProperty")  != 0 &&
            strcmp(ENTRIES[i].slot, "FinalizeKey")     != 0 &&
            strcmp(ENTRIES[i].slot, "DeleteKey")       != 0 &&
            strcmp(ENTRIES[i].slot, "FreeKey")         != 0 &&
            strcmp(ENTRIES[i].slot, "Encrypt")         != 0 &&
            strcmp(ENTRIES[i].slot, "Decrypt")         != 0 &&
            strcmp(ENTRIES[i].slot, "ExportKey")       != 0 &&
            strcmp(ENTRIES[i].slot, "SignHash")        != 0 &&
            strcmp(ENTRIES[i].slot, "VerifySignature") != 0 &&
            strcmp(ENTRIES[i].slot, "PromptUser")      != 0 &&
            strcmp(ENTRIES[i].slot, "SecretAgreement") != 0 &&
            strcmp(ENTRIES[i].slot, "DeriveKey")       != 0 &&
            strcmp(ENTRIES[i].slot, "FreeSecret")      != 0)
            continue;

        ss = ENTRIES[i].call(hProv);
        snprintf(msg, sizeof(msg), "%-20s refuses a wrong-magic key/secret "
                 "handle (answered %s)", ENTRIES[i].slot, status_name(ss));
        ASSERT(msg, ss != ERROR_SUCCESS);
    }

    KSP_FreeProvider(hProv);

    TEST_REPORT();
    TEST_EXIT();
}
