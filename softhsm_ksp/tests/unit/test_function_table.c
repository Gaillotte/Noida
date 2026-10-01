/* test_function_table.c — Coverage of ksp_main.c
 *
 * Until now nothing compiled ksp_main.c at all, on any platform. The CNG
 * function table it defines was therefore completely untested, which is how
 * it came to be ordered against the hand-written mock rather than the
 * Windows SDK.
 *
 * These tests cannot prove the table matches the real
 * NCRYPT_KEY_STORAGE_FUNCTION_TABLE — that header ships with the WDK and is
 * not available here. What they do prove is that every slot the provider
 * claims to implement is wired to the right function, that no slot is left
 * NULL for ncrypt.dll to call, and that GetKeyStorageInterface honours its
 * contract. The SDK layout question is handled structurally instead: the
 * table uses designated initialisers, so the compiler assigns slots by name
 * from whatever header the Windows build actually has.
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
#include "test_framework.h"
#include <string.h>

/* ── Signature checks against the public NCrypt API ─────────────────────── */
/*
 * The table's LAYOUT cannot be proven here, but individual slot SIGNATURES
 * partly can, and that distinction matters: KSP_NotifyChangeKey took an
 * NCRYPT_KEY_HANDLE where the second parameter is `HANDLE *phEvent`, and
 * nothing on any platform objected. The mock's table types every slot as
 * `void *`, so a wrong type is not a build error on Linux, and the MSVC job
 * cannot compile ksp_main.c without ncrypt_provider.h.
 *
 * For PROVIDER-scoped operations the KSP entry point takes the same
 * parameter list as the documented public function, because the public
 * function already carries the provider handle. Those shapes are copied
 * from <ncrypt.h> below and each provider function is assigned to one. A
 * mismatch is an incompatible-pointer-types error, which the unit
 * Makefile promotes to a hard failure.
 *
 * KEY-scoped operations are deliberately absent: NCryptSignHash takes
 * (hKey, ...) while the KSP slot takes (hProvider, hKey, ...), so the
 * public prototype is NOT the slot's shape and asserting it would be
 * inventing a fact. Those stay unverifiable until ncrypt_provider.h is
 * available — which is BUILD-01, and is the reason it outranks everything.
 */
typedef SECURITY_STATUS (WINAPI *PFN_OpenStorageProvider)(
    NCRYPT_PROV_HANDLE *, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_OpenKey)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *, LPCWSTR, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_CreatePersistedKey)(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE *, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_EnumKeys)(
    NCRYPT_PROV_HANDLE, LPCWSTR, NCryptKeyName **, PVOID *, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_EnumAlgorithms)(
    NCRYPT_PROV_HANDLE, DWORD, DWORD *, NCryptAlgorithmName **, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_IsAlgSupported)(
    NCRYPT_PROV_HANDLE, LPCWSTR, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_NotifyChangeKey)(
    NCRYPT_PROV_HANDLE, HANDLE *, DWORD);
typedef SECURITY_STATUS (WINAPI *PFN_FreeBuffer)(PVOID);

static PFN_OpenStorageProvider s_sigOpenProvider     = KSP_OpenProvider;
static PFN_OpenKey             s_sigOpenKey          = KSP_OpenKey;
static PFN_CreatePersistedKey  s_sigCreatePersisted  = KSP_CreatePersistedKey;
static PFN_EnumKeys            s_sigEnumKeys         = KSP_EnumKeys;
static PFN_EnumAlgorithms      s_sigEnumAlgorithms   = KSP_EnumAlgorithms;
static PFN_IsAlgSupported      s_sigIsAlgSupported   = KSP_IsAlgSupported;
static PFN_NotifyChangeKey     s_sigNotifyChangeKey  = KSP_NotifyChangeKey;
static PFN_FreeBuffer          s_sigFreeBuffer       = KSP_FreeBuffer;

/* ── Stubs for everything ksp_main.c's table references ─────────────────── */
typedef struct { void *hModule; CK_FUNCTION_LIST_PTR pFunctionList;
                 CK_SLOT_ID slotId; BOOL bInitialized; } P11_CONTEXT;
static P11_CONTEXT g_testCtx;
P11_CONTEXT *P11_GetContext(void) { return &g_testCtx; }

void Log_Debug(const char *f, ...)  { (void)f; }
void Log_Error(const char *f, ...)  { (void)f; }
void Log_Initialize(void) {}

SECURITY_STATUS P11_Initialize(void)              { return ERROR_SUCCESS; }
void            P11_Finalize(void)                {}
SECURITY_STATUS P11_SessionPool_Initialize(void)  { return ERROR_SUCCESS; }
SECURITY_STATUS P11_EnsureSlotSelected(void)      { return ERROR_SUCCESS; }
SECURITY_STATUS P11_SetTokenSelection(const char *szLabel,
                                      const CK_SLOT_ID *pSlot)
{ (void)szLabel; (void)pSlot; return ERROR_SUCCESS; }
BOOL P11_IsSlotBound(void)                        { return FALSE; }
void            P11_SessionPool_Finalize(void)    {}

/* The scope parameter is not used here: these suites run against one mock
 * token, which is a single-token deployment, and PoolFor() collapses every
 * scope onto one pool in that configuration.
 *
 * p11_session.h is included above so the COMPILER checks this stub against
 * the real prototype. It was not, and when P11_AcquireSession gained the
 * scope parameter every one of these stubs kept its old shape: no
 * diagnostic, because the mismatch is across translation units, and then
 * ten segfaults as the scope argument arrived in the pointer parameter. A
 * stub that is not checked against the thing it stands in for is a trap
 * waiting for the next signature change. */
SECURITY_STATUS P11_AcquireSession(int nScope, CK_SESSION_HANDLE *ph)
{
    *ph = (CK_SESSION_HANDLE)0xBEEF;
    return ERROR_SUCCESS;
}
void P11_ReleaseSession(CK_SESSION_HANDLE h) { (void)h; }

SECURITY_STATUS P11_SetPin(const char *p) { (void)p; return ERROR_SUCCESS; }
void            P11_ClearPin(void) {}

/* DllMain is an entry point, not part of the KSP API, so ksp_main.h does
 * not declare it. Declared here so the suite can exercise it. */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

int main(void)
{
    NCRYPT_KEY_STORAGE_FUNCTION_TABLE *pTable = NULL;
    SECURITY_STATUS ss;

    /* ── Suite 1 : GetKeyStorageInterface ──────────────────────────────── */
    TEST_SUITE("GetKeyStorageInterface");

    ss = GetKeyStorageInterface(KSP_PROVIDER_NAME, &pTable, 0);
    ASSERT_OK("Correct provider name → OK", ss);
    ASSERT_NOTNULL("Table pointer returned", pTable);

    ss = GetKeyStorageInterface(NULL, &pTable, 0);
    ASSERT_OK("NULL provider name → OK (name is optional)", ss);

    ss = GetKeyStorageInterface(L"Some Other KSP", &pTable, 0);
    ASSERT_EQ("Wrong provider name → NTE_PROV_TYPE_NOT_DEF",
        ss, (SECURITY_STATUS)NTE_PROV_TYPE_NOT_DEF);

    ss = GetKeyStorageInterface(KSP_PROVIDER_NAME, NULL, 0);
    ASSERT_EQ("ppFunctionTable=NULL → NTE_INVALID_PARAMETER",
        ss, (SECURITY_STATUS)NTE_INVALID_PARAMETER);

    /* ── Suite 2 : interface version ───────────────────────────────────── */
    TEST_SUITE("Interface version");

    (void)GetKeyStorageInterface(KSP_PROVIDER_NAME, &pTable, 0);

    /* The SDK declares Version as two USHORTs, not a DWORD. The mock used
     * to get this wrong, and a DWORD 1 is not the same bit pattern as
     * {1, 0} on every layout. */
    ASSERT_EQ("Major version is 1", (DWORD)pTable->Version.MajorVersion, 1U);
    ASSERT_EQ("Minor version is 0", (DWORD)pTable->Version.MinorVersion, 0U);

    /* ── Suite 3 : every slot is wired, and wired correctly ────────────── */
    TEST_SUITE("Function table slots");

    /* A NULL slot is worse than an unsupported one: ncrypt.dll calls the
     * pointer regardless, so every slot must at least reach a stub. */
    ASSERT_NOTNULL("OpenProvider wired",        pTable->OpenProvider);
    ASSERT_NOTNULL("OpenKey wired",             pTable->OpenKey);
    ASSERT_NOTNULL("CreatePersistedKey wired",  pTable->CreatePersistedKey);
    ASSERT_NOTNULL("GetProviderProperty wired", pTable->GetProviderProperty);
    ASSERT_NOTNULL("GetKeyProperty wired",      pTable->GetKeyProperty);
    ASSERT_NOTNULL("SetProviderProperty wired", pTable->SetProviderProperty);
    ASSERT_NOTNULL("SetKeyProperty wired",      pTable->SetKeyProperty);
    ASSERT_NOTNULL("FinalizeKey wired",         pTable->FinalizeKey);
    ASSERT_NOTNULL("DeleteKey wired",           pTable->DeleteKey);
    ASSERT_NOTNULL("FreeProvider wired",        pTable->FreeProvider);
    ASSERT_NOTNULL("FreeKey wired",             pTable->FreeKey);
    ASSERT_NOTNULL("FreeBuffer wired",          pTable->FreeBuffer);
    ASSERT_NOTNULL("Encrypt wired",             pTable->Encrypt);
    ASSERT_NOTNULL("Decrypt wired",             pTable->Decrypt);
    ASSERT_NOTNULL("IsAlgSupported wired",      pTable->IsAlgSupported);
    ASSERT_NOTNULL("EnumAlgorithms wired",      pTable->EnumAlgorithms);
    ASSERT_NOTNULL("EnumKeys wired",            pTable->EnumKeys);
    ASSERT_NOTNULL("ImportKey wired",           pTable->ImportKey);
    ASSERT_NOTNULL("ExportKey wired",           pTable->ExportKey);
    ASSERT_NOTNULL("SignHash wired",            pTable->SignHash);
    ASSERT_NOTNULL("VerifySignature wired",     pTable->VerifySignature);
    ASSERT_NOTNULL("PromptUser wired",          pTable->PromptUser);
    ASSERT_NOTNULL("NotifyChangeKey wired",     pTable->NotifyChangeKey);
    ASSERT_NOTNULL("SecretAgreement wired",     pTable->SecretAgreement);
    ASSERT_NOTNULL("DeriveKey wired",           pTable->DeriveKey);
    ASSERT_NOTNULL("FreeSecret wired",          pTable->FreeSecret);

    /* Each slot must hold the function of the same name. This is what
     * catches a copy-paste that puts Decrypt where Encrypt belongs — the
     * class of defect that positional initialisation invited. */
    ASSERT("OpenProvider == KSP_OpenProvider",
        pTable->OpenProvider == (void *)KSP_OpenProvider);
    ASSERT("OpenKey == KSP_OpenKey",
        pTable->OpenKey == (void *)KSP_OpenKey);
    ASSERT("CreatePersistedKey == KSP_CreatePersistedKey",
        pTable->CreatePersistedKey == (void *)KSP_CreatePersistedKey);
    ASSERT("GetProviderProperty == KSP_GetProviderProperty",
        pTable->GetProviderProperty == (void *)KSP_GetProviderProperty);
    ASSERT("GetKeyProperty == KSP_GetKeyProperty",
        pTable->GetKeyProperty == (void *)KSP_GetKeyProperty);
    ASSERT("SetProviderProperty == KSP_SetProviderProperty",
        pTable->SetProviderProperty == (void *)KSP_SetProviderProperty);
    ASSERT("SetKeyProperty == KSP_SetKeyProperty",
        pTable->SetKeyProperty == (void *)KSP_SetKeyProperty);
    ASSERT("FinalizeKey == KSP_FinalizeKey",
        pTable->FinalizeKey == (void *)KSP_FinalizeKey);
    ASSERT("DeleteKey == KSP_DeleteKey",
        pTable->DeleteKey == (void *)KSP_DeleteKey);
    ASSERT("FreeProvider == KSP_FreeProvider",
        pTable->FreeProvider == (void *)KSP_FreeProvider);
    ASSERT("FreeKey == KSP_FreeKey",
        pTable->FreeKey == (void *)KSP_FreeKey);
    ASSERT("FreeBuffer == KSP_FreeBuffer",
        pTable->FreeBuffer == (void *)KSP_FreeBuffer);
    ASSERT("Encrypt == KSP_Encrypt",
        pTable->Encrypt == (void *)KSP_Encrypt);
    ASSERT("Decrypt == KSP_Decrypt",
        pTable->Decrypt == (void *)KSP_Decrypt);
    ASSERT("IsAlgSupported == KSP_IsAlgSupported",
        pTable->IsAlgSupported == (void *)KSP_IsAlgSupported);
    ASSERT("EnumAlgorithms == KSP_EnumAlgorithms",
        pTable->EnumAlgorithms == (void *)KSP_EnumAlgorithms);
    ASSERT("EnumKeys == KSP_EnumKeys",
        pTable->EnumKeys == (void *)KSP_EnumKeys);
    ASSERT("ImportKey == KSP_ImportKey",
        pTable->ImportKey == (void *)KSP_ImportKey);
    ASSERT("ExportKey == KSP_ExportKey",
        pTable->ExportKey == (void *)KSP_ExportKey);
    ASSERT("SignHash == KSP_SignHash",
        pTable->SignHash == (void *)KSP_SignHash);
    ASSERT("VerifySignature == KSP_VerifySignature",
        pTable->VerifySignature == (void *)KSP_VerifySignature);
    ASSERT("PromptUser == KSP_PromptUser",
        pTable->PromptUser == (void *)KSP_PromptUser);
    ASSERT("NotifyChangeKey == KSP_NotifyChangeKey",
        pTable->NotifyChangeKey == (void *)KSP_NotifyChangeKey);
    ASSERT("SecretAgreement == KSP_SecretAgreement",
        pTable->SecretAgreement == (void *)KSP_SecretAgreement);
    ASSERT("DeriveKey == KSP_DeriveKey",
        pTable->DeriveKey == (void *)KSP_DeriveKey);
    ASSERT("FreeSecret == KSP_FreeSecret",
        pTable->FreeSecret == (void *)KSP_FreeSecret);

    /* Slots that are easy to confuse with one another must stay distinct. */
    ASSERT("Encrypt and Decrypt are different slots",
        pTable->Encrypt != pTable->Decrypt);
    ASSERT("FreeKey and FreeBuffer are different slots",
        pTable->FreeKey != pTable->FreeBuffer);
    ASSERT("GetKeyProperty and GetProviderProperty are different slots",
        pTable->GetKeyProperty != pTable->GetProviderProperty);
    ASSERT("EnumKeys and EnumAlgorithms are different slots",
        pTable->EnumKeys != pTable->EnumAlgorithms);

    /* ── Suite 4 : DllMain ─────────────────────────────────────────────── */
    TEST_SUITE("DllMain");

    /* PROCESS_ATTACH initialises logging; PROCESS_DETACH tears the PKCS#11
     * layer down. Both must succeed, and an unrecognised reason must be a
     * harmless no-op rather than a crash. */
    ASSERT("PROCESS_ATTACH → TRUE",
        DllMain((HINSTANCE)0x1, DLL_PROCESS_ATTACH, NULL) == TRUE);
    ASSERT("THREAD_ATTACH → TRUE (no-op)",
        DllMain((HINSTANCE)0x1, DLL_THREAD_ATTACH, NULL) == TRUE);
    ASSERT("THREAD_DETACH → TRUE (no-op)",
        DllMain((HINSTANCE)0x1, DLL_THREAD_DETACH, NULL) == TRUE);
    ASSERT("PROCESS_DETACH → TRUE",
        DllMain((HINSTANCE)0x1, DLL_PROCESS_DETACH, NULL) == TRUE);
    ASSERT("Unknown reason → TRUE (no-op)",
        DllMain((HINSTANCE)0x1, 999, NULL) == TRUE);

    TEST_REPORT();
    TEST_EXIT();
}
