/* p11_context.c — PKCS#11 context singleton implementation */
#include "p11_context.h"
#include "p11_caps.h"
#include "p11_utils.h"
#include "../common/config.h"
#include "../common/logging.h"
#include <stdlib.h>
#include <string.h>

/* Singleton, guarded so that a FAILED initialisation can be retried.
 *
 * This used to be a bare InitOnceExecuteOnce, which runs its callback
 * exactly once per process whether it succeeded or not. One bad module path
 * therefore poisoned the provider for the lifetime of the host: correcting
 * KSP_PKCS11_LIB changed nothing, because the callback would never run
 * again, and the only cure was restarting the application. For a service
 * that loads this DLL that meant a restart of the service.
 *
 * A critical section replaces it. A successful initialisation is still
 * one-shot — C_Initialize must not be called twice — but a failed one
 * leaves the context in its not-initialised state and the next caller tries
 * again. The retry costs a LoadLibrary on the failure path only.
 *
 * INIT_ONCE is still used, for the one thing that genuinely cannot fail:
 * creating the critical section itself, which Windows gives no static
 * initialiser for. */
static P11_CONTEXT  g_ctx;
static CRITICAL_SECTION g_initLock;

/* Token selection set by the caller through NCryptSetProperty, and whether
 * the slot has been bound yet.
 *
 * The slot used to be chosen inside TryInitialize, which runs during
 * KSP_OpenProvider — so by the time a caller could set a property the
 * choice was already made, and token selection had to be refused. It is
 * chosen lazily now, on the first operation that needs a session or a
 * capability answer, which gives the property the same window the PIN has
 * always had. Once bound it cannot move: PKCS#11 offers no way to migrate a
 * session between tokens, so a later change would be a lie. */
static char       g_szSelLabel[P11_TOKEN_LABEL_LEN + 1];
static BOOL       g_bSelLabelSet;
static CK_SLOT_ID g_selSlot;
static BOOL       g_bSelSlotSet;
static BOOL       g_bSlotBound;

/* ── Per-scope tokens (LIFE-08) ────────────────────────────────────────────
 *
 * When the deployment gives the machine and user scopes separate tokens,
 * there is no longer one slot: there are two, and which one an operation
 * uses depends on the scope of the key it is operating on.
 *
 * g_aScopeSlot[] holds them. When per-scope tokens are NOT configured both
 * entries are the single bound slot, so every caller can ask for a scope
 * unconditionally and an unconfigured deployment behaves exactly as before
 * — the collapse is in the data rather than in each caller's reasoning,
 * which is what stops it being forgotten at one of twenty-nine call sites.
 */
static CK_SLOT_ID g_aScopeSlot[P11_SCOPE_COUNT];
static BOOL       g_bPerScope;          /* resolved once, with the slots */
static INIT_ONCE    g_lockOnce = INIT_ONCE_STATIC_INIT;
static SECURITY_STATUS g_initStatus = NTE_PROVIDER_DLL_FAIL;

static BOOL CALLBACK CreateInitLock(PINIT_ONCE p1, PVOID p2, PVOID *p3)
{
    (void)p1; (void)p2; (void)p3;
    InitializeCriticalSection(&g_initLock);
    return TRUE;
}

/* Load the PKCS#11 module and retrieve its function list.
 *
 * KSP_PKCS11_LIB names the module; SOFTHSM2_LIB is the older name for the
 * same thing and is honoured when the new one is unset. With neither, the
 * SoftHSM2 path baked in at build time is used. */
static BOOL LoadP11Module(P11_CONTEXT *pCtx)
{
    WCHAR   wszLibPath[MAX_PATH];
    char    szLibPath[MAX_PATH];
    DWORD   dwLen;
    CK_C_GetFunctionList pfnGetFunctionList;

    dwLen = GetEnvironmentVariableA(KSP_PKCS11_LIB_ENV, szLibPath, MAX_PATH);
    if (dwLen == 0 || dwLen >= MAX_PATH)
        dwLen = GetEnvironmentVariableA(SOFTHSM2_LIB_ENV, szLibPath, MAX_PATH);

    if (dwLen == 0 || dwLen >= MAX_PATH) {
        /* Use the default path */
        wcscpy_s(wszLibPath, MAX_PATH, SOFTHSM2_LIB_DEFAULT);
    } else {
        MultiByteToWideChar(CP_ACP, 0, szLibPath, -1, wszLibPath, MAX_PATH);
    }

    LOG_INFO("Loading PKCS#11 module: %ls", wszLibPath);

    pCtx->hModule = LoadLibraryW(wszLibPath);
    if (!pCtx->hModule) {
        LOG_ERROR("P11_Initialize", NTE_PROVIDER_DLL_FAIL);
        return FALSE;
    }

    pfnGetFunctionList = (CK_C_GetFunctionList)GetProcAddress(
        pCtx->hModule, "C_GetFunctionList");
    if (!pfnGetFunctionList) {
        FreeLibrary(pCtx->hModule);
        pCtx->hModule = NULL;
        return FALSE;
    }

    if (pfnGetFunctionList(&pCtx->pFunctionList) != CKR_OK) {
        FreeLibrary(pCtx->hModule);
        pCtx->hModule = NULL;
        return FALSE;
    }

    return TRUE;
}

/* Choose the token this process will use.
 *
 * Order of preference:
 *   1. SOFTHSM2_TOKEN_LABEL — matched against each slot's token label
 *   2. SOFTHSM2_SLOT        — an explicit slot ID
 *   3. the first slot reporting a token present (the historical default)
 *
 * An explicit selection that cannot be satisfied is an error rather than a
 * silent fallback: falling back to slot 0 would sign with the wrong key and
 * look like it worked. */
static BOOL SelectSlot(P11_CONTEXT *pCtx)
{
    CK_SLOT_ID  aSlots[P11_MAX_SLOTS];
    CK_ULONG    ulCount = P11_MAX_SLOTS;
    CK_RV       rv;
    char        szLabel[P11_TOKEN_LABEL_LEN + 1] = {0};
    char        szSlot[32] = {0};
    DWORD       dwLen;
    CK_ULONG    i;

    rv = pCtx->pFunctionList->C_GetSlotList(CK_TRUE, aSlots, &ulCount);
    if (rv != CKR_OK || ulCount == 0) {
        LOG_ERROR("SelectSlot - C_GetSlotList", P11RvToSecStatus(rv));
        return FALSE;
    }

    /* 0. Set by the caller through NCryptSetProperty, which outranks the
     * environment: a property is a deliberate act by this process, an
     * environment variable is ambient. An explicit choice that matches no
     * token is still an error and never a fallback. */
    if (g_bSelLabelSet) {
        for (i = 0; i < ulCount; i++) {
            CK_TOKEN_INFO info;
            memset(&info, 0, sizeof(info));
            if (pCtx->pFunctionList->C_GetTokenInfo(aSlots[i], &info) != CKR_OK)
                continue;
            if (P11_TokenLabelMatches(info.label, g_szSelLabel)) {
                pCtx->slotId = aSlots[i];
                LOG_INFO("Selected slot %lu by caller-set token label",
                         (unsigned long)pCtx->slotId);
                return TRUE;
            }
        }
        LOG_ERROR("SelectSlot - no token matches the label set through "
                  "NCryptSetProperty", NTE_NO_KEY);
        return FALSE;
    }
    if (g_bSelSlotSet) {
        for (i = 0; i < ulCount; i++) {
            if (aSlots[i] == g_selSlot) {
                pCtx->slotId = aSlots[i];
                LOG_INFO("Selected slot %lu (caller-set)",
                         (unsigned long)pCtx->slotId);
                return TRUE;
            }
        }
        LOG_ERROR("SelectSlot - the slot set through NCryptSetProperty names "
                  "no present token", NTE_NO_KEY);
        return FALSE;
    }

    /* 1. By token label. */
    dwLen = GetEnvironmentVariableA(SOFTHSM2_TOKEN_LABEL_ENV,
                                    szLabel, sizeof(szLabel));
    if (dwLen > 0 && dwLen < sizeof(szLabel)) {
        for (i = 0; i < ulCount; i++) {
            CK_TOKEN_INFO info;
            memset(&info, 0, sizeof(info));
            if (pCtx->pFunctionList->C_GetTokenInfo(aSlots[i], &info) != CKR_OK)
                continue;
            if (P11_TokenLabelMatches(info.label, szLabel)) {
                pCtx->slotId = aSlots[i];
                LOG_INFO("Selected slot %lu by token label '%s'",
                         (unsigned long)pCtx->slotId, szLabel);
                return TRUE;
            }
        }
        LOG_ERROR("SelectSlot - no token matches " SOFTHSM2_TOKEN_LABEL_ENV,
                  NTE_NO_KEY);
        return FALSE;
    }

    /* 2. By explicit slot ID. */
    dwLen = GetEnvironmentVariableA(SOFTHSM2_SLOT_ENV, szSlot, sizeof(szSlot));
    if (dwLen > 0 && dwLen < sizeof(szSlot)) {
        char     *pszEnd = NULL;
        unsigned long ulWanted = strtoul(szSlot, &pszEnd, 10);

        if (pszEnd == szSlot || (pszEnd && *pszEnd != '\0')) {
            LOG_ERROR("SelectSlot - " SOFTHSM2_SLOT_ENV " is not a number",
                      NTE_INVALID_PARAMETER);
            return FALSE;
        }

        for (i = 0; i < ulCount; i++) {
            if (aSlots[i] == (CK_SLOT_ID)ulWanted) {
                pCtx->slotId = aSlots[i];
                LOG_INFO("Selected slot %lu (explicit)",
                         (unsigned long)pCtx->slotId);
                return TRUE;
            }
        }
        LOG_ERROR("SelectSlot - " SOFTHSM2_SLOT_ENV " names no present token",
                  NTE_NO_KEY);
        return FALSE;
    }

    /* 3. Default: first token present. */
    pCtx->slotId = aSlots[0];
    LOG_INFO("Selected slot %lu (first token present, of %lu)",
             (unsigned long)pCtx->slotId, (unsigned long)ulCount);
    return TRUE;
}

/* One initialisation attempt. Caller holds g_initLock. */
static void TryInitialize(void)
{
    CK_C_INITIALIZE_ARGS initArgs;
    CK_RV rv;

    memset(&g_ctx, 0, sizeof(g_ctx));

    if (!LoadP11Module(&g_ctx)) {
        g_initStatus = NTE_PROVIDER_DLL_FAIL;
        return;
    }

    /* Initialise Cryptoki with OS locking */
    memset(&initArgs, 0, sizeof(initArgs));
    initArgs.flags = CKF_OS_LOCKING_OK;

    rv = g_ctx.pFunctionList->C_Initialize(&initArgs);
    if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
        LOG_ERROR("C_Initialize", P11RvToSecStatus(rv));
        FreeLibrary(g_ctx.hModule);
        g_ctx.hModule = NULL;
        g_initStatus  = P11RvToSecStatus(rv);
        return;
    }

    g_ctx.bInitialized = TRUE;

    /* The slot is NOT chosen here, and neither is the capability probe run:
     * both need a token, and choosing one now would close the window in
     * which a caller can select it. P11_EnsureSlotSelected does both, on
     * the first operation that needs an answer. */
    g_initStatus = ERROR_SUCCESS;
    LOG_INFO("P11_Initialize: module loaded and Cryptoki initialised; "
             "slot selection deferred");
}

/* Bind the slot, and probe the token, on first use.
 *
 * Idempotent and cheap after the first call. Everything that needs a token
 * calls it: acquiring a session, and answering a capability question —
 * because the probe reads the token's mechanism list and cannot run before
 * there is a token to read. Without the second caller,
 * NCryptEnumAlgorithms immediately after NCryptOpenStorageProvider would
 * answer from an unprobed state, which is permissive, and the provider
 * would advertise algorithms the token may not have. */
/* Find the slot whose token carries this label. */
static BOOL FindSlotByLabel(P11_CONTEXT *pCtx, const CK_SLOT_ID *aSlots,
                            CK_ULONG ulCount, const char *szLabel,
                            CK_SLOT_ID *pOut)
{
    CK_ULONG i;

    for (i = 0; i < ulCount; i++) {
        CK_TOKEN_INFO info;
        memset(&info, 0, sizeof(info));
        if (pCtx->pFunctionList->C_GetTokenInfo(aSlots[i], &info) != CKR_OK)
            continue;
        if (P11_TokenLabelMatches(info.label, szLabel)) {
            *pOut = aSlots[i];
            return TRUE;
        }
    }
    return FALSE;
}

/* Read a slot ID from an environment variable. */
static BOOL SlotFromEnv(const char *szVar, const CK_SLOT_ID *aSlots,
                        CK_ULONG ulCount, CK_SLOT_ID *pOut)
{
    char      szVal[32] = {0};
    char     *pszEnd    = NULL;
    unsigned long ul;
    CK_ULONG  i;
    DWORD     dwLen;

    dwLen = GetEnvironmentVariableA(szVar, szVal, sizeof(szVal));
    if (dwLen == 0 || dwLen >= sizeof(szVal))
        return FALSE;

    ul = strtoul(szVal, &pszEnd, 10);
    if (pszEnd == szVal || (pszEnd && *pszEnd != '\0')) {
        LOG_ERROR("Per-scope slot variable is not a number",
                  NTE_INVALID_PARAMETER);
        return FALSE;
    }

    for (i = 0; i < ulCount; i++) {
        if (aSlots[i] == (CK_SLOT_ID)ul) {
            *pOut = aSlots[i];
            return TRUE;
        }
    }
    LOG_ERROR("Per-scope slot variable names no present token", NTE_NO_KEY);
    return FALSE;
}

/* Resolve a token for each scope, if the deployment asked for that.
 *
 * Returns FALSE only when per-scope tokens WERE asked for and cannot be
 * satisfied. Returning TRUE with g_bPerScope FALSE is the ordinary
 * single-token case and not a failure.
 *
 * Setting only one of a pair is refused. A deployment that named a machine
 * token and forgot the user one would put user keys on the machine token
 * and report success — isolation that does not isolate, which nobody
 * re-checks because it appeared to work.
 */
static BOOL SelectScopeSlots(P11_CONTEXT *pCtx)
{
    CK_SLOT_ID aSlots[P11_MAX_SLOTS];
    CK_ULONG   ulCount = P11_MAX_SLOTS;
    char       szMachine[P11_TOKEN_LABEL_LEN + 1] = {0};
    char       szUser[P11_TOKEN_LABEL_LEN + 1]    = {0};
    DWORD      dwM, dwU;
    CK_SLOT_ID slotM = 0, slotU = 0;

    /* Default: both scopes on the one bound slot. */
    g_aScopeSlot[P11_SCOPE_USER]    = pCtx->slotId;
    g_aScopeSlot[P11_SCOPE_MACHINE] = pCtx->slotId;
    g_bPerScope                     = FALSE;

    /* A caller selection names ONE token; per-scope tokens name two. The
     * two cannot both be honoured, so this is refused rather than resolved
     * by precedence. Silently letting the per-scope configuration win would
     * leave the caller's NCryptSetProperty accepted and ignored, which is
     * the failure mode the deferred binding exists to eliminate — and the
     * caller is the party least able to notice, because it asked and was
     * told yes. */
    if ((g_bSelLabelSet || g_bSelSlotSet) &&
        (GetEnvironmentVariableA(KSP_MACHINE_TOKEN_LABEL_ENV, NULL, 0) ||
         GetEnvironmentVariableA(KSP_USER_TOKEN_LABEL_ENV, NULL, 0) ||
         GetEnvironmentVariableA(KSP_MACHINE_SLOT_ENV, NULL, 0) ||
         GetEnvironmentVariableA(KSP_USER_SLOT_ENV, NULL, 0))) {
        LOG_ERROR("A token chosen through NCryptSetProperty cannot be "
                  "reconciled with per-scope tokens: one names a single "
                  "token, the other names two", NTE_INVALID_PARAMETER);
        return FALSE;
    }

    dwM = GetEnvironmentVariableA(KSP_MACHINE_TOKEN_LABEL_ENV,
                                  szMachine, sizeof(szMachine));
    dwU = GetEnvironmentVariableA(KSP_USER_TOKEN_LABEL_ENV,
                                  szUser, sizeof(szUser));
    if (dwM >= sizeof(szMachine) || dwU >= sizeof(szUser)) {
        LOG_ERROR("A per-scope token label is longer than CKA_LABEL",
                  NTE_INVALID_PARAMETER);
        return FALSE;
    }

    if (dwM > 0 || dwU > 0) {
        /* Belt and braces, and recorded as such: an absent label is the
         * empty string, which P11_TokenLabelMatches matches against no
         * token, so the lookup below would fail anyway. Removing this check
         * does not change the OUTCOME, only the error message — which is
         * why no test distinguishes the two, and why claiming it as the
         * thing that refuses a half configuration would be false. The
         * SLOT path's equivalent check further down IS load-bearing. */
        if (dwM == 0 || dwU == 0) {
            LOG_ERROR("Per-scope tokens need BOTH "
                      KSP_MACHINE_TOKEN_LABEL_ENV " and "
                      KSP_USER_TOKEN_LABEL_ENV ": one alone would put the "
                      "other scope's keys on the named token",
                      NTE_INVALID_PARAMETER);
            return FALSE;
        }
        if (pCtx->pFunctionList->C_GetSlotList(CK_TRUE, aSlots,
                                               &ulCount) != CKR_OK)
            return FALSE;
        if (!FindSlotByLabel(pCtx, aSlots, ulCount, szMachine, &slotM)) {
            LOG_ERROR("No token carries " KSP_MACHINE_TOKEN_LABEL_ENV,
                      NTE_NO_KEY);
            return FALSE;
        }
        if (!FindSlotByLabel(pCtx, aSlots, ulCount, szUser, &slotU)) {
            LOG_ERROR("No token carries " KSP_USER_TOKEN_LABEL_ENV,
                      NTE_NO_KEY);
            return FALSE;
        }
    } else {
        CK_ULONG n = P11_MAX_SLOTS;
        BOOL     bM, bU;

        if (pCtx->pFunctionList->C_GetSlotList(CK_TRUE, aSlots, &n) != CKR_OK)
            return TRUE;        /* no per-scope request to satisfy */
        ulCount = n;

        bM = SlotFromEnv(KSP_MACHINE_SLOT_ENV, aSlots, ulCount, &slotM);
        bU = SlotFromEnv(KSP_USER_SLOT_ENV,    aSlots, ulCount, &slotU);
        if (!bM && !bU)
            return TRUE;        /* ordinary single-token deployment */
        /* Load-bearing, unlike its counterpart on the label path. An
         * unset slot variable leaves slotU at 0, which is a perfectly
         * valid slot — so without this check a deployment naming only
         * KSP_MACHINE_SLOT=1 would silently put every user key on slot 0,
         * a token it never asked for, and report success. */
        if (!bM || !bU) {
            LOG_ERROR("Per-scope tokens need BOTH " KSP_MACHINE_SLOT_ENV
                      " and " KSP_USER_SLOT_ENV, NTE_INVALID_PARAMETER);
            return FALSE;
        }
    }

    /* Two names resolving to one token is not isolation, and saying so is
     * the whole point of this feature. Refused rather than accepted: a
     * deployment believing its scopes are separated when they share a
     * token and a PIN is in a worse position than one that knows they are
     * not. */
    if (slotM == slotU) {
        LOG_ERROR("The machine and user scopes resolve to the SAME token; "
                  "that is not isolation", NTE_INVALID_PARAMETER);
        return FALSE;
    }

    g_aScopeSlot[P11_SCOPE_MACHINE] = slotM;
    g_aScopeSlot[P11_SCOPE_USER]    = slotU;
    g_bPerScope                     = TRUE;

    /* The context's own slotId is the USER scope's. It is what
     * KSP_SLOT_PROPERTY reports and what the capability probe reads, and
     * the user scope is the one an unscoped caller gets. */
    pCtx->slotId = slotU;

    LOG_INFO("Per-scope tokens: machine=slot %lu, user=slot %lu",
             (unsigned long)slotM, (unsigned long)slotU);
    return TRUE;
}

SECURITY_STATUS P11_EnsureSlotSelected(void)
{
    SECURITY_STATUS ss;

    ss = P11_Initialize();
    if (ss != ERROR_SUCCESS)
        return ss;

    if (g_bSlotBound)
        return ERROR_SUCCESS;

    EnterCriticalSection(&g_initLock);
    if (!g_bSlotBound) {
        if (!SelectSlot(&g_ctx)) {
            LeaveCriticalSection(&g_initLock);
            return NTE_NO_KEY;
        }
        /* Per-scope tokens, if the deployment asked for them. This runs
         * after SelectSlot because it defaults both scopes to that slot,
         * and it can override the context's own slotId. */
        if (!SelectScopeSlots(&g_ctx)) {
            LeaveCriticalSection(&g_initLock);
            return NTE_NO_KEY;
        }
        /* A refusal is not fatal — see P11_ProbeCapabilities. */
        (void)P11_ProbeCapabilities();
        g_bSlotBound = TRUE;
        LOG_INFO("Slot bound: %lu", (unsigned long)g_ctx.slotId);
    }
    LeaveCriticalSection(&g_initLock);
    return ERROR_SUCCESS;
}

/* The slot a scope's keys live in. Valid once the slot is bound; before
 * that both answers are the unbound context's slotId, which is why every
 * caller goes through P11_EnsureSlotSelected first. */
CK_SLOT_ID P11_GetScopeSlot(int nScope)
{
    if (nScope < 0 || nScope >= P11_SCOPE_COUNT)
        nScope = P11_SCOPE_USER;
    return g_aScopeSlot[nScope];
}

/* TRUE when the two scopes are on different tokens. */
BOOL P11_HasPerScopeTokens(void)
{
    return g_bPerScope;
}

/* Choose the token, until the slot is bound.
 *
 * Refused once bound rather than accepted and ignored: a caller told its
 * selection succeeded would go on using the previous token believing it had
 * switched, which is the failure mode KSP_NotifyChangeKey had. */
SECURITY_STATUS P11_SetTokenSelection(const char *szLabel,
                                      const CK_SLOT_ID *pSlot)
{
    SECURITY_STATUS ss = ERROR_SUCCESS;

    if ((szLabel == NULL) == (pSlot == NULL))
        return NTE_INVALID_PARAMETER;   /* exactly one of the two */

    InitOnceExecuteOnce(&g_lockOnce, CreateInitLock, NULL, NULL);
    EnterCriticalSection(&g_initLock);

    if (g_bSlotBound) {
        LOG_ERROR("Token selection is too late: the slot is already bound "
                  "and PKCS#11 cannot move a session between tokens",
                  NTE_INVALID_HANDLE);
        ss = NTE_INVALID_HANDLE;
    } else if (szLabel) {
        size_t cb = strlen(szLabel);
        if (cb == 0 || cb > P11_TOKEN_LABEL_LEN) {
            ss = NTE_INVALID_PARAMETER;
        } else {
            memcpy(g_szSelLabel, szLabel, cb);
            g_szSelLabel[cb] = '\0';
            g_bSelLabelSet = TRUE;
            g_bSelSlotSet  = FALSE;   /* one selection at a time */
        }
    } else {
        g_selSlot      = *pSlot;
        g_bSelSlotSet  = TRUE;
        g_bSelLabelSet = FALSE;
    }

    LeaveCriticalSection(&g_initLock);
    return ss;
}

/* Forget a token selection, reverting to the environment and then the
 * default. Refused once the slot is bound, like setting one.
 *
 * P11_Finalize deliberately KEEPS the selection, so that a re-initialise
 * honours what the caller asked for; this is how a caller takes it back. */
SECURITY_STATUS P11_ClearTokenSelection(void)
{
    SECURITY_STATUS ss = ERROR_SUCCESS;

    InitOnceExecuteOnce(&g_lockOnce, CreateInitLock, NULL, NULL);
    EnterCriticalSection(&g_initLock);
    if (g_bSlotBound) {
        ss = NTE_INVALID_HANDLE;
    } else {
        g_bSelLabelSet   = FALSE;
        g_bSelSlotSet    = FALSE;
        g_szSelLabel[0]  = '\0';
    }
    LeaveCriticalSection(&g_initLock);
    return ss;
}

/* TRUE once the slot can no longer change. */
BOOL P11_IsSlotBound(void)
{
    return g_bSlotBound;
}

/* Initialise the PKCS#11 context (thread-safe, idempotent on success).
 *
 * Idempotent once it has succeeded; retried while it has not. See the note
 * on the guard above for why that distinction exists. */
SECURITY_STATUS P11_Initialize(void)
{
    SECURITY_STATUS ss;

    InitOnceExecuteOnce(&g_lockOnce, CreateInitLock, NULL, NULL);

    EnterCriticalSection(&g_initLock);
    if (g_initStatus != ERROR_SUCCESS)
        TryInitialize();
    ss = g_initStatus;
    LeaveCriticalSection(&g_initLock);

    return ss;
}

/* Free the PKCS#11 context */
void P11_Finalize(void)
{
    P11_ReleaseCapabilities();

    /* Return to the not-initialised state so a later P11_Initialize starts
     * over. Finalising while another thread holds a session is unsafe and
     * always has been — this is called from DllMain on process detach. */
    g_initStatus = NTE_PROVIDER_DLL_FAIL;

    /* The slot binding goes with it. Leaving it set would make a later
     * P11_EnsureSlotSelected return success without selecting or probing
     * anything, against a context that no longer has a module loaded —
     * a stale "already done" for work that has been undone. The caller's
     * selection is kept, so a re-initialise honours what was asked for. */
    g_bSlotBound = FALSE;
    g_bPerScope  = FALSE;
    g_aScopeSlot[P11_SCOPE_USER]    = 0;
    g_aScopeSlot[P11_SCOPE_MACHINE] = 0;

    if (g_ctx.bInitialized && g_ctx.pFunctionList) {
        g_ctx.pFunctionList->C_Finalize(NULL);
        g_ctx.bInitialized = FALSE;
    }
    if (g_ctx.hModule) {
        FreeLibrary(g_ctx.hModule);
        g_ctx.hModule = NULL;
    }
}

/* Return a pointer to the global context */
P11_CONTEXT *P11_GetContext(void)
{
    return &g_ctx;
}
