/* p11_caps.c — token capability probe. See p11_caps.h for why. */
/* Deliberately does not include p11_utils.h. The only thing it would want
 * from there is P11RvToSecStatus, and depending on it would drag the whole
 * utility module into every unit suite that links the provider. The probe's
 * return value is advisory — nothing branches on which failure it was — so
 * the CK_RV is logged and a single status returned. */
#include "p11_caps.h"
#include "p11_context.h"
#include "../common/config.h"
#include "../common/logging.h"
#include "../common/memory.h"
#include <string.h>

typedef struct _P11_MECH_CAP {
    CK_MECHANISM_TYPE type;
    CK_FLAGS          flags;
} P11_MECH_CAP;

static P11_MECH_CAP *g_pCaps       = NULL;
static CK_ULONG      g_ulCapCount  = 0;
static BOOL          g_bProbed     = FALSE;
static CK_BYTE       g_bMajor      = 0;
static CK_BYTE       g_bMinor      = 0;

void P11_ReleaseCapabilities(void)
{
    if (g_pCaps) {
        KSP_Free(g_pCaps);
        g_pCaps = NULL;
    }
    g_ulCapCount = 0;
    g_bProbed    = FALSE;
    g_bMajor     = 0;
    g_bMinor     = 0;
}

BOOL P11_CapsProbed(void)
{
    return g_bProbed;
}

void P11_GetCryptokiVersion(CK_BYTE *pbMajor, CK_BYTE *pbMinor)
{
    if (pbMajor) *pbMajor = g_bMajor;
    if (pbMinor) *pbMinor = g_bMinor;
}

BOOL P11_CryptokiAtLeast(CK_BYTE bMajor, CK_BYTE bMinor)
{
    if (!g_bProbed)
        return FALSE;
    if (g_bMajor != bMajor)
        return g_bMajor > bMajor;
    return g_bMinor >= bMinor;
}

BOOL P11_HasMechanism(CK_MECHANISM_TYPE mech)
{
    CK_ULONG i;

    /* No probe, no opinion. Answering FALSE here would empty the provider's
     * algorithm list on any token that declines C_GetMechanismList. */
    if (!g_bProbed)
        return TRUE;

    for (i = 0; i < g_ulCapCount; i++) {
        if (g_pCaps[i].type == mech)
            return TRUE;
    }
    return FALSE;
}

CK_FLAGS P11_MechanismFlags(CK_MECHANISM_TYPE mech)
{
    CK_ULONG i;

    if (!g_bProbed)
        return 0;

    for (i = 0; i < g_ulCapCount; i++) {
        if (g_pCaps[i].type == mech)
            return g_pCaps[i].flags;
    }
    return 0;
}

SECURITY_STATUS P11_ProbeCapabilities(void)
{
    P11_CONTEXT       *pCtx = P11_GetContext();
    CK_MECHANISM_TYPE *pList = NULL;
    CK_ULONG           ulCount = 0;
    CK_ULONG           i;
    CK_RV              rv;
    CK_INFO            info;

    P11_ReleaseCapabilities();

    if (!pCtx || !pCtx->pFunctionList)
        return NTE_PROVIDER_DLL_FAIL;

    /* Cryptoki version first: it decides whether the v3.2 mechanism numbers
     * mean anything coming back from this module. A module that cannot
     * answer C_GetInfo is treated as pre-3.x, which only ever withholds
     * features. */
    memset(&info, 0, sizeof(info));
    rv = pCtx->pFunctionList->C_GetInfo(&info);
    if (rv == CKR_OK) {
        g_bMajor = info.cryptokiVersion.major;
        g_bMinor = info.cryptokiVersion.minor;
    } else {
        LOG_INFO("P11_ProbeCapabilities: C_GetInfo failed (0x%08lX), "
                 "treating the module as pre-3.x", (unsigned long)rv);
    }

    /* Two-call idiom: NULL asks how many, then the buffer is filled. */
    rv = pCtx->pFunctionList->C_GetMechanismList(pCtx->slotId, NULL, &ulCount);
    if (rv != CKR_OK) {
        LOG_INFO("P11_ProbeCapabilities: C_GetMechanismList refused "
                 "(0x%08lX); advertising the compiled-in list unfiltered",
                 (unsigned long)rv);
        return NTE_FAIL;
    }

    if (ulCount == 0) {
        /* A token that implements nothing is not a token this provider can
         * use, but it is also not this function's call to make. Record the
         * empty answer so advertisement reflects it. */
        LOG_INFO("P11_ProbeCapabilities: token advertises no mechanisms");
        g_bProbed = TRUE;
        return ERROR_SUCCESS;
    }

    /* Abandon the probe rather than truncate.
     *
     * Truncating looks tempting — keep the first N and carry on — but the
     * result is a capability view that is quietly wrong, and the provider
     * would then refuse algorithms the token really has. A view known to be
     * incomplete is worse than no view: with no view, P11_HasMechanism
     * answers permissively and nothing is lost. The bound is what stops a
     * module reporting an absurd count from driving the allocation. */
    if (ulCount > P11_MAX_MECHANISMS) {
        LOG_ERROR("P11_ProbeCapabilities - token reports an implausible "
                  "mechanism count; abandoning the probe", NTE_FAIL);
        LOG_INFO("P11_ProbeCapabilities: %lu mechanisms reported, limit is %d",
                 (unsigned long)ulCount, P11_MAX_MECHANISMS);
        return NTE_FAIL;
    }

    pList = (CK_MECHANISM_TYPE *)KSP_Alloc(ulCount * sizeof(CK_MECHANISM_TYPE));
    if (!pList)
        return NTE_NO_MEMORY;

    /* ulCount goes back in as the buffer's capacity. A module that grew its
     * list between the two calls returns CKR_BUFFER_TOO_SMALL rather than
     * overrunning, and that failure abandons the probe below. */
    rv = pCtx->pFunctionList->C_GetMechanismList(pCtx->slotId, pList, &ulCount);
    if (rv != CKR_OK) {
        KSP_Free(pList);
        LOG_INFO("P11_ProbeCapabilities: C_GetMechanismList failed on the "
                 "second call (0x%08lX)", (unsigned long)rv);
        return NTE_FAIL;
    }

    /* The module must not report back more than the buffer it was given. */
    if (ulCount > P11_MAX_MECHANISMS) {
        KSP_Free(pList);
        LOG_ERROR("P11_ProbeCapabilities - module returned more mechanisms "
                  "than the buffer it was given", NTE_FAIL);
        return NTE_FAIL;
    }

    g_pCaps = (P11_MECH_CAP *)KSP_AllocZero(ulCount * sizeof(P11_MECH_CAP));
    if (!g_pCaps) {
        KSP_Free(pList);
        return NTE_NO_MEMORY;
    }

    for (i = 0; i < ulCount; i++) {
        CK_MECHANISM_INFO mi;

        g_pCaps[i].type  = pList[i];
        g_pCaps[i].flags = 0;

        memset(&mi, 0, sizeof(mi));
        if (pCtx->pFunctionList->C_GetMechanismInfo(pCtx->slotId, pList[i],
                                                    &mi) == CKR_OK) {
            g_pCaps[i].flags = mi.flags;
        }
        /* A mechanism whose info cannot be read still counts as present:
         * C_GetMechanismList is the authority on what exists, and
         * C_GetMechanismInfo only adds detail. */
    }

    g_ulCapCount = ulCount;
    g_bProbed    = TRUE;
    KSP_Free(pList);

    LOG_INFO("P11_ProbeCapabilities: Cryptoki %u.%u, %lu mechanisms",
             (unsigned)g_bMajor, (unsigned)g_bMinor,
             (unsigned long)g_ulCapCount);
    return ERROR_SUCCESS;
}
