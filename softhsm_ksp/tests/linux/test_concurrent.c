/* test_concurrent.c — the re-entrancy claim, tested.
 *
 * CLAUDE.md states, under Code Conventions, that "all 22 KSP functions are
 * re-entrant". Nothing had ever tested it. Every one of the 1572 unit
 * assertions and 228 live-token assertions runs on a single thread, so the
 * claim rested entirely on reading the code.
 *
 * That matters more here than it would in most code, for two reasons.
 *
 * The provider multiplexes every caller onto a pool of 16 long-lived
 * PKCS#11 sessions. A session is not a passive handle: C_SignInit binds an
 * operation to it, and PKCS#11 v2.40 §5.2 says a second C_SignInit on a
 * session with a live operation must fail. So a pool bug does not merely
 * slow things down — it lets one caller's operation land on another
 * caller's session. Session 10 found exactly that defect (a size query
 * leaving an operation active on a pooled session) and found it
 * single-threaded, by luck.
 *
 * And the failure is silent. If two threads' operations cross, the
 * plausible outcome is not a crash but a signature computed over the wrong
 * data, or with the wrong key, returned with SECURITY_STATUS ERROR_SUCCESS.
 * A test that only checks return codes would pass through all of it.
 *
 * So correctness here is checked by VALUE, not by status:
 *
 *   RSA PKCS#1 v1.5 signing is deterministic. The same key over the same
 *   hash yields the same bytes, every time. This suite computes each
 *   reference signature on one thread, then has many threads recompute it
 *   under contention and compares byte for byte. Any crossing of keys,
 *   hashes or sessions changes the bytes, and the comparison catches it
 *   whatever the return code says.
 *
 * ECDSA is deliberately not used for that check: it is randomised, so two
 * correct signatures over the same hash differ, and the comparison would
 * have nothing to say.
 *
 * Thread count is deliberately larger than the pool. With 32 threads and
 * 16 sessions every thread must block on the semaphore and reuse a session
 * another thread has just returned, which is the state the pool is least
 * exercised in and the only state in which a release-side bug can show.
 *
 * Run this under ThreadSanitizer as well as plain: `make tsan`. The two
 * answer different questions — TSan reports races whether or not they
 * corrupted anything on this run, and the value checks report corruption
 * whether or not TSan saw the race that caused it.
 *
 * What this suite detects, established by injecting each defect:
 *
 *   - Unsynchronised pool state (the pool lock removed from
 *     P11_AcquireSession): caught by TSan, which names bInUse in
 *     P11_AcquireSession and P11_ReleaseSession. NOT caught by the value
 *     checks on the runs tried — the window is narrow and the wrong entry
 *     usually still yields a usable session. That asymmetry is the reason
 *     both are run.
 *   - A release freeing the wrong entry: caught by the value checks
 *     (CKR_OPERATION_ACTIVE surfacing as failures) and by the pool
 *     integrity check.
 *   - A leaked session: caught by the pool integrity check between
 *     phases, at the cost of one five-second timeout. Honest limitation —
 *     a PARTIAL leak degrades throughput long before it fails anything,
 *     because a pool of 2 still serves 32 threads, just slowly. So the
 *     phase that leaked runs to completion first and the suite is slow
 *     before it is red. Bounding each worker's failures (below) caps the
 *     fully-drained case; nothing cheap caps the partial one.
 */
#include "../mock/windows_compat.h"
#include "../../src/pkcs11/pkcs11.h"
#include "../../src/pkcs11/p11_context.h"
#include "../../src/pkcs11/p11_caps.h"
#include "../../src/pkcs11/p11_session.h"
#include "../../src/pkcs11/p11_utils.h"
#include "../../src/ksp/ksp_key.h"
#include "../../src/ksp/ksp_crypto.h"
#include "../../src/ksp/ksp_properties.h"
#include "../../src/ksp/ksp_provider.h"
#include "../../src/common/config.h"
#include "../../src/common/memory.h"
#include "../unit/test_framework.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <pthread.h>

/* More threads than P11_SESSION_POOL_SIZE, on purpose — see the header. */
#define N_THREADS     32
#define N_ITERATIONS  12

/* A worker gives up after this many failures of its own.
 *
 * Not a tolerance — any failure at all fails the suite. It bounds how long
 * a BROKEN pool takes to report. A leaked session is permanent, so once
 * the pool has drained every acquire waits out the full five-second
 * timeout; without this, one dropped release turned a three-second suite
 * into one still grinding after five minutes, which is a worse way to
 * learn about a bug than a prompt red. Found by injecting exactly that. */
#define MAX_FAILS_PER_WORKER 3

#define RSA_BITS      2048
#define RSA_SIG_BYTES (RSA_BITS / 8)

static NCRYPT_PROV_HANDLE g_hProv;

/* Counters written by every worker. Each has its own slot, so the array
 * itself needs no lock — a shared counter would be a race introduced by
 * the test rather than found by it. */
typedef struct {
    int nOk;
    int nStatusFail;
    int nWrongLength;
    int nWrongBytes;     /* the one that matters: right status, wrong data */
    SECURITY_STATUS ssFirstFail;
} WORKER_RESULT;

static WORKER_RESULT g_results[N_THREADS];

/* ── Phase 1: many threads, one shared key ──────────────────────────────── */
/*
 * The sharpest test of the pool. Every thread signs the SAME hash with the
 * SAME key, so every thread must produce identical bytes. Sessions are
 * drawn and returned continuously, so if a release ever hands a session
 * back while another thread still holds it, two C_SignInit calls collide
 * on one session and the result is either an error or the wrong bytes.
 */
typedef struct {
    int    idx;
    NCRYPT_KEY_HANDLE hKey;
    const BYTE *pbHash;
    DWORD  cbHash;
    const BYTE *pbExpected;
    DWORD  cbExpected;
} SHARED_ARG;

static void *SharedKeyWorker(void *pv)
{
    SHARED_ARG    *pArg = (SHARED_ARG *)pv;
    WORKER_RESULT *pRes = &g_results[pArg->idx];
    int i;

    for (i = 0; i < N_ITERATIONS; i++) {
        BYTE  abSig[RSA_SIG_BYTES + 64];
        DWORD cbSig = 0;
        SECURITY_STATUS ss;

        memset(abSig, 0, sizeof(abSig));

        ss = KSP_SignHash(g_hProv, pArg->hKey, NULL,
                          (BYTE *)pArg->pbHash, pArg->cbHash,
                          abSig, sizeof(abSig), &cbSig,
                          NCRYPT_PAD_PKCS1_FLAG);

        if (ss != ERROR_SUCCESS) {
            if (pRes->nStatusFail == 0) pRes->ssFirstFail = ss;
            pRes->nStatusFail++;
            if (pRes->nStatusFail >= MAX_FAILS_PER_WORKER) break;
            continue;
        }
        if (cbSig != pArg->cbExpected) {
            pRes->nWrongLength++;
            continue;
        }
        /* The whole point. A crossed session or a crossed key returns
         * ERROR_SUCCESS and the wrong bytes. */
        if (memcmp(abSig, pArg->pbExpected, cbSig) != 0) {
            pRes->nWrongBytes++;
            continue;
        }
        pRes->nOk++;
    }
    return NULL;
}

/* ── Phase 2: many threads, one key each ────────────────────────────────── */
/*
 * Each thread owns a key and a hash nobody else uses, and knows the bytes
 * its own key must produce. If thread N ever receives thread M's
 * signature, N sees bytes it did not expect. This separates "the pool is
 * corrupt" from "the token is unhappy under load": here a wrong-bytes
 * count is unambiguously a key or session crossing.
 */
typedef struct {
    int   idx;
    NCRYPT_KEY_HANDLE hKey;
    BYTE  abHash[32];
    BYTE  abExpected[RSA_SIG_BYTES];
    DWORD cbExpected;
} OWN_ARG;

static OWN_ARG g_ownArgs[N_THREADS];

static void *OwnKeyWorker(void *pv)
{
    OWN_ARG       *pArg = (OWN_ARG *)pv;
    WORKER_RESULT *pRes = &g_results[pArg->idx];
    int i;

    for (i = 0; i < N_ITERATIONS; i++) {
        BYTE  abSig[RSA_SIG_BYTES + 64];
        DWORD cbSig = 0;
        SECURITY_STATUS ss;

        memset(abSig, 0, sizeof(abSig));

        ss = KSP_SignHash(g_hProv, pArg->hKey, NULL,
                          pArg->abHash, sizeof(pArg->abHash),
                          abSig, sizeof(abSig), &cbSig,
                          NCRYPT_PAD_PKCS1_FLAG);

        if (ss != ERROR_SUCCESS) {
            if (pRes->nStatusFail == 0) pRes->ssFirstFail = ss;
            pRes->nStatusFail++;
            if (pRes->nStatusFail >= MAX_FAILS_PER_WORKER) break;
            continue;
        }
        if (cbSig != pArg->cbExpected)          { pRes->nWrongLength++; continue; }
        if (memcmp(abSig, pArg->abExpected, cbSig) != 0) {
            pRes->nWrongBytes++;
            continue;
        }
        pRes->nOk++;
    }
    return NULL;
}

/* ── Phase 3: mixed traffic ─────────────────────────────────────────────── */
/*
 * Signing alone exercises one acquire/release shape. Real callers
 * interleave size queries, exports, property reads and enumeration, each
 * of which takes and returns a session on a different path — and the size
 * query is the operation whose pooled-session handling was already wrong
 * once. Mixing them is what makes a release-side bug likely to land while
 * another thread is mid-acquire.
 */
typedef struct {
    int idx;
    NCRYPT_KEY_HANDLE hKey;
} MIXED_ARG;

static void *MixedWorker(void *pv)
{
    MIXED_ARG     *pArg = (MIXED_ARG *)pv;
    WORKER_RESULT *pRes = &g_results[pArg->idx];
    int i;

    for (i = 0; i < N_ITERATIONS; i++) {
        SECURITY_STATUS ss;
        DWORD cb = 0;
        BYTE  ab[1024];

        if (pRes->nStatusFail >= MAX_FAILS_PER_WORKER) break;

        /* Size query — no output buffer. */
        {
            BYTE abHash[32];
            memset(abHash, (BYTE)(pArg->idx + 1), sizeof(abHash));
            ss = KSP_SignHash(g_hProv, pArg->hKey, NULL, abHash, 32,
                              NULL, 0, &cb, NCRYPT_PAD_PKCS1_FLAG);
            if (ss != ERROR_SUCCESS) {
                if (pRes->nStatusFail == 0) pRes->ssFirstFail = ss;
                pRes->nStatusFail++;
            } else if (cb != RSA_SIG_BYTES) {
                pRes->nWrongLength++;
            } else {
                pRes->nOk++;
            }
        }

        /* Public key export. */
        cb = 0;
        ss = KSP_ExportKey(g_hProv, pArg->hKey, 0, BCRYPT_RSAPUBLIC_BLOB,
                           NULL, ab, sizeof(ab), &cb, 0);
        if (ss != ERROR_SUCCESS) {
            if (pRes->nStatusFail == 0) pRes->ssFirstFail = ss;
            pRes->nStatusFail++;
        } else {
            pRes->nOk++;
        }

        /* A key property read. */
        cb = 0;
        ss = KSP_GetKeyProperty(g_hProv, pArg->hKey, NCRYPT_LENGTH_PROPERTY,
                                ab, sizeof(ab), &cb, 0);
        if (ss != ERROR_SUCCESS) {
            if (pRes->nStatusFail == 0) pRes->ssFirstFail = ss;
            pRes->nStatusFail++;
        } else {
            pRes->nOk++;
        }
    }
    return NULL;
}

/* ── Helpers ────────────────────────────────────────────────────────────── */

static void ResetResults(void)
{
    memset(g_results, 0, sizeof(g_results));
}

/* Sum the per-thread counters and assert on the totals. */
static void ReportPhase(const char *szPhase, int nExpectedOk)
{
    int i, nOk = 0, nStatus = 0, nLen = 0, nBytes = 0;
    SECURITY_STATUS ssFirst = ERROR_SUCCESS;

    for (i = 0; i < N_THREADS; i++) {
        nOk     += g_results[i].nOk;
        nStatus += g_results[i].nStatusFail;
        nLen    += g_results[i].nWrongLength;
        nBytes  += g_results[i].nWrongBytes;
        if (ssFirst == ERROR_SUCCESS && g_results[i].ssFirstFail != ERROR_SUCCESS)
            ssFirst = g_results[i].ssFirstFail;
    }

    printf("      [%s: ok=%d status_fail=%d wrong_len=%d wrong_bytes=%d",
           szPhase, nOk, nStatus, nLen, nBytes);
    if (ssFirst != ERROR_SUCCESS)
        printf(" first_fail=0x%08lX", (unsigned long)ssFirst);
    printf("]\n");

    /* Wrong bytes first: it is the finding that a status-only test misses,
     * and the one that reaches a caller as a bad signature. */
    ASSERT_EQ("No operation returned success with the wrong bytes",
              (DWORD)nBytes, 0U);
    ASSERT_EQ("No operation returned the wrong length", (DWORD)nLen, 0U);
    ASSERT_EQ("No operation failed outright", (DWORD)nStatus, 0U);
    ASSERT_EQ("Every operation completed", (DWORD)nOk, (DWORD)nExpectedOk);
}

static SECURITY_STATUS MakeRsaKey(NCRYPT_KEY_HANDLE *phKey, LPCWSTR szName)
{
    SECURITY_STATUS   ss;
    NCRYPT_KEY_HANDLE hOld = 0;
    DWORD             dwBits = RSA_BITS;

    if (KSP_OpenKey(g_hProv, &hOld, szName, 0, 0) == ERROR_SUCCESS)
        KSP_DeleteKey(g_hProv, hOld, 0);

    ss = KSP_CreatePersistedKey(g_hProv, phKey, ALG_RSA, szName,
                                AT_SIGNATURE, 0);
    if (ss != ERROR_SUCCESS) {
        printf("      [CreatePersistedKey(%ls) = 0x%08lX]\n",
               szName, (unsigned long)ss);
        return ss;
    }

    /* KSP_CreatePersistedKey generates and finalizes here — the default
     * size is RSA_BITS. Setting NCRYPT_LENGTH_PROPERTY afterwards is
     * rejected, correctly, because the key already exists. */
    (void)dwBits;
    return ERROR_SUCCESS;
}

/* The reference signature, computed on one thread with nothing else
 * running. Everything the workers produce is compared against this. */
static SECURITY_STATUS ReferenceSignature(
    NCRYPT_KEY_HANDLE hKey, const BYTE *pbHash, DWORD cbHash,
    BYTE *pbOut, DWORD cbOut, DWORD *pcbOut)
{
    return KSP_SignHash(g_hProv, hKey, NULL, (BYTE *)pbHash, cbHash,
                        pbOut, cbOut, pcbOut, NCRYPT_PAD_PKCS1_FLAG);
}

/* Is the pool whole — all 16 sessions available, all distinct?
 *
 * Called after every phase rather than only at the end. A leaked session
 * (acquired and never released) is permanent, so once the pool has drained
 * every later acquire waits out the full 5-second timeout and fails. Left
 * to the end, one leaked release turned a 3-second suite into one that was
 * still running after five minutes — thousands of slow failures instead of
 * one clear answer. Checking between phases costs nothing when the pool is
 * healthy and names the phase that broke it when it is not.
 */
static void AssertPoolWhole(const char *szAfter)
{
    CK_SESSION_HANDLE aSessions[P11_SESSION_POOL_SIZE];
    int  nTaken = 0;
    BOOL bAllDistinct = TRUE;
    int  i, a, b;
    char szMsg[160];

    for (i = 0; i < P11_SESSION_POOL_SIZE; i++) {
        if (P11_AcquireSession(&aSessions[nTaken]) != ERROR_SUCCESS)
            break;
        nTaken++;
    }

    snprintf(szMsg, sizeof(szMsg),
             "All %d sessions still available after %s",
             P11_SESSION_POOL_SIZE, szAfter);
    ASSERT_EQ(szMsg, (DWORD)nTaken, (DWORD)P11_SESSION_POOL_SIZE);

    /* Two pool entries handing out one session handle would mean two
     * callers sharing a session, which is the corruption this file exists
     * to find. */
    for (a = 0; a < nTaken && bAllDistinct; a++)
        for (b = a + 1; b < nTaken; b++)
            if (aSessions[a] == aSessions[b]) { bAllDistinct = FALSE; break; }

    snprintf(szMsg, sizeof(szMsg),
             "and no two pool entries share a session handle after %s",
             szAfter);
    ASSERT(szMsg, bAllDistinct);

    for (i = 0; i < nTaken; i++)
        P11_ReleaseSession(aSessions[i]);
}

int main(void)
{
    SECURITY_STATUS   ss;
    pthread_t         aThreads[N_THREADS];
    int               i;

    /* Line-buffered, so a run that has to be killed still shows how far it
     * got. Block buffering lost the entire transcript of a deliberately
     * broken run, which is the run whose output matters most. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    printf("\n╔══ KSP concurrency against a live token ══\n");

    ss = P11_Initialize();
    ASSERT_OK("PKCS#11 initialised", ss);
    if (ss != ERROR_SUCCESS) {
        TEST_REPORT();
        TEST_EXIT();
    }

    ss = P11_SessionPool_Initialize();
    ASSERT_OK("Session pool initialised", ss);

    ss = KSP_OpenProvider(&g_hProv, KSP_PROVIDER_NAME, 0);
    ASSERT_OK("Provider opened", ss);

    printf("  %d threads over a pool of %d sessions, %d iterations each\n",
           N_THREADS, P11_SESSION_POOL_SIZE, N_ITERATIONS);

    /* ── Suite 1 : one key, every thread, identical expected bytes ──────── */
    TEST_SUITE("Shared key under contention");
    {
        NCRYPT_KEY_HANDLE hKey = 0;
        BYTE   abHash[32];
        BYTE   abRef[RSA_SIG_BYTES + 64];
        DWORD  cbRef = 0;
        SHARED_ARG aArgs[N_THREADS];

        for (i = 0; i < 32; i++)
            abHash[i] = (BYTE)(i * 7 + 1);

        ss = MakeRsaKey(&hKey, L"conc-shared");
        ASSERT_OK("Shared RSA key created", ss);

        if (ss == ERROR_SUCCESS) {
            ss = ReferenceSignature(hKey, abHash, sizeof(abHash),
                                    abRef, sizeof(abRef), &cbRef);
            ASSERT_OK("Reference signature computed single-threaded", ss);
            ASSERT_EQ("and it is the modulus size", cbRef,
                      (DWORD)RSA_SIG_BYTES);

            /* If RSA PKCS#1 were not deterministic the whole comparison
             * would be meaningless, so this checks the premise rather than
             * assuming it. */
            {
                BYTE  abAgain[RSA_SIG_BYTES + 64];
                DWORD cbAgain = 0;
                ss = ReferenceSignature(hKey, abHash, sizeof(abHash),
                                        abAgain, sizeof(abAgain), &cbAgain);
                ASSERT_OK("Signed a second time", ss);
                ASSERT("PKCS#1 v1.5 is deterministic — the premise of the "
                       "byte comparison below",
                       cbAgain == cbRef &&
                       memcmp(abAgain, abRef, cbRef) == 0);
            }

            ResetResults();
            for (i = 0; i < N_THREADS; i++) {
                aArgs[i].idx        = i;
                aArgs[i].hKey       = hKey;
                aArgs[i].pbHash     = abHash;
                aArgs[i].cbHash     = sizeof(abHash);
                aArgs[i].pbExpected = abRef;
                aArgs[i].cbExpected = cbRef;
                pthread_create(&aThreads[i], NULL, SharedKeyWorker, &aArgs[i]);
            }
            for (i = 0; i < N_THREADS; i++)
                pthread_join(aThreads[i], NULL);

            ReportPhase("shared key", N_THREADS * N_ITERATIONS);

            AssertPoolWhole("the shared-key phase");

            ss = KSP_DeleteKey(g_hProv, hKey, 0);
            ASSERT_OK("Shared key deleted", ss);
        }
    }

    /* ── Suite 2 : a key per thread, each with its own expected bytes ───── */
    TEST_SUITE("One key per thread");
    {
        int nCreated = 0;

        for (i = 0; i < N_THREADS; i++) {
            WCHAR szName[64];
            int   j;

            swprintf(szName, 64, L"conc-own-%d", i);
            g_ownArgs[i].idx  = i;
            g_ownArgs[i].hKey = 0;

            for (j = 0; j < 32; j++)
                g_ownArgs[i].abHash[j] = (BYTE)(i * 31 + j);

            if (MakeRsaKey(&g_ownArgs[i].hKey, szName) != ERROR_SUCCESS)
                continue;

            if (ReferenceSignature(g_ownArgs[i].hKey,
                                   g_ownArgs[i].abHash, 32,
                                   g_ownArgs[i].abExpected,
                                   sizeof(g_ownArgs[i].abExpected),
                                   &g_ownArgs[i].cbExpected) == ERROR_SUCCESS)
                nCreated++;
        }

        ASSERT_EQ("A key per thread, each with a reference signature",
                  (DWORD)nCreated, (DWORD)N_THREADS);

        if (nCreated == N_THREADS) {
            /* Every thread's expected bytes must differ from every other's,
             * or "thread N got thread M's signature" would be undetectable. */
            BOOL bAllDistinct = TRUE;
            int  a, b;
            for (a = 0; a < N_THREADS && bAllDistinct; a++)
                for (b = a + 1; b < N_THREADS; b++)
                    if (memcmp(g_ownArgs[a].abExpected,
                               g_ownArgs[b].abExpected,
                               g_ownArgs[a].cbExpected) == 0) {
                        bAllDistinct = FALSE;
                        break;
                    }
            ASSERT("Each thread's expected signature is distinct, so a "
                   "crossed key cannot go unnoticed", bAllDistinct);

            ResetResults();
            for (i = 0; i < N_THREADS; i++)
                pthread_create(&aThreads[i], NULL, OwnKeyWorker,
                               &g_ownArgs[i]);
            for (i = 0; i < N_THREADS; i++)
                pthread_join(aThreads[i], NULL);

            ReportPhase("own key", N_THREADS * N_ITERATIONS);
            AssertPoolWhole("the own-key phase");
        }

        for (i = 0; i < N_THREADS; i++)
            if (g_ownArgs[i].hKey)
                KSP_DeleteKey(g_hProv, g_ownArgs[i].hKey, 0);
    }

    /* ── Suite 3 : mixed operations, mixed acquire/release paths ────────── */
    TEST_SUITE("Mixed traffic");
    {
        NCRYPT_KEY_HANDLE hKey = 0;
        MIXED_ARG aArgs[N_THREADS];

        ss = MakeRsaKey(&hKey, L"conc-mixed");
        ASSERT_OK("Mixed-traffic RSA key created", ss);

        if (ss == ERROR_SUCCESS) {
            ResetResults();
            for (i = 0; i < N_THREADS; i++) {
                aArgs[i].idx  = i;
                aArgs[i].hKey = hKey;
                pthread_create(&aThreads[i], NULL, MixedWorker, &aArgs[i]);
            }
            for (i = 0; i < N_THREADS; i++)
                pthread_join(aThreads[i], NULL);

            /* Three operations per iteration. */
            ReportPhase("mixed", N_THREADS * N_ITERATIONS * 3);
            AssertPoolWhole("the mixed-traffic phase");

            ss = KSP_DeleteKey(g_hProv, hKey, 0);
            ASSERT_OK("Mixed-traffic key deleted", ss);
        }
    }

    /* ── Suite 4 : the pool is whole afterwards ─────────────────────────── */
    TEST_SUITE("The pool survived");
    AssertPoolWhole("everything");

    KSP_FreeProvider(g_hProv);
    P11_SessionPool_Finalize();
    P11_Finalize();

    TEST_REPORT();
    TEST_EXIT();
}
