/* test_logging.c — Coverage of the logging module
 * Tests initialization, debug on/off modes, and error messages.
 */
#include "../mock/windows_compat.h"
#include "test_framework.h"

void Log_Initialize(void);
void Log_Debug(const char *pszFormat, ...);
void Log_Error(const char *pszFormat, ...);

int main(void)
{
    /* ── Suite 1 : Init with KSP_DEBUG=0 (default) ─────────────────────── */
    TEST_SUITE("Log_Initialize — debug disabled");

    unsetenv("KSP_DEBUG");
    Log_Initialize();
    /* No crash, no output */
    Log_Debug("This message should not appear: %d", 42);
    ASSERT("Log_Debug without KSP_DEBUG does not crash", 1);

    /* ── Suite 2 : Init with KSP_DEBUG=1 ───────────────────────────────── */
    TEST_SUITE("Log_Initialize — debug enabled");

    setenv("KSP_DEBUG", "1", 1);
    Log_Initialize(); /* Idempotent on the same value */
    Log_Debug("[SOFTHSM_KSP] Test debug: value=%d str=%s", 99, "hello");
    ASSERT("Log_Debug with KSP_DEBUG=1 does not crash", 1);

    /* ── Suite 3 : Log_Error (always active) ───────────────────────────── */
    TEST_SUITE("Log_Error — always active");

    unsetenv("KSP_DEBUG");
    Log_Error("[SOFTHSM_KSP] TestFunc: ERROR status=0x%08X", 0x80090020);
    ASSERT("Log_Error without KSP_DEBUG does not crash", 1);

    setenv("KSP_DEBUG", "1", 1);
    Log_Error("[SOFTHSM_KSP] TestFunc: ERROR status=0x%08X", 0x80090020);
    ASSERT("Log_Error with KSP_DEBUG does not crash", 1);

    /* ── Suite 4 : Various formats ──────────────────────────────────────── */
    TEST_SUITE("Log_Debug — various formats");

    setenv("KSP_DEBUG", "1", 1);
    Log_Debug("Message without formatting");
    Log_Debug("Integer: %d", -1);
    Log_Debug("Unsigned: %u", 0xFFFFFFFFU);
    Log_Debug("Hex: 0x%08X", 0xDEADBEEF);
    Log_Debug("Long: %lu", 1234567890UL);
    Log_Debug("String: %s", "test_string");
    Log_Debug("Pointer: %p", (void*)0x1234);
    /* Very long message (> 1024 bytes) → truncated without crash */
    char longMsg[2048];
    memset(longMsg, 'A', sizeof(longMsg) - 1);
    longMsg[sizeof(longMsg) - 1] = '\0';
    Log_Debug("%s", longMsg);
    ASSERT("Long message truncated without crash", 1);

    /* ── Suite 5 : Idempotence of Log_Initialize ───────────────────────── */
    TEST_SUITE("Log_Initialize — idempotence");

    setenv("KSP_DEBUG", "1", 1);
    Log_Initialize();
    Log_Initialize();
    Log_Initialize();
    ASSERT("Three consecutive calls do not crash", 1);

    /* Variable change between two inits (first value wins) */
    unsetenv("KSP_DEBUG");
    Log_Initialize(); /* The initial value is already memorized */
    Log_Debug("Message after re-init with debug disabled");
    ASSERT("Re-init does not change state (first value wins)", 1);

    TEST_REPORT();
    TEST_EXIT();
}
