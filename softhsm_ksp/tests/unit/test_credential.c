/* test_credential.c — KspAcceptPinBytes, the testable half of ADCS C-b.
 *
 * The DPAPI call and the registry read cannot run here; they are
 * compile-checked against the real mingw headers by the cross-compile job
 * and are unproven until Phase B. What CAN be tested is the part that
 * decides whether decrypted bytes become a credential, and that is
 * deliberately where the logic lives, because it is where this project's
 * recurring defect is:
 *
 *   A counted buffer whose terminator is mishandled. Session 15 found the
 *   same off-by-one in the PIN path and in a counted wide-string property,
 *   written independently, and fixed both by routing them through one
 *   helper. The bound here is `cb >= cbOut`, not `cb > cbOut`, because the
 *   terminator needs the last byte.
 *
 * Every assertion is about a rejection or an exact boundary. A PIN that is
 * silently truncated still fails the login — but it fails it with nothing
 * pointing at the credential, which is the failure mode that costs an
 * administrator an afternoon.
 */
#include "../mock/windows_compat.h"
#include "../../src/common/config.h"
#include "../../src/pkcs11/p11_credential.h"
#include "test_framework.h"
#include <string.h>
#include <stdio.h>

/* The provider's allocator is linked in; logging is not needed by the pure
 * function but p11_credential.c includes the header. */
void Log_Debug(const char *f, ...) { (void)f; }
void Log_Error(const char *f, ...) { (void)f; }

int main(void)
{
    char  szPin[P11_MAX_PIN_LEN + 1];
    BYTE  buf[P11_MAX_PIN_LEN + 8];
    char  msg[96];
    DWORD i;

    TEST_SUITE("KspAcceptPinBytes — accepting a decrypted credential");

    ASSERT("A plain value is accepted",
           KspAcceptPinBytes((const BYTE *)"1234", 4, szPin, sizeof(szPin)));
    ASSERT_EQ("and arrives intact", strcmp(szPin, "1234"), 0);

    /* DPAPI returns exactly what was protected, so a producer that
     * included a terminator and one that did not must give the same PIN. */
    ASSERT("A value WITH a trailing NUL is accepted",
           KspAcceptPinBytes((const BYTE *)"1234", 5, szPin, sizeof(szPin)));
    ASSERT_EQ("and is the same credential as without one",
              strcmp(szPin, "1234"), 0);

    TEST_SUITE("KspAcceptPinBytes — refusals");

    ASSERT("NULL input is refused",
           !KspAcceptPinBytes(NULL, 4, szPin, sizeof(szPin)));
    ASSERT("Zero length is refused",
           !KspAcceptPinBytes((const BYTE *)"x", 0, szPin, sizeof(szPin)));
    ASSERT("A lone NUL is refused, not accepted as an empty PIN",
           !KspAcceptPinBytes((const BYTE *)"", 1, szPin, sizeof(szPin)));

    /* An embedded NUL would make the stored credential and the string that
     * reaches C_Login two different values, and the login would fail with
     * the blob looking correct in the registry. */
    ASSERT("An embedded NUL is refused rather than silently truncated",
           !KspAcceptPinBytes((const BYTE *)"12\0 34", 6, szPin,
                              sizeof(szPin)));

    ASSERT("A NULL output buffer is refused",
           !KspAcceptPinBytes((const BYTE *)"1234", 4, NULL, sizeof(szPin)));
    ASSERT("A zero-size output buffer is refused",
           !KspAcceptPinBytes((const BYTE *)"1234", 4, szPin, 0));

    TEST_SUITE("KspAcceptPinBytes — the length boundary, exactly");

    memset(buf, 'A', sizeof(buf));

    /* sizeof(szPin) is P11_MAX_PIN_LEN + 1. The longest acceptable value
     * is P11_MAX_PIN_LEN bytes, because the terminator takes the last. */
    ASSERT("The longest permitted PIN is accepted",
           KspAcceptPinBytes(buf, P11_MAX_PIN_LEN, szPin, sizeof(szPin)));
    ASSERT_EQ("and is not short by one",
              (int)strlen(szPin), P11_MAX_PIN_LEN);
    ASSERT_EQ("and is NUL-terminated in the last byte",
              (int)szPin[P11_MAX_PIN_LEN], 0);

    ASSERT("One byte longer is REFUSED, not truncated",
           !KspAcceptPinBytes(buf, P11_MAX_PIN_LEN + 1, szPin,
                              sizeof(szPin)));
    ASSERT_EQ("and leaves the output empty rather than half-written",
              (int)szPin[0], 0);

    /* The same boundary with the terminator counted in: a producer that
     * stored MAX+1 bytes ending in NUL is storing a MAX-byte PIN, and that
     * must be accepted. This is the case the naive `cb > cbOut` test gets
     * wrong in one direction and `cb >= cbIn` in the other. */
    memset(buf, 'B', sizeof(buf));
    buf[P11_MAX_PIN_LEN] = '\0';
    ASSERT("The longest PIN, stored WITH its terminator, is accepted",
           KspAcceptPinBytes(buf, P11_MAX_PIN_LEN + 1, szPin,
                             sizeof(szPin)));
    ASSERT_EQ("and is still full length",
              (int)strlen(szPin), P11_MAX_PIN_LEN);

    memset(buf, 'C', sizeof(buf));
    buf[P11_MAX_PIN_LEN + 1] = '\0';
    ASSERT("One over, stored with its terminator, is still refused",
           !KspAcceptPinBytes(buf, P11_MAX_PIN_LEN + 2, szPin,
                              sizeof(szPin)));

    /* Walk every length into a small buffer. A boundary tested at one
     * value can be right by accident; tested across the whole range it
     * cannot. */
    TEST_SUITE("KspAcceptPinBytes — every length into a small buffer");
    for (i = 1; i <= 12; i++) {
        char small[9];              /* holds 8 characters + terminator */
        BOOL got;
        memset(buf, 'Z', sizeof(buf));
        got = KspAcceptPinBytes(buf, i, small, sizeof(small));
        snprintf(msg, sizeof(msg), "%lu bytes into a 9-byte buffer → %s",
                 (unsigned long)i, (i <= 8) ? "accept" : "refuse");
        ASSERT(msg, got == (i <= 8));
        if (got) {
            snprintf(msg, sizeof(msg), "  and its length is %lu",
                     (unsigned long)i);
            ASSERT(msg, strlen(small) == i);
        }
    }

    TEST_REPORT();
    TEST_EXIT();
}
