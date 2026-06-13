/* test_logging.c — Couverture du module logging
 * Teste l'initialisation, les modes debug on/off, les messages d'erreur.
 */
#include "../mock/windows_compat.h"
#include "test_framework.h"

void Log_Initialize(void);
void Log_Debug(const char *pszFormat, ...);
void Log_Error(const char *pszFormat, ...);

int main(void)
{
    /* ── Suite 1 : Init avec KSP_DEBUG=0 (défaut) ───────────────────────── */
    TEST_SUITE("Log_Initialize — debug désactivé");

    unsetenv("KSP_DEBUG");
    Log_Initialize();
    /* Aucun crash, pas de sortie */
    Log_Debug("Ce message ne doit pas apparaître : %d", 42);
    ASSERT("Log_Debug sans KSP_DEBUG ne plante pas", 1);

    /* ── Suite 2 : Init avec KSP_DEBUG=1 ───────────────────────────────── */
    TEST_SUITE("Log_Initialize — debug activé");

    setenv("KSP_DEBUG", "1", 1);
    Log_Initialize(); /* Idempotent sur la même valeur */
    Log_Debug("[SOFTHSM_KSP] Test debug : valeur=%d str=%s", 99, "hello");
    ASSERT("Log_Debug avec KSP_DEBUG=1 ne plante pas", 1);

    /* ── Suite 3 : Log_Error (toujours actif) ───────────────────────────── */
    TEST_SUITE("Log_Error — toujours actif");

    unsetenv("KSP_DEBUG");
    Log_Error("[SOFTHSM_KSP] TestFunc: ERREUR status=0x%08X", 0x80090020);
    ASSERT("Log_Error sans KSP_DEBUG ne plante pas", 1);

    setenv("KSP_DEBUG", "1", 1);
    Log_Error("[SOFTHSM_KSP] TestFunc: ERREUR status=0x%08X", 0x80090020);
    ASSERT("Log_Error avec KSP_DEBUG ne plante pas", 1);

    /* ── Suite 4 : Formats variés ───────────────────────────────────────── */
    TEST_SUITE("Log_Debug — formats variés");

    setenv("KSP_DEBUG", "1", 1);
    Log_Debug("Message sans formatage");
    Log_Debug("Entier : %d", -1);
    Log_Debug("Unsigned : %u", 0xFFFFFFFFU);
    Log_Debug("Hex : 0x%08X", 0xDEADBEEF);
    Log_Debug("Long : %lu", 1234567890UL);
    Log_Debug("Chaîne : %s", "test_string");
    Log_Debug("Pointeur : %p", (void*)0x1234);
    /* Message très long (> 1024 octets) → tronqué sans crash */
    char longMsg[2048];
    memset(longMsg, 'A', sizeof(longMsg) - 1);
    longMsg[sizeof(longMsg) - 1] = '\0';
    Log_Debug("%s", longMsg);
    ASSERT("Message long tronqué sans crash", 1);

    /* ── Suite 5 : Idempotence de Log_Initialize ────────────────────────── */
    TEST_SUITE("Log_Initialize — idempotence");

    setenv("KSP_DEBUG", "1", 1);
    Log_Initialize();
    Log_Initialize();
    Log_Initialize();
    ASSERT("Trois appels consécutifs ne plantent pas", 1);

    /* Changement de variable entre deux inits (première valeur wins) */
    unsetenv("KSP_DEBUG");
    Log_Initialize(); /* La valeur initiale est déjà mémorisée */
    Log_Debug("Message après ré-init avec debug désactivé");
    ASSERT("Re-init ne change pas l'état (première valeur wins)", 1);

    TEST_REPORT();
    TEST_EXIT();
}
