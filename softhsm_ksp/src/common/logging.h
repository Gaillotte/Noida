/* logging.h — Interface de journalisation debug du KSP SoftHSM2
 * Utilise OutputDebugString, activé via KSP_DEBUG=1.
 */
#ifndef LOGGING_H
#define LOGGING_H

#include <windows.h>

/* Initialise le sous-système de logging (lit KSP_DEBUG) */
void Log_Initialize(void);

/* Journalise un message si le debug est activé */
void Log_Debug(const char *pszFormat, ...);

/* Journalise toujours (erreurs critiques) */
void Log_Error(const char *pszFormat, ...);

/* Macros pratiques */
#define LOG_ENTER(fn)          Log_Debug("[SOFTHSM_KSP] " fn ": entree")
#define LOG_LEAVE(fn, status)  Log_Debug("[SOFTHSM_KSP] " fn ": sortie status=0x%08X", (DWORD)(status))
#define LOG_ERROR(fn, status)  Log_Error("[SOFTHSM_KSP] " fn ": ERREUR status=0x%08X", (DWORD)(status))
#define LOG_INFO(fmt, ...)     Log_Debug("[SOFTHSM_KSP] " fmt, ##__VA_ARGS__)

#endif /* LOGGING_H */
