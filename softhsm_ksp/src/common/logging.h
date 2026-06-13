/* logging.h — Debug logging interface for the SoftHSM2 KSP
 * Uses OutputDebugString, enabled via KSP_DEBUG=1.
 */
#ifndef LOGGING_H
#define LOGGING_H

#include <windows.h>

/* Initialise the logging subsystem (reads KSP_DEBUG) */
void Log_Initialize(void);

/* Log a message only when debug mode is enabled */
void Log_Debug(const char *pszFormat, ...);

/* Always log (critical errors) */
void Log_Error(const char *pszFormat, ...);

/* Convenience macros */
#define LOG_ENTER(fn)          Log_Debug("[SOFTHSM_KSP] " fn ": enter")
#define LOG_LEAVE(fn, status)  Log_Debug("[SOFTHSM_KSP] " fn ": leave status=0x%08X", (DWORD)(status))
#define LOG_ERROR(fn, status)  Log_Error("[SOFTHSM_KSP] " fn ": ERROR status=0x%08X", (DWORD)(status))
#define LOG_INFO(fmt, ...)     Log_Debug("[SOFTHSM_KSP] " fmt, ##__VA_ARGS__)

#endif /* LOGGING_H */
