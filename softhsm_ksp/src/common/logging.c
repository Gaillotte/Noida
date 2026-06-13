/* logging.c — Debug logging implementation via OutputDebugString */
#include "logging.h"
#include "config.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static BOOL g_bDebugEnabled = FALSE;
static BOOL g_bInitialized  = FALSE;

/* Initialise the logging subsystem by reading KSP_DEBUG */
void Log_Initialize(void)
{
    if (!g_bInitialized) {
        char szVal[8] = {0};
        DWORD dwLen = GetEnvironmentVariableA(KSP_DEBUG_ENV, szVal, sizeof(szVal));
        g_bDebugEnabled = (dwLen > 0 && szVal[0] == '1');
        g_bInitialized  = TRUE;
    }
}

/* Log a message only when debug mode is enabled */
void Log_Debug(const char *pszFormat, ...)
{
    char szBuf[1024];
    va_list args;

    if (!g_bDebugEnabled)
        return;

    va_start(args, pszFormat);
    _vsnprintf_s(szBuf, sizeof(szBuf), _TRUNCATE, pszFormat, args);
    va_end(args);

    strncat_s(szBuf, sizeof(szBuf), "\n", _TRUNCATE);
    OutputDebugStringA(szBuf);
}

/* Log an error (always active) */
void Log_Error(const char *pszFormat, ...)
{
    char szBuf[1024];
    va_list args;

    va_start(args, pszFormat);
    _vsnprintf_s(szBuf, sizeof(szBuf), _TRUNCATE, pszFormat, args);
    va_end(args);

    strncat_s(szBuf, sizeof(szBuf), "\n", _TRUNCATE);
    OutputDebugStringA(szBuf);
}
