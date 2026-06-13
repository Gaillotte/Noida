/* ksp_main.h — DLL entry point and CNG function table */
#ifndef KSP_MAIN_H
#define KSP_MAIN_H

#include <windows.h>
#include <ncrypt.h>

/* Exported KSP entry point.
 * Verifies the provider name and returns the function table. */
SECURITY_STATUS WINAPI GetKeyStorageInterface(
    LPCWSTR                          pszProviderName,
    NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    DWORD                            dwFlags);

/* Global function table, initialised in ksp_main.c */
extern NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_KspFunctionTable;

#endif /* KSP_MAIN_H */
