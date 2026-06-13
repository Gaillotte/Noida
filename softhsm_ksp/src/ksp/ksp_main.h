/* ksp_main.h — Point d'entrée DLL et table des fonctions CNG */
#ifndef KSP_MAIN_H
#define KSP_MAIN_H

#include <windows.h>
#include <ncrypt.h>

/* Point d'entrée exporté du KSP.
 * Vérifie le nom du fournisseur et retourne la table des fonctions. */
SECURITY_STATUS WINAPI GetKeyStorageInterface(
    LPCWSTR                          pszProviderName,
    NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    DWORD                            dwFlags);

/* Table des fonctions globale, initialisée dans ksp_main.c */
extern NCRYPT_KEY_STORAGE_FUNCTION_TABLE g_KspFunctionTable;

#endif /* KSP_MAIN_H */
