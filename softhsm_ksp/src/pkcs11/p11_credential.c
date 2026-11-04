/* p11_credential.c — see p11_credential.h for what this is and why.
 *
 * The split in this file is the point. KspAcceptPinBytes is pure and
 * tested; everything below the #ifdef is a registry read and one DPAPI
 * call, compile-checked against the real mingw headers and not yet run.
 */
#include "p11_credential.h"
#include "../common/logging.h"
#include "../common/memory.h"

#include <string.h>

BOOL KspAcceptPinBytes(const BYTE *pbIn, DWORD cbIn,
                       char *pszOut, size_t cbOut)
{
    DWORD cb = cbIn;

    if (!pszOut || cbOut == 0)
        return FALSE;
    pszOut[0] = '\0';
    if (!pbIn || cbIn == 0)
        return FALSE;

    /* A terminator the producer happened to include is not part of the
     * PIN. Only ONE is stripped: a PIN legitimately ending in a NUL byte
     * is not a thing, but a blob of several trailing NULs is a provisioning
     * mistake and silently accepting it would change the credential. */
    if (pbIn[cb - 1] == '\0')
        cb--;
    if (cb == 0)
        return FALSE;

    /* Rejected, never truncated. A silently shortened PIN fails the login
     * with nothing pointing at the credential as the cause — the same
     * reasoning that makes an over-long PIN a refusal everywhere else here.
     *
     * The bound is cb >= cbOut, not cb > cbOut: the terminator needs the
     * last byte. Writing it the other way is the off-by-one this project
     * has already shipped twice, which is why this is its own function with
     * its own tests rather than three lines inside a caller. */
    if (cb >= cbOut)
        return FALSE;

    /* An embedded NUL would make the stored credential and the string that
     * reaches C_Login different values. Refuse rather than silently send
     * the prefix. */
    if (memchr(pbIn, '\0', cb) != NULL)
        return FALSE;

    memcpy(pszOut, pbIn, cb);
    pszOut[cb] = '\0';
    return TRUE;
}

#ifdef _WIN32

#include <dpapi.h>

/* Everything below is Windows-only and HAS NOT BEEN RUN. It cross-compiles
 * against the real mingw-w64 dpapi.h and wincrypt.h, so the types and the
 * call shapes are checked; nothing else about it is. */

BOOL P11_ReadProtectedPin(int nScope, char *pszOut, size_t cbOut)
{
    const char *szValue = (nScope == P11_SCOPE_MACHINE)
                        ? KSP_PIN_BLOB_VALUE_MACHINE
                        : KSP_PIN_BLOB_VALUE_USER;
    HKEY       hKey    = NULL;
    BYTE      *pbBlob  = NULL;
    DWORD      cbBlob  = 0;
    DWORD      dwType  = 0;
    DATA_BLOB  in, out;
    BOOL       bOk     = FALSE;
    LSTATUS    ls;

    if (!pszOut || cbOut == 0)
        return FALSE;
    pszOut[0] = '\0';

    ls = RegOpenKeyExA(HKEY_LOCAL_MACHINE, KSP_PIN_BLOB_KEY, 0,
                       KEY_QUERY_VALUE, &hKey);
    if (ls != ERROR_SUCCESS)
        return FALSE;              /* not provisioned: a normal state */

    ls = RegQueryValueExA(hKey, szValue, NULL, &dwType, NULL, &cbBlob);
    if (ls != ERROR_SUCCESS || cbBlob == 0) {
        RegCloseKey(hKey);
        return FALSE;              /* not provisioned for this scope */
    }
    /* Past this point a blob EXISTS, so every failure is a provisioning
     * fault and is logged. A quiet fallback to an ambient environment
     * variable would be the worst outcome: the deployment would appear to
     * work while using a credential the administrator thought they had
     * replaced. */
    if (dwType != REG_BINARY) {
        RegCloseKey(hKey);
        LOG_ERROR("KSP PIN blob is not REG_BINARY", NTE_PERM);
        return FALSE;
    }

    pbBlob = (BYTE *)KSP_AllocZero(cbBlob);
    if (!pbBlob) {
        RegCloseKey(hKey);
        LOG_ERROR("KSP PIN blob allocation", NTE_NO_MEMORY);
        return FALSE;
    }
    ls = RegQueryValueExA(hKey, szValue, NULL, &dwType, pbBlob, &cbBlob);
    RegCloseKey(hKey);
    if (ls != ERROR_SUCCESS) {
        KSP_Free(pbBlob);
        LOG_ERROR("KSP PIN blob read", NTE_PERM);
        return FALSE;
    }

    memset(&in, 0, sizeof(in));
    memset(&out, 0, sizeof(out));
    in.pbData = pbBlob;
    in.cbData = cbBlob;

    /* CRYPTPROTECT_UI_FORBIDDEN because this runs in a service with no
     * desktop: without it a prompt would block certsrv forever rather than
     * fail. */
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL,
                           CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        bOk = KspAcceptPinBytes(out.pbData, out.cbData, pszOut, cbOut);
        if (!bOk)
            LOG_ERROR("KSP PIN blob unprotected but rejected: empty, too "
                      "long for P11_MAX_PIN_LEN, or containing a NUL",
                      NTE_PERM);
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);
    } else {
        /* Wrong machine, or the blob was protected at user scope by an
         * account this service is not. */
        LOG_ERROR("CryptUnprotectData on the KSP PIN blob", NTE_PERM);
    }

    SecureZeroMemory(pbBlob, cbBlob);
    KSP_Free(pbBlob);
    return bOk;
}

#else  /* !_WIN32 */

/* There is no DPAPI and no registry here. Returning FALSE means the Linux
 * suites exercise the other credential sources exactly as before, which is
 * what makes this addition safe to land without a Windows machine. */
BOOL P11_ReadProtectedPin(int nScope, char *pszOut, size_t cbOut)
{
    (void)nScope;
    if (pszOut && cbOut)
        pszOut[0] = '\0';
    return FALSE;
}

#endif /* _WIN32 */
