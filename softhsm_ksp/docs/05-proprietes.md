# CNG Properties — Complete mapping

## Provider properties

| CNG property | Returned value | Type | Implemented |
|--------------|----------------|------|-------------|
| `NCRYPT_NAME_PROPERTY` | `L"SoftHSM KSP"` | `WCHAR[]` | ✓ |
| `NCRYPT_VERSION_PROPERTY` | `1` | `DWORD` | ✓ |
| `NCRYPT_IMPL_TYPE_PROPERTY` | `NCRYPT_IMPL_HARDWARE_FLAG` | `DWORD` | ✓ |
| Any other property | — | — | `NTE_NOT_SUPPORTED` |

The `NCRYPT_IMPL_HARDWARE_FLAG` flag tells Windows that this provider behaves
like a hardware HSM (non-exportable keys, enhanced security).

---

## Key properties

### Mapping table

| CNG property | PKCS#11 / KSP_KEY source | Type | Read | Write |
|--------------|--------------------------|------|------|-------|
| `NCRYPT_ALGORITHM_PROPERTY` | `pKey->szAlgId` | `WCHAR[]` | ✓ | ✗ |
| `NCRYPT_LENGTH_PROPERTY` | `pKey->dwKeyBitLen` | `DWORD` | ✓ | ✓ (before FinalizeKey) |
| `NCRYPT_KEY_TYPE_PROPERTY` | `pKey->dwKeySpec` | `DWORD` | ✓ | ✗ |
| `NCRYPT_NAME_PROPERTY` | `pKey->szKeyName` | `WCHAR[]` | ✓ | ✗ |
| `NCRYPT_UNIQUE_NAME_PROPERTY` | `pKey->szKeyName` | `WCHAR[]` | ✓ | ✗ |
| `NCRYPT_EXPORT_POLICY_PROPERTY` | `0` (non-exportable) | `DWORD` | ✓ | ✗ |
| `NCRYPT_KEY_USAGE_PROPERTY` | calculated from `dwKeySpec` | `DWORD` | ✓ | ✗ |
| `NCRYPT_ALGORITHM_GROUP_PROPERTY` | `"RSA"` or `"ECDSA"` | `WCHAR[]` | ✓ | ✗ |
| Any other property | — | — | `NTE_NOT_SUPPORTED` | `NTE_NOT_SUPPORTED` |

### Computing NCRYPT_KEY_USAGE_PROPERTY

```
dwKeySpec == AT_SIGNATURE    → NCRYPT_ALLOW_SIGNING_FLAG  (0x00000002)
dwKeySpec == AT_KEYEXCHANGE  → NCRYPT_ALLOW_DECRYPT_FLAG  (0x00000001)
```

### Validating NCRYPT_LENGTH_PROPERTY (write)

Only standard RSA sizes are accepted before `FinalizeKey`:

```
2048, 3072, 4096  → accepted
Other value       → NTE_BAD_LEN
After FinalizeKey → NTE_INVALID_HANDLE
```

---

## Sequence diagram — GetKeyProperty

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_properties.c

    App->>NCrypt: NCryptGetProperty(hKey,<br/>NCRYPT_ALGORITHM_PROPERTY,<br/>NULL, 0, &cbResult, 0)
    NCrypt->>KSP: KSP_GetKeyProperty(hProv, hKey,<br/>L"Algorithm", NULL, 0, &cbResult, 0)

    KSP->>KSP: Validate dwMagic (KSP_KEY_MAGIC)
    KSP->>KSP: wcsicmp(pszProperty, L"Algorithm") → match
    KSP->>KSP: cbNeeded = (wcslen("RSA") + 1) * 2 = 8
    KSP->>KSP: *pcbResult = 8<br/>pbOutput == NULL → no copy

    KSP-->>NCrypt: ERROR_SUCCESS, cbResult=8
    NCrypt-->>App: ERROR_SUCCESS, cbResult=8

    App->>NCrypt: NCryptGetProperty(hKey,<br/>NCRYPT_ALGORITHM_PROPERTY,<br/>pbBuf, 8, &cbResult, 0)
    NCrypt->>KSP: KSP_GetKeyProperty(..., pbBuf, 8)

    KSP->>KSP: cbOutput(8) >= cbNeeded(8) → OK<br/>memcpy(pbBuf, L"RSA\0", 8)

    KSP-->>NCrypt: ERROR_SUCCESS
    NCrypt-->>App: pbBuf = L"RSA", ERROR_SUCCESS
```

---

## Sequence diagram — SetKeyProperty (RSA key length)

```mermaid
sequenceDiagram
    participant App as Application
    participant NCrypt as ncrypt.dll
    participant KSP as ksp_properties.c

    App->>NCrypt: NCryptSetProperty(hKey,<br/>NCRYPT_LENGTH_PROPERTY,<br/>&dwBits=4096, 4, 0)
    NCrypt->>KSP: KSP_SetKeyProperty(hProv, hKey,<br/>L"Length", &4096, 4, 0)

    KSP->>KSP: Validate KSP_KEY_MAGIC
    KSP->>KSP: wcsicmp → NCRYPT_LENGTH_PROPERTY

    alt Key not yet finalised
        KSP->>KSP: pKey->bFinalized == FALSE → OK
        KSP->>KSP: dwBits ∈ {2048, 3072, 4096} → valid
        KSP->>KSP: pKey->dwKeyBitLen = 4096
        KSP-->>NCrypt: ERROR_SUCCESS
    else Key already finalised
        KSP->>KSP: pKey->bFinalized == TRUE
        KSP-->>NCrypt: NTE_INVALID_HANDLE
    else Invalid size
        KSP->>KSP: dwBits ∉ {2048, 3072, 4096}
        KSP-->>NCrypt: NTE_BAD_LEN
    end

    NCrypt-->>App: (return code)
```

---

## Unsupported properties

The following properties always return `NTE_NOT_SUPPORTED`:

- `SetProviderProperty` (all)
- `SetKeyProperty` for any property other than `NCRYPT_LENGTH_PROPERTY`
- `GetOperationProperty`
- `PromptUser`
