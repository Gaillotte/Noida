# KMIP on PKCS#11

A **OASIS Key Management Interoperability Protocol (KMIP) 2.1** server built on top of a
**PKCS#11 Hardware Security Module**.

Cryptographic material never leaves the HSM. The KMIP layer manages object lifecycle,
metadata, access control, and binary protocol framing while delegating every key
operation to PKCS#11.

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Supported Operations](#supported-operations)
7. [Access Control](#access-control)
8. [Algorithm Coverage](#algorithm-coverage)
9. [Running the Tests](#running-the-tests)
10. [Test Specification](#test-specification)
11. [Configuration](#configuration)
12. [Key Lifecycle States](#key-lifecycle-states)
13. [Known Limitations](#known-limitations)
14. [References](#references)

---

## Features

- **KMIP 2.1 wire protocol** — full TTLV binary encoding/decoding, batching,
  `BatchErrorContinuationOption`, `MaximumResponseSize`
- **41 of 53 KMIP operations** — see [Supported Operations](#supported-operations);
  the other 12 are session/async/vendor operations that don't fit a
  synchronous, per-request-auth server (see [Known Limitations](#known-limitations))
- **Full key lifecycle** — Pre-Active → Active → Deactivated / Compromised → Destroyed,
  plus Archive/Recover, ReKey/ReKeyKeyPair/ReCertify, split-key XOR sharing
- **HSM-backed** — all keys live inside SoftHSM2 (or any PKCS#11 HSM); the shim is the
  only file that imports `pkcs11`, so swapping in a different (e.g. FIPS-validated)
  token needs no change above `pkcs11_shim/`
- **Capability-probed algorithms** — the shim queries the token's actual mechanism
  list at startup and rejects unsupported algorithms/modes cleanly
  (`OperationNotSupported`) instead of leaking a raw PKCS#11 error
- **Access control** — every object records its creator; operations against an
  existing object require ownership, the admin role, or an explicit delegated
  grant (see [Access Control](#access-control))
- **Optional TLS + mTLS** — standard TCP, KMIP's IANA port 5696
- **SQLite metadata store** — thread-safe (connection-per-thread), WAL mode,
  JSON attribute values
- **649 automated tests** — 100% pass rate, run live against a real SoftHSM2 token

---

## Architecture

```
┌────────────────────────────────────────────┐
│           KMIP Client (TCP/TLS)            │  ← test_app/client.py
└───────────────────┬────────────────────────┘
                    │ TTLV binary (port 5696)
┌───────────────────▼────────────────────────┐
│           KMIPServer (TCP)                 │  ← server/server.py
│  • thread-per-client                       │
│  • per-identity auth, request caps, TLS    │
└───────────────────┬────────────────────────┘
                    │ TTLVItem tree
┌───────────────────▼────────────────────────┐
│         OperationDispatcher                │  ← operations/dispatcher.py
│  • routes BatchItem → handler (41 ops)     │
│  • error → KMIP OperationFailed response   │
└──────┬─────────────────────────┬───────────┘
       │                         │
┌──────▼──────────┐   ┌──────────▼──────────────┐
│  Operations     │   │  Lifecycle              │
│  create.py      │   │  state_machine.py        │
│  get.py   ...   │   │  PreActive→Active…       │
│  (41 files)     │   │  access_control.py        │
│                 │   │  owner / admin / grants   │
└──────┬──────────┘   └──────────────────────────┘
       │
┌──────▼────────────────┬──────────────────────┐
│  PKCS11Shim            │  MetadataStore        │
│  pkcs11_shim/shim.py   │  metadata/store.py    │
│  • single locked       │  SQLite (WAL)         │
│    session (see        │  • objects/attrs      │
│    Known Limitations)  │  • identities/roles    │
│  • capability probe    │                        │
│  SoftHSM2 / PKCS#11    │                        │
└────────────────────────┴────────────────────────┘
```

---

## Project Structure

```
kmip_pkcs11/
├── core/
│   ├── enums.py               # KMIP enumerations (Tag, Operation, State, …)
│   ├── ttlv.py                # TTLV encoder / decoder
│   └── exceptions.py          # KMIP exception hierarchy
├── lifecycle/
│   ├── state_machine.py       # Key lifecycle state transitions
│   └── access_control.py      # Owner / admin role / delegated grants
├── metadata/
│   └── store.py               # SQLite metadata store (objects, attrs, identities, roles, grants)
├── pkcs11_shim/
│   └── shim.py                # PKCS#11 / SoftHSM2 wrapper, capability probe, session lock
├── operations/                # One file per KMIP operation (41 files) — dispatcher.py routes
│   ├── dispatcher.py
│   ├── create.py, create_keypair.py, register.py, import_op.py, export_op.py
│   ├── get.py, get_attributes.py, get_usage_allocation.py, locate.py
│   ├── add_attribute.py, modify_attribute.py, delete_attribute.py,
│   │   set_attribute.py, adjust_attribute.py
│   ├── activate.py, revoke.py, destroy.py, archive.py, recover.py, check.py
│   ├── encrypt.py, decrypt.py, sign.py, signature_verify.py
│   ├── mac.py, mac_verify.py, hash_op.py
│   ├── rekey.py, rekey_keypair.py, certify.py, recertify.py
│   ├── derive_key.py, create_split_key.py, join_split_key.py
│   ├── validate.py, obtain_lease.py, rng_retrieve.py, rng_seed.py
│   └── query.py, discover_versions.py
├── server/
│   └── server.py               # TCP server (thread-per-client, Credential auth, optional TLS)
├── test_app/
│   ├── client.py                # Synchronous KMIP 2.1 client
│   └── demo.py                  # End-to-end demo
└── tests/
    ├── conftest.py
    ├── test_ttlv.py              #  22 TTLV unit tests
    ├── test_lifecycle.py         #  26 lifecycle state-machine tests
    ├── test_metadata.py          #  18 metadata store unit tests
    ├── test_operations.py        #   8 operation integration tests
    ├── test_conformance.py       #  48 OASIS KMIP conformance tests
    └── test_extended_coverage.py # 527 live tests: every operation, algorithm
                                   #  coverage, error paths, authentication,
                                   #  access control, session concurrency
```

---

## Installation

### Prerequisites

| Dependency     | Version  | How to install                  |
|---------------|----------|---------------------------------|
| Python        | ≥ 3.9    | —                               |
| SoftHSM2      | ≥ 2.6    | `apt install softhsm2`          |
| python-pkcs11 | 0.9.5    | `pip install python-pkcs11`     |
| pytest        | ≥ 7.0    | `pip install pytest`            |

### Steps

```bash
# 1. Install system dependencies
sudo apt install softhsm2

# 2. Install Python package (editable mode)
pip install -e .[dev]

# 3. Initialize a SoftHSM2 token
softhsm2-util --init-token --slot 0 \
  --label KMIPTest --pin 1234 --so-pin 5678
```

---

## Quick Start

### Run the demo

```bash
python -m kmip_pkcs11.test_app.demo
```

Walks through DiscoverVersions, Query, Create AES-256, GetAttributes, Locate,
Encrypt/Decrypt, CreateKeyPair, Register, and a full Revoke → Destroy lifecycle.

### Embed in your code

```python
from kmip_pkcs11.metadata.store import MetadataStore
from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
from kmip_pkcs11.server.server import KMIPServer
from kmip_pkcs11.test_app.client import KMIPClient
from kmip_pkcs11.core.enums import CryptographicAlgorithm

# Start the server
store  = MetadataStore("/var/kmip/kmip.db")
shim   = PKCS11Shim("/usr/lib/.../libsofthsm2.so", "MyToken", "userpin")
server = KMIPServer(store, shim, host="127.0.0.1", port=5696)
server.start_background()

# Provision identities before anyone connects — there's no wire operation
# for this, by design (see Access Control)
store.create_identity("ops-team", "a-strong-password")
store.assign_role("ops-team", "admin")

# Connect a client
with KMIPClient(port=5696, username="ops-team", password="a-strong-password") as c:
    uid = c.create(algorithm=CryptographicAlgorithm.AES, length=256)
    ct, iv, tag = c.encrypt(uid, b"Hello KMIP!")
    pt = c.decrypt(uid, ct, iv=iv, auth_tag=tag)
    c.destroy(uid)
```

---

## Supported Operations

**41 of 53** KMIP 2.1 operations, grouped by category. The remaining 12 are a
deliberate scope decision — see [Known Limitations](#known-limitations).

| Category | Operations |
|---|---|
| **Object lifecycle** | Create, CreateKeyPair, Register, ReKey, ReKeyKeyPair, DeriveKey, Certify, ReCertify, CreateSplitKey, JoinSplitKey, Import, Export, Activate, Revoke, Destroy, Archive, Recover, Check |
| **Retrieval & discovery** | Get, GetAttributes, GetAttributeList, Locate, Query, DiscoverVersions, ObtainLease, GetUsageAllocation |
| **Attributes** | AddAttribute, ModifyAttribute, DeleteAttribute, SetAttribute, AdjustAttribute |
| **Cryptographic operations** | Encrypt, Decrypt, Sign, SignatureVerify, MAC, MACVerify, Hash, RNGRetrieve, RNGSeed, Validate |
| **Deferred** (12) | Cancel, Poll, Notify, Put, Log, Login, Logout, DelegatedLogin, SetEndpointRole, PKCS11, Interop, ReProvision |

---

## Access Control

### Authentication

Each identity has its own credential, stored as a per-identity salted
**scrypt** hash (`kmip_identities`). A client authenticates with a KMIP
`UsernameAndPassword` Credential, and the password is verified against *that
identity's* hash:

```python
store.create_identity("alice", "alice-password")   # provision
store.set_password("alice", "new-password")        # rotate
store.set_identity_disabled("alice")               # suspend without deleting
store.delete_identity("alice")
```

An identity that was never provisioned cannot authenticate, whatever password
it supplies. Requests with no Credential are accepted as the identity
`anonymous`. The PKCS#11 token PIN authenticates the *server to the HSM* and
is no longer a KMIP credential — previously it was the only password, which
meant any caller holding it could claim any username, including one carrying
the admin role.

A client certificate's Common Name is used as the identity only when mTLS is
configured *and* `require_client_cert=True`, so the subject has actually been
verified against the CA.

### Authorization

Every managed object records the identity that created it. Operations against
an *existing* object are authorized in this order (`lifecycle/access_control.py`):

1. **Admin role** — `store.assign_role(identity, "admin")` grants unconditional
   access to every object.
2. **Ownership** — `identity == owner_identity` (set at Create/Register/etc. time).
3. **Delegated grant** — `store.grant_access(uid, grantee, "read" | "full")`
   lets a specific identity reach a specific object without owning it.
   `"read"` covers Get/GetAttributes/GetAttributeList/Check/Export/ObtainLease;
   everything else (Encrypt, Destroy, ReKey, …) needs `"full"`.

Objects with no recorded owner (`owner_identity=None`) stay reachable by any
identity — this only applies to objects created outside the normal Create/Register
path, so nothing gets orphaned by adding access control on top of an existing store.

**There is no KMIP wire operation for identity, role or grant management** —
the spec doesn't define one. Call the `MetadataStore` methods directly from an
admin script or console:

```python
store.create_identity("alice", "alice-password")   # authentication
store.assign_role("alice", "admin")                # alice can touch anything
store.grant_access(uid, "bob", "read")             # bob can Get this one object
store.revoke_access(uid, "bob")
store.revoke_role("alice", "admin")
```

`Locate` results are filtered to the caller's own objects — a non-admin
identity can't enumerate objects it doesn't own. An identity holding the admin
role skips that filter and sees everything, so it can both find and read any
object.

---

## Algorithm Coverage

**15 of 40** `CryptographicAlgorithm` values map to a working PKCS#11 mechanism
on this SoftHSM2 build: AES, DES, TDES, RSA, EC, ECDSA, ECDH, DSA, DH, and
HMAC-MD5/SHA1/224/256/384/512.

The shim probes `slot.get_mechanisms()` at startup and gates every
algorithm/mode dispatch on it, so an unsupported request fails cleanly with
`OperationNotSupported` rather than a raw PKCS#11 error. Several mappings —
SHA-3 HMAC (224/256/384/512), SHA-3 hashing, Blowfish, and Twofish — are wired
in but inactive on *this* token; point the shim at a token that implements
those mechanisms (a Botan-backed SoftHSM2 build, a newer OpenSSL-3 build, or
real hardware) and they activate with no code change. A further 12 algorithms
(RC2/RC4/RC5, IDEA, CAST5, Camellia, ChaCha20/Poly1305, SKIPJACK, MARS,
OneTimePad, SHAKE128/256) have no PKCS#11 mechanism implemented by any
backend this project has tested against, or — for SKIPJACK/MARS/OneTimePad —
no PKCS#11 mechanism was ever standardized for them at all.

---

## Running the Tests

```bash
# Run all 649 tests
pytest

# Run with verbose output
pytest -v

# Run a specific module
pytest kmip_pkcs11/tests/test_conformance.py -v

# Run unit tests only (no SoftHSM2 required)
pytest kmip_pkcs11/tests/test_ttlv.py kmip_pkcs11/tests/test_lifecycle.py

# Run with coverage
pytest --cov=kmip_pkcs11 --cov-report=html
```

### Test Results

| Module               | Tests | Passed | Failed | Pass Rate |
|---------------------|-------|--------|--------|-----------|
| test_ttlv.py            |  22 |  22 | 0 | 100 % |
| test_lifecycle.py       |  26 |  26 | 0 | 100 % |
| test_metadata.py        |  18 |  18 | 0 | 100 % |
| test_operations.py      |   8 |   8 | 0 | 100 % |
| test_conformance.py     |  48 |  48 | 0 | 100 % |
| test_extended_coverage.py | 527 | 527 | 0 | 100 % |
| **TOTAL**            | **649** | **649** | **0** | **100 %** |

---

## Test Specification

### Test ID mapping to OASIS KMIP TC identifiers

| TC-ID          | Class / Test                                          | Classification |
|----------------|-------------------------------------------------------|----------------|
| TC-DISC-001    | TestDiscoverVersions (4 tests)                        | CS-AC-M        |
| TC-QUERY-001   | TestQuery (6 tests)                                   | CS-AC-M        |
| TC-CREATE-001  | TestCreate (5 tests)                                  | CS-AC-M        |
| TC-CKP-001     | TestCreateKeyPair (2 tests)                           | CS-AC-O        |
| TC-GET-001     | TestGet (2 tests)                                     | CS-AC-M        |
| TC-GETATTR-001 | TestGetAttributes (5 tests)                           | CS-AC-M        |
| TC-LOCATE-001  | TestLocate (6 tests)                                  | CS-AC-M        |
| TC-LC-001      | TestLifecycle (6 tests)                               | CS-AC-M        |
| TC-CRYPT-001   | TestEncryptDecrypt (5 tests)                          | CS-AC-O        |
| TC-ATTR-001    | TestAttributes (2 tests)                              | CS-AC-M        |
| TC-ERR-001     | TestErrorHandling (5 tests)                           | CS-AC-M        |

`test_conformance.py` covers the mandatory/optional KMIP TC surface above;
`test_extended_coverage.py` covers everything added since — the remaining 25
operations, algorithm/mode coverage, error paths, and the access-control and
session-concurrency work described in this document.

### Key conformance assertions

- **DiscoverVersions** must return a list including (2, 1); versions descending
- **Create** must return a UUID-format UniqueIdentifier; state must be Active immediately
- **Lifecycle**: Revoke(KeyCompromise) → Compromised; Destroy after Revoke → Destroyed
- **Encrypt** must fail on Deactivated key; **Decrypt** must succeed on Deactivated key (data recovery)
- **Error handling**: unknown UIDs must return `OperationFailed / ItemNotFound`;
  cross-identity access to an owned object must return `OperationFailed / PermissionDenied`

---

## Configuration

### Server options

```python
KMIPServer(
    store,
    shim,
    host="127.0.0.1",      # bind address
    port=5696,              # IANA KMIP port
    tls_cert="server.pem", # optional: path to server certificate
    tls_key="server.key",  # optional: server private key
    tls_ca="ca.pem",       # optional: CA for client cert verification
    require_client_cert=False,  # True = enforce mTLS
)
```

### Environment variables

| Variable        | Default                                                | Purpose              |
|----------------|----------------------------------------------------------|----------------------|
| `SOFTHSM2_LIB`  | `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`   | PKCS#11 library path |
| `SOFTHSM2_CONF` | auto-created by test fixtures                          | SoftHSM2 config path |

### Roles and grants

No environment variable or server constructor argument — assign the first
admin identity directly against the store before starting the server (see
the [Access Control](#access-control) and [Quick Start](#quick-start) sections).

---

## Key Lifecycle States

```
           ┌──────────────┐
           │  Pre-Active  │──activate──►┌────────┐
           └──────────────┘             │ Active │
                  │                     └────────┘
                  │ revoke(normal)          │ revoke(normal)
                  ▼                         ▼
           ┌─────────────────────────────────────┐
           │            Deactivated              │
           └─────────────────────────────────────┘
                  │ revoke(compromise)      │ revoke(compromise)
                  ▼                         │
           ┌────────────┐◄─────────────────┘
           │ Compromised│
           └────────────┘
                  │ destroy
                  ▼
        ┌──────────────────────┐
        │ DestroyedCompromised │
        └──────────────────────┘

   All states (except DestroyedCompromised) can transition to Destroyed via destroy.
   Archive/Recover is orthogonal to State — an archived object keeps its State
   but is unusable for anything but metadata reads until Recovered.
```

---

## Known Limitations

| Limitation | Detail |
|---|---|
| Single, locked PKCS#11 session | `server.py` runs one thread per connection, but they share one `PKCS11Shim` session serialized by a `threading.RLock`. **This is the deliberate, permanent design, not a stopgap** — a session-pool (separate session per thread) was built and tested, and reproducibly segfaults or corrupts operations under concurrency: `python-pkcs11` 0.9.5 calls `C_Initialize(NULL)`, so the library's own internal thread safety is never enabled, and separate sessions don't work around that. A real fix needs a PKCS#11 binding that passes `CKF_OS_LOCKING_OK`, or a multi-process worker pool. |
| Identity management has no wire protocol | Identity, role and grant management (`create_identity`, `assign_role`, `grant_access`, …) is a `MetadataStore` admin surface only — KMIP itself doesn't define operations for it, and there is no CLI yet. No groups, no per-role operation allowlist, and no dual-control approval for destructive operations; every non-admin identity is evaluated individually against ownership and grants. |
| Key material at rest | `SecretData`, `OpaqueObject` and every `SplitKey` share are stored as plaintext BLOBs in SQLite (`raw_key_value`) with no encryption at rest — unlike keys held on the token, a copy of the database file exposes them directly. |
| No audit trail | Operations are logged via Python `logging` only — nothing persisted, queryable, or tamper-evident. |
| TLS optional, not enforced | The server accepts plain TCP if no certificate is configured; cert/key load from a static path with no rotation or ACME integration. |
| Not FIPS/CC validated | SoftHSM2 isn't a validated HSM. The PKCS#11 boundary means a validated token can be swapped in with no code change above `pkcs11_shim/`, but that swap hasn't happened here. |
| SoftHSM2 SENSITIVE bug | `SENSITIVE=True AND EXTRACTABLE=True` blocks `CKA_VALUE` read; the shim downgrades sensitivity automatically when extractability is explicitly requested. |
| No batch atomicity | Failure in one `BatchItem` does not roll back previous items in the same batch. |
| Algorithm coverage | 15 of 40 `CryptographicAlgorithm` values work against this token — see [Algorithm Coverage](#algorithm-coverage). |
| No HA / backup tooling | Single process, single SQLite file, single HSM token; no clustering, replication, or coordinated backup/restore. |

---

## References

- [OASIS KMIP Specification v2.1](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)
- [OASIS KMIP Test Cases v2.1](https://docs.oasis-open.org/kmip/kmip-testcases/v2.1/)
- [PKCS #11 Specification v3.0](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.0/)
- [SoftHSM2](https://github.com/opendnssec/SoftHSMv2)
- [python-pkcs11](https://python-pkcs11.readthedocs.io/)
