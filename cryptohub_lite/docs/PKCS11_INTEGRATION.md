# PKCS#11 Integration Guide

How CryptoHub Lite talks to a PKCS#11 token, and what changes when you move
from SoftHSM2 to validated hardware.

## Architecture

```
KMIP operation handler ─┐
REST API write path    ─┼─► PKCS11Shim ──► vendor .so/.dll ──► token
PKCS#11 Explorer       ─┘   (one session,
                             one lock)
```

Everything goes through `kmip_pkcs11/pkcs11_shim/shim.py`. Nothing else in the
system opens a PKCS#11 session, and that is a hard rule rather than a
convention — see *Concurrency* below.

## The shim

| Responsibility | Notes |
|---|---|
| Session ownership | Exactly one session, opened at `initialize()` |
| Serialisation | Every session-touching method carries `@_synchronized` |
| Capability probe | Reads the token's live mechanism list once at startup |
| Key generation | Symmetric and asymmetric, with usage flags |
| Cryptographic ops | Encrypt, decrypt, sign, verify, MAC, digest, derive |
| Introspection | `list_slots()`, `list_objects()` for the Explorer |

### The capability probe

At startup the shim records `slot.get_mechanisms()` and checks against it
before every operation. An unsupported algorithm is therefore rejected as
`OperationNotSupported` *before* the native call, instead of surfacing as a
raw `CKR_MECHANISM_INVALID` from somewhere deep in the binding. This is why
the same code gives a legible answer on a Botan SoftHSM2 build, which lacks
`CKM_ECDSA_SHA256`, rather than an opaque failure.

## Concurrency — read this before "optimising" it

The shim holds **one session, shared by every thread, behind an `RLock`**.
That looks like an obvious bottleneck and it is; it is also deliberate.

A session-pool design — one session per thread, no cross-thread lock — was
implemented and load-tested. It reproducibly either segfaulted the native
extension or returned `GeneralError`/`MechanismInvalid` on most threads. The
cause is that `python-pkcs11` calls `C_Initialize(NULL)`, so the library never
enables its own internal thread safety; separate sessions do not work around
that.

Lifting the ceiling therefore requires one of:

* a binding that passes `CKF_OS_LOCKING_OK` at `C_Initialize`; or
* a multi-process worker pool, each process owning one session.

Both are larger changes than swapping a lock for a pool. **Do not open a
second session as a shortcut** — that is precisely the configuration that
crashes.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SOFTHSM2_LIB` | `/usr/local/lib/softhsm/libsofthsm2.so` | Path to the vendor module |
| `PKCS11_TOKEN` | `CryptoHubLite` | Token label to open |
| `PKCS11_PIN` | `1234` | User PIN for HSM login |
| `PKCS11_SO_PIN` | `4321` | Security Officer PIN, initialisation only |

The variable is named `SOFTHSM2_LIB` for historical reasons; it accepts any
PKCS#11 module path.

> **The PIN is now only an HSM credential.** It used to double as the KMIP
> client password, which meant anyone holding it could claim any identity.
> KMIP clients authenticate against portal accounts instead. Do not reintroduce
> `KMIP_ALLOW_PIN_FALLBACK=true` except while migrating existing clients.

## Moving to a vendor HSM

The shim is vendor-neutral: a PKCS#11 module is fully described by its library
path, so switching is configuration plus the vendor's own client setup.

### 1. Install the vendor client

| HSM | Typical module path |
|---|---|
| Thales Luna | `/usr/safenet/lunaclient/lib/libCryptoki2_64.so` |
| Entrust nShield | `/opt/nfast/toolkits/pkcs11/libcknfast.so` |
| Utimaco | `/opt/utimaco/lib/libcs_pkcs11_R3.so` |
| AWS CloudHSM | `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` |

The vendor client must be installed *inside the API and KMIP containers*, or
those services must run on a host that has it. Extend
`docker/Dockerfile.api`; the rest of the image is unchanged.

### 2. Point the configuration at it

```yaml
environment:
  SOFTHSM2_LIB: /usr/safenet/lunaclient/lib/libCryptoki2_64.so
  PKCS11_TOKEN: production-partition
  PKCS11_PIN:   ${HSM_PIN}
```

Supply the PIN from a secrets manager, not the compose file. The system reads
it as an environment variable and does no secrets-manager integration itself.

### 3. Verify before trusting

```bash
docker compose -f cryptohub_lite/docker-compose.yml exec api python - <<'PY'
from kmip_pkcs11.pkcs11_shim.shim import PKCS11Shim
import os
s = PKCS11Shim(os.environ["SOFTHSM2_LIB"], os.environ["PKCS11_TOKEN"], os.environ["PKCS11_PIN"])
s.initialize()
print("token:", s.get_token_info())
print("mechanisms:", len(s.get_mechanism_list()))
print("slots:", s.list_slots())
PY
```

Then open the **PKCS#11 Explorer** and confirm the slot, token serial and
objects are what you expect.

### 4. Expect mechanism differences

Vendors implement different mechanism sets. The capability probe means an
absent mechanism fails cleanly rather than mysteriously, but it also means
**an operation that worked on SoftHSM2 may be refused by the HSM**. Check the
mechanism list before assuming parity; a common example is OAEP with SHA-256,
which several modules do not offer even though they advertise OAEP.

## Attributes the Explorer reads

`CKA_CLASS`, `CKA_LABEL`, `CKA_ID`, `CKA_KEY_TYPE`, `CKA_TOKEN`, `CKA_PRIVATE`,
`CKA_MODIFIABLE`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`,
`CKA_NEVER_EXTRACTABLE`, `CKA_SIGN`, `CKA_VERIFY`, `CKA_ENCRYPT`,
`CKA_DECRYPT`, `CKA_WRAP`, `CKA_UNWRAP`, `CKA_DERIVE`, `CKA_MODULUS_BITS`.

Read **one at a time**, so a token refusing a sensitive attribute costs that
attribute rather than the whole object. Secret-bearing attributes — `CKA_VALUE`
on a secret key, `CKA_PRIVATE_EXPONENT` on an RSA key — are never requested: a
correctly configured token would refuse them anyway, and a management plane
should not be the thing asking.

## Key material policy

Keys are generated `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`. Material
cannot leave the token, and a KMIP `Get` against such a key raises
`NotExtractable` rather than returning anything. This is the property the HSM
exists to provide; overriding it per request is possible in the engine but
should be a deliberate, reviewed decision.
