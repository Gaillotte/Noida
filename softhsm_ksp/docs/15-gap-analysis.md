# Gap analysis

**Generated — do not edit.** `python3 generate_gap_analysis.py`, from
`docs/feature-matrix.csv`, `docs/coverage_blockers.py` and
`docs/gap_detail.py`. Last generated 2026-10-02.

The feature matrix answers *is it supported*, row by row. This answers
the question a reader asks next and cannot get from a status column:
**of everything still open, how much is waiting on somebody else, and
how much is a decision this project could revisit?**

---

## Where things stand

103 capabilities assessed: **73 Covered · 10 Partial · 20 Not covered**.

Of the **30 open rows**, **19 are blocked outside this repository** — a
CNG identifier Microsoft has not defined, a PKCS#11 mechanism that does
not exist, a header nobody here has, hardware, or a purchase. The
remaining **11 are decisions this project made**.

### Partial does not mean broken

This is the most misread thing in the matrix. Most Partial rows
describe features that **work**, and several are verified against an
independent PKCS#11 token rather than against our own mock. They are
Partial because no stock Windows application can ask for them:
`EDDSA_ED25519`, `EDDSA_ED448`, `ChainingModeCTR` and `HMAC_SHA*` are
this provider's own identifiers, because CNG defines none. Reading the
status column alone gets that exactly backwards, which is why the
tables below carry a *What works today* column.

### Why "deliberate position" needs a test

Three rows were recorded as deliberate positions and have since been
closed: **`IFACE-04`** (token selection through `NCryptSetProperty`),
**`LIFE-08`** (machine/user isolation) and **`FMT-08`** (symmetric key
export). The error was identical each time — the "position" rested on
how the provider happened to work at that moment, not on anything in
CNG or PKCS#11:

| Row | What the position rested on | Why that was not a constraint |
|---|---|---|
| `IFACE-04` | The session pool was already bound to a slot by the time a caller held a provider handle | Loading the module and calling `C_Initialize` need no token. Binding the slot lazily opened a window that had always been available |
| `LIFE-08` | Scoping was a `CKA_LABEL` prefix, and a prefix cannot isolate | PKCS#11 *does* have a boundary with a credential on it — the token. The scope can choose one instead of a prefix |
| `FMT-08` | Every key is `CKA_SENSITIVE=TRUE` / `CKA_EXTRACTABLE=FALSE` | That was a **default**, not a constraint. A policy property can relax it when, and only when, the caller asks |

So every row below carries **what the blocker rests on**, named
specifically, and whether that thing is outside this repository. A
claim that something cannot be done has to rest on something external,
or it is a description masquerading as a constraint.

`docs/gap_detail.py` enforces the pairing: a row classified as a
deliberate position must have `external=False` and vice versa, and
every generator that reads the module fails the build if they drift.

---

## Waiting on `ncrypt_provider.h` and a Windows machine (3)

The header declares `NCRYPT_KEY_STORAGE_FUNCTION_TABLE`. A `dir /s /b` across both drives of a `windows-latest` runner returned exactly one copy — this repository's own test mock — and that was after a WDK install reported success. It is not in the Windows SDK. Where it does come from is still unestablished; it is associated with the Cryptographic Provider Development Kit, but that is unconfirmed and two guesses at its location were wrong. **These three rows close together, on one machine, and not before.**

| ID | Feature | St | Eff | What works today | What the blocker rests on |
|---|---|---|---|---|---|
| `BUILD-01` | Builds for Windows at all | P | M | MSVC compiles nine of the ten source files clean at /W3 /WX and links test_p11_layer.exe. The mingw cross-compile is clean on all ten minus ksp_main.c. | ncrypt_provider.h, which declares NCRYPT_KEY_STORAGE_FUNCTION_TABLE. A dir /s /b across C: and D: on a windows-latest runner returned only this repository's own test mock, after a WDK install that reported success. It is not in the Windows SDK. |
| `PQC-01` | ML-DSA (Dilithium) | P | M | ML-DSA generates, reopens by parameter set and signs at all three sets, verified against Kryoptic built with its pqc feature over OpenSSL 3.5.8. Gated on the capability probe, so it is dark on SoftHSM2 and live on a v3.2 token. | The CNG post-quantum key blob layout, which is in a Windows SDK header not available here. Public key export is the only thing missing. A guessed layout would pass every test here and fail only on Windows — the BCRYPT_SHA224_ALGORITHM mistake exactly. |
| `TABLE-01` | Function table layout matches the SDK | P | S | Designated initialisers make a wrong slot NAME a build error. Eight provider-scoped slots are also signature-checked against &lt;ncrypt.h&gt;, which is what caught KSP_NotifyChangeKey holding an NCRYPT_KEY_HANDLE where the parameter is HANDLE *phEvent. | The same missing header. Key-scoped slots cannot be checked against the public prototype, because it is not the slot's shape: NCryptSignHash takes (hKey, ...) while the slot takes (hProvider, hKey, ...). Asserting the public shape there would be inventing a fact. |

## Waiting on Microsoft — CNG defines no identifier or no slot (5)

**All four of these work.** Three are verified end to end against an independent PKCS#11 token. They are open because CNG has no standard string for them, so they are reachable only from an application written against this provider by name, and cannot be BCrypt-verified end to end. Nothing in this repository can change that — the fix is a Microsoft decision.

| ID | Feature | St | Eff | What works today | What the blocker rests on |
|---|---|---|---|---|---|
| `AES-06` | AES-CTR | P | N/A | AES-CTR encrypts and decrypts, verified against a live token, selected through NCRYPT_CHAINING_MODE_PROPERTY. | CNG defines no counter-mode chaining string, so ChainingModeCTR is a provider extension that no stock application will select. |
| `EDDSA-01` | Ed25519 signing | P | N/A | Ed25519 signs, and is verified end to end against Kryoptic. The absent CK_EDDSA_PARAMS that selects the pure context-free form is deliberate and fault-injected. | CNG defines no EdDSA algorithm identifier at all, so EDDSA_ED25519 is this provider's own string and no stock application will ask for it. Nothing in the KSP can change that. |
| `EDDSA-02` | Ed448 signing | P | N/A | Ed448 signs against Kryoptic with CK_EDDSA_PARAMS supplied, which Ed448 requires and Ed25519 must not have. The asymmetry is deliberate and both mistakes are fault-injected. It did NOT work before session 10: SoftHSM2 tolerates the missing parameter, so a second token was needed to see it. | Same as EDDSA-01 — no CNG identifier exists. |
| `HMAC-01` | HMAC-SHA1 / 256 / 384 / 512 | P | N/A | HMAC signing works over CKM_SHA*_HMAC for SHA-1 through SHA-512, verified against a live token. It had never actually worked before session 10 — KSP_SignHash passed hPrivKey unconditionally and secret keys live in hSecretKey. | CNG reaches HMAC through BCrypt algorithm handles, not through KSP key algorithms, so HMAC_SHA* are this provider's own identifiers. |
| `PQC-02` | ML-KEM (Kyber) | No | L | The probe recognises CKM_ML_KEM, so the backend is not the obstacle. Nothing is advertised, deliberately. | The function table has no slot for encapsulation or decapsulation, so a KSP could hold an ML-KEM key with no entry point to use it. Whether a newer ncrypt_provider.h adds such slots cannot be established here — the same missing header. |

## Waiting on PKCS#11 — no mechanism exists to build on (7)

Each of these would need a primitive PKCS#11 does not define. Writing one anyway means inventing a facility the provider cannot actually deliver: a notification that is really a timer, an access-control model with no enforcement, a use count that is wrong under concurrency.

| ID | Feature | St | Eff | What works today | What the blocker rests on |
|---|---|---|---|---|---|
| `FMT-10` | OPAQUETRANSPORT blob | No | L | Nothing. Not advertised. | OPAQUETRANSPORT has no defined wrapping format to follow, so there is no standard to implement against — only a format this provider would invent and no one else could read. |
| `IFACE-05` | NotifyChangeKey | P | L | Validates the provider and flags, clears *phEvent and refuses registration with NTE_NOT_SUPPORTED. Unregistering succeeds, because there is nothing to tear down. Before session 14 it returned ERROR_SUCCESS without writing the handle, so a caller waited on an uninitialised HANDLE. | PKCS#11 has no object-change channel: there is no C_WaitForSlotEvent equivalent for objects. Polling C_FindObjects on a timer would be a fabrication dressed as a notification. THIS IS THE ROW CLOSEST IN SHAPE TO the three that were wrongly called deliberate — it would become actionable the moment a backend offered such a channel, so it is worth re-reading rather than inheriting. |
| `IFACE-06` | GetOperationProperty | No | L | Refused with NTE_NOT_SUPPORTED. | The property reports on an asynchronous operation and PKCS#11 is synchronous, so there is no operation state to report however much code is written. This row sat in the deliberate column until the pairing check was run against its own text, which already said "a fact about PKCS#11 rather than about this code" — so it was mislabelled by the person who wrote the reason, and the cross-check is what caught it. |
| `OPS-05` | Key attestation | No | L | Nothing. Not advertised. | Key attestation has no standard PKCS#11 mechanism. It is vendor-specific, so it is unreachable through a portable PKCS#11 layer by construction. |
| `PQC-03` | LMS / XMSS | No | L | Nothing. Not advertised. | No PKCS#11 v3.2 token surveyed implements LMS or XMSS, so unlike PQC-01 this is blocked at the backend. The stateful schemes also need one-time-key state persistence the KSP has no model for, and a lost state update forges signatures — a correctness hazard, not just missing code. |
| `PROP-11` | NCRYPT_SECURITY_DESCR_PROPERTY | No | L | Refused with NTE_NOT_SUPPORTED rather than accepted and ignored. | PKCS#11 has no ACL model, so there is nothing to map an SDDL string onto. A side store from key label to descriptor would be this provider inventing an access control system it cannot enforce. |
| `PROP-16` | NCRYPT_USE_COUNT_PROPERTY | No | L | Refused with NTE_NOT_SUPPORTED. | No atomic counter primitive in PKCS#11 or SoftHSM2. A read-modify-write on an object attribute is not a use count under concurrency, and a wrong count is worse than no count. |

## Waiting on hardware, a purchase, or a validation programme (4)

None of these is an engineering task, and one is worth reading carefully: `OPS-03` is **fully tooled**. The signing script signs, timestamps and verifies, and CI signs automatically once the secret exists. What is missing is a code-signing certificate, which has to be bought by a verified legal entity.

| ID | Feature | St | Eff | What works today | What the blocker rests on |
|---|---|---|---|---|---|
| `OPS-01` | Hardware key protection | No | N/A | Nothing, and it cannot: SoftHSM2 is a software token over encrypted SQLite. The provider reports NCRYPT_IMPL_SOFTWARE_FLAG, truthfully — it used to say hardware in the source while emitting the software value. | Hardware. The PKCS#11 abstraction already allows pointing the KSP at a real HSM, so this closes by deployment rather than by code. |
| `OPS-02` | FIPS 140-2/3 validation | No | N/A | Nothing. | Certified hardware and a formal validation programme. Follows from OPS-01 and is not an engineering task. |
| `OPS-03` | Authenticode-signed binary | No | N/A | The signing pipeline is complete and self-tested: tools/sign_ksp.ps1 signs, timestamps and verifies, taking a certificate from the Windows store, a PFX whose password comes from the environment and never a parameter, or Azure Trusted Signing. CI signs automatically once the secret exists. | An OV or EV code-signing certificate, which must be bought by a verified legal entity. Nothing in this repository can supply that, so the shipped binary is unsigned and the row stays Not covered. |
| `OPS-06` | Load balancing / HA | No | N/A | Nothing here, and nothing needs to: it is handled inside vendor PKCS#11 libraries. | A vendor library. The provider inherits load balancing and failover automatically when pointed at one, so there is nothing to implement. |

## Decisions this project made — revisitable by definition (11)

**These are the only rows a reader can argue with**, and the only ones where "open" reflects a judgement rather than an obstacle. Each one's "rests on" has to survive a single question: *is that a fact about CNG, or a fact about our code?*

| ID | Feature | St | Eff | What works today | What the blocker rests on |
|---|---|---|---|---|---|
| `3DES-01` | 3DES / DES | No | L | Nothing, although SoftHSM2 implements fourteen DES mechanisms, so the backend is not the obstacle. | Scope and age. Excluded from modern HLK requirements. Implementable at any time; deliberately not implemented. |
| `AES-08` | AES-CFB | P | M | Both feedback sizes CNG can actually reach: the 8-bit default, and full-block through BCRYPT_MESSAGE_BLOCK_LENGTH. CKM_AES_CFB64 is mapped for a MessageBlockLength of 8. All gated on the capability probe and verified against a live token, which asserts the two sizes produce DIFFERENT ciphertext — a provider ignoring the property cannot pass. | Two things, and only one of them is ours. The ASYMMETRY is external: CNG permits any feedback size up to the block, PKCS#11 defines mechanisms for four of them, and nothing here can add the missing ones. What is DELIBERATE is the handling — a size with no mechanism is refused rather than rounded to the nearest, because rounding would silently select a different cipher and produce ciphertext nothing else could decrypt. The row is classified as our decision because that refusal is the part a reader might want to argue with. |
| `DSA-01` | DSA signing | No | L | Nothing. | Scope. Deprecated in modern Windows PKI and absent from every HSM KSP surveyed. |
| `ECDH-06` | Finite-field Diffie-Hellman | No | L | Nothing. ECDH on nine curves covers the agreement surface. | Scope. CKM_DH_PKCS_KEY_PAIR_GEN and CKM_DH_PKCS_DERIVE both exist, so this IS implementable — it is excluded because ECDH supersedes it and no surveyed HSM KSP exposes it. Of all the deliberate rows this is the one with the clearest path if a deployment ever needed it. |
| `FMT-06` | Private key export | No | N/A | Public key export in CNG blob format for every supported family. Private key export is refused with NTE_NOT_SUPPORTED. | The HSM posture, enforced on the token rather than in the provider: keys are CKA_EXTRACTABLE=FALSE unless NCRYPT_EXPORT_POLICY_PROPERTY relaxes it, and even then only wrapped export opens. This is correct behaviour, not an unfinished feature. |
| `FMT-07` | Private key import | No | L | Public key import creates a real CKO_PUBLIC_KEY; truncated and unknown-curve blobs are rejected rather than silently accepted. Symmetric key unwrap works and creates the key sensitive and non-extractable, so wrapping is a way IN and not a way back out. | The HSM posture again. C_CreateObject with private material or C_UnwrapKey would both work, so this is a choice: a key the provider did not generate has an unknown history. Worth revisiting only if a migration workflow demands it. |
| `FMT-09` | PKCS#8 blob | No | L | Nothing: it is a private-key format. | FMT-07, exactly. Same posture, same reconsideration trigger. |
| `IFACE-07` | PromptUser | No | L | Refused with NTE_NOT_SUPPORTED. | A UI thread and a window handle. A KSP is loaded into whatever process called NCrypt, including services with no desktop, so prompting is a deployment decision rather than a capability to add unconditionally. |
| `PROP-12` | NCRYPT_UI_POLICY_PROPERTY | No | L | Refused with NTE_NOT_SUPPORTED. | IFACE-07. A UI policy with no prompt to govern would be a stored value nothing reads. |
| `PROP-15` | NCRYPT_WINDOW_HANDLE_PROPERTY | No | L | Refused with NTE_NOT_SUPPORTED. | IFACE-07, for the same reason as PROP-12. |
| `RSA-02` | RSA 1024 and below | P | S | Any multiple of 64 from KSP_RSA_MIN_BITS to 16384. A legacy build can lower the floor; the shipped default refuses below 2048 with NTE_BAD_LEN. | A security choice, not a constraint: the mechanism exists and the code path works. Silently allowing 1024 would weaken every deployment that did not ask for it, so it is an opt-in at build time rather than a refusal. |

---

## Gaps outside this matrix’s scope

Every row above is a capability observed across shipping CNG KSPs —
the market. **A defect in this provider’s own conformance surface
is not such a capability**, so no row here would ever point at one.

That blind spot has cost three findings: session 14’s two stubs,
found by reading the function table rather than the matrix, and the
first entry below, found by making a test repeatable. They are
recorded here rather than left in a commit message.

### NCryptCreatePersistedKey does not return NTE_EXISTS

Nothing checks whether the name is already taken, so a second create adds a second object with the same CKA_LABEL and NCryptOpenKey returns whichever the token's search hands back first. Microsoft documents NTE_EXISTS for this case, with NCRYPT_OVERWRITE_KEY_FLAG as the way to ask for replacement.

**How it was found.** While making the two-token suite repeatable: two deletes both reported success and a key was still openable, because earlier runs had left duplicates behind.

**Status.** Open. Not fixed as part of proposals A to D, because doing it properly means the overwrite flag as well as the check, with tests in both directions.

### Key-scoped function table slots are unverifiable

The mock types every slot as void *, so a wrong parameter TYPE is not a build error on Linux, and MSVC cannot compile ksp_main.c without ncrypt_provider.h. Eight provider-scoped slots are now checked against <ncrypt.h>; key-scoped ones cannot be, because the public prototype is not the slot's shape.

**How it was found.** Session 14, by asking why KSP_NotifyChangeKey had survived with the wrong parameter type.

**Status.** Tracked as TABLE-01, which is the one matrix row that does cover a conformance question rather than a capability.

---

## Maintaining this

To record a gap as closed, set its row’s `status` to `Covered` and
clear its `gap_solution` in `docs/feature-matrix.csv`, then **delete
its entry from `docs/gap_detail.py`** — leaving it would keep
describing a gap that no longer exists, which is the same failure as a
stale coverage figure. Then regenerate:

```bash
python3 generate_feature_matrix.py   # the PDF, including this analysis
python3 generate_cng_coverage_xlsx.py  # the workbook’s Open Items
python3 generate_gap_analysis.py     # this document
```

All three call `gap_detail.validate()` first, so a row added to the
matrix without its detail, a stale entry, or a mismatch between
"deliberate position" and `external` fails the build instead of
producing an artifact with a silently blank column.
