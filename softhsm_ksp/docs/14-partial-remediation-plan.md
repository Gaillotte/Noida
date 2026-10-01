# Plan: closing the Partial rows

Fourteen capabilities are recorded **Partial** in `docs/feature-matrix.csv` —
implemented and usable, but with a stated limit. This document proposes what
to do about each, favouring what can be done **with SoftHSM2 2.7.0 as the
backend** rather than only against a second token.

A Partial row is not automatically a defect. Several are Partial *because* the
provider takes a deliberate position, and the right outcome for those is to
leave the code alone and say so more clearly. This plan separates the two.

---

## Verdict at a glance

| ID | Capability | Verdict | Works on SoftHSM2? | Effort |
|---|---|---|---|---|
| **AES-09** | AES key wrap | **Fix — proposal A** | Yes | M |
| **FMT-08** | `BCRYPT_KEY_DATA_BLOB` export | **Fix — proposal A** | Yes | S (rides on A) |
| **IFACE-04** | `SetProviderProperty` token selection | **Fix — proposal B** | Yes | M |
| **LIFE-08** | Machine vs user scope isolation | **Fix — proposal C** | Yes | M |
| **AES-08** | AES-CFB feedback sizes | **Partial fix — proposal D** | **No** — SoftHSM2 has no CFB | S |
| RSA-02 | RSA ≤ 1024 | Leave; document | n/a | — |
| IFACE-05 | `NotifyChangeKey` | Leave; a fix would be fabrication | n/a | — |
| EDDSA-01 | Ed25519 signing | Blocked on Microsoft | Yes, already works | — |
| EDDSA-02 | Ed448 signing | Blocked on Microsoft | Yes, already works | — |
| HMAC-01 | HMAC-SHA* | Blocked on Microsoft | Yes, already works | — |
| AES-06 | AES-CTR | Blocked on Microsoft | Yes, already works | — |
| PQC-01 | ML-DSA export | Blocked on a Windows SDK header | **No** — SoftHSM2 has no ML-DSA | — |
| TABLE-01 | Function table layout | Blocked on `ncrypt_provider.h` | n/a | — |
| BUILD-01 | Windows build | Blocked on `ncrypt_provider.h` | n/a | — |

**Five rows are genuinely actionable. Four of the five work on SoftHSM2.**
The other nine are blocked outside this repository or are deliberate
positions; proposing work for them would be inventing a task.

---

---

## Status — all four implemented

| ID | Proposal | Status | Where it is tested |
|---|---|---|---|
| AES-09, FMT-08 | A — export policy | **Covered** | unit + live token |
| IFACE-04 | B — deferred slot binding | **Covered** | unit + **two** live tokens |
| LIFE-08 | C — per-scope tokens | **Covered** | unit + two live tokens with different PINs |
| AES-08 | D — CFB64 | **Partial by choice** | unit; the live case skips, no token here has `CKM_AES_CFB64` |

`AES-08` stays Partial deliberately: CNG permits any feedback size up to the
block, PKCS#11 defines mechanisms for four of them, and a size with no
mechanism is refused rather than rounded to a different cipher.

### What implementing B and C found

Neither proposal's own code was where the interesting defects were.

- **A counted CNG wide-string property was bounded before its terminator was
  stripped.** `cbInput` is a buffer size and callers differ on whether they
  count the terminator, so a maximum-length value passed *with* one is
  `cchMax + 1` characters and was refused — something entirely legal. The
  **PIN path had the same off-by-one**, written independently and predating
  this work. Both now go through one helper, which is the point: the bug
  existed twice because the subtle part was written twice. Found by
  strengthening a vacuous assertion — the original "terminator stripped"
  check used a short label, where the terminator is harmless, so it could
  not have failed.
- **`make <binary>` from `tests/unit/` silently rebuilt nothing.** The
  wrapper Makefile had no rule for a single test binary, so GNU make matched
  its implicit rules against the existing file and reported "up to date".
  **Four fault injections in a row therefore ran against a stale binary and
  looked undetected** — the worst possible failure for a tool whose only job
  is to show that a test can fail. A match-anything pattern rule does not
  fix it either, because make declines to apply one to a target that already
  exists; the rule needs a `FORCE` prerequisite.
- **Ten test stubs for `P11_AcquireSession` were never checked against the
  real prototype.** None of the suites that stub it included
  `p11_session.h`, so when the function gained its scope parameter every
  stub kept its old shape: no diagnostic, because the mismatch is across
  translation units, and then ten segfaults as the scope argument arrived in
  the pointer parameter. They include the header now. This is the same class
  as the function-table slot types in session 14 — a stub that is not
  checked against the thing it stands in for is a trap waiting for the next
  signature change.
- **`mock_GetTokenInfo` returned `CKR_OK` and filled nothing**, exactly as
  `mock_GetInfo` did before session 8. Selection by token label reads
  `info.label`, so against an untouched struct a label test would have
  compared against whatever was on the caller's stack. It now gives each
  slot a distinct blank-padded `CKA_LABEL`, which is what makes selecting
  between two tokens a real question under the mock.
- **A guard that looked load-bearing was not.** On the label path, refusing
  a half-configured per-scope setup changes the error message and not the
  outcome: an absent label is the empty string and matches no token, so the
  lookup fails anyway. No injection could distinguish the two, and the code
  now says so. The **slot** path's equivalent guard *is* load-bearing — an
  unset variable leaves the other scope at slot 0, a perfectly valid slot —
  and that one is injected and caught.
- **Two redundant guards meant neither could be injected alone.**
  `P11_EnsureSlotSelected` checks `g_bSlotBound` outside the lock and again
  inside it. Removing either leaves the other working, so the idempotence
  assertion only fails when both go. Defence in depth, recorded as such
  rather than claimed as two tested properties.

### One thing found and deliberately not fixed here

**`NCryptCreatePersistedKey` does not return `NTE_EXISTS` for a name that is
already taken.** Nothing in the provider checks, so a second create with the
same name adds a second object with the same `CKA_LABEL`, and `NCryptOpenKey`
then returns whichever the token's search hands back first. It surfaced while
making the two-token suite repeatable: two deletes both reported success and
a key was still openable, because earlier runs had left duplicates.

It is a real conformance gap — Microsoft documents `NTE_EXISTS`, and
`NCRYPT_OVERWRITE_KEY_FLAG` as the way to ask for replacement — and it is
**not** part of proposals A to D. Fixing it properly means the flag as well
as the check, with its own tests in both directions, so it belongs in its own
change rather than smuggled into this one.


## Proposal A — honour `NCRYPT_EXPORT_POLICY_PROPERTY`

**Closes: AES-09 (wrap) and FMT-08 (symmetric export). Two rows, one change.**

### Why these are Partial

Both say the same thing in different words: *every key this provider creates
is `CKA_EXTRACTABLE=FALSE`*, so `C_WrapKey` answers `CKR_KEY_UNEXTRACTABLE`
and `C_GetAttributeValue(CKA_VALUE)` refuses. Wrapping is a way in and not a
way back out.

That default is correct and must stay the default. What is missing is the
**caller's ability to ask for something else**, which CNG already defines a
property for:

```c
#define NCRYPT_EXPORT_POLICY_PROPERTY       L"Export Policy"   /* ncrypt.h */
#define NCRYPT_ALLOW_EXPORT_FLAG                0x1
#define NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG      0x2
```

`ksp_properties.c` already answers a **read** of this property — it returns a
hard-coded `0`. It has never accepted a **write**. So a caller following the
standard CNG pattern (create deferred → set export policy → finalize) is
silently given a key that cannot do what it asked for.

### What to implement

The two flags mean different things and must map to different PKCS#11
attributes. Getting this wrong in either direction is a security bug.

| CNG export policy | `CKA_EXTRACTABLE` | `CKA_SENSITIVE` | What the caller can then do |
|---|---|---|---|
| *(unset — the default)* | `FALSE` | `TRUE` | Nothing leaves the token. Today's behaviour, unchanged. |
| `NCRYPT_ALLOW_EXPORT_FLAG` | `TRUE` | `TRUE` | `C_WrapKey` succeeds. Key leaves **only wrapped** under a KEK already on the token. Plaintext export still refused. |
| `NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG` | `TRUE` | `FALSE` | `CKA_VALUE` becomes readable, so `BCRYPT_KEY_DATA_BLOB` export works. |

`CKA_SENSITIVE=TRUE` is what stops `CKA_VALUE` being read, so plaintext
export needs both attributes relaxed. Wrapped export needs only
`CKA_EXTRACTABLE`. **These are not interchangeable and the code must not
collapse them into one boolean.**

Work items:

1. `src/ksp/ksp_key.h` — add `DWORD dwExportPolicy` to `KSP_KEY`.
2. `src/ksp/ksp_properties.c` — accept a **set** of
   `NCRYPT_EXPORT_POLICY_PROPERTY` (a `DWORD`), **only before the key is
   finalized**. Setting it on a finalized key must fail: the attributes are
   fixed on the token at generation and pretending otherwise would be the
   `NotifyChangeKey` mistake again. Reject unknown flag bits with
   `NTE_BAD_FLAGS`; `ALLOW_ARCHIVING`/`ALLOW_PLAINTEXT_ARCHIVING` are about
   key escrow and are **not** in scope — refuse them explicitly.
3. `src/ksp/ksp_key.c` — five templates currently hard-code
   `{ CKA_EXTRACTABLE, &bFalse }` (lines ~298, ~371, ~461, ~551, ~658). Each
   takes its value from the policy instead. The `bSensitive` value follows
   the table above.
4. `src/ksp/ksp_properties.c` — the **read** returns the stored policy rather
   than a constant `0`.
5. `src/ksp/ksp_crypto.c` — `KSP_ExportKey` for `BCRYPT_KEY_DATA_BLOB` stops
   refusing outright and instead reads `CKA_VALUE`, letting the token refuse
   if the policy was not set. **Let the token be the enforcement point**; a
   provider-side check that disagreed with the token would be the worse of
   the two answers.

### Why it works on SoftHSM2

SoftHSM2 2.7.0 enforces both attributes, verified in the vendored source:
`SoftHSM.cpp:6738` returns `CKR_KEY_UNEXTRACTABLE` from `C_WrapKey` when
`CKA_EXTRACTABLE` is false, and the `C_GetAttributeValue` path checks
`CKA_EXTRACTABLE`/`CKA_SENSITIVE` before releasing `CKA_VALUE`. It also
implements `CKM_AES_KEY_WRAP` (`SoftHSM.cpp:787`), so the wrap path is
reachable on SoftHSM2 today — it is the key attributes, not the mechanism,
that block it.

### Testing

- **Unit** — the mock records the template, so assert the exact
  `CKA_EXTRACTABLE`/`CKA_SENSITIVE` pair for each of the three policies, and
  that setting the policy after finalize is refused.
- **Live token (SoftHSM2 and Kryoptic)** — create a key with each policy and
  check the token agrees: wrap succeeds only with `ALLOW_EXPORT`, `CKA_VALUE`
  reads back only with `ALLOW_PLAINTEXT_EXPORT`, and the default key still
  refuses both. *This is the assertion that matters* — the mock can be told
  to say anything.
- **Fault injection** — collapse the two flags into one boolean and confirm
  the plaintext-export test fails. If it does not, the test is not testing
  the distinction.

### Risk, stated plainly

This adds a way to create an extractable key. That is a real reduction in the
guarantee the provider offers, and it is why the default must not move and
why the property must be refused after finalize. The justification is that
CNG defines this property, callers legitimately use it for key backup and
migration, and a provider that silently ignores it is not safer — it is just
harder to reason about. A deployment that wants the old absolute guarantee
should build with the policy disabled; consider a `KSP_ALLOW_EXPORT_POLICY`
compile-time switch defaulting to **on**, mirroring how `KSP_RSA_MIN_BITS`
handles the RSA-1024 question.

**Moves AES-09 and FMT-08 from Partial to Covered.**

---

## Proposal B — let `SetProviderProperty` choose the token

**Closes: IFACE-04.**

### Why it is Partial

Only `NCRYPT_PIN_PROPERTY` is writable. Token selection is refused because
"the session pool is already bound to a slot by then". That is true of the
current code and not a law: `P11_Initialize` picks the slot
(`p11_context.c:123/148/160`) during `KSP_OpenProvider`, so by the time a
caller can set a property the choice is made.

The PIN does not have this problem, and the reason is instructive — sessions
open **lazily**, so a PIN set before the first cryptographic call is the one
used to log in. The slot can work the same way.

### What to implement

Split initialisation in two:

1. **At `KSP_OpenProvider`** — load the module and call `C_Initialize` only.
   Do not select a slot.
2. **At first `P11_AcquireSession`** — select the slot, using (in order) a
   value set through `SetProviderProperty`, then `SOFTHSM2_TOKEN_LABEL`, then
   `SOFTHSM2_SLOT`, then the first slot reporting a token. This is the
   existing precedence with one entry added in front.
3. Accept `KSP_SLOT_PROPERTY` and a new `KSP_TOKEN_LABEL_PROPERTY` as
   writable **until the first session opens**, and refuse them after with
   `NTE_INVALID_HANDLE` — the same "too late to change" rule as proposal A.

An explicit selection that matches no token must remain an error, never a
silent fallback to slot 0. That rule is already in `Known Limitations` and
this change must not weaken it.

### Why it works on SoftHSM2

SoftHSM2 supports several tokens in one configuration — `softhsm2-util
--init-token --slot N` — so a test can stand up two tokens and prove the
selection actually takes effect rather than returning success and using the
first slot anyway.

### Testing

- **Unit** — selection before the first session is honoured; after it, refused.
- **Live token** — initialise **two** SoftHSM2 tokens with different labels,
  create a key in one, select the other and confirm the key is *not* visible.
  A test with one token cannot tell a working selection from an ignored one.

**Moves IFACE-04 from Partial to Covered.**

---

## Proposal C — real isolation for machine vs user scope

**Closes: LIFE-08, honestly rather than cosmetically.**

### Why it is Partial

`NCRYPT_MACHINE_KEY_FLAG` becomes a `CKA_LABEL` prefix (`m/`, `u/`). Names no
longer collide, which is worth having, but **anyone who can log into the
token reads both scopes**. The matrix says so in capitals, and correctly: no
amount of label work supplies an ACL model PKCS#11 does not have.

### What to implement

Stop trying to get isolation from labels and get it from **tokens**, which
PKCS#11 does have: a token has its own PIN and its own login state.

1. Two optional settings — `KSP_MACHINE_TOKEN_LABEL` and
   `KSP_USER_TOKEN_LABEL` (or slots).
2. When both are set, `NCRYPT_MACHINE_KEY_FLAG` selects **which token** the
   operation uses, not which prefix the label gets.
3. When they are not set, behaviour is exactly as today — prefixing in one
   token — so no existing deployment changes.
4. The session pool becomes per-token. This is the substantial part of the
   work and the reason the effort is M rather than S: `p11_session.c` holds
   one pool bound to one slot, and it needs to hold one per token in use.

Isolation is then as strong as the token boundary: a caller who logs in with
the user PIN cannot read machine keys, because they are in a different token
with a different PIN.

### Why it works on SoftHSM2

Two tokens, two PINs, one `softhsm2.conf`. This is exactly the deployment the
`Known Limitations` note already recommends — *"use separate tokens if
separation must be enforced"* — so the proposal is to make the provider
support what the documentation already tells people to do.

### Testing

- **Live token** — two SoftHSM2 tokens with **different PINs**. Create a
  machine key; log in as the user scope; confirm `KSP_EnumKeys` does not list
  it and `KSP_OpenKey` cannot open it. Then confirm the machine scope still
  can. Anything less does not demonstrate isolation.

**Moves LIFE-08 from Partial to Covered when both tokens are configured, and
leaves it Partial-by-configuration otherwise** — which should be stated in
the matrix rather than glossed.

---

## Proposal D — the third CFB feedback size

**Improves AES-08. Does not fully close it, and not on SoftHSM2.**

### Why it is Partial

CNG permits any feedback size up to the block; PKCS#11 defines mechanisms for
only four. The provider wires two of them:

| `MessageBlockLength` | Feedback | PKCS#11 mechanism | Wired today |
|---|---|---|---|
| 1 byte | 8-bit (CNG's default) | `CKM_AES_CFB8` (0x2106) | Yes |
| 8 bytes | 64-bit | **`CKM_AES_CFB64` (0x2105)** | **No — refused** |
| 16 bytes | 128-bit (full block) | `CKM_AES_CFB128` (0x2107) | Yes |

`CKM_AES_CFB64` exists in the OASIS header vendored in the submodule and is
simply not mapped. Adding it is a few lines in `KspBuildAesMechanism` and one
branch in the `BCRYPT_MESSAGE_BLOCK_LENGTH` setter.

`CKM_AES_CFB1` stays unreachable: CNG expresses the size in **bytes**, and
one bit is not a byte count.

### Why this does not close the row

Two reasons, both worth stating rather than hiding:

1. Even with all three wired, a caller asking for, say, 4-byte feedback is
   still refused — PKCS#11 has no mechanism and rounding would silently
   select a different cipher.
2. **SoftHSM2 2.7.0 implements no CFB mechanism at all.** It has
   `CKM_AES_CTR` and `CKM_AES_KEY_WRAP` and no `CKM_AES_CFB*`. So this whole
   row is dark on SoftHSM2 regardless of what the provider maps, the
   capability probe correctly keeps it dark, and the improvement is visible
   only on a token that implements CFB, such as Kryoptic.

   **Do not confirm this with a bare grep.** `CKM_AES_CFB64/8/128/1` appear
   twice in the SoftHSM2 tree — in the vendored OASIS constant header, and
   in `src/bin/dump/tables.h`, which is a mechanism-name table for a
   debugging tool. Neither is an implementation. The question to ask is
   whether the mechanism appears in `SoftHSM.cpp`'s mechanism table and
   dispatch; for CFB it does not.

### Testing

- **Live token (Kryoptic)** — extend the existing CFB suite to the 8-byte
  size and assert its ciphertext differs from **both** CFB8 and CFB128. Two
  comparisons, not one: a provider that mapped 8 to CFB128 would pass a test
  that only compared against CFB8.

**Leaves AES-08 Partial, with a smaller gap and a clearer reason.**

---

## Not proposed, and why

These are the nine remaining Partial rows. Each is Partial for a reason no
implementation in this repository can remove.

### Blocked on Microsoft — the CNG surface has no way to ask

| Row | The wall |
|---|---|
| **EDDSA-01 / EDDSA-02** | CNG defines **no EdDSA algorithm identifier at all**. `EDDSA_ED25519` / `EDDSA_ED448` are this provider's own names, so only an application written against this KSP can request them. Both work correctly on SoftHSM2 and were proven end to end against Kryoptic. |
| **HMAC-01** | CNG performs HMAC through BCrypt **algorithm** handles, not KSP **key** algorithms. `HMAC_SHA*` are our names for the same reason. |
| **AES-06** | CNG defines no counter-mode chaining string. `ChainingModeCTR` is our extension. |

For all four, the code is correct, the mechanism works on SoftHSM2, and the
limit is that no stock application will ever name them. Writing more code
does not change that. **The honest action is to keep them Partial and keep
the reason visible** — the market comparison already grades this as the
provider's main divergence from the field, and it should stay that way.

### Blocked on a header this workspace does not have

| Row | The wall |
|---|---|
| **BUILD-01** | `ncrypt_provider.h` declares `NCRYPT_KEY_STORAGE_FUNCTION_TABLE`. A `dir /s /b` across both drives of a `windows-latest` runner — after a WDK install that reported success — found only this repository's own test mock. Nine of ten source files compile clean at `/W3 /WX`; `ksp_main.c` cannot. |
| **TABLE-01** | Eight provider-scoped slots are now signature-checked against `<ncrypt.h>`, which caught a real defect. Key-scoped slots cannot be: `NCryptSignHash` takes `(hKey, …)` while the table slot takes `(hProvider, hKey, …)`, so the public prototype is not the slot's shape and asserting it would be inventing a fact. |
| **PQC-01** | Only the **export** half is open. The CNG post-quantum blob layout lives in a Windows SDK header not available here, and a guessed layout would pass every test in this repository and fail only on Windows — precisely the `BCRYPT_SHA224_ALGORITHM` mistake. Also unreachable on SoftHSM2, which defines the ML-DSA mechanisms and implements none. |

**The single most valuable action available to this project is to establish
where `ncrypt_provider.h` comes from and build on a machine that has it.** It
would close BUILD-01 and TABLE-01, unblock the export half of PQC-01, and —
more importantly than any row — convert every other claim here from
"verified on Linux against a PKCS#11 token" to "verified as a Windows
provider". Two guesses at its location have already been wrong; it is
associated with the Cryptographic Provider Development Kit, unconfirmed.

### Deliberate positions — changing them would be a regression

| Row | Why it stays |
|---|---|
| **RSA-02** | `KSP_RSA_MIN_BITS` defaults to 2048 and a legacy build can lower it. Making 1024 available by default would weaken every deployment to satisfy one matrix cell. The build-time switch is the correct shape for this. |
| **IFACE-05** | Key-change notification needs a channel PKCS#11 does not provide. There is no `C_WaitForSlotEvent` for objects. Polling `C_FindObjects` on a timer and signalling an event would look like support and would not be — it would miss changes between polls and report changes that are only the poll catching up. **A fabricated notification is worse than an honest refusal**, which is what the slot now returns. |

---

## Suggested order

1. **Proposal A** (AES-09, FMT-08) — two rows for one change, standard CNG
   property, works on SoftHSM2. Highest value per unit of work.
2. **Proposal B** (IFACE-04) — self-contained, and the two-token test
   infrastructure it needs is also what proposal C needs.
3. **Proposal C** (LIFE-08) — builds on B's per-token session pool.
4. **Proposal D** (AES-08) — small, but only demonstrable on a non-SoftHSM2
   token, so it is worth doing last and honestly reporting as an improvement
   rather than a closure.

Expected outcome: **Partial 14 → 10, Covered 68 → 71** (AES-09, FMT-08,
IFACE-04 close outright; LIFE-08 closes when two tokens are configured).

Every proposal above should be built the way this project has learned to
build things: the assertion that matters runs against a **live token**, and
each claim is confirmed by injecting the defect it is supposed to catch.
