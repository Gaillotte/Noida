# Per-row detail for every open row in the feature matrix.
#
# The matrix's own columns answer "is it supported" and "what would close
# it". Two questions they do not answer, and that turned out to matter:
#
#   works     What the provider does TODAY. A Partial row is not a hole —
#             most of these work and are tested, and are Partial only
#             because no stock application can ask for them. Reading the
#             status column alone gets that exactly backwards.
#
#   rests_on  What the blocker rests on, named specifically. Paired with
#             `external`, this is the test that three rows failed:
#             IFACE-04, LIFE-08 and FMT-08 were all recorded as deliberate
#             positions, and all three were closed by proposals A to C. In
#             every case the "position" rested on a property of the
#             then-current code — the slot was bound during initialisation,
#             scoping was a label prefix, keys were non-extractable by
#             default — rather than on anything in CNG or PKCS#11.
#
#   external  True  the blocker is outside this repository: a CNG
#                   identifier Microsoft has not defined, a PKCS#11
#                   mechanism that does not exist, a header nobody here
#                   has, hardware, or a purchase.
#             False the blocker is a choice this project made. Those are
#                   legitimate, but they are revisitable by definition,
#                   and `rests_on` has to survive the question "is that a
#                   fact about CNG, or a fact about our code?"
#
# Keep `works` honest about verification. "Verified against Kryoptic" and
# "passes the unit suite" are different claims, and this project has been
# wrong before by treating mock coverage as evidence about real tokens.
GAP_DETAIL = {

    # ── Blocked on ncrypt_provider.h and a Windows machine ────────────────
    'BUILD-01': dict(
        works='MSVC compiles nine of the ten source files clean at /W3 /WX '
              'and links test_p11_layer.exe. The mingw cross-compile is '
              'clean on all ten minus ksp_main.c.',
        rests_on='ncrypt_provider.h, which declares '
                 'NCRYPT_KEY_STORAGE_FUNCTION_TABLE. A dir /s /b across C: '
                 'and D: on a windows-latest runner returned only this '
                 'repository\'s own test mock, after a WDK install that '
                 'reported success. It is not in the Windows SDK.',
        external=True),
    'TABLE-01': dict(
        works='Designated initialisers make a wrong slot NAME a build '
              'error. Eight provider-scoped slots are also signature-'
              'checked against <ncrypt.h>, which is what caught '
              'KSP_NotifyChangeKey holding an NCRYPT_KEY_HANDLE where the '
              'parameter is HANDLE *phEvent.',
        rests_on='The same missing header. Key-scoped slots cannot be '
                 'checked against the public prototype, because it is not '
                 'the slot\'s shape: NCryptSignHash takes (hKey, ...) while '
                 'the slot takes (hProvider, hKey, ...). Asserting the '
                 'public shape there would be inventing a fact.',
        external=True),
    'PQC-01': dict(
        works='ML-DSA generates, reopens by parameter set and signs at all '
              'three sets, verified against Kryoptic built with its pqc '
              'feature over OpenSSL 3.5.8. Gated on the capability probe, '
              'so it is dark on SoftHSM2 and live on a v3.2 token.',
        rests_on='The CNG post-quantum key blob layout, which is in a '
                 'Windows SDK header not available here. Public key export '
                 'is the only thing missing. A guessed layout would pass '
                 'every test here and fail only on Windows — the '
                 'BCRYPT_SHA224_ALGORITHM mistake exactly.',
        external=True),
    'PQC-02': dict(
        works='The probe recognises CKM_ML_KEM, so the backend is not the '
              'obstacle. Nothing is advertised, deliberately.',
        rests_on='The function table has no slot for encapsulation or '
                 'decapsulation, so a KSP could hold an ML-KEM key with no '
                 'entry point to use it. Whether a newer '
                 'ncrypt_provider.h adds such slots cannot be established '
                 'here — the same missing header.',
        external=True),

    # ── Blocked because CNG defines no identifier or no slot ──────────────
    'EDDSA-01': dict(
        works='Ed25519 signs, and is verified end to end against Kryoptic. '
              'The absent CK_EDDSA_PARAMS that selects the pure '
              'context-free form is deliberate and fault-injected.',
        rests_on='CNG defines no EdDSA algorithm identifier at all, so '
                 'EDDSA_ED25519 is this provider\'s own string and no '
                 'stock application will ask for it. Nothing in the KSP '
                 'can change that.',
        external=True),
    'EDDSA-02': dict(
        works='Ed448 signs against Kryoptic with CK_EDDSA_PARAMS supplied, '
              'which Ed448 requires and Ed25519 must not have. The '
              'asymmetry is deliberate and both mistakes are '
              'fault-injected. It did NOT work before session 10: '
              'SoftHSM2 tolerates the missing parameter, so a second token '
              'was needed to see it.',
        rests_on='Same as EDDSA-01 — no CNG identifier exists.',
        external=True),
    'AES-06': dict(
        works='AES-CTR encrypts and decrypts, verified against a live '
              'token, selected through NCRYPT_CHAINING_MODE_PROPERTY.',
        rests_on='CNG defines no counter-mode chaining string, so '
                 'ChainingModeCTR is a provider extension that no stock '
                 'application will select.',
        external=True),
    'HMAC-01': dict(
        works='HMAC signing works over CKM_SHA*_HMAC for SHA-1 through '
              'SHA-512, verified against a live token. It had never '
              'actually worked before session 10 — KSP_SignHash passed '
              'hPrivKey unconditionally and secret keys live in '
              'hSecretKey.',
        rests_on='CNG reaches HMAC through BCrypt algorithm handles, not '
                 'through KSP key algorithms, so HMAC_SHA* are this '
                 'provider\'s own identifiers.',
        external=True),

    # ── Blocked because PKCS#11 has no mechanism for it ───────────────────
    'IFACE-05': dict(
        works='Validates the provider and flags, clears *phEvent and '
              'refuses registration with NTE_NOT_SUPPORTED. Unregistering '
              'succeeds, because there is nothing to tear down. Before '
              'session 14 it returned ERROR_SUCCESS without writing the '
              'handle, so a caller waited on an uninitialised HANDLE.',
        rests_on='PKCS#11 has no object-change channel: there is no '
                 'C_WaitForSlotEvent equivalent for objects. Polling '
                 'C_FindObjects on a timer would be a fabrication dressed '
                 'as a notification. THIS IS THE ROW CLOSEST IN SHAPE TO '
                 'the three that were wrongly called deliberate — it would '
                 'become actionable the moment a backend offered such a '
                 'channel, so it is worth re-reading rather than '
                 'inheriting.',
        external=True),
    'IFACE-06': dict(
        works='Refused with NTE_NOT_SUPPORTED.',
        rests_on='The property reports on an asynchronous operation and '
                 'PKCS#11 is synchronous, so there is no operation state to '
                 'report however much code is written. This row sat in the '
                 'deliberate column until the pairing check was run against '
                 'its own text, which already said "a fact about PKCS#11 '
                 'rather than about this code" — so it was mislabelled by '
                 'the person who wrote the reason, and the cross-check is '
                 'what caught it.',
        external=True),
    'PROP-11': dict(
        works='Refused with NTE_NOT_SUPPORTED rather than accepted and '
              'ignored.',
        rests_on='PKCS#11 has no ACL model, so there is nothing to map an '
                 'SDDL string onto. A side store from key label to '
                 'descriptor would be this provider inventing an access '
                 'control system it cannot enforce.',
        external=True),
    'PROP-16': dict(
        works='Refused with NTE_NOT_SUPPORTED.',
        rests_on='No atomic counter primitive in PKCS#11 or SoftHSM2. A '
                 'read-modify-write on an object attribute is not a use '
                 'count under concurrency, and a wrong count is worse than '
                 'no count.',
        external=True),
    'PQC-03': dict(
        works='Nothing. Not advertised.',
        rests_on='No PKCS#11 v3.2 token surveyed implements LMS or XMSS, so '
                 'unlike PQC-01 this is blocked at the backend. The '
                 'stateful schemes also need one-time-key state '
                 'persistence the KSP has no model for, and a lost state '
                 'update forges signatures — a correctness hazard, not '
                 'just missing code.',
        external=True),
    'FMT-10': dict(
        works='Nothing. Not advertised.',
        rests_on='OPAQUETRANSPORT has no defined wrapping format to follow, '
                 'so there is no standard to implement against — only a '
                 'format this provider would invent and no one else could '
                 'read.',
        external=True),
    'OPS-05': dict(
        works='Nothing. Not advertised.',
        rests_on='Key attestation has no standard PKCS#11 mechanism. It is '
                 'vendor-specific, so it is unreachable through a portable '
                 'PKCS#11 layer by construction.',
        external=True),

    # ── Blocked on hardware, a purchase, or a validation programme ────────
    'OPS-01': dict(
        works='Nothing, and it cannot: SoftHSM2 is a software token over '
              'encrypted SQLite. The provider reports '
              'NCRYPT_IMPL_SOFTWARE_FLAG, truthfully — it used to say '
              'hardware in the source while emitting the software value.',
        rests_on='Hardware. The PKCS#11 abstraction already allows pointing '
                 'the KSP at a real HSM, so this closes by deployment '
                 'rather than by code.',
        external=True),
    'OPS-02': dict(
        works='Nothing.',
        rests_on='Certified hardware and a formal validation programme. '
                 'Follows from OPS-01 and is not an engineering task.',
        external=True),
    'OPS-03': dict(
        works='The signing pipeline is complete and self-tested: '
              'tools/sign_ksp.ps1 signs, timestamps and verifies, taking a '
              'certificate from the Windows store, a PFX whose password '
              'comes from the environment and never a parameter, or Azure '
              'Trusted Signing. CI signs automatically once the secret '
              'exists.',
        rests_on='An OV or EV code-signing certificate, which must be '
                 'bought by a verified legal entity. Nothing in this '
                 'repository can supply that, so the shipped binary is '
                 'unsigned and the row stays Not covered.',
        external=True),
    'OPS-06': dict(
        works='Nothing here, and nothing needs to: it is handled inside '
              'vendor PKCS#11 libraries.',
        rests_on='A vendor library. The provider inherits load balancing '
                 'and failover automatically when pointed at one, so there '
                 'is nothing to implement.',
        external=True),

    # ── Choices this project made ─────────────────────────────────────────
    #
    # Legitimate, and revisitable by definition. Each `rests_on` has to
    # survive "is that a fact about CNG, or a fact about our code?"
    'RSA-02': dict(
        works='Any multiple of 64 from KSP_RSA_MIN_BITS to 16384. A legacy '
              'build can lower the floor; the shipped default refuses '
              'below 2048 with NTE_BAD_LEN.',
        rests_on='A security choice, not a constraint: the mechanism '
                 'exists and the code path works. Silently allowing 1024 '
                 'would weaken every deployment that did not ask for it, '
                 'so it is an opt-in at build time rather than a refusal.',
        external=False),
    'AES-08': dict(
        works='Both feedback sizes CNG can actually reach: the 8-bit '
              'default, and full-block through '
              'BCRYPT_MESSAGE_BLOCK_LENGTH. CKM_AES_CFB64 is mapped for a '
              'MessageBlockLength of 8. All gated on the capability probe '
              'and verified against a live token, which asserts the two '
              'sizes produce DIFFERENT ciphertext — a provider ignoring '
              'the property cannot pass.',
        rests_on='Two things, and only one of them is ours. The ASYMMETRY '
                 'is external: CNG permits any feedback size up to the '
                 'block, PKCS#11 defines mechanisms for four of them, and '
                 'nothing here can add the missing ones. What is DELIBERATE '
                 'is the handling — a size with no mechanism is refused '
                 'rather than rounded to the nearest, because rounding '
                 'would silently select a different cipher and produce '
                 'ciphertext nothing else could decrypt. The row is '
                 'classified as our decision because that refusal is the '
                 'part a reader might want to argue with.',
        external=False),

    'IFACE-07': dict(
        works='Refused with NTE_NOT_SUPPORTED.',
        rests_on='A UI thread and a window handle. A KSP is loaded into '
                 'whatever process called NCrypt, including services with '
                 'no desktop, so prompting is a deployment decision rather '
                 'than a capability to add unconditionally.',
        external=False),
    'PROP-12': dict(
        works='Refused with NTE_NOT_SUPPORTED.',
        rests_on='IFACE-07. A UI policy with no prompt to govern would be '
                 'a stored value nothing reads.',
        external=False),
    'PROP-15': dict(
        works='Refused with NTE_NOT_SUPPORTED.',
        rests_on='IFACE-07, for the same reason as PROP-12.',
        external=False),
    'ECDH-06': dict(
        works='Nothing. ECDH on nine curves covers the agreement surface.',
        rests_on='Scope. CKM_DH_PKCS_KEY_PAIR_GEN and CKM_DH_PKCS_DERIVE '
                 'both exist, so this IS implementable — it is excluded '
                 'because ECDH supersedes it and no surveyed HSM KSP '
                 'exposes it. Of all the deliberate rows this is the one '
                 'with the clearest path if a deployment ever needed it.',
        external=False),
    'DSA-01': dict(
        works='Nothing.',
        rests_on='Scope. Deprecated in modern Windows PKI and absent from '
                 'every HSM KSP surveyed.',
        external=False),
    '3DES-01': dict(
        works='Nothing, although SoftHSM2 implements fourteen DES '
              'mechanisms, so the backend is not the obstacle.',
        rests_on='Scope and age. Excluded from modern HLK requirements. '
                 'Implementable at any time; deliberately not implemented.',
        external=False),
    'FMT-06': dict(
        works='Public key export in CNG blob format for every supported '
              'family. Private key export is refused with '
              'NTE_NOT_SUPPORTED.',
        rests_on='The HSM posture, enforced on the token rather than in '
                 'the provider: keys are CKA_EXTRACTABLE=FALSE unless '
                 'NCRYPT_EXPORT_POLICY_PROPERTY relaxes it, and even then '
                 'only wrapped export opens. This is correct behaviour, '
                 'not an unfinished feature.',
        external=False),
    'FMT-07': dict(
        works='Public key import creates a real CKO_PUBLIC_KEY; truncated '
              'and unknown-curve blobs are rejected rather than silently '
              'accepted. Symmetric key unwrap works and creates the key '
              'sensitive and non-extractable, so wrapping is a way IN and '
              'not a way back out.',
        rests_on='The HSM posture again. C_CreateObject with private '
                 'material or C_UnwrapKey would both work, so this is a '
                 'choice: a key the provider did not generate has an '
                 'unknown history. Worth revisiting only if a migration '
                 'workflow demands it.',
        external=False),
    'FMT-09': dict(
        works='Nothing: it is a private-key format.',
        rests_on='FMT-07, exactly. Same posture, same reconsideration '
                 'trigger.',
        external=False),
}


# Gaps that are real and that the matrix cannot show, because the matrix
# tracks capabilities observed across shipping CNG KSPs — the market — and
# not this provider's own conformance surface.
#
# This blind spot has now cost three defects. Session 14's two stubs were
# found by reading the function table, not the matrix, and NTE_EXISTS below
# was found by making a test repeatable. Nothing in the matrix would ever
# have pointed at any of them, because none is a capability a competitor
# advertises.
OUT_OF_SCOPE_GAPS = [
    dict(
        what='NCryptCreatePersistedKey does not return NTE_EXISTS',
        detail='Nothing checks whether the name is already taken, so a '
               'second create adds a second object with the same '
               'CKA_LABEL and NCryptOpenKey returns whichever the token\'s '
               'search hands back first. Microsoft documents NTE_EXISTS '
               'for this case, with NCRYPT_OVERWRITE_KEY_FLAG as the way '
               'to ask for replacement.',
        found='While making the two-token suite repeatable: two deletes '
              'both reported success and a key was still openable, '
              'because earlier runs had left duplicates behind.',
        status='Open. Not fixed as part of proposals A to D, because doing '
               'it properly means the overwrite flag as well as the check, '
               'with tests in both directions.'),
    dict(
        what='Key-scoped function table slots are unverifiable',
        detail='The mock types every slot as void *, so a wrong parameter '
               'TYPE is not a build error on Linux, and MSVC cannot '
               'compile ksp_main.c without ncrypt_provider.h. Eight '
               'provider-scoped slots are now checked against <ncrypt.h>; '
               'key-scoped ones cannot be, because the public prototype is '
               'not the slot\'s shape.',
        found='Session 14, by asking why KSP_NotifyChangeKey had survived '
              'with the wrong parameter type.',
        status='Tracked as TABLE-01, which is the one matrix row that does '
               'cover a conformance question rather than a capability.'),
]


def validate(rows, blocker):
    """Fail loudly if the matrix and this module have drifted apart.

    Called by every generator that reads GAP_DETAIL, so adding a row to the
    CSV without a detail entry breaks the build rather than producing an
    artifact with a silently blank column. The stale direction matters too:
    a closed row leaving its entry behind would keep describing a gap that
    no longer exists, which is the same failure as a stale coverage figure.

    The external/deliberate cross-check is the one that earns its place.
    "Deliberate position" and external=False have to mean the same thing,
    because a row classified as a deliberate position whose blocker is
    genuinely outside this repository is mislabelled — and so is its
    opposite, which is how IFACE-04, LIFE-08 and FMT-08 sat in the
    deliberate column until somebody looked.
    """
    open_ids = {r['id'] for r in rows if r['status'].strip() != 'Covered'}
    missing = sorted(open_ids - set(GAP_DETAIL))
    stale = sorted(set(GAP_DETAIL) - open_ids)
    unclassified = sorted(open_ids - set(blocker))
    problems = []
    if missing:
        problems.append('open rows with no entry in GAP_DETAIL: %s'
                        % ', '.join(missing))
    if stale:
        problems.append('GAP_DETAIL entries for rows that are now Covered: %s'
                        % ', '.join(stale))
    if unclassified:
        problems.append('open rows with no entry in coverage_blockers.py: %s'
                        % ', '.join(unclassified))

    # Report what is missing before looking anything up, or a new row raises
    # a bare KeyError from the loop below and the reader gets a traceback
    # instead of the sentence naming the row they forgot. Found by injecting
    # exactly that case.
    if problems:
        raise SystemExit('gap_detail.py is out of step with the matrix:\n  - '
                         + '\n  - '.join(problems))

    for rid in sorted(open_ids):
        want_deliberate = (blocker[rid] == 'Deliberate position')
        if want_deliberate != (GAP_DETAIL[rid]['external'] is False):
            problems.append(
                '%s is classified "%s" but external=%r — one of the two is '
                'wrong' % (rid, blocker[rid], GAP_DETAIL[rid]['external']))
    for rid in sorted(open_ids):
        d = GAP_DETAIL[rid]
        for field in ('works', 'rests_on'):
            if not d.get(field, '').strip():
                problems.append('%s has an empty %s' % (rid, field))
    if problems:
        raise SystemExit('gap_detail.py is out of step with the matrix:\n  - '
                         + '\n  - '.join(problems))
    return len(open_ids)
