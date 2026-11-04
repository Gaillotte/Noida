# Why each non-Covered row is open. Assigned per ID by reading the matrix's
# own remedy text, not by keyword matching - a keyword pass put 15 rows in
# "actionable engineering" that the texts plainly describe as deliberate or
# externally blocked.
#
# IFACE-04, LIFE-08, AES-09 and FMT-08 used to be listed here as deliberate
# positions and are now Covered: proposals A, B and C implemented them. A
# row dropping out of this table is the normal way an entry leaves it - the
# classification describes why a gap is open, so a closed gap has no entry.
BLOCKER = {
    # The provider chose this, and the reason is recorded in the matrix.
    'RSA-02':   'Deliberate position',
    'ECDH-06':  'Deliberate position',
    'DSA-01':   'Deliberate position',
    '3DES-01':  'Deliberate position',
    'AES-08':   'Deliberate position',
    'FMT-06':   'Deliberate position',
    'FMT-07':   'Deliberate position',
    'FMT-09':   'Deliberate position',
    'IFACE-07': 'Deliberate position',
    'PROP-12':  'Deliberate position',
    'PROP-15':  'Deliberate position',

    # CNG itself offers no identifier or no function-table slot. Nothing in
    # this repository can close these; they are blocked on Microsoft.
    'EDDSA-01': 'Blocked: CNG has no identifier or slot',
    'EDDSA-02': 'Blocked: CNG has no identifier or slot',
    'HMAC-01':  'Blocked: CNG has no identifier or slot',
    'AES-06':   'Blocked: CNG has no identifier or slot',
    'PQC-02':   'Blocked: CNG has no identifier or slot',

    # Needs ncrypt_provider.h and a Windows machine to prove.
    'BUILD-01': 'Blocked: needs ncrypt_provider.h / Windows',
    'TABLE-01': 'Blocked: needs ncrypt_provider.h / Windows',
    'PQC-01':   'Blocked: needs ncrypt_provider.h / Windows',

    # PKCS#11 or the backend offers no mechanism, so a portable provider
    # cannot reach it however much code is written.
    'IFACE-05': 'Blocked: no PKCS#11 mechanism',
    # IFACE-06 was in the deliberate column until the gap_detail.py pairing
    # check ran against its own text, which reads "that is a fact about
    # PKCS#11 rather than about this code". It is: GetOperationProperty
    # reports on an asynchronous operation and PKCS#11 is synchronous, so
    # there is no state to report however much code is written. Caught by the
    # cross-check rather than by review, which is the point of having one.
    'IFACE-06': 'Blocked: no PKCS#11 mechanism',
    'PROP-11':  'Blocked: no PKCS#11 mechanism',
    'PROP-16':  'Blocked: no PKCS#11 mechanism',
    'OPS-05':   'Blocked: no PKCS#11 mechanism',
    'PQC-03':   'Blocked: no PKCS#11 mechanism',
    'FMT-10':   'Blocked: no PKCS#11 mechanism',

    # Hardware, a purchased certificate, or an external programme.
    'OPS-01':   'Blocked: hardware / commercial',
    'OPS-02':   'Blocked: hardware / commercial',
    'OPS-03':   'Blocked: hardware / commercial',
    'OPS-06':   'Blocked: hardware / commercial',
}
