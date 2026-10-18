#!/usr/bin/env python3
"""tools/register_ksp.ps1 must publish what the provider advertises.

WHY THIS EXISTS

Two lists describe one fact, and nothing compared them:

  g_KspAlgorithms in src/ksp/ksp_provider.c is what NCryptEnumAlgorithms
  answers — the provider's own account of what it does, filtered by the
  capability probe.

  $SignatureAlgorithms / $SecretAgreementAlgorithms / $CipherAlgorithms in
  tools/register_ksp.ps1 are what BCryptAddContextFunctionProvider
  publishes to CNG — what makes this provider findable, by certutil, by a
  certificate-request UI, by an application enumerating providers for an
  algorithm.

An algorithm in the first list and not the second is implemented and
unfindable. An algorithm in the second and not the first is advertised to
Windows and then refused at run time, which is worse: the caller was told
to come here.

This is on the critical path for the AD CS pilot. Registration is the first
thing that has to work, the script has never been run on Windows, and a
wrong algorithm list would not fail at registration — it fails later, in
the CA setup wizard, as an absence.

The interface constants are checked against the REAL mingw-w64 headers
rather than recalled, the same rule check_mock_drift.py follows: this
project once invented two constants and mis-valued two more, and every
test passed because the tests read the same wrong numbers.

WHAT IT DELIBERATELY TOLERATES

An entry can be in the provider's table and legitimately absent from
registration, when its CNG identifier is this project's own invention
rather than a Microsoft one — ML-DSA-44/65/87 are the case. Those are
listed in UNREGISTERED_BY_DESIGN below with the reason. Listing them is the
point: "deliberately not registered" is a claim, and a silent omission
looks exactly like one somebody forgot.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONFIG_H = os.path.join(ROOT, 'src', 'common', 'config.h')
PROVIDER_C = os.path.join(ROOT, 'src', 'ksp', 'ksp_provider.c')
SCRIPT = os.path.join(ROOT, 'tools', 'register_ksp.ps1')

MINGW = '/usr/share/mingw-w64/include'

# Which NCrypt operation flag belongs under which BCrypt interface, and
# which PowerShell array is meant to carry it.
OPERATION_TO_INTERFACE = {
    'NCRYPT_SIGNATURE_OPERATION':
        ('BCRYPT_SIGNATURE_INTERFACE', 'SignatureAlgorithms'),
    'NCRYPT_SECRET_AGREEMENT_OPERATION':
        ('BCRYPT_SECRET_AGREEMENT_INTERFACE', 'SecretAgreementAlgorithms'),
    'NCRYPT_CIPHER_OPERATION':
        ('BCRYPT_CIPHER_INTERFACE', 'CipherAlgorithms'),
    'NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION':
        ('BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE',
         'AsymmetricEncryptionAlgorithms'),
}

# Advertised by the provider, deliberately not registered, with the reason.
UNREGISTERED_BY_DESIGN = {
    'ML-DSA-44': 'CNG declares no post-quantum algorithm identifier that '
                 'could be confirmed from any source reachable here, so '
                 'this spelling is a KSP extension. Registering an invented '
                 'identifier would publish a name no Windows caller knows.',
    'ML-DSA-65': 'as ML-DSA-44',
    'ML-DSA-87': 'as ML-DSA-44',
}


def read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def alg_literals():
    """Every algorithm macro and the string it expands to.

    config.h carries this provider's own names; the standard CNG ones, such
    as BCRYPT_AES_CMAC_ALGORITHM, come from the REAL mingw-w64 header.
    Deliberately not from tests/mock/windows_compat.h: that mock once
    invented two constants and mis-valued two more, and every test passed
    because the tests read the same wrong numbers. A checker that resolved
    identifiers through the mock would inherit exactly that.
    """
    out = {}
    for m in re.finditer(r'#define\s+(\w+)\s+L"([^"]*)"', read(CONFIG_H)):
        out[m.group(1)] = m.group(2)
    for name in ('bcrypt.h', 'ncrypt.h'):
        path = os.path.join(MINGW, name)
        if not os.path.exists(path):
            continue
        for m in re.finditer(r'#define\s+(\w+)\s+L"([^"]*)"', read(path)):
            out.setdefault(m.group(1), m.group(2))
    return out


def provider_algorithms(names):
    """[(algorithm string, [operation flags])] from g_KspAlgorithms."""
    body = strip_comments(read(PROVIDER_C))
    m = re.search(r'g_KspAlgorithms\[\]\s*=\s*\{(.*?)\n\};', body, re.S)
    if not m:
        sys.exit('check_registration: g_KspAlgorithms not found in %s'
                 % os.path.basename(PROVIDER_C))

    out = []
    # One entry per brace group; the first token is the name, and every
    # NCRYPT_*_OPERATION before the first mechanism is an operation flag.
    for entry in re.finditer(r'\{\s*([A-Za-z_]\w*)\s*,(.*?)\}', m.group(1),
                             re.S):
        macro = entry.group(1)
        ops = re.findall(r'(NCRYPT_\w+_OPERATION)', entry.group(2))
        name = names.get(macro)
        if name is None:
            sys.exit('check_registration: cannot resolve %s to a string — '
                     'is it #defined in config.h?' % macro)
        out.append((name, ops))
    if not out:
        sys.exit('check_registration: g_KspAlgorithms parsed as empty')
    return out


def script_arrays():
    """{array name: [algorithm strings]} from the PowerShell script."""
    text = read(SCRIPT)
    out = {}
    for m in re.finditer(r'^\$(\w+)\s*=\s*@\(([^)]*)\)', text, re.M):
        out[m.group(1)] = re.findall(r'"([^"]+)"', m.group(2))
    return out


def script_interfaces():
    """{constant name: value} as the PowerShell script declares them."""
    out = {}
    for m in re.finditer(r'public\s+const\s+uint\s+(\w+)\s*=\s*(0x[0-9A-Fa-f]+)',
                         read(SCRIPT)):
        out[m.group(1)] = int(m.group(2), 16)
    return out


def header_interfaces():
    """{constant name: value} from the real mingw-w64 CNG headers."""
    out = {}
    for name in ('bcrypt.h', 'ncrypt.h'):
        path = os.path.join(MINGW, name)
        if not os.path.exists(path):
            return None
        for m in re.finditer(r'#define\s+(\w*_INTERFACE)\s+(0x[0-9A-Fa-f]+)',
                             read(path)):
            out[m.group(1)] = int(m.group(2), 16)
    return out


def main():
    names = alg_literals()
    provider = provider_algorithms(names)
    arrays = script_arrays()
    problems = []
    notes = []

    # ── The interface constants, against the real headers ────────────────
    real = header_interfaces()
    if real is None:
        notes.append('mingw-w64 headers not present; interface constants '
                     'not verified (install gcc-mingw-w64-x86-64)')
    else:
        for const, value in sorted(script_interfaces().items()):
            if const in real and real[const] != value:
                problems.append('%s is 0x%08X in the script and 0x%08X in '
                                'the real header' % (const, value, real[const]))

    # ── The two algorithm lists, both directions ─────────────────────────
    expected = {}
    for name, ops in provider:
        for op in ops:
            if op not in OPERATION_TO_INTERFACE:
                problems.append('%s declares %s, which this check does not '
                                'map to an interface' % (name, op))
                continue
            _, array = OPERATION_TO_INTERFACE[op]
            expected.setdefault(array, set()).add(name)

    for array, want in sorted(expected.items()):
        have = set(arrays.get(array, []))
        if array not in arrays:
            missing = sorted(n for n in want
                             if n not in UNREGISTERED_BY_DESIGN)
            if missing:
                problems.append(
                    'the script has no $%s array, so %s %s advertised by '
                    'NCryptEnumAlgorithms and never published to CNG'
                    % (array, ', '.join(missing),
                       'is' if len(missing) == 1 else 'are'))
            continue
        for name in sorted(want - have):
            if name in UNREGISTERED_BY_DESIGN:
                notes.append('%s advertised but not registered, by design: %s'
                             % (name, UNREGISTERED_BY_DESIGN[name]))
            else:
                problems.append('%s is advertised by NCryptEnumAlgorithms '
                                'but missing from $%s — implemented and '
                                'unfindable' % (name, array))
        for name in sorted(have - want):
            problems.append('$%s publishes %s, which the provider does not '
                            'advertise — Windows would send callers here for '
                            'an algorithm that is then refused'
                            % (array, name))

    for array in sorted(set(arrays) - set(expected)):
        if array.endswith('Algorithms'):
            problems.append('$%s is registered but no provider entry maps to '
                            'it' % array)

    for n in notes:
        print('  note: %s' % n)
    if problems:
        print('register_ksp.ps1 does not match the provider\'s algorithm '
              'table:')
        for p in problems:
            print('  - %s' % p)
        return 1

    total = sum(len(v) for v in expected.values())
    print('register_ksp.ps1 matches the provider: %d algorithm/interface '
          'pairs across %d interfaces.' % (total, len(expected)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
