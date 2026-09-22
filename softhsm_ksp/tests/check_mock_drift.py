#!/usr/bin/env python3
"""Compare tests/mock/windows_compat.h against the real Windows headers.

The unit suite compiles against a hand-written stand-in for the Windows
headers. That stand-in once defined two constants Windows does not have
(BCRYPT_SHA224_ALGORITHM, NTE_KEY_DOES_NOT_EXIST) and gave two others the
wrong value (NCRYPT_IMPL_HARDWARE_FLAG, NTE_BAD_KEYSET_PARAM). Every test
passed anyway, because the tests and the code under test read the same wrong
numbers. Seven of ten source files could not compile for Windows at all.

This script is the guard against that recurring. It reads the mingw-w64
headers as a reference copy of the Windows API and reports:

  * a macro the mock defines with a different value than Windows uses
  * a macro the mock defines that does not exist in Windows at all, if the
    project's own sources depend on it

mingw-w64 is a reference, not an authority: it lags the Windows SDK, so a
name being absent there does not prove it is absent from Windows. Anything
the mock legitimately adds — names genuinely absent from mingw, or the
project's own KSP_* extensions — belongs in ALLOWED below, with a reason.

Usage:
    python3 tests/check_mock_drift.py [--headers DIR]

Exits non-zero on drift, so CI fails.
"""

import argparse
import glob
import os
import re
import sys

# Names the mock may define even though mingw-w64 does not know them.
# Each needs a reason, so the list cannot quietly become a dumping ground.
ALLOWED = {
    "NCRYPT_KEY_STORAGE_INTERFACE_VERSION": "WDK ncrypt_provider.h",
    "BCRYPT_MAKE_INTERFACE_VERSION":        "WDK ncrypt_provider.h",
}

MACRO_RE = re.compile(
    r"^\s*#define\s+((?:NTE|BCRYPT|NCRYPT)_[A-Z0-9_]+)\s+"
    r"(?:_HRESULT_TYPEDEF_\()?\s*(0x[0-9A-Fa-f]+|\d+)",
    re.MULTILINE,
)

# Wide-string macros: L"..." algorithm identifiers and property names.
# BCRYPT_SHA224_ALGORITHM was one of these, so leaving them unchecked would
# leave the guard blind to the very family that caused the problem.
STR_RE = re.compile(
    r'^\s*#define\s+((?:NTE|BCRYPT|NCRYPT)_[A-Z0-9_]+)\s+L"([^"]*)"',
    re.MULTILINE,
)

# Windows aliases heavily: ncrypt.h defines NCRYPT_INITIALIZATION_VECTOR as
# BCRYPT_INITIALIZATION_VECTOR rather than repeating L"IV". Without
# following these one hop, every aliased name looks like an invention, and
# a guard that cries wolf gets its exceptions list padded until it is
# useless.
ALIAS_RE = re.compile(
    r"^\s*#define\s+((?:NTE|BCRYPT|NCRYPT)_[A-Z0-9_]+)\s+"
    r"((?:NTE|BCRYPT|NCRYPT)_[A-Z0-9_]+)\s*$",
    re.MULTILINE,
)


def read_real_strings(headers_dir):
    """Map macro -> wide-string value from the reference Windows headers.

    Alias definitions are resolved transitively, so a name defined as
    another macro reports that macro's string value.
    """
    real, alias = {}, {}
    for path in glob.glob(os.path.join(headers_dir, "*.h")):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        for name, value in STR_RE.findall(text):
            real.setdefault(name, value)
        for name, target in ALIAS_RE.findall(text):
            alias.setdefault(name, target)

    for name, target in alias.items():
        seen = set()
        while target in alias and target not in seen:
            seen.add(target)
            target = alias[target]
        if target in real:
            real.setdefault(name, real[target])
    return real


def read_mock_strings(mock_path):
    with open(mock_path, encoding="utf-8") as fh:
        return dict(STR_RE.findall(fh.read()))


def read_real(headers_dir):
    """Map macro -> int value from the reference Windows headers."""
    real = {}
    for path in glob.glob(os.path.join(headers_dir, "*.h")):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        for name, value in MACRO_RE.findall(text):
            real.setdefault(name, int(value, 0))
    return real


def read_mock(mock_path):
    with open(mock_path, encoding="utf-8") as fh:
        text = fh.read()
    return {name: int(value, 0) for name, value in MACRO_RE.findall(text)}


def sources_text(src_dir):
    out = []
    for pattern in ("**/*.c", "**/*.h"):
        for path in glob.glob(os.path.join(src_dir, pattern), recursive=True):
            with open(path, encoding="utf-8", errors="ignore") as fh:
                out.append(fh.read())
    return "\n".join(out)


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(here)

    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--headers",
        default="/usr/share/mingw-w64/include",
        help="directory of reference Windows headers (mingw-w64)",
    )
    args = ap.parse_args()

    if not os.path.isdir(args.headers):
        print(
            "SKIP: reference headers not found at %s\n"
            "      install with: apt-get install mingw-w64-common" % args.headers
        )
        return 0

    real = read_real(args.headers)
    if not real:
        print("SKIP: no macros parsed from %s" % args.headers)
        return 0

    mock = read_mock(os.path.join(here, "mock", "windows_compat.h"))
    src = sources_text(os.path.join(root, "src"))

    real_str = read_real_strings(args.headers)
    mock_str = read_mock_strings(os.path.join(here, "mock", "windows_compat.h"))

    wrong_value, invented = [], []

    for name, value in sorted(mock_str.items()):
        if name in real_str and value != real_str[name]:
            wrong_value.append((name, '"%s"' % value, '"%s"' % real_str[name]))
        elif name not in real_str and name not in ALLOWED:
            if re.search(r"\b%s\b" % re.escape(name), src):
                invented.append(name)

    for name, value in sorted(mock.items()):
        if name in real:
            if value != real[name]:
                wrong_value.append((name, "0x%08X" % value, "0x%08X" % real[name]))
        elif name not in ALLOWED:
            # Only a problem if the project actually depends on it: the mock
            # may carry extra names harmlessly, but src/ must never rely on
            # something Windows will not provide.
            if re.search(r"\b%s\b" % re.escape(name), src):
                invented.append(name)

    print("mock macros checked : %d numeric, %d string"
          % (len(mock), len(mock_str)))
    print("reference headers   : %s" % args.headers)

    if wrong_value:
        print("\nWRONG VALUE (%d) — the mock disagrees with Windows:" % len(wrong_value))
        for name, got, want in wrong_value:
            print("  %-38s mock=%s  windows=%s" % (name, got, want))

    if invented:
        print(
            "\nNOT A WINDOWS SYMBOL (%d) — defined by the mock and used by src/:"
            % len(invented)
        )
        for name in invented:
            print("  %s" % name)
        print(
            "\n  Either it is a real Windows name newer than the reference\n"
            "  headers (add it to ALLOWED with a reason), or the source must\n"
            "  stop depending on it."
        )

    if wrong_value or invented:
        print("\nFAIL: the mock has drifted from the Windows headers.")
        return 1

    print("\nOK: no drift.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
