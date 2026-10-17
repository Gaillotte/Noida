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
import shutil
import subprocess
import sys
import tempfile

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


# ── Typedef widths ──────────────────────────────────────────────────────────
#
# The checks above compare macro VALUES. A wrong typedef is invisible to
# them, and one went unnoticed for thirteen sessions: BOOL was `unsigned
# char` in the mock where Windows makes it `int`. That is a different width
# and a different ABI — a function returning a masked flag wider than eight
# bits truncates on Linux and not on Windows, and every struct carrying a
# BOOL lays out differently in the tests than in production.
#
# WIDTH is the thing to compare, not spelling. mingw-w64 writes DWORD as
# `unsigned long`, which is 32 bits under Windows x64 (LLP64) and 64 bits
# under Linux x86-64 (LP64) — so a checker that matched the SPELLING would
# demand a change that doubled the width and made the mock worse. The
# numbers below are the Windows x64 widths in bytes, which are ABI and do
# not move; the mock's are measured by compiling it.
TYPEDEF_WIDTHS = {
    "BOOL":   4,
    "DWORD":  4,
    "ULONG":  4,
    "BYTE":   1,
    "WORD":   2,
}


# Struct layouts the mock declares and the real headers also declare.
#
# A wrong layout here is invisible on Linux: every test reads the mock, so
# a struct missing a field agrees with itself perfectly and fails only on
# Windows. That is exactly how two invented constants and two mis-valued
# ones survived before this script existed.
#
# NCRYPT_SUPPORTED_LENGTHS is the reason this check exists. It sits next to
# BCRYPT_KEY_LENGTHS_STRUCT, looks like it, and is NOT it: three ULONGs
# there, four DWORDs here. Copying the neighbour would be the natural
# mistake and nothing would have caught it.
#
# Compared by FIELD NAME AND ORDER, not by type spelling. mingw writes
# DWORD as "unsigned long", which is 32 bits on Windows x64 and 64 on
# Linux, so demanding the spellings match would demand a change that made
# the mock wrong — the mistake session 14 made and caught by running it.
# The underlying widths are already checked by check_typedefs above, so
# names and order are the part left to verify.
STRUCT_LAYOUTS = {
    "NCRYPT_SUPPORTED_LENGTHS": "ncrypt.h",
    "BCRYPT_KEY_LENGTHS_STRUCT": "bcrypt.h",
}

FIELD_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_ *]*?\s+\*?([A-Za-z_][A-Za-z0-9_]*)\s*;")


def struct_fields(text, name):
    """Field names, in order, of `struct ... } name;` in `text`.

    Returns None when the struct is not declared there, which is a
    different answer from "declared with no fields" and is reported
    differently.
    """
    # [^{}]* , not .*? — a non-greedy body still starts at the FIRST
    # "typedef struct {" that can reach this closing brace, which swallowed
    # every declaration in between and reported thirty-odd phantom fields.
    # Forbidding braces inside the body pins it to the right struct. Both
    # structs here are flat; a nested one would simply not match, which is
    # reported as "not declared" rather than guessed at.
    m = re.search(r"typedef\s+struct\s+\w*\s*\{([^{}]*)\}\s*"
                  + re.escape(name) + r"\s*;", text, re.S)
    if not m:
        return None
    fields = []
    for line in m.group(1).split("\n"):
        line = line.split("/*")[0]
        fm = FIELD_RE.match(line)
        if fm:
            fields.append(fm.group(1))
    return fields


def check_structs(mock_path, include_dir):
    """Compare each struct's field list between the mock and the real header.

    Returns a list of (name, mock_fields, real_fields) that disagree, or
    None when a reference header could not be read — skipped rather than
    guessed, like every other check here.
    """
    try:
        with open(mock_path, encoding="utf-8", errors="replace") as fh:
            mock_text = fh.read()
    except OSError:
        return None

    bad = []
    for name, header in sorted(STRUCT_LAYOUTS.items()):
        hpath = os.path.join(include_dir, header)
        if not os.path.exists(hpath):
            return None
        with open(hpath, encoding="utf-8", errors="replace") as fh:
            real_text = fh.read()
        real = struct_fields(real_text, name)
        mine = struct_fields(mock_text, name)
        if real is None:
            continue                      # not in this header; nothing to compare
        if mine != real:
            bad.append((name, mine, real))
    return bad


def check_typedefs(mock_path):
    """Compile a probe against the mock and compare sizeof to Windows x64.

    Returns a list of (name, mock_bytes, windows_bytes) that disagree, or
    None when the probe could not be built (no compiler — skip rather than
    invent a result).
    """
    names = sorted(TYPEDEF_WIDTHS)
    src = ['#include "%s"' % mock_path, "#include <stdio.h>", "int main(void){"]
    for n in names:
        src.append('    printf("%s %%zu\\n", sizeof(%s));' % (n, n))
    src.append("    return 0; }")

    tmp = tempfile.mkdtemp()
    try:
        cpath = os.path.join(tmp, "probe.c")
        bpath = os.path.join(tmp, "probe")
        with open(cpath, "w") as fh:
            fh.write("\n".join(src) + "\n")
        rc = subprocess.call(
            ["gcc", "-o", bpath, cpath],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if rc != 0:
            return None
        out = subprocess.check_output([bpath]).decode()
    except (OSError, subprocess.CalledProcessError):
        return None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    bad = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        name, got = parts[0], int(parts[1])
        want = TYPEDEF_WIDTHS.get(name)
        if want is not None and got != want:
            bad.append((name, got, want))
    return bad


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

    wrong_type = check_typedefs(os.path.join(here, "mock", "windows_compat.h"))
    if wrong_type is None:
        print("\n  (typedef widths not checked: no working compiler)")
        wrong_type = []
    if wrong_type:
        print(
            "\nTYPEDEF WIDTH MISMATCH (%d) — the mock's type is a different "
            "size than Windows x64:" % len(wrong_type)
        )
        for name, have, want in wrong_type:
            print("  %-38s mock=%d bytes  windows=%d bytes"
                  % (name, have, want))
        print(
            "\n  A wrong width is a different ABI, not a cosmetic issue: it\n"
            "  changes struct layout and can truncate return values on one\n"
            "  platform and not the other."
        )

    bad_structs = check_structs(
        os.path.join(here, "mock", "windows_compat.h"), args.headers)
    if bad_structs is None:
        print("\n  (struct layouts not checked: reference header missing)")
        bad_structs = []
    if bad_structs:
        print(
            "\nSTRUCT LAYOUT MISMATCH (%d) — the mock declares different "
            "fields than Windows:" % len(bad_structs)
        )
        for name, mine, real in bad_structs:
            print("  %s" % name)
            print("    mock    : %s" % (", ".join(mine) if mine else "(absent)"))
            print("    windows : %s" % ", ".join(real))
        print(
            "\n  Every test reads the mock, so a struct with the wrong fields\n"
            "  agrees with itself and fails only on Windows."
        )

    if wrong_value or invented or wrong_type or bad_structs:
        print("\nFAIL: the mock has drifted from the Windows headers.")
        return 1

    print("\nOK: no drift.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
