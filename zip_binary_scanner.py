#!/usr/bin/env python3
"""
zip_binary_scanner.py - Detect executable binaries inside a ZIP archive.

Every entry of the archive is inspected by CONTENT (magic bytes and headers),
not only by file extension, so a renamed binary (e.g. "notes.txt" that is
really a DLL) is still caught. Nested ZIP archives are scanned recursively.

Detected formats
    * Windows PE   : EXE, DLL (also .sys/.ocx/... via the PE header flags)
    * MS-DOS MZ    : legacy executables without a PE header
    * Linux ELF    : executables, PIE executables, shared objects (.so),
                     relocatable objects (.o), core dumps
    * macOS Mach-O : executables, dylibs, bundles, universal (fat) binaries

If the archive is clean, a report file is written containing:
    * the scan date (ISO-8601, UTC)
    * SHA-256 of the ZIP file alone
    * SHA-256 of (date string encoded as UTF-8 + raw bytes of the ZIP file)

The combined checksum can be re-computed independently with, for example:
    ( printf '%s' "<date>"; cat archive.zip ) | sha256sum

Exit codes
    0  archive is clean, report written
    1  binaries detected (no report written)
    2  no binary found, but some content could not be inspected
       (unreadable archive, encrypted entries, ...) - no report written

Usage
    python3 zip_binary_scanner.py archive.zip
    python3 zip_binary_scanner.py archive.zip -o result.txt --max-depth 3
    python3 zip_binary_scanner.py archive.zip --json
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import sys
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Bytes read from each entry for content detection. PE headers are normally in
# the first few hundred bytes; if e_lfanew points further we read more.
HEADER_READ_SIZE = 64 * 1024
MAX_PE_OFFSET = 16 * 1024 * 1024
# Maximum size of a nested ZIP loaded in memory for recursive scanning.
MAX_NESTED_ZIP_SIZE = 512 * 1024 * 1024

SUSPICIOUS_EXTENSIONS = {
    # Windows
    ".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".drv", ".efi",
    ".com", ".msi", ".mui", ".ax", ".acm", ".tlb",
    # Linux / Unix
    ".so", ".elf", ".bin", ".run", ".out", ".ko", ".o", ".a",
    # macOS
    ".dylib", ".bundle",
}

PE_MACHINES = {
    0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0x01C4: "ARMv7",
    0xAA64: "ARM64", 0x0200: "IA-64", 0x5032: "RISC-V32", 0x5064: "RISC-V64",
}
ELF_MACHINES = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64",
    0x08: "MIPS", 0x14: "PowerPC", 0x15: "PowerPC64", 0xF3: "RISC-V",
    0x2B: "SPARC V9", 0x16: "S390",
}


@dataclass
class Finding:
    path: str                 # path inside the archive ("outer.zip!inner/file")
    detected_type: str        # e.g. "PE DLL (x86-64)"
    by_content: bool          # True if the content is a binary
    by_extension: bool        # True if the extension is a binary extension
    note: str = ""


@dataclass
class ScanResult:
    zip_path: str
    entries_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings and not self.errors


# --------------------------------------------------------------------------- #
# Content detection
# --------------------------------------------------------------------------- #
def detect_pe(data: bytes, read_more) -> str | None:
    """Detect MZ / PE files. `read_more(n)` returns the first n bytes."""
    if data[:2] != b"MZ":
        return None
    if len(data) < 0x40:
        return "MS-DOS executable (truncated MZ header)"
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 24 > len(data):
        if e_lfanew > MAX_PE_OFFSET:
            return "MS-DOS executable (MZ)"
        data = read_more(e_lfanew + 256)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00" or e_lfanew + 24 > len(data):
        return "MS-DOS executable (MZ)"

    machine, _, _, _, _, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, e_lfanew + 4)
    arch = PE_MACHINES.get(machine, f"machine 0x{machine:04X}")

    kind = "DLL" if characteristics & 0x2000 else "EXE"
    if characteristics & 0x1000:
        kind = "system file/driver"

    opt_off = e_lfanew + 24
    if opt_size >= 2 and opt_off + 2 <= len(data):
        (opt_magic,) = struct.unpack_from("<H", data, opt_off)
        bitness = {0x10B: "PE32", 0x20B: "PE32+"}.get(opt_magic, "PE")
        # CLR runtime header data directory -> .NET assembly
        clr_dir = opt_off + (208 if opt_magic == 0x20B else 192)
        if opt_off + opt_size >= clr_dir + 8 and clr_dir + 8 <= len(data):
            rva, size = struct.unpack_from("<II", data, clr_dir)
            if rva and size:
                bitness += " .NET"
    else:
        bitness = "PE"
    return f"Windows {bitness} {kind} ({arch})"


def detect_elf(data: bytes) -> str | None:
    if data[:4] != b"\x7fELF" or len(data) < 20:
        return None if data[:4] != b"\x7fELF" else "ELF (truncated header)"
    ei_class, ei_data = data[4], data[5]
    end = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    e_type, e_machine = struct.unpack_from(end + "HH", data, 16)
    arch = ELF_MACHINES.get(e_machine, f"machine 0x{e_machine:X}")
    bits = "64-bit" if is64 else "32-bit"

    if e_type == 1:
        kind = "relocatable object (.o)"
    elif e_type == 2:
        kind = "executable"
    elif e_type == 3:
        # ET_DYN is either a shared library or a PIE executable. A PIE
        # executable has a PT_INTERP program header (dynamic loader path).
        kind = "shared object (.so)"
        try:
            if is64:
                phoff, = struct.unpack_from(end + "Q", data, 32)
                phentsize, phnum = struct.unpack_from(end + "HH", data, 54)
            else:
                phoff, = struct.unpack_from(end + "I", data, 28)
                phentsize, phnum = struct.unpack_from(end + "HH", data, 42)
            for i in range(phnum):
                off = phoff + i * phentsize
                if off + 4 > len(data):
                    break
                p_type, = struct.unpack_from(end + "I", data, off)
                if p_type == 3:  # PT_INTERP
                    kind = "PIE executable"
                    break
        except struct.error:
            pass
    elif e_type == 4:
        kind = "core dump"
    else:
        kind = f"type 0x{e_type:X}"
    return f"Linux/Unix ELF {bits} {kind} ({arch})"


def detect_macho(data: bytes) -> str | None:
    if len(data) < 8:
        return None
    magic = data[:4]
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                 b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        end = ">" if magic[0] == 0xFE else "<"
        if len(data) < 16:
            return "Mach-O binary"
        filetype, = struct.unpack_from(end + "I", data, 12)
        kinds = {1: "object", 2: "executable", 6: "dylib", 8: "bundle",
                 7: "dynamic linker", 0xB: "kext"}
        return f"macOS Mach-O {kinds.get(filetype, 'binary')}"
    if magic == b"\xca\xfe\xba\xbe":
        # Same magic as Java .class files; fat binaries have a small arch count
        # whereas Java class major versions are >= 45.
        nfat, = struct.unpack_from(">I", data, 4)
        if 0 < nfat < 30:
            return "macOS Mach-O universal (fat) binary"
    return None


def detect_binary(data: bytes, read_more) -> str | None:
    return detect_pe(data, read_more) or detect_elf(data) or detect_macho(data)


def has_binary_extension(name: str) -> bool:
    lower = name.lower().rsplit("/", 1)[-1]
    suffixes = Path(lower).suffixes
    if not suffixes:
        return False
    if suffixes[-1] in SUSPICIOUS_EXTENSIONS:
        return True
    # versioned shared libraries: libfoo.so.1.2.3
    return ".so" in suffixes


# --------------------------------------------------------------------------- #
# Archive walking
# --------------------------------------------------------------------------- #
def scan_zip(zf: zipfile.ZipFile, prefix: str, result: ScanResult,
             depth: int, max_depth: int) -> None:
    for info in zf.infolist():
        if info.is_dir():
            continue
        display = f"{prefix}{info.filename}"
        result.entries_scanned += 1

        if info.flag_bits & 0x1:
            result.errors.append(f"{display}: entry is encrypted, cannot inspect content")
            continue

        def read_first(n: int, _info=info) -> bytes:
            with zf.open(_info) as fh:
                return fh.read(n)

        try:
            header = read_first(HEADER_READ_SIZE)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError,
                EOFError, ValueError) as exc:
            result.errors.append(f"{display}: cannot read entry ({exc})")
            continue

        try:
            detected = detect_binary(header, read_first)
        except (struct.error, zipfile.BadZipFile, OSError) as exc:
            result.errors.append(f"{display}: header parsing failed ({exc})")
            continue

        by_ext = has_binary_extension(info.filename)
        if detected or by_ext:
            note = ""
            if detected and not by_ext:
                note = "binary content hidden behind a non-binary extension"
            elif by_ext and not detected:
                note = "binary extension but content not recognised as executable"
            result.findings.append(Finding(
                path=display,
                detected_type=detected or "unknown (extension only)",
                by_content=bool(detected),
                by_extension=by_ext,
                note=note,
            ))

        # Recurse into nested ZIP archives (detected by content, not name).
        if header[:4] == b"PK\x03\x04":
            if depth >= max_depth:
                result.errors.append(
                    f"{display}: nested archive exceeds max depth {max_depth}, not scanned")
            elif info.file_size > MAX_NESTED_ZIP_SIZE:
                result.errors.append(
                    f"{display}: nested archive too large to scan ({info.file_size} bytes)")
            else:
                try:
                    with zf.open(info) as fh:
                        blob = fh.read()
                    with zipfile.ZipFile(io.BytesIO(blob)) as inner:
                        scan_zip(inner, f"{display}!", result, depth + 1, max_depth)
                except zipfile.BadZipFile as exc:
                    result.errors.append(f"{display}: invalid nested archive ({exc})")


def scan(zip_path: Path, max_depth: int) -> ScanResult:
    result = ScanResult(zip_path=str(zip_path))
    try:
        with zipfile.ZipFile(zip_path) as zf:
            scan_zip(zf, "", result, depth=0, max_depth=max_depth)
    except (zipfile.BadZipFile, OSError) as exc:
        result.errors.append(f"cannot open archive: {exc}")
    return result


# --------------------------------------------------------------------------- #
# Checksum report
# --------------------------------------------------------------------------- #
def write_report(zip_path: Path, out_path: Path, result: ScanResult) -> dict:
    date_str = datetime.now(timezone.utc).isoformat(timespec="seconds")

    zip_hash = hashlib.sha256()
    combined = hashlib.sha256(date_str.encode("utf-8"))
    with open(zip_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            zip_hash.update(chunk)
            combined.update(chunk)

    report = {
        "file": zip_path.name,
        "scan_date": date_str,
        "entries_scanned": result.entries_scanned,
        "status": "CLEAN - no executable binaries detected",
        "zip_sha256": zip_hash.hexdigest(),
        "checksum_algorithm": "SHA-256(utf8(scan_date) || zip_bytes)",
        "checksum": combined.hexdigest(),
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        width = max(len(k) for k in report)
        for key, value in report.items():
            fh.write(f"{key.ljust(width)} : {value}\n")
    return report


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect DLL/EXE/SO/ELF/Mach-O binaries inside a ZIP by content.")
    parser.add_argument("zip_file", type=Path, help="ZIP archive to inspect")
    parser.add_argument("-o", "--output", type=Path,
                        help="report file (default: <zip_name>.checksum.txt next to the zip)")
    parser.add_argument("--max-depth", type=int, default=5,
                        help="maximum nesting depth for ZIPs inside ZIPs (default: 5)")
    parser.add_argument("--json", action="store_true",
                        help="print the scan result as JSON on stdout")
    args = parser.parse_args(argv)

    zip_path: Path = args.zip_file
    if not zip_path.is_file():
        print(f"error: {zip_path} is not a file", file=sys.stderr)
        return 2

    result = scan(zip_path, args.max_depth)
    report = None
    if result.ok:
        out_path = args.output or zip_path.with_name(zip_path.name + ".checksum.txt")
        report = write_report(zip_path, out_path, result)

    if args.json:
        payload = {
            "zip": result.zip_path,
            "ok": result.ok,
            "entries_scanned": result.entries_scanned,
            "findings": [asdict(f) for f in result.findings],
            "errors": result.errors,
            "report": report,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(f"Scanned {result.entries_scanned} file(s) in {zip_path}")
        for f in result.findings:
            src = "+".join(s for s, on in (("content", f.by_content),
                                            ("extension", f.by_extension)) if on)
            line = f"  [BINARY] {f.path}  ->  {f.detected_type}  (by {src})"
            if f.note:
                line += f"  ! {f.note}"
            print(line)
        for err in result.errors:
            print(f"  [ERROR]  {err}")
        if result.ok:
            print(f"OK: no binaries found. Report written to {out_path}")
            print(f"  date     : {report['scan_date']}")
            print(f"  checksum : {report['checksum']}")
        else:
            print(f"FAILED: {len(result.findings)} binary finding(s), "
                  f"{len(result.errors)} error(s). No report generated.")

    if result.findings:
        return 1
    return 2 if result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
