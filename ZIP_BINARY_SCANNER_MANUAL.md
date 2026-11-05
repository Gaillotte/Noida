# ZIP Binary Scanner — User Manual

`zip_binary_scanner.py` inspects a ZIP archive and detects executable binaries
(Windows EXE/DLL, Linux ELF executables and `.so` libraries, macOS Mach-O)
**by their content**, not only by their file extension. When the archive is
clean, it produces a report file containing the scan date and a SHA-256
checksum of *the date + the full ZIP content*.

---

## Table of contents

1. [Requirements](#1-requirements)
2. [Quick start](#2-quick-start)
3. [Command-line reference](#3-command-line-reference)
4. [What is detected](#4-what-is-detected)
5. [Reading the console output](#5-reading-the-console-output)
6. [The report file](#6-the-report-file)
7. [Verifying a checksum](#7-verifying-a-checksum)
8. [Exit codes](#8-exit-codes)
9. [JSON output](#9-json-output)
10. [Examples](#10-examples)
11. [Automation (CI / scripts)](#11-automation-ci--scripts)
12. [Limitations](#12-limitations)
13. [Troubleshooting](#13-troubleshooting)

---

## 1. Requirements

- Python **3.8 or later**
- No third-party packages: only the Python standard library is used
- Works on Linux, macOS and Windows

The archive is **never extracted to disk**: entries are read in memory and
only their first bytes are inspected (except nested ZIPs, see §4.3).

---

## 2. Quick start

```bash
python3 zip_binary_scanner.py release.zip
```

- If the archive is clean, a report `release.zip.checksum.txt` is created next
  to the ZIP and the command exits with code `0`.
- If binaries are found, they are listed, **no report is written**, and the
  command exits with code `1`.

---

## 3. Command-line reference

```
usage: zip_binary_scanner.py [-h] [-o OUTPUT] [--max-depth MAX_DEPTH] [--json]
                             zip_file
```

| Argument | Description | Default |
|---|---|---|
| `zip_file` | ZIP archive to inspect (required) | — |
| `-o`, `--output OUTPUT` | Path of the report file written when the archive is clean | `<zip_name>.checksum.txt` next to the ZIP |
| `--max-depth N` | Maximum nesting depth for ZIPs inside ZIPs | `5` |
| `--json` | Print the full scan result as JSON instead of the human-readable text | off |
| `-h`, `--help` | Show help and exit | — |

> The report file is overwritten if it already exists.

---

## 4. What is detected

### 4.1 Detection by content (magic bytes / headers)

| Format | Signature | Details reported |
|---|---|---|
| Windows PE | `MZ` + `PE\0\0` header | EXE, DLL, or system file/driver; PE32 / PE32+; `.NET` assemblies; CPU (x86, x86-64, ARM64…) |
| MS-DOS | `MZ` without PE header | Legacy DOS executable |
| Linux / Unix ELF | `\x7fELF` | Executable, **PIE executable**, **shared object (.so)**, relocatable object (.o), core dump; 32/64-bit; CPU |
| macOS Mach-O | `FEEDFACE`, `FEEDFACF` (both byte orders) | Executable, dylib, bundle, object, kext |
| macOS universal | `CAFEBABE` (with small arch count) | Fat binary (Java `.class` files, which share this magic, are not flagged) |

Notes:

- **DLL vs EXE** is decided by the `IMAGE_FILE_DLL` flag in the PE header,
  not by the file name.
- **Shared library vs PIE executable**: modern Linux executables are usually
  "PIE", which uses the same ELF type as `.so` libraries. The scanner tells
  them apart by the presence of a program interpreter (`PT_INTERP`) header.

### 4.2 Detection by extension

An entry is also flagged if its name ends with a binary extension, even when
the content is not recognised:

```
Windows : .exe .dll .sys .ocx .scr .cpl .drv .efi .com .msi .mui .ax .acm .tlb
Unix    : .so .elf .bin .run .out .ko .o .a   (and versioned libs: libfoo.so.1.2.3)
macOS   : .dylib .bundle
```

Extensions are compared case-insensitively (`SETUP.EXE` is flagged).

### 4.3 Nested archives

Any entry whose content starts with a ZIP signature (`PK\x03\x04`) is opened
and scanned recursively, **regardless of its name** (a ZIP renamed to
`archive.data` is still opened). Paths of nested entries are shown with `!`:

```
outer/inner.zip!folder/program.exe
```

Nested archives larger than 512 MB, or deeper than `--max-depth`, are not
scanned and are reported as errors (the scan then fails, see §8).

### 4.4 Fail-safe behaviour

The scanner never reports "clean" for content it could not inspect. The
following produce an **error** and prevent the report from being written:

- encrypted (password-protected) entries
- corrupted entries or an invalid / non-ZIP file
- unsupported compression methods
- nested archives that are too deep or too large

---

## 5. Reading the console output

Each finding is printed on one line:

```
  [BINARY] <path in zip>  ->  <detected type>  (by <method>)  ! <note>
```

| Field | Meaning |
|---|---|
| `by content` | The bytes of the file are an executable |
| `by extension` | The name has a binary extension |
| `by content+extension` | Both |
| `! binary content hidden behind a non-binary extension` | **Disguised binary**, e.g. a DLL named `notes.txt`. Treat as highly suspicious. |
| `! binary extension but content not recognised as executable` | Named like a binary but content is not one (e.g. a text file called `fake.dll`). Still flagged. |

Errors are printed as:

```
  [ERROR]  <path>: <reason>
```

---

## 6. The report file

Written **only** when no binary was found and no error occurred.

```
file               : good.zip
scan_date          : 2026-11-05T12:25:53+00:00
entries_scanned    : 2
status             : CLEAN - no executable binaries detected
zip_sha256         : fdc3a94b8f15dbda94217802e2a418c0a8839d9bd9a3bfc5462a491979348e8c
checksum_algorithm : SHA-256(utf8(scan_date) || zip_bytes)
checksum           : afb4feb81a19512c6d61207fdf856082b76bcda3f4c4fa0c99e0280bcf1024f4
```

| Field | Meaning |
|---|---|
| `file` | Name of the scanned ZIP |
| `scan_date` | Date and time of the scan, ISO-8601, **UTC** |
| `entries_scanned` | Number of files inspected (nested archive contents included) |
| `status` | Always `CLEAN` (no report is written otherwise) |
| `zip_sha256` | SHA-256 of the ZIP file alone |
| `checksum_algorithm` | How `checksum` is computed |
| `checksum` | SHA-256 of the `scan_date` text (UTF-8) immediately followed by the raw bytes of the ZIP file |

The `checksum` binds the scan date to the exact archive content: changing a
single byte of the ZIP, or the date in the report, produces a different value.

---

## 7. Verifying a checksum

Anyone can re-compute the checksum from the report and the ZIP, without the
scanner.

**Linux / macOS (shell):**

```bash
DATE=$(sed -n 's/^scan_date *: //p' good.zip.checksum.txt)
( printf '%s' "$DATE"; cat good.zip ) | sha256sum      # macOS: shasum -a 256
```

The result must equal the `checksum` line of the report.

> Use `printf '%s'`, not `echo`: `echo` adds a newline that changes the hash.

**Python (any OS):**

```python
import hashlib

date = "2026-11-05T12:25:53+00:00"          # scan_date from the report
h = hashlib.sha256(date.encode("utf-8"))
with open("good.zip", "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
```

**Windows PowerShell:**

```powershell
$date  = "2026-11-05T12:25:53+00:00"
$bytes = [Text.Encoding]::UTF8.GetBytes($date) + [IO.File]::ReadAllBytes("good.zip")
$sha   = [Security.Cryptography.SHA256]::Create()
-join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })
```

---

## 8. Exit codes

| Code | Meaning | Report written? |
|---|---|---|
| `0` | Archive is clean | Yes |
| `1` | At least one binary was found (by content or extension) | No |
| `2` | No binary found, but something could not be inspected (invalid ZIP, encrypted entry, nested archive too large/deep…), or the input path is not a file | No |

If both binaries and errors are present, the exit code is `1`.

---

## 9. JSON output

`--json` prints a machine-readable result on stdout (the report file is still
written when the archive is clean):

```bash
python3 zip_binary_scanner.py good.zip --json
```

```json
{
  "zip": "good.zip",
  "ok": true,
  "entries_scanned": 2,
  "findings": [],
  "errors": [],
  "report": {
    "file": "good.zip",
    "scan_date": "2026-11-05T13:21:58+00:00",
    "entries_scanned": 2,
    "status": "CLEAN - no executable binaries detected",
    "zip_sha256": "fdc3a94b8f15dbda94217802e2a418c0a8839d9bd9a3bfc5462a491979348e8c",
    "checksum_algorithm": "SHA-256(utf8(scan_date) || zip_bytes)",
    "checksum": "c00c0a8bf416c652217581f5d5a7d0349f4a22a1b82862ac706660a6f5ecbd58"
  }
}
```

For a rejected archive, `ok` is `false`, `report` is `null`, and each finding
looks like:

```json
{
  "path": "app/notes.txt",
  "detected_type": "Windows PE32+ DLL (x86-64)",
  "by_content": true,
  "by_extension": false,
  "note": "binary content hidden behind a non-binary extension"
}
```

---

## 10. Examples

### Example 1 — Clean archive

```bash
$ python3 zip_binary_scanner.py good.zip
Scanned 2 file(s) in good.zip
OK: no binaries found. Report written to good.zip.checksum.txt
  date     : 2026-11-05T12:25:53+00:00
  checksum : afb4feb81a19512c6d61207fdf856082b76bcda3f4c4fa0c99e0280bcf1024f4
$ echo $?
0
```

### Example 2 — Archive containing binaries (some disguised)

Content of `bad.zip`:

```
readme.txt              text file
app/tool.exe            Windows executable
app/notes.txt           a DLL renamed to .txt
bin/ls_renamed.dat      Linux /bin/ls renamed to .dat
lib/libz.so.1           Linux shared library
fake.dll                plain text named .dll
nested/archive.data     a ZIP (renamed) containing deep/true, a Linux executable
```

```bash
$ python3 zip_binary_scanner.py bad.zip
Scanned 8 file(s) in bad.zip
  [BINARY] app/tool.exe  ->  Windows PE32+ EXE (x86-64)  (by content+extension)
  [BINARY] app/notes.txt  ->  Windows PE32+ DLL (x86-64)  (by content)  ! binary content hidden behind a non-binary extension
  [BINARY] bin/ls_renamed.dat  ->  Linux/Unix ELF 64-bit PIE executable (x86-64)  (by content)  ! binary content hidden behind a non-binary extension
  [BINARY] lib/libz.so.1  ->  Linux/Unix ELF 64-bit shared object (.so) (x86-64)  (by content+extension)
  [BINARY] fake.dll  ->  unknown (extension only)  (by extension)  ! binary extension but content not recognised as executable
  [BINARY] nested/archive.data!deep/true  ->  Linux/Unix ELF 64-bit PIE executable (x86-64)  (by content)  ! binary content hidden behind a non-binary extension
FAILED: 6 binary finding(s), 0 error(s). No report generated.
$ echo $?
1
```

`readme.txt` is the only file not flagged. The renamed ZIP was opened even
though its name ends in `.data`.

### Example 3 — Custom report location

```bash
python3 zip_binary_scanner.py deliveries/v2.3.zip -o reports/v2.3-scan.txt
```

The `reports/` directory must already exist.

### Example 4 — Password-protected archive

```bash
$ python3 zip_binary_scanner.py protected.zip
Scanned 1 file(s) in protected.zip
  [ERROR]  secret.bin: entry is encrypted, cannot inspect content
FAILED: 0 binary finding(s), 1 error(s). No report generated.
$ echo $?
2
```

### Example 5 — Not a ZIP file

```bash
$ python3 zip_binary_scanner.py broken.zip
Scanned 0 file(s) in broken.zip
  [ERROR]  cannot open archive: File is not a zip file
FAILED: 0 binary finding(s), 1 error(s). No report generated.
```

### Example 6 — Limit nested archive depth

```bash
# Only scan the top-level archive; any ZIP inside it is reported as an error
python3 zip_binary_scanner.py bundle.zip --max-depth 0
```

### Example 7 — List only the paths of detected binaries (with `jq`)

```bash
python3 zip_binary_scanner.py bad.zip --json | jq -r '.findings[].path'
```

### Example 8 — Scan every ZIP in a folder

**Linux / macOS:**

```bash
for z in incoming/*.zip; do
    if python3 zip_binary_scanner.py "$z" > /dev/null; then
        echo "CLEAN    $z"
    else
        echo "REJECTED $z"
    fi
done
```

**Windows PowerShell:**

```powershell
Get-ChildItem incoming\*.zip | ForEach-Object {
    python zip_binary_scanner.py $_.FullName | Out-Null
    if ($LASTEXITCODE -eq 0) { "CLEAN    $($_.Name)" } else { "REJECTED $($_.Name)" }
}
```

### Example 9 — Use from another Python program

```python
from pathlib import Path
import zip_binary_scanner as zbs

result = zbs.scan(Path("release.zip"), max_depth=5)
if result.ok:
    report = zbs.write_report(Path("release.zip"), Path("release.zip.checksum.txt"), result)
    print("clean, checksum:", report["checksum"])
else:
    for f in result.findings:
        print("binary:", f.path, f.detected_type)
    for e in result.errors:
        print("error:", e)
```

---

## 11. Automation (CI / scripts)

The exit code makes the scanner easy to use as a gate.

**Shell script:**

```bash
#!/usr/bin/env bash
set -e
python3 zip_binary_scanner.py "$1"      # stops the script on exit code 1 or 2
echo "Archive accepted"
```

**GitHub Actions step:**

```yaml
- name: Check archive for binaries
  run: python3 zip_binary_scanner.py dist/package.zip -o dist/package.checksum.txt

- name: Upload scan report
  uses: actions/upload-artifact@v4
  with:
    name: scan-report
    path: dist/package.checksum.txt
```

---

## 12. Limitations

- **Scripts are not binaries**: shell, Python, PowerShell, batch, JavaScript
  files, etc. are not flagged.
- **Only ZIP archives are opened recursively.** Other archive formats inside
  the ZIP (`.tar`, `.gz`, `.7z`, `.rar`, `.cab`) are not unpacked, so a
  binary inside them is not seen. Note that `.jar`, `.apk`, `.docx`, `.xlsx`
  are ZIP files and **are** scanned recursively.
- **Windows Installer (`.msi`)** files are flagged by extension only; their
  content format is not analysed.
- **Java `.class`, WebAssembly, and bytecode** files are not treated as
  binaries.
- **Self-extracting or polyglot files** are detected by their leading
  executable header (they *are* flagged).
- Nested archives are loaded in memory (up to 512 MB each).
- The date in the report is in UTC; the checksum depends on the exact
  `scan_date` text, so keep the report unchanged.

---

## 13. Troubleshooting

| Symptom | Cause / solution |
|---|---|
| `error: <path> is not a file` (exit 2) | Wrong path, or a directory was given. |
| `cannot open archive: File is not a zip file` | The file is corrupted or is not a ZIP (e.g. a `.rar` renamed `.zip`). |
| `entry is encrypted, cannot inspect content` | Password-protected ZIP: decrypt it first, then re-zip and scan. |
| `cannot read entry (... compression method ...)` | The entry uses a compression method Python does not support (e.g. Deflate64). Re-create the ZIP with standard Deflate. |
| `nested archive exceeds max depth` | Increase `--max-depth`. |
| `nested archive too large to scan` | Inner ZIP over 512 MB: extract it and scan it separately. |
| Checksum verification does not match | Make sure the date string is copied exactly (including `+00:00`) and that no newline is added (`printf '%s'`, not `echo`). |
| `FileNotFoundError` when writing the report | The directory given to `-o` does not exist. |
