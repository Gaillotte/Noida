#!/usr/bin/env python3
"""Assemble a self-contained, hand-to-someone-else bundle for this skill.

    python3 build_bundle.py [OUTDIR]        # default: ./dist

Produces pdf-safety-scan-bundle-<date>.zip containing the skill in both
installable forms, the setup guide and user manual at top level where a
recipient will actually find them, ready-made configs and CI snippets, a
verify script, and a manifest of SHA-256 digests.

Two decisions worth knowing about.

THE GUIDES LIVE IN THE SKILL, NOT IN THIS SCRIPT. references/setup.md and
references/manual.md are part of the skill, so they travel with the .skill
file and are available to Claude through progressive disclosure. The bundle
copies them to its top level under friendlier names, because someone who
unzips an archive looking for a manual should not have to guess that it is
two directories down. One source, two locations, and the manifest records
both.

THE FIXTURES ARE NOT SHIPPED AS PDFs. Several carry a live JavaScript action
and one a credential-shaped string; as files in an archive they would trip
antivirus on the recipient's machine, which is a poor first impression for a
tool whose job is to tell them their documents are fine. make_fixtures.py
ships instead and verify.sh builds them locally.
"""
import datetime
import hashlib
import os
import shutil
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.basename(HERE)

# Skill files that go into the bundle's skill/ directory, by relative path.
# Declared rather than globbed: a stray scratch file in the skill directory
# should not silently become part of something handed to a third party.
SKILL_FILES = [
    'SKILL.md',
    'scripts/pdf_safety_scan.py',
    'references/manual.md',
    'references/setup.md',
    'references/config.md',
    'assets/pdfscan.example.json',
    'evals/make_fixtures.py',
]
# Plus every eval case, which is how a recipient re-runs the tests.
EVAL_GLOB = ('prompt.md', 'case.yaml', 'place-files.sh')

START_HERE = """\
# pdf-safety-scan

Checks PDFs for two different things before they cross a trust boundary:

  ACTIVE CONTENT   is this dangerous to OPEN?   JavaScript, actions that
                   fire on open, launches, embedded files, remote fetches.
  DISCLOSURE       is this dangerous to SEND?   addresses, absolute build
                   paths, credentials, leftover metadata, reviewer
                   comments, and prior revisions that a "deleted"
                   paragraph is still sitting in.

Needs Python 3.8+ and nothing else. `pypdf` is strongly recommended and the
reason is in SETUP-GUIDE.md.


TRY IT RIGHT NOW
----------------

    ./verify.sh

That builds known-good and known-bad test files, scans them, and checks
both that the bad ones are reported and that the good ones are not. It
takes a few seconds and it is the only way to know the install works - a
tool whose job is to report that something is ABSENT fails silently when it
is broken.


THEN
----

    SETUP-GUIDE.md     installing it (three routes), installing pypdf,
                       verifying, wiring it into CI, platform notes
    USER-MANUAL.md     every option, every check, exit codes, recipes,
                       troubleshooting
    CONFIG-REFERENCE.md  every pdfscan.json key, with worked examples

    skill/             the skill as a plain directory - copy it to
                       .claude/skills/ or ~/.claude/skills/
    pdf-safety-scan.skill
                       the same thing packaged; open it in Claude and
                       press "Save skill"
    examples/          starting configs and CI snippets
    MANIFEST.txt       SHA-256 of every file in this archive


SCAN SOMETHING
--------------

    python3 skill/scripts/pdf_safety_scan.py ~/Documents/outgoing

Exit 0 clean, 1 findings to review, 2 blocked.


ONE THING TO KEEP IN MIND
-------------------------

A scan run by whoever built a set of files is self-certification: same
author for the tool and the documents, and a scanner only finds what it was
taught to look for. A clean result means nothing in the file asks a reader
to run code, fetch a remote resource, open an attachment or post a form. It
does not mean the file is safe. USER-MANUAL.md ends with what independent
verification looks like, in order of value per minute.
"""

VERIFY = r"""#!/usr/bin/env bash
# Prove the install works, in both directions.
#
# Checking that bad files are reported is only half of it. A scanner that
# flagged everything would pass that half and be useless, so this also
# checks that the known-good files come back clean.
#
# WHAT THIS EXPECTS DEPENDS ON WHETHER A PARSER IS INSTALLED, and getting
# that wrong is how this script first failed. Two of the bad files cannot be
# detected without one: deploy-notes.pdf needs a text layer to read its
# credential out of, and quarterly-report.pdf hides its JavaScript inside a
# compressed object stream. At raw-only fidelity those are SKIPPED with the
# reason given, not failed - a verifier that reports a failure for correct
# behaviour teaches the reader to ignore it.
#
# Override the interpreter if the default one lacks a parser:
#     PYTHON=python3.13 ./verify.sh
set -u

cd "$(dirname "$0")"
PY=${PYTHON:-python3}
SCAN=skill/scripts/pdf_safety_scan.py
FX=$(mktemp -d)
trap 'rm -rf "$FX"' EXIT
fail=0

say()  { printf '%s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }
skip() { printf '  SKIP  %s\n' "$*"; }

parser_of() {   # which parser a given interpreter can import
    "$1" - <<'PY' 2>/dev/null || echo unavailable
try:
    import pypdf; print("pypdf")
except ImportError:
    try:
        import pymupdf; print("pymupdf")
    except ImportError:
        try:
            import fitz; print("pymupdf")
        except ImportError:
            print("raw-only")
PY
}

say "pdf-safety-scan: verifying the install"
say ""

# ---- 1. does it run at all --------------------------------------------
if ! command -v "$PY" >/dev/null 2>&1; then
    bad "$PY is not on PATH"
    exit 1
fi
if "$PY" "$SCAN" --help >/dev/null 2>&1; then
    ok "the scanner runs under $("$PY" -V 2>&1)"
else
    bad "the scanner will not run under $PY - Python 3.8+ is required"
    exit 1
fi

# ---- 2. which parser THIS interpreter has -----------------------------
FID=$(parser_of "$PY")
if [ "$FID" = "raw-only" ]; then
    say "  NOTE  $PY has no PDF parser, so this run is raw-only fidelity."
    # A parser installed for a DIFFERENT interpreter is invisible to this
    # one, and that is the single most common reason for an unexpected
    # raw-only result. Look for a better interpreter and name it.
    found=""
    for cand in python3.13 python3.12 python3.11 python3.10 python3.9; do
        command -v "$cand" >/dev/null 2>&1 || continue
        if [ "$(parser_of "$cand")" != "raw-only" ]; then found=$cand; break; fi
    done
    if [ -n "$found" ]; then
        say "        But $found HAS one. A parser installed for one Python is"
        say "        invisible to another, which is probably what happened:"
        say "            PYTHON=$found ./verify.sh"
        say "        and use $found to run the scanner."
    else
        say "        Install one, then re-run this script:"
        say "            $PY -m pip install pypdf"
    fi
    say "        SETUP-GUIDE.md explains what raw-only cannot see."
else
    ok "parser available to $PY: $FID"
fi
say ""

# ---- 3. build the fixtures -------------------------------------------
if "$PY" skill/evals/make_fixtures.py "$FX" >/dev/null 2>&1; then
    ok "test files built"
else
    bad "could not build the test files"
    exit 1
fi

# ---- 4. known-BAD files must be reported -----------------------------
# annual-report.pdf is detectable either way: its JavaScript action sits in
# plain bytes, so even a raw-only read finds it.
"$PY" "$SCAN" "$FX/annual-report.pdf" --quiet >/dev/null 2>&1
[ $? -eq 2 ] && ok "reported as blocked: annual-report.pdf" \
             || bad "NOT reported: annual-report.pdf  (expected exit 2)"

for f in deploy-notes.pdf quarterly-report.pdf; do
    case $f in
      deploy-notes.pdf)      why="needs a text layer to read the credential" ;;
      quarterly-report.pdf)  why="hides its JavaScript in a compressed object stream" ;;
    esac
    if [ "$FID" = "raw-only" ]; then
        skip "$f - $why, so a parser is required"
        continue
    fi
    "$PY" "$SCAN" "$FX/$f" --quiet >/dev/null 2>&1
    [ $? -eq 2 ] && ok "reported as blocked: $f" \
                 || bad "NOT reported: $f  (expected exit 2)"
done

# ---- 5. known-GOOD files must NOT be reported ------------------------
for f in cover-letter.pdf appendix.pdf handbook.pdf; do
    "$PY" "$SCAN" "$FX/$f" --quiet >/dev/null 2>&1
    rc=$?
    if [ "$FID" = "raw-only" ] && [ $rc -eq 1 ]; then
        ok "clean apart from the fidelity warning: $f"
    elif [ $rc -eq 0 ]; then
        ok "clean: $f"
    else
        bad "false positive on a good file: $f  (exit $rc)"
    fi
done

# ---- 6. the grep demonstration ---------------------------------------
if grep -q /JavaScript "$FX/quarterly-report.pdf" 2>/dev/null; then
    bad "quarterly-report.pdf should hide /JavaScript from grep but did not"
elif [ "$FID" = "raw-only" ]; then
    skip "the grep demonstration - it needs a parser to show the contrast"
else
    ok "/JavaScript is invisible to grep in quarterly-report.pdf, and the"
    say "        scanner found it anyway. That is the whole argument for"
    say "        installing a parser."
fi

say ""
if [ $fail -eq 0 ] && [ "$FID" != "raw-only" ]; then
    say "All checks passed. Start with USER-MANUAL.md, or scan something:"
    say "    $PY $SCAN /path/to/pdfs"
elif [ $fail -eq 0 ]; then
    say "Checks passed, but at raw-only fidelity: some were skipped and a"
    say "clean result from this install should not be trusted. Install a"
    say "parser and re-run."
    exit 1
else
    say "Something failed above. SETUP-GUIDE.md and USER-MANUAL.md both have"
    say "a troubleshooting table."
fi
exit $fail
"""

EXAMPLES = {
    'pdfscan.minimal.json': """\
{
  "fail_on": "critical",
  "allow_emails": ["*@yourcompany.example"]
}
""",
    'pdfscan.docs-site.json': """\
{
  "fail_on": "critical",
  "allow_emails": ["*@yourcompany.example", "support@yourcompany.example"],
  "allow_uri_hosts": ["docs.yourcompany.example", "github.com"],
  "ignore_identifier_prefixes": ["MYAPP_"],
  "extra_patterns": [
    {
      "label": "internal hostname",
      "pattern": "\\\\b[\\\\w-]+\\\\.corp\\\\.yourcompany\\\\.example\\\\b",
      "severity": "critical",
      "advice": "names internal infrastructure; strip before publishing"
    }
  ]
}
""",
    'pdfscan.redacted-release.json': """\
{
  "fail_on": "warn",
  "expect_no_text_layer": true,
  "allow_incremental_updates": false
}
""",
    'pdfscan.signed-invoices.json': """\
{
  "fail_on": "critical",
  "allow_embedded_files": true,
  "allow_incremental_updates": true
}
""",
    'ci/github-actions.yml': """\
# Release gate, not a commit gate: scan where documents are published.
# --strict makes a warning fatal too, so a new finding needs a person.
name: pdf-safety-scan
on:
  workflow_dispatch:
  release:
    types: [created]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install a PDF parser
        # Without this the scan drops to raw-only fidelity and cannot see
        # inside compressed object streams.
        run: python3 -m pip install --quiet pypdf
      - name: Scan the release PDFs
        run: |
          python3 tools/pdf_safety_scan.py dist/pdf --strict --json > scan.json
      - name: Keep the report either way
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: pdf-safety-scan
          path: scan.json
""",
    'ci/gitlab-ci.yml': """\
pdf-safety-scan:
  stage: release
  image: python:3.12-slim
  script:
    - pip install --quiet pypdf
    - python3 tools/pdf_safety_scan.py dist/pdf --strict --json > scan.json
  artifacts:
    when: always
    paths: [scan.json]
  rules:
    - if: $CI_COMMIT_TAG
""",
    'ci/release-gate.sh': """\
#!/usr/bin/env bash
# Drop-in gate for a Makefile or release script.
set -euo pipefail

PDFS=${1:-dist/pdf}

python3 tools/pdf_safety_scan.py "$PDFS" --strict --json > scan.json || {
    echo
    echo "The PDF safety scan refused this release. scan.json has the detail."
    echo "If a finding is known-benign, configure it in pdfscan.json rather"
    echo "than lowering fail_on - and then confirm the rule still fires."
    exit 1
}
echo "PDF safety scan passed: $PDFS"
""",
}


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            h.update(chunk)
    return h.hexdigest()


def main(argv):
    outdir = os.path.abspath(argv[0]) if argv else os.path.join(HERE, 'dist')
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.date.today().isoformat()
    root = 'pdf-safety-scan-bundle-%s' % stamp
    staging = os.path.join(outdir, '.staging-%s' % stamp)
    shutil.rmtree(staging, ignore_errors=True)
    os.makedirs(staging)

    def put(rel, data, mode=None):
        dest = os.path.join(staging, rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if isinstance(data, bytes):
            with open(dest, 'wb') as f:
                f.write(data)
        else:
            with open(dest, 'w', encoding='utf-8') as f:
                f.write(data)
        if mode:
            os.chmod(dest, mode)

    # the skill, as a directory
    missing = []
    for rel in SKILL_FILES:
        src = os.path.join(HERE, rel)
        if not os.path.exists(src):
            missing.append(rel)
            continue
        with open(src, 'rb') as f:
            put('skill/%s' % rel, f.read())
    evals = os.path.join(HERE, 'evals')
    if os.path.isdir(evals):
        for case in sorted(os.listdir(evals)):
            cdir = os.path.join(evals, case)
            if not os.path.isdir(cdir):
                continue
            for name in EVAL_GLOB:
                p = os.path.join(cdir, name)
                if os.path.exists(p):
                    with open(p, 'rb') as f:
                        put('skill/evals/%s/%s' % (case, name), f.read(),
                            0o755 if name.endswith('.sh') else None)
            gdir = os.path.join(cdir, 'graders')
            for g in sorted(os.listdir(gdir)) if os.path.isdir(gdir) else []:
                with open(os.path.join(gdir, g), 'rb') as f:
                    put('skill/evals/%s/graders/%s' % (case, g), f.read())
    if missing:
        raise SystemExit('missing skill file(s): %s' % ', '.join(missing))

    # the guides, surfaced at top level under names a recipient will look for
    for src, dest in (('references/setup.md', 'SETUP-GUIDE.md'),
                      ('references/manual.md', 'USER-MANUAL.md'),
                      ('references/config.md', 'CONFIG-REFERENCE.md')):
        with open(os.path.join(HERE, src), encoding='utf-8') as f:
            put(dest, f.read())

    put('START-HERE.md', START_HERE)
    put('verify.sh', VERIFY, 0o755)
    for rel, body in EXAMPLES.items():
        put('examples/%s' % rel, body,
            0o755 if rel.endswith('.sh') else None)

    # the packaged skill, if one has been built beside the skill
    for cand in (os.path.join(outdir, 'pdf-safety-scan.skill'),
                 os.path.join(HERE, '..', 'pdf-safety-scan.skill')):
        if os.path.exists(cand):
            with open(cand, 'rb') as f:
                put('pdf-safety-scan.skill', f.read())
            break

    # manifest, computed over the staged tree so it describes what shipped
    rows = []
    for dirpath, _, names in os.walk(staging):
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            rel = os.path.relpath(p, staging)
            rows.append((rel, os.path.getsize(p), sha256(p)))
    rows.sort()
    man = ['pdf-safety-scan bundle - %s' % stamp, '',
           'Verify a file with:  sha256sum <file>', '',
           '%-56s %9s  %s' % ('FILE', 'BYTES', 'SHA-256')]
    man += ['%-56s %9d  %s' % r for r in rows]
    man += ['', '%d files, %d bytes total.' % (len(rows),
                                               sum(r[1] for r in rows)), '',
            'This manifest ships inside the same archive, so it proves the',
            'files were not damaged in transit - NOT that they came from who',
            'you think. Only a signature over the archive, with a key you',
            'already trust, does that.']
    put('MANIFEST.txt', '\n'.join(man) + '\n')

    zpath = os.path.join(outdir, '%s.zip' % root)
    with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
        for dirpath, _, names in os.walk(staging):
            for n in sorted(names):
                p = os.path.join(dirpath, n)
                arc = os.path.join(root, os.path.relpath(p, staging))
                zi = zipfile.ZipInfo.from_file(p, arc)
                zi.compress_type = zipfile.ZIP_DEFLATED
                # Keep the executable bit: verify.sh and place-files.sh are
                # meant to be run straight out of the archive.
                zi.external_attr = (os.stat(p).st_mode & 0xFFFF) << 16
                with open(p, 'rb') as f:
                    z.writestr(zi, f.read())
    shutil.rmtree(staging, ignore_errors=True)

    print('%d files -> %s (%.0f kB)'
          % (len(rows), os.path.relpath(zpath), os.path.getsize(zpath) / 1024))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
