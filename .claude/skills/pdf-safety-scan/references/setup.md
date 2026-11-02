# Setup guide

Everything needed to install `pdf-safety-scan`, confirm it actually works,
and wire it into a release pipeline. Read `manual.md` for what the tool does
and how to drive it; this file is only about getting it running.

## Contents

- [Requirements](#requirements)
- [Choose an install route](#choose-an-install-route)
  - [A — as a skill (Claude picks it up automatically)](#a--as-a-skill)
  - [B — as a standalone script](#b--as-a-standalone-script)
  - [C — vendored into a repository, for CI](#c--vendored-into-a-repository)
- [Installing pypdf](#installing-pypdf)
- [Verify the install](#verify-the-install)
- [First run on your own files](#first-run-on-your-own-files)
- [Your first config](#your-first-config)
- [Wiring it into CI](#wiring-it-into-ci)
- [Platform notes](#platform-notes)
- [Upgrading and removing](#upgrading-and-removing)

---

## Requirements

| | |
|---|---|
| **Python** | 3.8 or newer. Standard library only — `argparse`, `json`, `re`, `zlib`, `hashlib`. |
| **`pypdf`** | *Strongly recommended.* Without it the tool still runs but reads less of each file. See [why that matters](#installing-pypdf). |
| **`pymupdf`** | Optional fallback if `pypdf` is unavailable. |
| OS | Anything that runs Python. No compiled extensions, no network access, no services. |

Nothing else. The scanner never writes to the PDFs it reads, never phones
home, and only writes files when you pass `--baseline --update-baseline`.

---

## Choose an install route

Three routes. They are not alternatives so much as different jobs: A is for
working *with* Claude, B for a one-off check, C for a gate that runs without
anyone present.

### A — as a skill

Claude then reaches for it on its own whenever PDFs are about to be sent or
have just arrived, which is the point of installing it this way.

**From the packaged file.** If you have `pdf-safety-scan.skill`, open it in
Claude and press **Save skill**. Done.

**From the directory**, copy it to wherever skills live:

```bash
# Just this project
mkdir -p .claude/skills
cp -r pdf-safety-scan .claude/skills/

# Every project for this user
mkdir -p ~/.claude/skills
cp -r pdf-safety-scan ~/.claude/skills/
```

Confirm it registered:

```bash
claude            # then type: /
                  # "pdf-safety-scan" should appear in the skill list
```

A skill is picked up at session start, so restart an open session.

### B — as a standalone script

The scanner has no imports from the rest of the skill, so one file is a
complete install:

```bash
cp pdf-safety-scan/scripts/pdf_safety_scan.py ~/bin/pdfscan
chmod +x ~/bin/pdfscan
pdfscan ~/Downloads/invoice.pdf
```

Use this when someone sends you a PDF and you want a look before opening it.

### C — vendored into a repository

For a release gate, commit the script rather than depending on an install
step — a gate that can fail to be present is not a gate.

```bash
mkdir -p tools
cp pdf-safety-scan/scripts/pdf_safety_scan.py tools/
cp pdf-safety-scan/assets/pdfscan.example.json pdfscan.json   # then edit
git add tools/pdf_safety_scan.py pdfscan.json
```

Keep `pdfscan.json` at the repository root: the scanner walks up from the
scan target to find it, so one file covers every directory of PDFs beneath
it.

---

## Installing pypdf

```bash
pip install pypdf          # or: pipx, uv pip, python -m pip --user
```

**Why it is worth the trouble.** A PDF can pack its objects into
Flate-compressed *object streams*, and a raw byte search cannot see inside
one. So a text search over a PDF's bytes can call a file clean when it is
not — a fact you can confirm for yourself in about ten seconds:

```bash
python3 evals/make_fixtures.py /tmp/fx quarterly-report.pdf
grep -c /JavaScript /tmp/fx/quarterly-report.pdf           # 0
python3 scripts/pdf_safety_scan.py /tmp/fx                 # critical, exit 2
```

Three fidelity levels, printed in the header of every run:

| Header says | What was read | Trust a clean result? |
|---|---|---|
| `fidelity via pypdf` | the resolved object graph | yes |
| `fidelity via pymupdf` | objects from the xref table | mostly |
| `fidelity via raw-only` | the bytes, nothing more | **no** |

In `raw-only` mode every file also carries a `warn: low fidelity` finding,
deliberately, so a quiet run can never be mistaken for a clean one.

### The trap: a parser installed for a different Python

This is the most likely reason an install looks fine and reports `raw-only`
anyway, and it is easy to miss because `pip install pypdf` succeeds. A
module installed for one interpreter is invisible to another, so a host with
several Pythons will happily put `pypdf` somewhere `python3` never looks:

```bash
$ pip install pypdf          # succeeded
$ python3 pdf_safety_scan.py out/
PDF SAFETY SCAN  v1.1  -  4 file(s), fidelity via raw-only    # ...but
python: 3.11.18
```

That is why the run prints its interpreter. Find out who actually has the
parser:

```bash
for p in python3 python3.13 python3.12 python3.11; do
    command -v $p >/dev/null || continue
    printf '%-12s %s  ' "$p" "$($p -V 2>&1)"
    $p -c 'import pypdf' 2>/dev/null && echo "pypdf: yes" || echo "pypdf: no"
done
```

Then either install into the interpreter you will actually run —

```bash
python3 -m pip install pypdf        # note: python3 -m pip, not bare pip
```

— or run the scanner with the one that already has it:

```bash
python3.13 pdf_safety_scan.py out/
PYTHON=python3.13 ./verify.sh
```

`python3 -m pip` is the habit worth keeping: it installs into *that*
interpreter by construction, which bare `pip` does not promise. In CI, pin
the interpreter and install with `-m pip` in the same job.

**No network?** Download the wheel on a connected machine and carry it over:

```bash
pip download pypdf -d wheels/          # connected
pip install --no-index --find-links wheels/ pypdf   # air-gapped
```

Or use the distro package (`python3-pypdf` on Debian/Ubuntu,
`python3-pypdf` on Fedora). A `pymupdf` install also works if that is what
your platform has.

---

## Verify the install

Do not skip this. The scanner's whole job is to tell you something is
*absent*, and the failure mode of such a tool is reporting absence because
it is broken. Run the bundled check:

```bash
./verify.sh                          # from the bundle root
```

Or by hand, which does the same thing in three steps:

```bash
# 1. the tool runs and finds its config schema
python3 skill/scripts/pdf_safety_scan.py --help >/dev/null && echo ok

# 2. known-bad files are reported
python3 skill/evals/make_fixtures.py /tmp/fx
python3 skill/scripts/pdf_safety_scan.py /tmp/fx --quiet
#    expect: critical on annual-report, deploy-notes, api-guide,
#            quarterly-report; clean on cover-letter and appendix;
#            info (not a finding) on handbook
echo "exit should be 2, was $?"

# 3. known-good files are NOT reported
python3 skill/scripts/pdf_safety_scan.py /tmp/fx/cover-letter.pdf --quiet
echo "exit should be 0, was $?"
```

Step 3 matters as much as step 2. A scanner that flags everything passes
step 2 and is useless.

---

## First run on your own files

```bash
python3 pdf_safety_scan.py path/to/pdfs
```

Expect findings on the first run over a real corpus — most will be
`review`, and many will be intended. Read them once before configuring
anything, because the first pass is the only time you see your documents
through a stranger's eyes. Things people are routinely surprised by:

- the converter's user-agent sitting in `/Creator`, naming their OS;
- a colleague's name on a review annotation nobody cleared;
- a `/home/<someone>` path in a figure caption;
- a document with three revisions, where two paragraphs were "deleted".

---

## Your first config

Copy the example and cut it down:

```bash
cp assets/pdfscan.example.json pdfscan.json
$EDITOR pdfscan.json          # delete the _comment block first
```

Start with just the two keys almost everyone needs:

```json
{
  "fail_on": "critical",
  "allow_emails": ["*@yourcompany.example"]
}
```

Add more only when a real document trips on something. `manual.md` and
`config.md` describe every key; the short rule is to prefer a key that
describes *why* a class of hit is benign over one that suppresses a
specific string.

An unknown key is a hard error, so a typo fails loudly instead of leaving
you believing you had configured something you had not.

---

## Wiring it into CI

A **release** gate, not a commit gate. Scan where documents are built or
published; running it on every push to catch nothing is waste.

**GitHub Actions**

```yaml
- name: Scan release PDFs
  run: |
    python3 -m pip install --quiet pypdf
    python3 tools/pdf_safety_scan.py dist/pdf --strict --json > scan.json
- name: Keep the report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: pdf-safety-scan
    path: scan.json
```

**GitLab CI**

```yaml
pdf-scan:
  stage: release
  script:
    - pip install --quiet pypdf
    - python3 tools/pdf_safety_scan.py dist/pdf --strict --json > scan.json
  artifacts:
    when: always
    paths: [scan.json]
```

**A plain shell gate**, for a Makefile or release script:

```bash
python3 tools/pdf_safety_scan.py dist/pdf --strict || {
    echo "PDF scan refused the release"; exit 1; }
```

Use `--strict` in CI so a `warn` is fatal too: a new finding should need a
person to look at it, not be absorbed into a log. Install `pypdf` in the job
or the gate silently drops to `raw-only`.

---

## Platform notes

**Windows.** Use `py -3` and quote paths with spaces:

```powershell
py -3 pdf_safety_scan.py "C:\Releases\Q4 bundle" --strict
```

Config paths in `pdfscan.json` are regexes, so a Windows path needs four
backslashes per literal one (`\\\\` in JSON produces `\\` for the regex,
which matches one `\`).

**macOS.** The system Python 3 is fine. If `pip install` is refused by an
externally-managed environment, use `pipx` or a venv:

```bash
python3 -m venv ~/.venv/pdfscan && ~/.venv/pdfscan/bin/pip install pypdf
~/.venv/pdfscan/bin/python pdf_safety_scan.py ~/Documents/out
```

**Air-gapped / regulated hosts.** Nothing in the tool reaches the network,
at install or at run time. The only outbound thing it mentions is advice in
its own output. It is safe to run on a host with no egress, and `--json`
output is the artefact to carry out.

---

## Upgrading and removing

Upgrading is replacing one file, or re-saving the skill. Two things to carry
across:

- your `pdfscan.json`, which is yours and is never touched;
- your baseline, if you use one. A new version may add checks, so expect
  new findings after an upgrade and re-accept deliberately rather than
  running `--update-baseline` reflexively — that would accept whatever the
  new checks found without anyone reading it.

Removing it is deleting the directory or the script. It leaves nothing
behind: no services, no registry entries, no cache.
