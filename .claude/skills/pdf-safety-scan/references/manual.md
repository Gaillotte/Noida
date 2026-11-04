# User manual

Complete reference for `pdf_safety_scan.py`. `setup.md` covers installation;
`config.md` covers `pdfscan.json` key by key. This file covers what the tool
checks, how to drive it, and how to read what it says.

## Contents

- [What it is for](#what-it-is-for)
- [Synopsis and options](#synopsis-and-options)
- [Exit codes](#exit-codes)
- [Reading the output](#reading-the-output)
- [Every check](#every-check)
  - [Active content](#active-content)
  - [Auto-fired actions](#auto-fired-actions)
  - [Structural and lifecycle](#structural-and-lifecycle)
  - [Disclosure](#disclosure)
  - [Metadata](#metadata)
- [Configuration](#configuration)
- [Baselines](#baselines)
- [Fidelity](#fidelity)
- [Recipes](#recipes)
- [Tuning without going blind](#tuning-without-going-blind)
- [Troubleshooting](#troubleshooting)
- [Limits, and what this is not](#limits-and-what-this-is-not)

---

## What it is for

A PDF is not a picture of a document. It is a container that can hold a
scripting engine, an action that fires before anyone clicks anything, an
attached file, a form that posts somewhere, and several earlier versions of
its own text. It also carries a metadata dictionary and an extractable text
layer, neither visible on the page and both of which travel with the file.

Two separate questions follow, with different audiences:

| | Question | Who cares | Typical finding |
|---|---|---|---|
| **Active content** | dangerous to **open**? | the recipient | JavaScript, launch, remote fetch |
| **Disclosure** | dangerous to **send**? | the producer | a build path, an address, a comment |

For *generated* documents — reports, exports, bundles — the expected active
content count is zero, which makes that half a cheap unambiguous gate.
Disclosure is the likelier accident: nobody embeds JavaScript in a quarterly
report by mistake, but a reviewer's name or a `/home/<user>` path lands in
one easily.

---

## Synopsis and options

```
pdf_safety_scan.py PATH [PATH ...] [options]
```

`PATH` may be a file or a directory; directories are walked recursively for
`*.pdf`.

| Option | Effect |
|---|---|
| `--config FILE` | use this `pdfscan.json`. Default: the nearest one found by walking up from the first `PATH`. |
| `--json` | machine-readable report on stdout. For gates and for keeping a record. |
| `--strict` | same as `fail_on: "warn"`: a warning becomes fatal. Recommended in CI. |
| `--baseline FILE` | suppress findings already accepted in this file. |
| `--update-baseline` | record the current findings as accepted and exit 0. Needs `--baseline`. |
| `--quiet` | findings only: omit the trailing caveat and verification guidance. For logs. |
| `--help` | usage. |

The tool never modifies a PDF. The only file it writes is the baseline, and
only with `--update-baseline`.

---

## Exit codes

| Code | Meaning | Use |
|---|---|---|
| **0** | nothing above `info` | the gate passes |
| **1** | findings to review, none at `fail_on` | a person should look |
| **2** | at least one finding at or above `fail_on` | the gate fails |

`fail_on` defaults to `critical`, so by default `warn` and `review` give
exit 1. `--strict` moves it to `warn`.

---

## Reading the output

```
======================================================================
PDF SAFETY SCAN  v1.1  -  25 file(s), fidelity via pypdf
config: /srv/docs/pdfscan.json
======================================================================
----------------------------------------------------------------------
annual-report.pdf                        12 pages, 142 kB, 3 revisions
  [critical] auto-action /OpenAction /JavaScript runs JavaScript when the file opens
  [warn    ] incremental updates          3 revisions in one file. Content removed...
  [review  ] metadata /Creator            'HeadlessChrome/141...' - the converter's...
----------------------------------------------------------------------
cover-letter.pdf                          2 pages, 31 kB
  clean: no active content, nothing flagged for review
======================================================================
TOTALS  critical 1   warn 1   review 1   info 0
fail_on = critical  ->  exit 2
```

Four severities. The ranking is about what a finding **forces you to do**,
not how exotic it is.

| Severity | Means | Default action |
|---|---|---|
| `critical` | something executes, fetches, posts, or is a live-looking credential | fails the gate |
| `warn` | an attachment, a form, encryption, prior revisions | fails with `--strict` |
| `review` | links, annotations, disclosure matches, metadata | a human decides |
| `info` | context only | never a reason to fail |

`clean:` appears when a file has nothing above `info`. An `info` line may
still print beneath it — that is not a contradiction, it is context.

---

## Every check

### Active content

Each of these is a PDF name whose only purpose is to make something happen.
They are found in the **resolved** object graph, in key *or* value position
(`/Type /EmbeddedFile` and `/S /Launch` are values, not keys).

| Name | Severity | What it is |
|---|---|---|
| `/JavaScript` | critical | embedded JavaScript |
| `/JS` | critical | a JavaScript action body |
| `/Launch` | critical | launches an external program |
| `/SubmitForm` | critical | posts form data to a URL |
| `/ImportData` | critical | reads a local file into a form |
| `/XFA` | critical | XML Forms Architecture — a second, scriptable format nested inside |
| `/RichMedia` | critical | embedded Flash or video |
| `/GoToR` | critical | jump into a remote document |
| `/GoToE` | critical | jump into an embedded file |
| `/Movie` `/Sound` `/3D` | warn | media annotations |
| `/EmbeddedFile` | warn | a file carried inside the PDF |
| `/AcroForm` | warn | interactive form dictionary |
| `/SetOCGState` | warn | toggles optional content — also how content is hidden from a reviewer |

A name found in the raw bytes but in **no** resolved object is reported as
`active? …` at `review`, and only for names of six characters or more. Short
ones like `/JS` and `/3D` occur inside compressed stream data by chance —
that false positive is real, not hypothetical — so they are trusted to the
object walk alone.

### Auto-fired actions

`/OpenAction` and `/AA` (additional actions, on the document or a page) are
the two places something runs with no click. **`/OpenAction` has two legal
shapes and they are nothing alike:**

```
/OpenAction [ 3 0 R /XYZ null null 0 ]          a DESTINATION  → info
/OpenAction << /S /JavaScript /JS (...) >>      an ACTION      → critical
```

The first means "open at the top of this page". Nearly every producer writes
one; it cannot do anything. The tool tells them apart structurally and
follows an indirect reference one hop, then judges the `/S` subtype:

| `/S` | Severity |
|---|---|
| `/JavaScript` `/Launch` `/URI` `/GoToR` `/GoToE` `/SubmitForm` `/ImportData` | critical |
| `/Movie` `/Sound` `/Rendition` | warn |
| `/Named` | review |
| `/GoTo` and anything else | info |

### Structural and lifecycle

| Check | Severity | Why |
|---|---|---|
| **not a PDF** | critical | no `%PDF-` header: a file named `.pdf` that is not one |
| **encrypted** | warn | an encrypted PDF resists inspection; decrypt it before trusting *any* scan, including this one |
| **no pages** | warn | parses but renders nothing — usually a failed conversion |
| **incremental updates** | warn | see below |
| **external link** (`/URI`) | review | every destination listed unless allowlisted |
| **annotations** | review | review comments and markup travel, and usually name people |
| **low fidelity** | warn | neither `pypdf` nor `pymupdf` present |

**Incremental updates deserve the detail.** A PDF saved incrementally
*appends* a revision rather than rewriting the file, so content deleted in a
later save is often still recoverable from an earlier one. This is how
redaction fails in practice: the paragraph is gone from the page and present
in the bytes. The check counts `%%EOF` markers.

A signature is legitimately an incremental update — it would invalidate
itself otherwise — so set `allow_incremental_updates: true` for a signing
workflow. Do **not** set it on a pipeline that builds documents from source:
there, more than one revision means something was edited in place.

### Disclosure

Matched against the extracted text layer.

| Pattern | Severity | Matches |
|---|---|---|
| email address | review | `name@example.com` |
| Windows user profile path | review | `C:\Users\jane\…` |
| UNC path | review | `\\fileserver\share\…` |
| Unix home or root path | review | `/home/jane/…`, `/root/…` |
| build or scratch path | review | `/tmp/…`, `/var/folders/…`, `scratchpad` |
| private key block | critical | `-----BEGIN … PRIVATE KEY-----` |
| certificate block | review | `-----BEGIN CERTIFICATE-----` |
| RFC1918 address | review | `10.x`, `192.168.x`, `172.16–31.x` |
| AWS access key id | critical | `AKIA…`, `ASIA…` |
| long hex secret | review | 40+ hex characters — a digest is fine, a key is not |
| assigned credential | critical | `password=`, `api_key:`, `client_secret:` … with a value |

The credential pattern is **deliberately narrow**. An early version accepted
a bare `token` or `secret` keyword; run over documentation about a hardware
security *token* it reported `CKA_TOKEN=TRUE` as a leaked credential ten
times over. The damage is not the noise — it is that a reader who sees
`critical` and finds nothing wrong, repeatedly, learns to skip criticals.
Breadth belongs in `extra_patterns`, where you choose the trade for your own
corpus and can see what it costs.

Values that look like placeholders (`TRUE`, `FALSE`, `NULL`, `...`, `***`,
`xxx`, `<…>`, `$VAR`, `%s`) are excluded, so documentation that *shows* the
shape of a credential does not trip the rule.

### Metadata

`/Author` `/Creator` `/Producer` `/Title` `/Subject` `/Keywords` `/Company`
`/Manager` are read and reported at `review` when a value contains an
absolute path, an email address, or a converter user-agent such as
`HeadlessChrome/141…`.

A *repo-relative* path is not flagged — `docs/09-tests.md` in `/Subject` is
provenance a reader wants. An earlier version flagged any value containing a
slash and therefore flagged every file, which is how a check becomes
wallpaper.

---

## Configuration

`pdfscan.json`, found by walking up from the scan target, or `--config`.
`config.md` is the full reference; the keys in brief:

| Key | Default | Purpose |
|---|---|---|
| `fail_on` | `"critical"` | severity that exits 2 |
| `allow_emails` | `[]` | expected addresses; `*@domain` allowed |
| `allow_uri_hosts` | `[]` | link destinations that need no comment |
| `ignore_identifier_prefixes` | `[]` | your codebase's constants, matched on the **value** side |
| `allow_text` | `[]` | regexes for specific known-benign matches |
| `extra_patterns` | `[]` | your own disclosure rules |
| `expect_no_text_layer` | `false` | for flattened/redacted output |
| `allow_embedded_files` | `false` | for formats where an attachment is the job |
| `allow_incremental_updates` | `false` | for signing workflows |

An unknown key is a hard error. A scan that silently ignored your tuning
would either drown you or stay quiet about something you believed you had
covered.

---

## Baselines

Pointing the tool at an existing archive for the first time can produce a
long list of findings somebody already decided are acceptable. A baseline
records those, so later runs report only what is **new** — which is what
turns a one-off audit into a gate.

```bash
# accept what is there today, after reading it
python3 pdf_safety_scan.py archive/ --baseline .pdfscan-baseline.json \
        --update-baseline

# from now on, only new findings are reported
python3 pdf_safety_scan.py archive/ --baseline .pdfscan-baseline.json
```

Each acceptance is keyed to the file's **SHA-256**. That is what keeps a
baseline honest: edit a file and its acceptances expire, so "we looked at
this and it was fine" cannot silently cover a document nobody has looked at
since. Commit the baseline so the whole team shares one set of decisions.

Two cautions. Read the findings before accepting them — `--update-baseline`
on an unread corpus formally accepts whatever is in it. And after upgrading
the tool, expect new findings from new checks and accept those deliberately
rather than reflexively.

---

## Fidelity

| Header | Read | Trust clean? |
|---|---|---|
| `fidelity via pypdf` | the resolved object graph | yes |
| `fidelity via pymupdf` | objects from the xref table | mostly |
| `fidelity via raw-only` | the bytes, nothing more | **no** |

In `raw-only` mode a `warn: low fidelity` is attached to every file,
deliberately, so a quiet run cannot pass for a clean one. Confirm the
difference yourself:

```bash
python3 evals/make_fixtures.py /tmp/fx quarterly-report.pdf
grep -c /JavaScript /tmp/fx/quarterly-report.pdf     # 0 — invisible to grep
python3 scripts/pdf_safety_scan.py /tmp/fx           # critical, exit 2
```

---

## Recipes

**Release gate.** Fail the build before anything ships.

```bash
python3 pdf_safety_scan.py dist/pdf --strict --json > scan.json
```

**A bundle for a vendor, auditor or client.** Scan, then ship the digests
so the recipient can confirm they scanned what you sent.

```bash
python3 pdf_safety_scan.py out/ --json > scan.json
sha256sum out/*.pdf > MANIFEST.txt
```

**Did the redaction actually work?** Set `expect_no_text_layer: true` and
watch for extractable text and extra revisions — the two ways a black box
over a paragraph fails.

```bash
echo '{"fail_on":"warn","expect_no_text_layer":true}' > pdfscan.json
python3 pdf_safety_scan.py redacted/
```

**An attachment someone emailed you.** Before opening it in a desktop
reader.

```bash
python3 pdf_safety_scan.py ~/Downloads/invoice.pdf
```

**A back catalogue already published.** Baseline it, then gate on new files
only — see [Baselines](#baselines).

**What does this document say about my machine?** Scan it and read only the
`metadata` and `discloses` lines.

```bash
python3 pdf_safety_scan.py report.pdf --quiet | grep -E "metadata|discloses"
```

---

## Tuning without going blind

Tune the noise: a report nobody trusts gets skipped, and a `critical` that
is usually wrong actively teaches its reader to ignore criticals. But every
allowlist entry is a decision to stop looking at something, so two habits
keep a tuned scanner trustworthy.

**1. Narrow the rule; don't list the hits.** Prefer a key that describes
*why* a class of hit is benign (`ignore_identifier_prefixes` for your own
constants) over `allow_text`, which suppresses a literal string and stops
matching the moment someone rewords a sentence — with nothing to tell you it
has stopped.

**2. After narrowing, prove the detector still fires.** This is the step
people skip and the only thing separating a tuned scanner from a disabled
one: on a clean corpus they produce identical output. Build a file that
*should* trip the rule you just tuned and watch it go red.

```bash
# After adding a prefix, confirm a real credential is still caught.
python3 evals/make_fixtures.py /tmp/fx deploy-notes.pdf
python3 pdf_safety_scan.py /tmp/fx --config pdfscan.json
echo "expect exit 2, got $?"
```

The same applies if you ever edit the built-in patterns in the script.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `fidelity via raw-only` | neither parser installed | `python3 -m pip install pypdf` |
| `raw-only` **after** a successful `pip install pypdf` | the parser went to a *different* interpreter | compare the `python:` line in the header against where `pypdf` lives; install with `python3 -m pip`, or run the Python that has it. `setup.md` has a one-liner that surveys every interpreter |
| every file has `warn: low fidelity` | no parser | same; it is intentional, not a bug |
| `unknown config key(s): …` | typo in `pdfscan.json` | the message lists the valid keys |
| `no PDFs found in: …` | path has no `*.pdf`, or the wrong directory | check the path; the walk is recursive and extension-based |
| ten criticals that are all constants | documentation quoting its own symbols | `ignore_identifier_prefixes` |
| `/OpenAction` reported on every file | an **older** scanner, not this one | this tool reports a destination array as `info` |
| `encrypted` and little else | the scan could not see in | decrypt, then re-scan |
| exit 1 with only `review` findings | working as intended | read them; use `fail_on` to choose what blocks |
| a finding you already accepted reappears | the file changed, so its acceptance expired | re-read it, then `--update-baseline` |
| `extra_patterns[0].pattern: …` | invalid regex | it fails at startup on purpose |
| config seems ignored | a nearer `pdfscan.json` won | pass `--config` explicitly; the header prints which one was used |

---

## Limits, and what this is not

**Say this when you report a clean result**, because it is the honest frame
and easy to leave out:

> A scan run by whoever built the files is self-certification. The tool and
> the documents have the same author, and a scanner only finds what it was
> taught to look for.

A clean result means no object asks a reader to run code, fetch a remote
resource, open an attachment or post a form, and no known pattern looks like
a credential or a build path. It does **not** mean the file is safe: a reader
vulnerability can be reached by a malformed object containing none of these
names.

So recommend independent verification rather than presenting a clean scan as
assurance. In order of value per minute:

1. **Antivirus or EDR the recipient administers**, not one the sender chose.
2. **A structural check by a different author** — `qpdf --check file.pdf`,
   or Didier Stevens' `pdfid.py`. Disagreement with this report is the
   signal worth having.
3. **Open it in a sandbox or a browser viewer**, not a full desktop reader,
   which carries far more attack surface.
4. **Flatten instead of trusting**, if policy demands it. Re-printing keeps
   only marks on a page and discards both active content and metadata:
   ```bash
   qpdf --qdf --object-streams=disable in.pdf out.pdf
   chromium --headless --print-to-pdf=out.pdf file://in.pdf
   ```
   The cost is selectable-text quality and bookmarks.
5. **Verify digests before scanning.** A manifest shipped inside the same
   archive proves transit integrity, not provenance; only a signature with
   a key the recipient already trusts does that.

**This tool is not:**

- **an antivirus.** It triages structure. It has no signatures and no
  sandbox, and it should never be presented as malware detection.
- **a redaction tool.** It can tell you a redaction *looks* unsafe —
  extractable text where none was expected, or extra revisions — but
  removing content is a different job.
- **a guarantee for a recipient.** That is the point of the caveat above.
- **worth running on a PDF you wrote and are about to read yourself.** The
  gate is for documents that cross a trust boundary.
