---
name: pdf-safety-scan
description: >-
  Scan PDFs for active content (JavaScript, actions that fire on open, launches,
  embedded files, remote references) and for information disclosure (emails,
  absolute build paths, credentials, leftover metadata, reviewer comments,
  recoverable prior revisions) before they are published, emailed, attached to a
  tender, or handed to a vendor, auditor, client or regulator. Use this whenever
  PDFs are about to leave the building or have just arrived from outside — and
  also when the user asks whether a PDF is safe to open, wants a release gate for
  generated documents, is assembling a documentation or due-diligence bundle,
  needs to confirm a redaction actually removed something, worries what a
  document leaks about the machine that built it, or asks about PDF metadata,
  sanitising, flattening or stripping. Run it after any step that generates or
  converts PDFs, even if the user did not ask for a check.
---

# PDF safety scan

A PDF is not a picture of a document. It is a container that can hold a
scripting engine, an action that fires before anyone clicks anything, an
attached file, a form that posts somewhere, and several earlier versions of
its own text. It also carries a metadata dictionary and an extractable text
layer, both of which travel with the file and neither of which is visible on
the page.

That makes two separate questions, with different audiences, and keeping them
apart is most of the value here:

| | Question | Who cares |
|---|---|---|
| **Active content** | Is this dangerous to **open**? | whoever receives a file |
| **Disclosure** | Is this dangerous to **send**? | whoever produced it |

For generated documents — reports, bundles, exports — the expected active
content count is **zero**, which makes it a cheap, unambiguous gate rather
than a judgement call. Disclosure is usually the likelier accident: nobody
embeds JavaScript in a quarterly report by mistake, but a build path, a
reviewer's name or a personal address lands in one easily.

## Run it

```bash
python3 scripts/pdf_safety_scan.py path/to/pdfs
python3 scripts/pdf_safety_scan.py report.pdf --json       # for a gate
python3 scripts/pdf_safety_scan.py out/ --strict           # warn is fatal too
```

Exit **0** clean · **1** findings to review · **2** at or above `fail_on`.

No required dependencies, but fidelity depends on what is installed, and this
matters more than it sounds:

| Installed | What is read |
|---|---|
| `pypdf` *(recommended)* | the object graph, resolved — the good path |
| `pymupdf` only | objects from the cross-reference table |
| neither | **raw bytes only**, and the report says so |

A raw byte search cannot see inside an object stream, which is where a modern
writer puts most of a document. So `grep /JavaScript` over a PDF's bytes can
report a clean file that is not one — this is demonstrated, not asserted.
Build the fixture and see for yourself:

```bash
python3 evals/make_fixtures.py /tmp/fx quarterly-report.pdf
grep -c /JavaScript /tmp/fx/quarterly-report.pdf        # 0
python3 scripts/pdf_safety_scan.py /tmp/fx              # critical, exit 2
```

Its catalog and a JavaScript action sit inside one Flate-compressed object
stream, so:

```
/JavaScript   absent from the raw bytes        grep finds nothing
/JavaScript   present after decompression      the scanner reports critical
```

If the report says `raw-only`, install `pypdf` before believing a clean
result. Note that it will still say `warn: low fidelity` on every file in
that mode, precisely so a clean-looking run cannot be mistaken for a clean
file.

## Reading the output

Four severities. The ranking is about what the finding *forces you to do*, not
how exotic it is.

- **critical** — something executes, fetches, posts, or is a live-looking
  credential. For a generated document this is always wrong.
- **warn** — an attachment, a form, encryption, or **incremental updates**.
- **review** — links, annotations, disclosure matches, metadata. A human
  decides; many are intended.
- **info** — context, never a reason to fail. The main one is `/OpenAction`
  as a *view destination*.

Two of these are worth understanding before you tune anything away.

**`/OpenAction` has two legal shapes and they are nothing alike.**

```
/OpenAction [ 3 0 R /XYZ null null 0 ]          a DESTINATION  → info
/OpenAction << /S /JavaScript /JS (...) >>      an ACTION      → critical
```

The first means "open at the top of this page". Nearly every producer writes
one. Treating it as a finding buries the second shape — the one that runs
code — under noise from every benign file in the directory. The script
distinguishes them structurally rather than by pattern-matching bytes.

**Incremental updates mean earlier revisions are still in the file.** Each
save can append a revision rather than rewriting. So text that someone
deleted before sending is often still recoverable, which is how redactions
fail in practice: the paragraph is gone from the page and present in the
bytes. If anything was edited *out* of a document before release, re-save it
as a single revision and verify rather than assuming the delete took.

## Tuning without going blind

The first run against a real corpus usually produces findings someone has
already decided are fine. Tune them — a report nobody trusts gets skipped,
and a critical finding that is usually wrong actively teaches its reader to
ignore critical findings. That costs more than having no check.

But every allowlist entry is a decision to stop looking at something, so two
rules make tuning safe:

1. **Narrow the pattern, don't widen the allowlist.** Prefer a config that
   describes *why* a class of hit is benign (`ignore_identifier_prefixes`
   for your codebase's constants) over listing each occurrence.
2. **After narrowing, prove the detector still fires.** Make a file that
   *should* trip the check you just tuned, and confirm it still does. A
   detector that was quietly disabled looks exactly like a clean corpus.

Configuration lives in `pdfscan.json`, found by walking up from the scan
target, or passed with `--config`. Read **`references/config.md`** for every
key, what it is for, and worked examples. The short version:

```json
{
  "fail_on": "critical",
  "allow_emails": ["*@yourcompany.com", "legal@client.example"],
  "allow_uri_hosts": ["docs.yourcompany.com"],
  "ignore_identifier_prefixes": ["MYAPP_", "CKA_"],
  "allow_text": ["\\\\\\\\build\\\\Release\\\\"],
  "extra_patterns": [
    {"label": "internal hostname", "pattern": "\\b\\w+\\.corp\\.internal\\b",
     "severity": "critical", "advice": "names internal infrastructure"}
  ]
}
```

An unknown config key is an error, not a warning. A scan that silently
ignores your tuning will either drown you or — worse — stay quiet about
something you believed you had configured it to catch.

## An existing pile of PDFs

Use a baseline. It records the findings already accepted, so later runs
report only what is **new**, which is what turns an audit into a gate:

```bash
python3 scripts/pdf_safety_scan.py archive/ --baseline .pdfscan-baseline.json \
        --update-baseline          # accept today's findings
python3 scripts/pdf_safety_scan.py archive/ --baseline .pdfscan-baseline.json
```

Each acceptance is keyed to the file's SHA-256, which is the part that keeps
a baseline honest: edit a file and its acceptances expire. "We looked at this
and it was fine" cannot silently cover a document nobody has looked at since.

## Where this belongs in a pipeline

A **release** gate, not a commit gate. Scan where documents are built or
published, not on every push — building a bundle to catch nothing is waste.
Use `--strict` there so a warning is fatal too, and a new finding has to be
looked at by a person instead of absorbed into a log.

```yaml
- run: python3 scripts/pdf_safety_scan.py dist/pdf --strict --json > scan.json
```

Pair the scan with a manifest of SHA-256 digests so a recipient can confirm
that what they scanned is what you sent.

## What a clean result does not mean

Lead with this whenever you report results, because it is the honest frame
and it is easy to leave out:

> A scan run by whoever built the files is self-certification. The tool and
> the documents have the same author, and a scanner only finds what it was
> taught to look for.

A clean result means no object asks a reader to run code, fetch a remote
resource, open an attachment or post a form, and no known pattern looks like
a credential or a build path. It does not mean the files are safe: a reader
vulnerability can be reached by a malformed object containing none of these
names.

So recommend independent verification rather than presenting a clean scan as
assurance. In order of value per minute:

1. **Antivirus or EDR the recipient administers**, not one the sender chose.
2. **A structural check by a different author** — `qpdf --check file.pdf`, or
   Didier Stevens' `pdfid.py`. Disagreement with this report is the signal
   worth having.
3. **Open the first one in a sandbox or a browser viewer**, not a full
   desktop reader, which carries far more attack surface.
4. **Flatten instead of trusting**, if policy demands it. Re-printing keeps
   only marks on a page and discards both active content and metadata:
   ```bash
   qpdf --qdf --object-streams=disable in.pdf out.pdf
   chromium --headless --print-to-pdf=out.pdf file://in.pdf
   ```
   The cost is selectable-text quality and bookmarks.
5. **Verify digests before scanning**, so what was scanned is what was sent.
   A manifest inside the same archive proves transit integrity, not
   provenance; only a signature with a key the recipient already trusts does
   that.

## When not to reach for this

- **Deciding whether a PDF is malware.** This triages structure; it is not an
  antivirus and should not be presented as one.
- **Redacting a document.** It can tell you a redaction *looks* unsafe —
  extractable text where none was expected, or multiple revisions — but
  removing content is a separate job.
- **One PDF the user wrote and is about to read themselves.** The gate is for
  documents that cross a trust boundary.

## Files

- `scripts/pdf_safety_scan.py` — the scanner. Self-contained; copy it alone
  into another project if that is easier than copying the skill.
- `references/config.md` — every config key, with worked examples and the
  tuning discipline in more detail.
- `assets/pdfscan.example.json` — a commented starting config.
