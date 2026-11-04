# pdfscan.json — every key, and when to reach for it

Found by walking up from the scan target, so one file at a repository root
covers every subdirectory of PDFs beneath it. Override with `--config PATH`.

An unknown key is a hard error. That is deliberate: a typo in a key name
would otherwise leave you believing you had configured something you had
not, which is the worst outcome available to a security tool — quieter than
no config and just as blind.

## Contents

- [The keys](#the-keys)
- [Choosing between allow_text, allow_emails and extra_patterns](#choosing)
- [Worked examples](#worked-examples)
- [The tuning discipline](#the-tuning-discipline)
- [Why some patterns are narrow](#why-some-patterns-are-narrow)

---

## The keys

### `fail_on`
`"critical"` (default) · `"warn"` · `"review"`

The severity at which the scan exits 2. `--strict` is shorthand for
`"warn"`. Leave it at `critical` for a first pass over an existing corpus
and tighten once the noise is tuned; a gate that fails on day one gets
turned off on day two.

### `allow_emails`
`["name@example.com", "*@example.com"]`

Addresses that are expected in these documents. `*@domain` allows a whole
domain. Use it for addresses that are the *point* of the document — a
support address, a submission address, the recipient's own contacts — not
for an address you would rather nobody noticed.

### `allow_uri_hosts`
`["docs.example.com", "github.com"]`

Hosts a hyperlink may point at without comment. Hostnames only, no scheme
or path. Every other destination is listed for a human to look at, which is
the point: an allowlist that grows without anyone reading it is not a
control.

### `ignore_identifier_prefixes`
`["MYAPP_", "CKA_", "GL_"]`

Drops a disclosure hit whose **value** begins with one of these. For
documentation that quotes its own codebase, where `client_secret:
NCRYPT_PIN_PROPERTY` reads as an assigned credential to any pattern and is
a symbol name.

It filters the value side only. A keyword in identifier *position* —
`MYAPP_PASSWORD = x` — is already excluded by the pattern's own lookbehind,
so you do not need a prefix for that case.

**Its blind spot, stated plainly, because every suppression has one.**
Because the filter matches on the value, a real secret whose value *begins*
with an allowed prefix is suppressed too:

```
client_secret: MYAPP_Gx8-2bQ91ZmLpT     ← suppressed by "MYAPP_"
```

That is narrow — credential generators do not emit your constant prefix — but
it is real. If you ever adopt a token format that starts with one of your
listed prefixes, that entry has to go. Add prefixes when a document actually
trips on one, not pre-emptively as a family sweep: each entry is a decision
to stop looking at something, and a prefix added "just in case" is a decision
nobody made consciously.

### `allow_text`
`["\\\\\\\\build\\\\Release\\\\", "jane@example\\.com"]`

Regexes (case-insensitive) for individual known-benign matches, checked
against both extracted text and metadata values. The escape-heavy one above
is a literal `\\build\Release\` — JSON needs `\\` for one backslash and the
regex needs another pair, so four produce one literal.

Reach for this **last**. It suppresses a specific string rather than
describing a class, so it is the entry most likely to go stale and hide a
real finding later.

### `extra_patterns`
```json
[{"label": "internal hostname",
  "pattern": "\\b[\\w-]+\\.corp\\.internal\\b",
  "severity": "critical",
  "advice": "names internal infrastructure"}]
```

Project-specific things that must not ship. `label` and `pattern` are
required; `severity` defaults to `review` and `advice` to a generic note.
An invalid regex is an error at startup rather than a silent skip.

This is the key that makes the tool yours. The built-ins cover what is
universal — addresses, paths, credentials, key blocks. Only you know that
`PROJ-` ticket numbers or a codename must not reach a customer.

### `expect_no_text_layer`
`false` (default) · `true`

Set `true` for output that is meant to be flattened images — a redacted
release, a signed scan. Any extractable text then becomes a `warn`, which
catches the classic failure where a black rectangle was drawn *over* text
that is still perfectly readable underneath.

### `allow_embedded_files`
`false` (default) · `true`

Set `true` only where attachments are the format's job, such as a ZUGFeRD
or Factur-X invoice carrying its own XML. Everywhere else an attachment in
a document you did not expect to have one is worth a look.

### `allow_incremental_updates`
`false` (default) · `true`

Silences the multiple-revisions warning. Reasonable for a workflow that
signs incrementally — a signature *must* be an incremental update, or it
would invalidate itself. Do not set it on a pipeline that produces
documents from source: there, more than one revision means something was
edited in place.

---

## Choosing

Three keys can suppress the same finding. Prefer them in this order, because
they differ in how much they stop looking at:

| Reach for | When | Risk |
|---|---|---|
| `ignore_identifier_prefixes` | the hit is your own symbol name | low: describes a class |
| `allow_emails` / `allow_uri_hosts` | the address or host is intended | low: scoped to one field |
| `extra_patterns` + narrower built-in | you want a *different* rule | low: adds signal |
| `allow_text` | one specific string, no class to describe | **highest**: a stale entry hides a real hit |

---

## Worked examples

**A documentation bundle going to a vendor.** Expected recipients allowed,
the codebase's own constants excluded, one ambiguous relative path
suppressed:

```json
{
  "fail_on": "critical",
  "allow_emails": ["*@microsoft.com", "support@vendor.example"],
  "allow_uri_hosts": ["learn.microsoft.com", "datatracker.ietf.org"],
  "ignore_identifier_prefixes": ["CKA_", "CKF_", "NCRYPT_", "BCRYPT_"],
  "allow_text": ["\\\\\\\\build\\\\Release\\\\"]
}
```

**A redacted release, where text under a box is the whole worry:**

```json
{
  "fail_on": "warn",
  "expect_no_text_layer": true,
  "allow_incremental_updates": false
}
```

**Invoices that legitimately carry an XML attachment:**

```json
{
  "fail_on": "critical",
  "allow_embedded_files": true,
  "allow_incremental_updates": true
}
```

**Protecting a codename and an internal domain:**

```json
{
  "extra_patterns": [
    {"label": "unreleased codename", "pattern": "\\bProject\\s+Halberd\\b",
     "severity": "critical", "advice": "not public until launch"},
    {"label": "internal domain", "pattern": "\\b[\\w-]+\\.corp\\.example\\b",
     "severity": "critical", "advice": "names internal infrastructure"}
  ]
}
```

---

## The tuning discipline

Two habits keep a tuned scanner trustworthy.

**Narrow the rule, don't list the hits.** A pattern that understands *why* a
class of match is benign keeps working as documents change. A list of
specific strings stops matching the moment someone rewords a sentence, and
nothing tells you it has stopped.

**After every narrowing, prove the detector still fires.** This is the part
people skip, and it is the only thing standing between a tuned scanner and
a disabled one — they produce identical output on a clean corpus.

```bash
# After excluding a prefix, confirm a REAL credential still trips the rule.
printf 'client_secret: Gx8-2bQ91ZmLpT' > /tmp/probe.txt
# ...put that string in a PDF, scan it, expect exit 2.
```

The same applies to the built-ins. If you ever edit `DISCLOSURE` or
`ACTIVE_KEYS` in the script, build a file that *should* trip the edited rule
and watch it go red before you trust the next green run.

---

## Why some patterns are narrow

Worth knowing before you widen one.

An early version of the credential pattern accepted a bare `token` or
`secret` keyword followed by anything. Run over documentation about a
hardware security *token*, it reported `CKA_TOKEN=TRUE` as a leaked
credential ten times over, alongside `secret: SecureZeroMemory()`.

Ten confident criticals, every one wrong. The damage is not the noise — it
is that a reader who sees `critical` and finds nothing wrong, repeatedly,
learns to skip criticals. A check nobody reads is worse than one that does
not exist, because it also provides false comfort.

The same applies to the raw-byte cross-check. It only runs for PDF names of
six characters or more, because a three-byte sequence like `/3D` or `/JS`
turns up inside compressed stream data by chance — observed, not
hypothesised, in a 50 kB document. Short names are trusted to the resolved
object walk alone, which is the authoritative read anyway.

So: the built-in patterns are narrow on purpose, and `extra_patterns` is
where breadth belongs — because there you decide the trade for your own
corpus and can see what it costs.
