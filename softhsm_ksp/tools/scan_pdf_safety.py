#!/usr/bin/env python3
"""Check a directory of PDFs before anyone is asked to open or receive them.

    python3 softhsm_ksp/tools/scan_pdf_safety.py <dir-or-file> [...]
    python3 softhsm_ksp/tools/scan_pdf_safety.py --strict dist/pdf

Exit 0 clean, 1 findings to review, 2 active content found.

READ THIS FIRST, IT IS THE MOST IMPORTANT PART OF THE FILE.

A scanner run by whoever built the archive is self-certification. If these
documents reached you with this report already inside them, the report tells
you what the sender's tool believed, which is not the same as what is true.
It cannot be, for two reasons: the tool and the files have the same author,
and a scanner only ever finds the things it was taught to look for. Treat it
as a build gate, never as the assurance a recipient relies on. The last
section of the output says what an independent check looks like.

What it does check, in two classes, because they are different risks with
different audiences:

  ACTIVE CONTENT - is this dangerous to OPEN?
      A PDF is a container that can hold JavaScript, an action that fires on
      open, a launch of a local program, an embedded file, a form that posts
      somewhere, or a reference that fetches a remote document. None of that
      is needed by any document in this project, so the correct count for
      every one of these is zero, and a non-zero count is a finding rather
      than a judgement call.

  DISCLOSURE - is this dangerous to SEND?
      The likelier accident by far for this project. These documents are
      destined for an HSM vendor, an auditor and a joining team, and they
      were produced on a developer's machine from a repository that contains
      an owner's email address, local paths and credential examples. A PDF
      carries extracted text and a metadata dictionary, and both travel.
      A leaked build path or address is not a vulnerability in the PDF; it
      is information the sender did not mean to publish.

Object inspection goes through PyMuPDF's cross-reference walk, which returns
each object's source AFTER decompression. That matters: a raw byte search
over the file misses anything inside an object stream, which is where a
modern writer puts most of the document - so a grep for /JavaScript over the
bytes can report a clean file that is not one. The raw scan still runs, as a
cross-check for objects the parser could not reach, and disagreement between
the two is itself reported.
"""
import os
import re
import sys

# ── Active content ──────────────────────────────────────────────────────────
#
# (token, severity, what it means, why this project should never have it)
ACTIVE = [
    ('/JavaScript', 'CRITICAL', 'embedded JavaScript',
     'no document here is interactive'),
    ('/JS', 'CRITICAL', 'JavaScript action body',
     'no document here is interactive'),
    ('/Launch', 'CRITICAL', 'launches an external program',
     'never legitimate in a report'),
    ('/AA', 'CRITICAL', 'additional actions on page or field events',
     'same reason as OpenAction, and easier to miss'),
    ('/SubmitForm', 'CRITICAL', 'posts form data to a URL',
     'these documents collect nothing'),
    ('/ImportData', 'CRITICAL', 'reads a local file into a form',
     'never legitimate here'),
    ('/XFA', 'CRITICAL', 'XML Forms Architecture',
     'a second, scriptable document format inside the PDF'),
    ('/RichMedia', 'CRITICAL', 'embedded Flash or video object',
     'a historically heavy source of reader vulnerabilities'),
    ('/Movie', 'CRITICAL', 'movie annotation', 'same'),
    ('/Sound', 'CRITICAL', 'sound annotation', 'same'),
    ('/3D', 'CRITICAL', '3D artwork stream', 'same'),
    ('/GoToR', 'CRITICAL', 'jumps into a REMOTE document',
     'turns opening a page into a network fetch'),
    ('/SetOCGState', 'WARN', 'toggles optional content groups',
     'benign alone, used to hide content from a reviewer'),
    ('/EmbeddedFile', 'WARN', 'a file carried inside the PDF',
     'nothing here needs an attachment; a container for anything'),
    ('/Filespec', 'WARN', 'file specification, often with an attachment',
     'see EmbeddedFile'),
    ('/AcroForm', 'WARN', 'interactive form dictionary',
     'these are read-only documents'),
    ('/URI', 'WARN', 'external hyperlink',
     'not dangerous, but every destination should be one you recognise'),
]

# ── Disclosure ──────────────────────────────────────────────────────────────
#
# Each is (label, compiled pattern, severity, what to do about it). Kept
# deliberately noisy: a false positive costs a glance, a missed address or
# build path is published for good.
DISCLOSE = [
    ('email address',
     re.compile(r'\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b'), 'REVIEW',
     'intended for the recipient, or a personal address nobody meant to '
     'publish?'),
    ('Windows user profile path',
     re.compile(r'[A-Za-z]:\\+Users\\+[^\s\\/"\')]+', re.I), 'REVIEW',
     'names an account on a real machine'),
    ('UNC path',
     re.compile(r'\\\\\\\\[A-Za-z0-9._-]{2,}\\\\+'), 'REVIEW',
     'names an internal host or share'),
    ('Unix home or root path',
     re.compile(r'/(?:home|Users)/[a-z0-9._-]{2,}|/root/[^\s"\')]+'),
     'REVIEW', 'names an account and a layout on a real machine'),
    ('build or scratch path',
     re.compile(r'/tmp/[^\s"\')]+|scratchpad|/var/folders/'), 'REVIEW',
     'a build-machine artefact that should not be in a deliverable'),
    ('private key block',
     re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'), 'CRITICAL',
     'key material must never appear in a document'),
    ('certificate block',
     re.compile(r'-----BEGIN CERTIFICATE-----'), 'REVIEW',
     'a certificate is public, but confirm it was meant to ship'),
    ('RFC1918 address',
     re.compile(r'\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))'
                r'\.\d{1,3}(?:\.\d{1,3})?\b'), 'REVIEW',
     'an internal address reveals network layout'),
    # NARROWED, and the first version is worth recording because it made
    # the tool useless rather than merely noisy. It accepted a bare
    # `token` or `secret` followed by anything, in a corpus about PKCS#11,
    # where "token" IS the hardware and CKK_GENERIC_SECRET is a key type.
    # It reported 10 CRITICALs, every one of them a false positive:
    # `CKA_TOKEN=TRUE`, `token: CKR_TEMPLATE_INCONSISTENT`,
    # `secret: SecureZeroMemory()`. A critical finding that is usually
    # wrong trains its reader to skip criticals, which costs more than
    # having no check - the same shape as a staleness check that flags the
    # historical record as drift.
    #
    # So: the keyword may not be part of a longer identifier, bare `token`
    # and `secret` are out in favour of the compound forms that only ever
    # mean a credential, and the VALUE must not be a constant, a C
    # expression or an obvious placeholder.
    ('assigned credential',
     re.compile(
         r'(?<![A-Za-z0-9_])'
         r'(?:password|passwd|passphrase|api[_-]?key|access[_-]?token'
         r'|auth[_-]?token|client[_-]?secret|bearer)'
         r'\s*[=:]\s*'
         r'(?!(?:TRUE|FALSE|NULL|NULL_PTR|None|CK[A-Z_]*|NCRYPT_|BCRYPT_'
         r'|NTE_|\.{2,}|\*{2,}|x{3,}|<|"?\$|%s|\{)'
         r')([^\s,;)\]}]{6,})', re.I), 'CRITICAL',
     'a credential with a value beside it'),
    ('PIN with a literal value',
     re.compile(r'\bPIN\b[^.\n]{0,24}?[=:]\s*["\']?\d{4,}', re.I), 'REVIEW',
     'confirm it is an illustration and not a real credential'),
]

METADATA_KEYS = ('/Author', '/Creator', '/Producer', '/Title', '/Subject',
                 '/Keywords', '/Company', '/Manager')

# Hosts a link may point at without comment. Everything else is listed for a
# human to look at, which is the entire point: an allowlist that grows
# without anyone reading it is not a control.
URI_ALLOW = ('fonts.googleapis.com', 'fonts.gstatic.com', 'github.com',
             'learn.microsoft.com', 'docs.oasis-open.org', 'www.rfc-editor.org',
             'datatracker.ietf.org')


def objects(path):
    """{xref number: decompressed object source}. None if unparseable.

    A dict rather than a list because /OpenAction and /AA usually hold an
    indirect reference, and deciding whether either is dangerous means
    following it. See open_action_findings.
    """
    try:
        import pymupdf
    except ImportError:
        try:
            import fitz as pymupdf
        except ImportError:
            return None
    try:
        doc = pymupdf.open(path)
    except Exception:
        return None
    out = {}
    for xref in range(1, doc.xref_length()):
        try:
            out[xref] = doc.xref_object(xref, compressed=False)
        except Exception:
            continue
    try:
        out[-1] = doc.xref_object(-1)            # the trailer
    except Exception:
        pass
    doc.close()
    return out


# The action subtypes that do something on their own behalf. A /GoTo or a
# /Named action moves the view and is not in this list.
DANGEROUS_ACTIONS = {
    'JavaScript': ('CRITICAL', 'runs JavaScript when the file opens'),
    'Launch': ('CRITICAL', 'launches a program when the file opens'),
    'URI': ('CRITICAL', 'fetches a URL when the file opens'),
    'GoToR': ('CRITICAL', 'opens a remote document when the file opens'),
    'GoToE': ('CRITICAL', 'opens an embedded file when the file opens'),
    'SubmitForm': ('CRITICAL', 'posts data when the file opens'),
    'ImportData': ('CRITICAL', 'reads a local file when the file opens'),
    'Movie': ('WARN', 'plays a movie when the file opens'),
    'Sound': ('WARN', 'plays a sound when the file opens'),
    'Rendition': ('WARN', 'starts a rendition when the file opens'),
    'Named': ('REVIEW', 'runs a named viewer command when the file opens'),
}


def open_action_findings(objsrc):
    """/OpenAction, judged by what it actually is.

    THIS IS THE CHECK THE FIRST VERSION GOT WRONG, and the error was the
    expensive direction: it reported CRITICAL for every LibreOffice-produced
    PDF in the bundle.

    /OpenAction has two completely different legal shapes:

        /OpenAction [ 1 0 R /XYZ null null 0 ]     a DESTINATION array
        /OpenAction << /S /JavaScript /JS (...) >> an ACTION dictionary

    The first says "open at the top of page one". Every word processor
    writes it, it cannot do anything, and flagging it buries the second
    shape - which is the one that runs code - under noise from benign
    files. A destination is reported as INFO so the count is still visible,
    and only an action dictionary with a dangerous /S is a finding.

    An indirect reference is followed one hop, which is how writers
    normally store an action; a reference that cannot be resolved is
    reported as unresolved rather than assumed benign.
    """
    out = []
    for src in objsrc.values():
        for m in re.finditer(r'/OpenAction\s*', src):
            tail = src[m.end():m.end() + 200].lstrip()

            ref = re.match(r'(\d+)\s+\d+\s+R', tail)
            if ref:
                target = objsrc.get(int(ref.group(1)))
                if target is None:
                    out.append(('REVIEW', 'active: /OpenAction',
                                'an indirect action that could not be '
                                'resolved - inspect object %s by hand'
                                % ref.group(1)))
                    continue
                tail = target.lstrip()

            if tail.startswith('['):
                out.append(('INFO', 'open destination',
                            'a view destination, not an action - benign, '
                            'written by most producers'))
                continue

            sub = re.search(r'/S\s*/(\w+)', tail[:400])
            if not sub:
                out.append(('REVIEW', 'active: /OpenAction',
                            'present but neither a destination nor a '
                            'recognisable action - inspect by hand'))
                continue
            name = sub.group(1)
            sev, what = DANGEROUS_ACTIONS.get(
                name, ('INFO', 'a view action (/%s), benign' % name))
            out.append((sev, 'active: /OpenAction /%s' % name, what))
    return out


def text_of(path):
    try:
        import pymupdf
    except ImportError:
        try:
            import fitz as pymupdf
        except ImportError:
            return ''
    try:
        doc = pymupdf.open(path)
        body = '\n'.join(p.get_text() for p in doc)
        doc.close()
        return body
    except Exception:
        return ''


def scan_one(path):
    """-> (findings, info) for one file. findings are (sev, label, detail)."""
    findings, info = [], {}
    size = os.path.getsize(path)
    info['bytes'] = size

    with open(path, 'rb') as f:
        raw = f.read()

    if not raw.startswith(b'%PDF-'):
        findings.append(('CRITICAL', 'not a PDF',
                         'no %PDF- header; a file named .pdf that is not one'))
        return findings, info
    info['version'] = raw[5:8].decode('latin-1', 'replace')

    # Encryption first: it changes what everything below can see.
    if re.search(rb'/Encrypt\b', raw):
        findings.append(('WARN', 'encrypted',
                         'an encrypted PDF resists inspection; decrypt it '
                         'before trusting any scan of it, including this one'))

    objs = objects(path)
    if objs is None:
        findings.append(('WARN', 'no parser',
                         'PyMuPDF unavailable, so only the raw byte scan ran '
                         'and anything inside an object stream was invisible'))
        objs = {}
    joined = '\n'.join(objs.values())
    info['objects'] = len(objs)
    findings += open_action_findings(objs)

    try:
        from pypdf import PdfReader
        reader = PdfReader(path)
        info['pages'] = len(reader.pages)
        meta = reader.metadata or {}
        info['meta'] = {k: str(v) for k, v in meta.items()
                        if k in METADATA_KEYS}
    except Exception as exc:
        info['pages'] = 0
        info['meta'] = {}
        findings.append(('WARN', 'unreadable structure',
                         '%s: %s' % (type(exc).__name__, exc)))

    if info.get('pages') == 0:
        findings.append(('WARN', 'no pages',
                         'parses but renders nothing - a failed conversion'))

    # ── active content ──────────────────────────────────────────────────
    #
    # RAW_MIN exists because the raw-byte cross-check produced a false
    # positive on the first real run, and the mechanism generalises badly.
    # It reported /3D in Feature-Matrix.pdf; the bytes were at offset 33859,
    # inside a Flate stream, surrounded by compressed garbage:
    #
    #     ...0jD3lg0[Pe*]@WW8m1Dc4``/3D&]jOg&ktB3r&XGm...
    #
    # A three-byte sequence turns up in compressed data by chance, so every
    # short token - /JS, /AA, /3D, /URI - carries the same exposure. The
    # cross-check is only meaningful for a token long enough that a chance
    # collision is not worth considering, so it runs at six characters and
    # up. Short tokens are still checked in the PARSED objects, which is the
    # authoritative read anyway; the raw scan exists only to catch objects
    # the parser could not reach.
    RAW_MIN = 6
    raw_text = raw.decode('latin-1', 'replace')
    for token, sev, what, why in ACTIVE:
        pat = re.compile(re.escape(token) + r'(?![A-Za-z])')
        in_obj = len(pat.findall(joined))
        if in_obj:
            findings.append((sev, 'active: %s' % token,
                             '%s x%d - %s' % (what, in_obj, why)))
        elif len(token) >= RAW_MIN and pat.search(raw_text):
            findings.append(('REVIEW', 'active?: %s' % token,
                             '%s found in the raw bytes x%d but not in any '
                             'parsed object - confirm by hand'
                             % (what, len(pat.findall(raw_text)))))

    # Every URI destination, listed unless allowlisted.
    for m in set(re.findall(r'/URI\s*\(([^)]{1,300})\)', joined)):
        host = re.sub(r'^\w+://', '', m).split('/')[0].split(':')[0]
        if host.lower() not in URI_ALLOW:
            findings.append(('REVIEW', 'external link',
                             '%s - confirm this destination is intended' % m))

    # ── disclosure ──────────────────────────────────────────────────────
    body = text_of(path)
    info['chars'] = len(body)
    for label, pat, sev, advice in DISCLOSE:
        hits = sorted(set(pat.findall(body)))
        if hits:
            shown = ', '.join(h if isinstance(h, str) else str(h)
                              for h in hits[:4])
            more = '' if len(hits) <= 4 else ' (+%d more)' % (len(hits) - 4)
            findings.append((sev, 'discloses: %s' % label,
                             '%s%s - %s' % (shown, more, advice)))

    # Metadata, judged on what would actually leak.
    #
    # The first version flagged any value containing a slash, which meant
    # every single file: these PDFs deliberately record their REPO-RELATIVE
    # source in /Subject, and "softhsm_ksp/docs/09-tests.md" is the
    # provenance a reader wants, not a disclosure. What leaks is an
    # ABSOLUTE path, an account name, a host or an address - so those are
    # what it looks for now.
    for key, value in (info.get('meta') or {}).items():
        if not value:
            continue
        leak = None
        if re.search(r'[A-Za-z]:\\|\\\\\\\\|^/(?:home|Users|root|tmp|var)/'
                     r'|/(?:home|Users)/', value):
            leak = 'an absolute path on the build machine'
        elif re.search(r'[\w.+-]+@[\w-]+\.\w+', value):
            leak = 'an email address'
        elif re.search(r'HeadlessChrome|Mozilla/|AppleWebKit', value):
            leak = ('the converter\'s user-agent string, which names the '
                    'build OS and browser build')
        if leak:
            findings.append(('REVIEW', 'metadata %s' % key,
                             '%r - %s; metadata travels with the file even '
                             'when the page does not show it' % (value, leak)))

    return findings, info


SEV_ORDER = {'CRITICAL': 0, 'WARN': 1, 'REVIEW': 2, 'INFO': 3}


def main(argv):
    strict = '--strict' in argv
    targets = [a for a in argv if not a.startswith('--')]
    if not targets:
        print(__doc__)
        return 1

    files = []
    for t in targets:
        if os.path.isdir(t):
            files += [os.path.join(t, f) for f in sorted(os.listdir(t))
                      if f.lower().endswith('.pdf')]
        elif os.path.isfile(t):
            files.append(t)
    if not files:
        print('No PDFs found in: %s' % ', '.join(targets))
        return 1

    print('=' * 74)
    print('PDF SAFETY SCAN - %d file(s)' % len(files))
    print('=' * 74)
    print(__doc__.split('READ THIS FIRST')[1].split('What it does check')[0]
          .replace(', IT IS THE MOST IMPORTANT PART OF THE FILE.\n', '')
          .strip())
    print()

    worst = 4
    totals = {'CRITICAL': 0, 'WARN': 0, 'REVIEW': 0, 'INFO': 0}

    for path in files:
        findings, info = scan_one(path)
        head = ('%-34s %s pages, %.0f kB, %s objects'
                % (os.path.basename(path), info.get('pages', '?'),
                   info['bytes'] / 1024.0, info.get('objects', '?')))
        print('-' * 74)
        print(head)
        if not [f for f in findings if f[0] != 'INFO']:
            print('  clean: no active content, nothing flagged for review')
        for sev, label, detail in sorted(findings,
                                         key=lambda f: SEV_ORDER[f[0]]):
            totals[sev] += 1
            worst = min(worst, SEV_ORDER[sev])
            print('  [%-8s] %-26s %s' % (sev, label, detail))
        meta = info.get('meta') or {}
        if meta:
            print('  metadata: %s'
                  % '; '.join('%s=%r' % (k.lstrip('/'), v)
                              for k, v in sorted(meta.items()) if v))

    print('=' * 74)
    print('TOTALS  critical %d   warn %d   review %d   info %d'
          % (totals['CRITICAL'], totals['WARN'], totals['REVIEW'],
             totals['INFO']))
    print()
    print('WHAT "CLEAN" HERE DOES AND DOES NOT MEAN')
    print("""
  It means: no object in these files asks a reader to run code, fetch a
  remote resource, open an attachment or post a form, and no pattern this
  tool knows about looks like a credential or a build path.

  It does not mean the files are safe. This tool was written by the same
  party that produced the documents, it only finds what it was taught to
  look for, and a reader vulnerability can be reached by a malformed object
  that contains none of the tokens above. Independent verification is the
  recipient's job and should stay that way.

  An independent check, roughly in order of value per minute:

    1. Scan the archive with antivirus or an EDR agent you administer, not
       one the sender chose.
    2. Structural check with a tool from a different author:
           qpdf --check file.pdf
           pdfid.py file.pdf          (Didier Stevens' PDF triage tool)
           pdf-parser.py --stats file.pdf
       qpdf and pdfid disagreeing with this report is the useful signal.
    3. Open the first one in a sandbox, a VM, or a browser's built-in
       viewer rather than a full desktop reader. Browser PDF engines run
       with far less of the attack surface that document readers carry.
    4. If your policy requires it, FLATTEN rather than trust. Re-printing
       destroys active content by discarding everything that is not marks
       on a page:
           qpdf --qdf --object-streams=disable in.pdf out.pdf
           chromium --headless --print-to-pdf=out.pdf file://in.pdf
       Flattening also drops the metadata dictionary, which is the second
       risk class above. The cost is selectable text quality and any
       bookmarks.
    5. Verify integrity against MANIFEST.txt before any of the above, so
       that what you scanned is what was sent:
           sha256sum -c  (or compare by eye against the manifest)
       Note what this does and does not give you: the manifest ships inside
       the same archive, so it proves the files were not damaged in
       transit, NOT that they came from who you think. Only a signature
       over the archive, with a key you already trust, does that.

  WHERE TO RUN IT IN A PIPELINE

    As a release gate, not a commit gate. These PDFs are built on demand
    rather than committed, so the natural place is the job that builds the
    bundle: build, scan, and refuse to publish on a non-zero exit. Run it
    with --strict there, so that a WARN is also fatal and a new finding has
    to be looked at by a person instead of being absorbed into a log.
""")

    if totals['CRITICAL']:
        return 2
    if totals['WARN'] and strict:
        return 2
    if totals['WARN'] or totals['REVIEW']:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
