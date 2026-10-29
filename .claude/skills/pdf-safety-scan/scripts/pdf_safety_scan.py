#!/usr/bin/env python3
"""Scan PDFs for active content and for information disclosure.

    pdf_safety_scan.py PATH [PATH ...] [--config FILE] [--json] [--strict]
                            [--baseline FILE] [--update-baseline]

Exit 0 clean, 1 findings to review, 2 at or above the configured fail level.

Two classes of risk, kept apart because they have different audiences:

  ACTIVE CONTENT - is this dangerous to OPEN?
      A PDF is a container. It can hold JavaScript, an action that fires on
      open, a launch of a local program, an embedded file, a form that posts
      somewhere, or a reference that turns opening a page into a network
      fetch. A report needs none of that, so for generated documents the
      expected count is zero and anything else is a finding rather than a
      judgement call.

  DISCLOSURE - is this dangerous to SEND?
      Usually the likelier accident. A PDF carries a text layer and a
      metadata dictionary, and both travel: an address, an absolute build
      path, a reviewer's comment, a converter's user-agent naming your OS.
      Worse, a PDF saved incrementally keeps its earlier revisions, so text
      someone deleted before sending can still be recoverable.

ZERO REQUIRED DEPENDENCIES, three levels of fidelity. With pypdf the object
graph is resolved and walked properly, which is the good path. With PyMuPDF
only, objects are read from the cross-reference table. With neither, only
the raw bytes are scanned and the report says so loudly - because a raw byte
search cannot see inside an object stream, which is where a modern writer
puts most of a document, so a grep for /JavaScript over the bytes can report
a clean file that is not one.

    pip install pypdf          # recommended
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys

VERSION = '1.1'

# ── Active content ──────────────────────────────────────────────────────────
#
# Each entry is a PDF name that only exists to make something happen.
# (key, severity, what it is, why a document should not have it)
ACTIVE_KEYS = [
    ('/JavaScript', 'critical', 'embedded JavaScript',
     'a document that renders text does not need a scripting engine'),
    ('/JS', 'critical', 'JavaScript action body', 'as above'),
    ('/Launch', 'critical', 'launches an external program',
     'never legitimate in a document you were sent'),
    ('/SubmitForm', 'critical', 'posts form data to a URL',
     'a report collects nothing'),
    ('/ImportData', 'critical', 'reads a local file into a form',
     'reaches outside the document for data'),
    ('/XFA', 'critical', 'XML Forms Architecture',
     'a second, scriptable document format nested inside the PDF'),
    ('/RichMedia', 'critical', 'embedded Flash or video object',
     'a long-standing source of reader vulnerabilities'),
    ('/GoToR', 'critical', 'jump into a remote document',
     'turns opening a page into a network fetch'),
    ('/GoToE', 'critical', 'jump into an embedded file', 'as above'),
    ('/Movie', 'warn', 'movie annotation', 'unexpected in a document'),
    ('/Sound', 'warn', 'sound annotation', 'unexpected in a document'),
    ('/3D', 'warn', '3D artwork stream', 'unexpected in a document'),
    ('/EmbeddedFile', 'warn', 'a file carried inside the PDF',
     'an attachment is a container for anything; confirm you expected one'),
    ('/AcroForm', 'warn', 'interactive form dictionary',
     'expected in a form, not in a report'),
    ('/SetOCGState', 'warn', 'toggles optional content groups',
     'benign alone; also how content is hidden from a reviewer'),
]

# Action subtypes that act on their own behalf when a file opens. /GoTo and
# /Named move the view; they are not in here.
AUTO_ACTIONS = {
    'JavaScript': ('critical', 'runs JavaScript'),
    'Launch': ('critical', 'launches a program'),
    'URI': ('critical', 'fetches a URL'),
    'GoToR': ('critical', 'opens a remote document'),
    'GoToE': ('critical', 'opens an embedded file'),
    'SubmitForm': ('critical', 'posts data'),
    'ImportData': ('critical', 'reads a local file'),
    'Movie': ('warn', 'plays a movie'),
    'Sound': ('warn', 'plays a sound'),
    'Rendition': ('warn', 'starts a rendition'),
    'Named': ('review', 'runs a named viewer command'),
}

# ── Disclosure ──────────────────────────────────────────────────────────────
#
# (label, pattern, severity, advice). Deliberately a little noisy: a false
# positive costs a glance, a published address costs more and is permanent.
#
# Note what is NOT here: a bare `token` or `secret` keyword. An early version
# had them and, run over documentation about a hardware security token, it
# reported CKA_TOKEN=TRUE as a leaked credential ten times over. A critical
# finding that is usually wrong teaches its reader to skip critical findings,
# which is worse than having no check. Narrow patterns, plus config for the
# rest, beats a broad pattern nobody trusts.
DISCLOSURE = [
    ('email address',
     r'\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b', 'review',
     'a recipient you intended, or an address nobody meant to publish?'),
    ('Windows user profile path',
     r'[A-Za-z]:\\+Users\\+[^\s\\/"\')]+', 'review',
     'names an account on a real machine'),
    ('UNC path',
     r'\\\\[A-Za-z0-9._-]{2,}\\+[^\s"\')]*', 'review',
     'names an internal host or share'),
    ('Unix home or root path',
     r'/(?:home|Users)/[a-z0-9._-]{2,}|/root/[^\s"\')]+', 'review',
     'names an account and a layout on a real machine'),
    ('build or scratch path',
     r'/tmp/[^\s"\')]+|/var/folders/[^\s"\')]+|\bscratchpad\b', 'review',
     'a build-machine artefact that should not be in a deliverable'),
    ('private key block',
     r'-----BEGIN [A-Z ]*PRIVATE KEY-----', 'critical',
     'key material must never appear in a document'),
    ('certificate block',
     r'-----BEGIN CERTIFICATE-----', 'review',
     'a certificate is public, but confirm it was meant to ship'),
    ('RFC1918 address',
     r'\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))'
     r'\.\d{1,3}(?:\.\d{1,3})?\b', 'review',
     'an internal address reveals network layout'),
    ('AWS access key id', r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b', 'critical',
     'a live-looking cloud credential'),
    ('private key fingerprint or long hex secret',
     r'\b[0-9a-f]{40,}\b', 'review',
     'a long hex string: a digest is fine, a key is not'),
    ('assigned credential',
     r'(?<![A-Za-z0-9_])'
     r'(?:password|passwd|passphrase|api[_-]?key|access[_-]?token'
     r'|auth[_-]?token|client[_-]?secret|bearer)'
     r'\s*[=:]\s*'
     r'(?!(?:TRUE|FALSE|NULL|None|nil|\.{2,}|\*{2,}|x{3,}|<|"?\$|%s|\{|\)))'
     r'([^\s,;)\]}]{6,})', 'critical',
     'a credential with a value beside it'),
]

METADATA_KEYS = ('/Author', '/Creator', '/Producer', '/Title', '/Subject',
                 '/Keywords', '/Company', '/Manager')

SEV = ('critical', 'warn', 'review', 'info')
SEV_RANK = {s: i for i, s in enumerate(SEV)}

DEFAULT_CONFIG = {
    'fail_on': 'critical',
    'allow_uri_hosts': [],
    'allow_emails': [],
    'allow_text': [],
    'ignore_identifier_prefixes': [],
    'extra_patterns': [],
    'expect_no_text_layer': False,
    'allow_embedded_files': False,
    'allow_incremental_updates': False,
}


# ── Config ──────────────────────────────────────────────────────────────────
def load_config(explicit, start):
    """Read pdfscan.json, from --config or by walking up from the target.

    Walking up means a repository keeps one config at its root and every
    subdirectory of PDFs inherits it, which is how people expect tool
    configuration to behave. An unreadable or malformed config is an error
    rather than a silent fallback to defaults: a scan that quietly ignores
    your tuning will either drown you in known-benign findings or, worse,
    stay silent about something you thought you had configured it to catch.
    """
    cfg = dict(DEFAULT_CONFIG)
    path = explicit
    if not path:
        d = os.path.abspath(start if os.path.isdir(start)
                            else os.path.dirname(start) or '.')
        while True:
            cand = os.path.join(d, 'pdfscan.json')
            if os.path.exists(cand):
                path = cand
                break
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    if path:
        with open(path, encoding='utf-8') as f:
            user = json.load(f)
        unknown = sorted(set(user) - set(DEFAULT_CONFIG))
        if unknown:
            raise SystemExit('%s: unknown config key(s): %s\nvalid keys: %s'
                             % (path, ', '.join(unknown),
                                ', '.join(sorted(DEFAULT_CONFIG))))
        cfg.update(user)
    if cfg['fail_on'] not in SEV:
        raise SystemExit('fail_on must be one of %s' % ', '.join(SEV))
    cfg['_path'] = path
    return cfg


def compile_disclosure(cfg):
    """Built-in patterns plus the config's, each compiled once."""
    out = []
    for label, pat, sev, advice in DISCLOSURE:
        out.append((label, re.compile(pat, re.I), sev, advice))
    for i, extra in enumerate(cfg['extra_patterns']):
        missing = {'label', 'pattern'} - set(extra)
        if missing:
            raise SystemExit('extra_patterns[%d] needs %s'
                             % (i, ', '.join(sorted(missing))))
        sev = extra.get('severity', 'review')
        if sev not in SEV:
            raise SystemExit('extra_patterns[%d].severity must be one of %s'
                             % (i, ', '.join(SEV)))
        try:
            rx = re.compile(extra['pattern'], re.I)
        except re.error as exc:
            raise SystemExit('extra_patterns[%d].pattern: %s' % (i, exc))
        out.append((extra['label'], rx, sev,
                    extra.get('advice', 'project-specific pattern')))
    return out


def allowed_text(cfg_patterns, value):
    return any(rx.search(value) for rx in cfg_patterns)


# ── Reading the file ────────────────────────────────────────────────────────
class Doc:
    """One PDF, read as well as the installed libraries allow.

    `fidelity` records which path was taken, because every finding has to be
    read in the light of how much of the file was actually visible.
    """

    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.raw = f.read()
        self.fidelity = 'raw-only'
        self.keys = {}          # PDF name -> times seen in resolved objects
        self.pages = None
        self.meta = {}
        self.text = ''
        self.uris = []
        self.auto_actions = []  # (where, subtype)
        self.annots = []        # (subtype, author)
        self.encrypted = bool(re.search(rb'/Encrypt[\s/\d]', self.raw))
        self.errors = []
        self._load()

    # Incremental updates: each save appends a revision and a new %%EOF.
    # Content "removed" in a later revision is still in the file.
    @property
    def revisions(self):
        return max(1, len(re.findall(rb'%%EOF', self.raw)))

    def _load(self):
        if self._try_pypdf():
            self.fidelity = 'pypdf'
        elif self._try_pymupdf():
            self.fidelity = 'pymupdf'

    def _try_pypdf(self):
        try:
            from pypdf import PdfReader
            from pypdf.generic import (ArrayObject, DictionaryObject,
                                       IndirectObject)
        except ImportError:
            return False
        try:
            reader = PdfReader(self.path)
            self.pages = len(reader.pages)
            md = reader.metadata or {}
            self.meta = {k: str(v) for k, v in md.items() if k in METADATA_KEYS}
            self.text = '\n'.join((p.extract_text() or '')
                                  for p in reader.pages)
        except Exception as exc:
            self.errors.append('pypdf: %s: %s' % (type(exc).__name__, exc))
            return False

        # Walk the resolved graph. pypdf follows object streams for us, so
        # this sees content a byte scan cannot, and it hands back real dicts
        # and arrays - which is what makes the /OpenAction check below exact
        # rather than a guess at a regex.
        seen = set()

        def note(name):
            self.keys[name] = self.keys.get(name, 0) + 1

        def visit(obj, where):
            if isinstance(obj, IndirectObject):
                if obj.idnum in seen:
                    return
                seen.add(obj.idnum)
                try:
                    obj = obj.get_object()
                except Exception:
                    return
            if isinstance(obj, DictionaryObject):
                for k, v in obj.items():
                    note(str(k))
                    if str(k) == '/URI':
                        try:
                            self.uris.append(str(v))
                        except Exception:
                            pass
                    visit(v, '%s%s' % (where, k))
            elif isinstance(obj, ArrayObject):
                for v in obj:
                    visit(v, where)
            # NAME VALUES COUNT TOO, and missing this would have been the
            # quiet kind of wrong. Most of the names in ACTIVE_KEYS appear
            # on the right-hand side, not the left: an attachment is
            # `/Type /EmbeddedFile`, a launch is `/S /Launch`, 3D artwork is
            # `/Subtype /RichMedia`. A walk that recorded only dictionary
            # keys would have reported those files clean while reporting the
            # few key-position names (/JS, /XFA) correctly - which is worse
            # than failing outright, because the output still looks like a
            # working scan.
            elif isinstance(obj, str) and obj.startswith('/'):
                note(str(obj))

        try:
            root = reader.trailer['/Root'].get_object()
            visit(root, '/Root')
            self._pypdf_actions(reader, root, DictionaryObject, ArrayObject)
        except Exception as exc:
            self.errors.append('walk: %s: %s' % (type(exc).__name__, exc))
        return True

    def _pypdf_actions(self, reader, root, DictionaryObject, ArrayObject):
        """Auto-fired actions and annotations, read structurally.

        /OpenAction has two legal shapes and conflating them is the mistake
        worth avoiding:

            /OpenAction [ 3 0 R /XYZ null null 0 ]      a DESTINATION array
            /OpenAction << /S /JavaScript /JS (...) >>  an ACTION dictionary

        The first says "open at the top of this page". Nearly every producer
        writes one, it cannot do anything, and treating it as a finding
        buries the second shape - the one that runs code - under noise from
        every benign file in the directory. Here the distinction is just the
        Python type, which is the advantage of resolving the graph instead of
        pattern-matching the bytes.
        """
        def classify(obj, where):
            try:
                obj = obj.get_object()
            except Exception:
                return
            if isinstance(obj, ArrayObject):
                self.auto_actions.append((where, None))      # destination
                return
            if isinstance(obj, DictionaryObject):
                sub = obj.get('/S')
                self.auto_actions.append(
                    (where, str(sub).lstrip('/') if sub else '?'))

        if '/OpenAction' in root:
            classify(root['/OpenAction'], '/OpenAction')
        if '/AA' in root:
            aa = root['/AA'].get_object()
            if isinstance(aa, DictionaryObject):
                for ev, act in aa.items():
                    classify(act, '/AA%s' % ev)

        for page in reader.pages:
            try:
                if '/AA' in page:
                    aa = page['/AA'].get_object()
                    if isinstance(aa, DictionaryObject):
                        for ev, act in aa.items():
                            classify(act, '/Page/AA%s' % ev)
                for ann in (page.get('/Annots') or []):
                    a = ann.get_object()
                    if not isinstance(a, DictionaryObject):
                        continue
                    sub = str(a.get('/Subtype', '')).lstrip('/')
                    if sub in ('Text', 'Popup', 'FreeText', 'Highlight',
                               'StrikeOut', 'Underline', 'Squiggly',
                               'Caret', 'FileAttachment'):
                        self.annots.append((sub, str(a.get('/T', '') or '')))
            except Exception:
                continue

    def _try_pymupdf(self):
        try:
            import pymupdf
        except ImportError:
            try:
                import fitz as pymupdf
            except ImportError:
                return False
        try:
            doc = pymupdf.open(self.path)
        except Exception as exc:
            self.errors.append('pymupdf: %s' % exc)
            return False
        src = []
        for x in range(1, doc.xref_length()):
            try:
                src.append(doc.xref_object(x, compressed=False))
            except Exception:
                continue
        joined = '\n'.join(src)
        for key, _, _, _ in ACTIVE_KEYS:
            n = len(re.findall(re.escape(key) + r'(?![A-Za-z])', joined))
            if n:
                self.keys[key] = n
        self.uris += re.findall(r'/URI\s*\(([^)]{1,300})\)', joined)
        for m in re.finditer(r'/OpenAction\s*', joined):
            tail = joined[m.end():m.end() + 200].lstrip()
            if tail.startswith('['):
                self.auto_actions.append(('/OpenAction', None))
            else:
                sub = re.search(r'/S\s*/(\w+)', tail[:400])
                self.auto_actions.append(
                    ('/OpenAction', sub.group(1) if sub else '?'))
        self.pages = doc.page_count
        self.text = '\n'.join(p.get_text() for p in doc)
        doc.close()
        return True


# ── The scan ────────────────────────────────────────────────────────────────
def scan(path, cfg, patterns):
    allow = [re.compile(p, re.I) for p in cfg['allow_text']]
    f = []                                         # (severity, label, detail)

    with open(path, 'rb') as fh:
        if fh.read(5) != b'%PDF-':
            return ([('critical', 'not a PDF',
                      'no %PDF- header: a file named .pdf that is not one')],
                    {'bytes': os.path.getsize(path), 'fidelity': 'none'})

    doc = Doc(path)
    info = {'bytes': len(doc.raw), 'pages': doc.pages,
            'fidelity': doc.fidelity, 'revisions': doc.revisions,
            'meta': doc.meta, 'chars': len(doc.text)}

    if doc.fidelity == 'raw-only':
        f.append(('warn', 'low fidelity',
                  'neither pypdf nor PyMuPDF is installed, so only the raw '
                  'bytes were read and anything inside an object stream was '
                  'invisible. Install pypdf before trusting a clean result'))
    for err in doc.errors:
        f.append(('review', 'parse problem', err))

    if doc.encrypted:
        f.append(('warn', 'encrypted',
                  'an encrypted PDF resists inspection; decrypt it before '
                  'trusting any scan of it, including this one'))
    if doc.pages == 0:
        f.append(('warn', 'no pages',
                  'parses but renders nothing - usually a failed conversion'))

    # Prior revisions. This is the check that catches a redaction done by
    # deleting a paragraph and saving: the old bytes are still in the file.
    if doc.revisions > 1 and not cfg['allow_incremental_updates']:
        f.append(('warn', 'incremental updates',
                  '%d revisions in one file. Content removed in a later save '
                  'may still be recoverable from an earlier one. If anything '
                  'was edited OUT before sending, re-save as a single '
                  'revision and verify' % doc.revisions))

    # ── active content ──────────────────────────────────────────────────
    for key, sev, what, why in ACTIVE_KEYS:
        if key == '/EmbeddedFile' and cfg['allow_embedded_files']:
            continue
        n = doc.keys.get(key)
        if n:
            f.append((sev, 'active %s' % key,
                      '%s, %d occurrence(s) - %s' % (what, n, why)))
            continue
        # Raw cross-check, only for tokens long enough that a chance
        # collision is not worth considering. A three-byte sequence like
        # /3D or /JS turns up inside compressed stream data by accident;
        # that false positive is real and was observed, so short names are
        # trusted to the parsed walk alone.
        if len(key) >= 6 and doc.fidelity != 'raw-only':
            rx = re.compile(re.escape(key).encode() + rb'(?![A-Za-z])')
            if rx.search(doc.raw):
                f.append(('review', 'active? %s' % key,
                          '%s appears in the raw bytes but in no resolved '
                          'object - confirm by hand' % what))
        elif len(key) >= 6 and doc.fidelity == 'raw-only':
            rx = re.compile(re.escape(key).encode() + rb'(?![A-Za-z])')
            if rx.search(doc.raw):
                f.append((sev, 'active %s' % key,
                          '%s found in the raw bytes - %s' % (what, why)))

    for where, sub in doc.auto_actions:
        if sub is None:
            f.append(('info', 'open destination',
                      '%s is a view destination, not an action - benign, and '
                      'most producers write one' % where))
            continue
        sev, what = AUTO_ACTIONS.get(
            sub, ('info', 'a view action (/%s), benign' % sub))
        f.append((sev, 'auto-action %s /%s' % (where, sub),
                  '%s when the file opens' % what))

    for uri in sorted(set(doc.uris)):
        host = re.sub(r'^\w+://', '', uri).split('/')[0].split(':')[0].lower()
        if host in [h.lower() for h in cfg['allow_uri_hosts']]:
            continue
        f.append(('review', 'external link',
                  '%s - confirm the destination is intended' % uri[:120]))

    if doc.annots:
        kinds = sorted({k for k, _ in doc.annots})
        who = sorted({a for _, a in doc.annots if a})
        f.append(('review', 'annotations',
                  '%d annotation(s) (%s)%s - review comments and markup '
                  'travel with the file and often name people'
                  % (len(doc.annots), ', '.join(kinds),
                     ' by ' + ', '.join(who[:4]) if who else '')))

    # ── disclosure ──────────────────────────────────────────────────────
    if cfg['expect_no_text_layer'] and doc.text.strip():
        f.append(('warn', 'unexpected text layer',
                  '%d characters of extractable text in a file configured to '
                  'have none. If this was meant to be a flattened image, the '
                  'original text is still readable' % len(doc.text)))

    allow_mail = [a.lower() for a in cfg['allow_emails']]
    prefixes = tuple(cfg['ignore_identifier_prefixes'])
    for label, rx, sev, advice in patterns:
        hits = []
        for m in rx.finditer(doc.text):
            hit = m.group(0)
            if allowed_text(allow, hit):
                continue
            # A hit that is really a constant from the codebase being
            # documented. `secret: NCRYPT_FOO` reads as an assigned
            # credential to any pattern and is a symbol name; a project
            # lists its own prefixes once rather than allow_text-ing each
            # occurrence. The value side is what this filters, because a
            # keyword in identifier POSITION (MYAPP_PASSWORD=x) is already
            # excluded by the lookbehind in the pattern itself.
            if prefixes:
                groups = [g for g in m.groups() if g] or [hit]
                if any(g.lstrip('\'"').startswith(prefixes) for g in groups):
                    continue
            if label == 'email address':
                low = hit.lower()
                dom = low.split('@')[-1]
                if low in allow_mail or ('*@' + dom) in allow_mail:
                    continue
            hits.append(hit)
        if hits:
            uniq = sorted(set(hits))
            more = '' if len(uniq) <= 4 else ' (+%d more)' % (len(uniq) - 4)
            f.append((sev, 'discloses %s' % label,
                      '%s%s - %s' % (', '.join(uniq[:4]), more, advice)))

    for key, value in (doc.meta or {}).items():
        if not value or allowed_text(allow, value):
            continue
        why = None
        if re.search(r'[A-Za-z]:\\|\\\\\\\\|/(?:home|Users|root|tmp|var)/',
                     value):
            why = 'an absolute path on the machine that built it'
        elif re.search(r'[\w.+-]+@[\w-]+\.\w+', value):
            why = 'an email address'
        elif re.search(r'HeadlessChrome|Mozilla/|AppleWebKit', value):
            why = ("the converter's user-agent, which names the build OS "
                   'and browser')
        if why:
            f.append(('review', 'metadata %s' % key,
                      '%r - %s; metadata travels even when the page does '
                      'not show it' % (value, why)))
    return f, info


# ── Baseline ────────────────────────────────────────────────────────────────
#
# Pointing this at an existing corpus for the first time can produce a long
# list of findings somebody has already decided are acceptable. A baseline
# records those so the next run reports only what is NEW - which is what
# makes the tool usable as a gate rather than a one-off audit.
#
# Each accepted finding is keyed to the file's SHA-256. That is the part that
# keeps a baseline honest: change the file and its acceptances expire, so
# "we looked at this and it was fine" cannot silently cover a document nobody
# has looked at since.
def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 16), b''):
            h.update(chunk)
    return h.hexdigest()


def load_baseline(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding='utf-8') as f:
        return json.load(f).get('accepted', {})


def write_baseline(path, accepted):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump({'version': VERSION,
                   'written': datetime.datetime.now(
                       datetime.timezone.utc).isoformat(timespec='seconds'),
                   'note': 'Findings accepted for these exact file digests. '
                           'Editing a file expires its acceptances.',
                   'accepted': accepted}, f, indent=2, sort_keys=True)
        f.write('\n')


CAVEAT = """\
A scan run by whoever built these files is self-certification. The tool and
the documents have the same author, and a scanner only finds what it was
taught to look for, so a clean result is a build gate - not the assurance a
recipient should rely on. Independent verification, in order of value:

  1. Antivirus or EDR that you administer, not one the sender chose.
  2. A structural check from a different author:
         qpdf --check file.pdf
         pdfid.py file.pdf          (Didier Stevens' triage tool)
     Disagreement with this report is the useful signal.
  3. Open the first one in a sandbox or a browser's viewer rather than a
     full desktop reader, which carries far more attack surface.
  4. If policy demands it, FLATTEN instead of trusting. Re-printing keeps
     only marks on a page and drops both active content and metadata:
         qpdf --qdf --object-streams=disable in.pdf out.pdf
         chromium --headless --print-to-pdf=out.pdf file://in.pdf
     The cost is selectable-text quality and bookmarks.
  5. Verify digests against a manifest BEFORE scanning, so what you scanned
     is what was sent. A manifest shipped inside the same archive proves
     transit integrity, not provenance; only a signature with a key you
     already trust does that."""


def main(argv=None):
    ap = argparse.ArgumentParser(
        description='Scan PDFs for active content and disclosure.')
    ap.add_argument('paths', nargs='+', help='PDF files or directories')
    ap.add_argument('--config', help='pdfscan.json (default: nearest one)')
    ap.add_argument('--json', action='store_true', dest='as_json',
                    help='machine-readable output for a CI gate')
    ap.add_argument('--strict', action='store_true',
                    help='fail on warn as well (same as fail_on: warn)')
    ap.add_argument('--baseline', help='accepted-findings file')
    ap.add_argument('--update-baseline', action='store_true',
                    help='record current findings as accepted and exit 0')
    ap.add_argument('--quiet', action='store_true',
                    help='findings only: no caveat, no guidance')
    args = ap.parse_args(argv)

    cfg = load_config(args.config, args.paths[0])
    if args.strict:
        cfg['fail_on'] = 'warn'
    patterns = compile_disclosure(cfg)

    files = []
    for t in args.paths:
        if os.path.isdir(t):
            for root, _, names in os.walk(t):
                files += [os.path.join(root, n) for n in sorted(names)
                          if n.lower().endswith('.pdf')]
        elif os.path.isfile(t):
            files.append(t)
        else:
            raise SystemExit('no such path: %s' % t)
    if not files:
        raise SystemExit('no PDFs found in: %s' % ', '.join(args.paths))

    baseline = load_baseline(args.baseline)
    accepted_out, results = {}, []
    totals = dict.fromkeys(SEV, 0)
    suppressed = 0

    for path in sorted(files):
        findings, info = scan(path, cfg, patterns)
        dg = digest(path)
        key = os.path.basename(path)
        was = baseline.get(key, {})
        known = set(was.get('findings', [])) if was.get('digest') == dg else set()

        kept = []
        for sev, label, detail in findings:
            if label in known:
                suppressed += 1
                continue
            kept.append((sev, label, detail))
            totals[sev] += 1
        kept.sort(key=lambda x: SEV_RANK[x[0]])

        accepted_out[key] = {'digest': dg,
                             'findings': sorted(l for _, l, _ in findings)}
        results.append({'file': path, 'digest': dg, 'info': info,
                        'findings': [{'severity': s, 'label': l,
                                      'detail': d} for s, l, d in kept]})

    fail_rank = SEV_RANK[cfg['fail_on']]
    failing = sum(n for s, n in totals.items() if SEV_RANK[s] <= fail_rank)
    reviewable = sum(n for s, n in totals.items() if s != 'info')

    if args.update_baseline:
        if not args.baseline:
            raise SystemExit('--update-baseline needs --baseline FILE')
        write_baseline(args.baseline, accepted_out)
        print('Recorded %d finding(s) across %d file(s) as accepted in %s'
              % (sum(len(v['findings']) for v in accepted_out.values()),
                 len(accepted_out), args.baseline))
        return 0

    if args.as_json:
        print(json.dumps({
            'version': VERSION, 'config': cfg.get('_path'),
            'fail_on': cfg['fail_on'], 'files': len(files),
            'totals': totals, 'suppressed_by_baseline': suppressed,
            'exit': 2 if failing else (1 if reviewable else 0),
            'results': results}, indent=2))
        return 2 if failing else (1 if reviewable else 0)

    print('=' * 74)
    print('PDF SAFETY SCAN  v%s  -  %d file(s), fidelity via %s'
          % (VERSION, len(files),
             ', '.join(sorted({r['info']['fidelity'] for r in results}))))
    if cfg.get('_path'):
        print('config: %s' % cfg['_path'])
    print('=' * 74)

    for r in results:
        print('-' * 74)
        print('%-40s %s pages, %.0f kB%s'
              % (os.path.basename(r['file']),
                 r['info'].get('pages') if r['info'].get('pages') is not None
                 else '?',
                 r['info']['bytes'] / 1024.0,
                 ', %d revisions' % r['info']['revisions']
                 if r['info'].get('revisions', 1) > 1 else ''))
        real = [x for x in r['findings'] if x['severity'] != 'info']
        if not real:
            print('  clean: no active content, nothing flagged for review')
        for x in r['findings']:
            print('  [%-8s] %-28s %s'
                  % (x['severity'], x['label'], x['detail']))

    print('=' * 74)
    print('TOTALS  ' + '   '.join('%s %d' % (s, totals[s]) for s in SEV)
          + ('   (%d suppressed by baseline)' % suppressed
             if suppressed else ''))
    print('fail_on = %s  ->  exit %d'
          % (cfg['fail_on'], 2 if failing else (1 if reviewable else 0)))
    if not args.quiet:
        print()
        print('WHAT A CLEAN RESULT DOES NOT MEAN')
        print()
        print(CAVEAT)
    return 2 if failing else (1 if reviewable else 0)


if __name__ == '__main__':
    sys.exit(main())
