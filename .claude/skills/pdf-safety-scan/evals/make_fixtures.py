#!/usr/bin/env python3
"""Generate the eval fixture PDFs.

    python3 make_fixtures.py OUTDIR [name ...]

WHY THE FIXTURES ARE GENERATED RATHER THAN COMMITTED. Several of them carry
a real JavaScript open action, and one carries a credential-shaped string.
Committed as binaries they would trip antivirus on checkout, add noise to
secret scanning, and put opaque blobs in the history. Generated, the
interesting part is readable in the diff: you can see exactly what makes
each file a positive or a negative case, which is the whole point of a
fixture.

The JavaScript payloads are `app.alert(...)` probes - the canonical "does
script execution work" string, inert in effect. They are here so the
scanner's detection can be shown to fail safely, and nothing in this file
reaches outside the PDF it is written into.

Everything is written with the standard library so this runs anywhere.

Fixtures:
  annual-report.pdf        /OpenAction -> a JavaScript ACTION dictionary
  cover-letter.pdf         nothing at all: the negative case
  handbook.pdf             /OpenAction -> a DESTINATION array (benign)
  api-guide.pdf            a constant in credential position (false positive)
  deploy-notes.pdf         a real-looking assigned credential (true positive)
  quarterly-report.pdf     JavaScript inside a Flate-compressed object
                           stream, so the name is ABSENT from the raw bytes
  appendix.pdf             the negative case beside quarterly-report
"""
import os
import sys
import zlib


def simple(path, extra_catalog='', extra_objs=(), text='test', trailing=b''):
    """A minimal, uncompressed PDF. Every object is readable in the file."""
    objs = [
        '1 0 obj << /Type /Catalog /Pages 2 0 R %s >> endobj' % extra_catalog,
        '2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj',
        '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] '
        '/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj',
        '4 0 obj << /Length %d >> stream\nBT /F1 11 Tf 15 100 Td (%s) Tj ET\n'
        'endstream endobj'
        % (len('BT /F1 11 Tf 15 100 Td (%s) Tj ET' % text), text),
        '5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj',
    ] + list(extra_objs)

    out, offsets = '%PDF-1.7\n', []
    for o in objs:
        offsets.append(len(out))
        out += o + '\n'
    start = len(out)
    out += 'xref\n0 %d\n0000000000 65535 f \n' % (len(objs) + 1)
    for off in offsets:
        out += '%010d 00000 n \n' % off
    out += ('trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n'
            % (len(objs) + 1, start))
    with open(path, 'wb') as f:
        f.write(out.encode('latin-1') + trailing)


def object_stream_pdf(path):
    """A PDF whose catalog and JavaScript action live in an ObjStm.

    This is the fixture that makes the case for resolving the object graph
    instead of searching the bytes. Objects 1, 2, 3, 5 and 6 are packed into
    one Flate-compressed object stream, so `/JavaScript`, `/JS`,
    `/OpenAction` and the payload text appear NOWHERE in the file's raw
    bytes. grep and strings find nothing; a parser finds a critical.

    Hand-built because no convenient library forces the catalog into an
    object stream, and the demonstration only works if it is in there.
    """
    inner = {
        1: b'<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R >>',
        2: b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        3: b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] '
           b'/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
        5: b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
        6: b"<< /S /JavaScript /JS (app.alert\\('ran'\\);) >>",
    }
    pairs, body = [], b''
    for num, data in inner.items():
        pairs.append(b'%d %d' % (num, len(body)))
        body += data + b' '
    header = b' '.join(pairs) + b'\n'
    comp = zlib.compress(header + body)

    content = b'BT /F1 11 Tf 15 100 Td (quarterly report) Tj ET'
    out, offsets = b'%PDF-1.7\n', {}

    offsets[4] = len(out)
    out += (b'4 0 obj << /Length %d >> stream\n%s\nendstream endobj\n'
            % (len(content), content))

    offsets[7] = len(out)
    out += (b'7 0 obj << /Type /ObjStm /N %d /First %d /Filter /FlateDecode '
            b'/Length %d >> stream\n' % (len(inner), len(header), len(comp))
            + comp + b'\nendstream endobj\n')

    # Cross-reference STREAM, W [1 2 2]: type 1 is (offset, gen) for a
    # top-level object, type 2 is (containing ObjStm, index) for a packed
    # one. A classic xref table cannot describe packed objects at all.
    index = {n: i for i, n in enumerate(inner)}
    xref_off = len(out)
    rows = []
    for n in range(9):
        if n == 0:
            rows.append(bytes([0, 0, 0, 255, 255]))
        elif n in inner:
            rows.append(bytes([2, 0, 7, 0, index[n]]))
        elif n in offsets:
            rows.append(bytes([1, offsets[n] >> 8 & 255,
                               offsets[n] & 255, 0, 0]))
        elif n == 8:
            rows.append(bytes([1, xref_off >> 8 & 255, xref_off & 255, 0, 0]))
        else:
            rows.append(bytes([0, 0, 0, 0, 0]))
    xdata = zlib.compress(b''.join(rows))
    out += (b'8 0 obj << /Type /XRef /Size 9 /W [1 2 2] /Root 1 0 R '
            b'/Filter /FlateDecode /Length %d >> stream\n' % len(xdata)
            + xdata + b'\nendstream endobj\n')
    out += b'startxref\n%d\n%%%%EOF\n' % xref_off
    with open(path, 'wb') as f:
        f.write(out)


# An inert probe payload, not an exploit: the string every PDF reader test
# corpus uses to answer "did script execution happen".
JS_ACTION = r"/OpenAction << /S /JavaScript /JS (app.alert\(1\)) >>"

# A made-up value with no provider's key format, so it looks like a secret
# to a pattern but matches no real credential scheme and cannot be live.
FAKE_SECRET = 'client_secret: Gx8-2bQ91ZmLpT'

FIXTURES = {
    'annual-report.pdf':
        lambda p: simple(p, JS_ACTION, text='annual report'),
    'cover-letter.pdf':
        lambda p: simple(p, text='nothing interesting here'),
    'handbook.pdf':
        lambda p: simple(p, '/OpenAction [ 3 0 R /XYZ null null 0 ]',
                         text='test'),
    'api-guide.pdf':
        lambda p: simple(p, text='client_secret: NCRYPT_PIN_PROPERTY '
                                 'is read-only'),
    'deploy-notes.pdf':
        lambda p: simple(p, text=FAKE_SECRET),
    'quarterly-report.pdf': object_stream_pdf,
    'appendix.pdf':
        lambda p: simple(p, text='nothing interesting here'),
}


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    outdir, wanted = argv[0], argv[1:] or sorted(FIXTURES)
    os.makedirs(outdir, exist_ok=True)
    unknown = sorted(set(wanted) - set(FIXTURES))
    if unknown:
        raise SystemExit('unknown fixture(s): %s\navailable: %s'
                         % (', '.join(unknown), ', '.join(sorted(FIXTURES))))
    for name in wanted:
        path = os.path.join(outdir, name)
        FIXTURES[name](path)
        print('  %-24s %5d B' % (name, os.path.getsize(path)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
