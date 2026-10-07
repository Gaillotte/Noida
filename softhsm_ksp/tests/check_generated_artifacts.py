#!/usr/bin/env python3
"""Fail if a generated artifact is out of step with the feature matrix.

The matrix's three artifacts — the PDF, the coverage workbook and
docs/15-gap-analysis.md — are all derived from docs/feature-matrix.csv,
docs/coverage_blockers.py and docs/gap_detail.py. Nothing checked that the
committed copies still matched those inputs, so editing the CSV and
forgetting to regenerate left three documents describing a matrix that no
longer existed, with no signal at all.

That is not a hypothetical failure mode in this project. A coverage figure
was quoted for two sessions after it stopped being true, and CLAUDE.md
documented the opposite of what the ECDSA code did for six.

Each artifact embeds a fingerprint of its own inputs (see
docs/matrix_fingerprint.py for why comparing outputs byte-for-byte cannot
work). This recomputes each one and reports every artifact that disagrees,
rather than stopping at the first — if the CSV moved, all three are stale
and naming one at a time wastes a CI round trip each.

    python3 tests/check_generated_artifacts.py

Exit status 0 if every artifact is current, 1 otherwise.
"""
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # softhsm_ksp/
REPO = os.path.dirname(ROOT)
sys.path.insert(0, os.path.join(ROOT, 'docs'))

from matrix_fingerprint import LABEL, fingerprint   # noqa: E402

PATTERN = re.compile(re.escape(LABEL) + r'\s*:?\s*([0-9a-f]{12})')


def found_in_text(path):
    """Fingerprints appearing in a text file."""
    with open(path, encoding='utf-8') as f:
        return PATTERN.findall(f.read())


def found_in_pdf(path):
    """Fingerprints in a PDF's Info dictionary.

    Read from the metadata rather than the page text on purpose: page
    content streams are compressed, so a regex over the raw bytes would
    miss the visible footer, while the Info dictionary is stored plainly.
    pypdf is used when it is installed and a byte scan is the fallback, so
    this check does not become a reason to add a dependency to CI.
    """
    try:
        from pypdf import PdfReader
    except Exception:
        with open(path, 'rb') as f:
            blob = f.read()
        return PATTERN.findall(blob.decode('latin-1'))
    reader = PdfReader(path)
    meta = reader.metadata or {}
    return PATTERN.findall(' '.join(str(v) for v in meta.values()))


def found_in_xlsx(path):
    """Fingerprints in a workbook, read from the shared string table.

    An xlsx is a zip of XML. Every string a cell displays lands in
    xl/sharedStrings.xml, so scanning that one member finds the stamp
    without needing openpyxl — the same reason as the PDF: a staleness
    check should not be the thing that makes CI need a library.
    """
    out = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if name.endswith('.xml'):
                out += PATTERN.findall(z.read(name).decode('utf-8', 'replace'))
    return out


ARTIFACTS = [
    # (artifact, the generator that produced it, how to read the stamp)
    ('softhsm_ksp/docs/15-gap-analysis.md',
     'generate_gap_analysis.py', found_in_text),
    ('softhsm_ksp/SoftHSM2_KSP_Feature_Matrix.pdf',
     'generate_feature_matrix.py', found_in_pdf),
    ('softhsm_ksp/SoftHSM2_KSP_CNG_Feature_Coverage.xlsx',
     'generate_cng_coverage_xlsx.py', found_in_xlsx),
]


def main():
    stale, ok = [], []
    for rel, generator, reader in ARTIFACTS:
        artifact = os.path.join(REPO, rel)
        gen_path = os.path.join(REPO, generator)

        if not os.path.exists(artifact):
            stale.append((rel, generator, 'the artifact is missing'))
            continue
        if not os.path.exists(gen_path):
            stale.append((rel, generator, 'the generator is missing'))
            continue

        want = fingerprint(gen_path)
        try:
            got = reader(artifact)
        except Exception as exc:                      # unreadable is stale
            stale.append((rel, generator, 'could not be read: %s' % exc))
            continue

        if not got:
            # An artifact predating the stamp, or one edited by hand.
            stale.append((rel, generator,
                          'carries no %s at all' % LABEL))
        elif want not in got:
            stale.append((rel, generator,
                          'carries %s, inputs now hash to %s'
                          % (', '.join(sorted(set(got))), want)))
        else:
            ok.append((rel, want))

    for rel, fp in ok:
        print('  OK    %-52s %s' % (rel, fp))
    for rel, generator, why in stale:
        print('  STALE %-52s %s' % (rel, why))

    if stale:
        print('\n%d of %d generated artifacts are out of step with the '
              'feature matrix.' % (len(stale), len(ARTIFACTS)))
        print('Regenerate them and commit the result:\n')
        for _, generator, _ in stale:
            print('    python3 %s' % generator)
        print('\nThe fingerprint covers docs/feature-matrix.csv, '
              'docs/coverage_blockers.py, docs/gap_detail.py and each\n'
              'artifact\'s own generator — so a change to the matrix makes '
              'all three stale, while a change to\none generator makes only '
              'its own artifact stale.')
        return 1

    print('\nAll %d generated artifacts match the current feature matrix.'
          % len(ARTIFACTS))
    return 0


if __name__ == '__main__':
    sys.exit(main())
