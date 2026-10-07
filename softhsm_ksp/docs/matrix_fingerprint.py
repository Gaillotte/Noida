# A fingerprint of the data a generated artifact was built from.
#
# The problem this solves: edit feature-matrix.csv, forget to regenerate,
# and the PDF, the workbook and 15-gap-analysis.md all go on describing a
# matrix that no longer exists. Nothing caught that. It is the same failure
# mode that produced a coverage figure quoted for two sessions after it
# stopped being true, and a CLAUDE.md passage that documented the opposite
# of what the ECDSA code did.
#
# Byte-comparing a regenerated artifact against the committed one does NOT
# work here, and it is worth saying why so nobody tries it again:
#
#   - Every artifact embeds its generation date, so regenerating on a
#     different day differs from the committed copy in a way that means
#     nothing.
#   - reportlab writes a PDF creation timestamp and an internal document ID.
#   - The xlsx is a zip; member order and timestamps are not stable.
#
# So instead of comparing outputs, each artifact carries a fingerprint of
# its INPUTS, and the check recomputes it. If the data has moved and the
# artifact has not, the fingerprints disagree and CI says which artifact to
# regenerate. Exact, cheap, and it works identically for text and binaries.
#
# The fingerprint covers the shared data files AND the one generator that
# produced that artifact. That split is deliberate: editing the CSV should
# invalidate all three artifacts, while editing the PDF's layout code should
# invalidate only the PDF. A single fingerprint over everything would make
# any cosmetic edit to one generator demand that all three be rebuilt.
import hashlib
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# Read in a fixed order — a dict's order is not a promise worth relying on
# for something whose whole job is to be reproducible.
DATA_INPUTS = (
    'feature-matrix.csv',
    'coverage_blockers.py',
    'gap_detail.py',
)

LABEL = 'Matrix fingerprint'


def fingerprint(generator_path):
    """Short hex digest of the data inputs plus one generator's source.

    The name of each file is hashed along with its bytes, so renaming an
    input is a change rather than a silent no-op.
    """
    h = hashlib.sha256()
    for name in DATA_INPUTS:
        path = os.path.join(HERE, name)
        h.update(name.encode('utf-8'))
        with open(path, 'rb') as f:
            h.update(f.read())
    gen = os.path.basename(generator_path)
    h.update(gen.encode('utf-8'))
    with open(generator_path, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()[:12]


def stamp(generator_path):
    """The line an artifact embeds, e.g. 'Matrix fingerprint: a1b2c3d4e5f6'."""
    return '%s: %s' % (LABEL, fingerprint(generator_path))
