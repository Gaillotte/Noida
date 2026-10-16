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

# This module hashes itself into every digest.
#
# Without it there is a hole in the middle of the mechanism: change how the
# digest is computed and every stored digest becomes meaningless while the
# checker goes on comparing them. In practice the LABEL rename would have
# been caught anyway, because the regex stops matching — but "caught by
# accident through a different check" is not the same as covered, and this
# is a staleness detector, so a blind spot in it is worse than elsewhere.
SELF = os.path.join(HERE, os.path.basename(__file__))

# Not "Matrix fingerprint" any more: the ADCS plan is derived from a markdown
# file, not from the matrix, and a stamp that says Matrix on it would be a
# small untruth printed on a document — the exact genre of error this
# repository keeps paying for.
LABEL = 'Content fingerprint'


def fingerprint_for(generator_path, inputs):
    """Short hex digest of an explicit input set plus one generator's source.

    `inputs` are absolute paths, hashed in the order given, each with its
    base name so that renaming an input is a change rather than a silent
    no-op. The order is the caller's and must stay stable: a set or a dict's
    iteration order would make the digest depend on something that is not
    the content.

    Generalised from the matrix-only version when the ADCS plan became the
    fourth generated artifact. Its input is one markdown file rather than
    the three matrix data files, and the alternative — a second, nearly
    identical hashing function — is how two copies of a subtle thing drift
    apart. That has already happened once in this repository, to a
    counted-string length check.
    """
    h = hashlib.sha256()
    for path in (SELF,) + tuple(inputs):
        h.update(os.path.basename(path).encode('utf-8'))
        with open(path, 'rb') as f:
            h.update(f.read())
    gen = os.path.basename(generator_path)
    h.update(gen.encode('utf-8'))
    with open(generator_path, 'rb') as f:
        h.update(f.read())
    return h.hexdigest()[:12]


def matrix_inputs():
    """The three files every matrix-derived artifact is built from."""
    return tuple(os.path.join(HERE, name) for name in DATA_INPUTS)


def fingerprint(generator_path):
    """Digest over the matrix data inputs plus one generator's source."""
    return fingerprint_for(generator_path, matrix_inputs())


def stamp(generator_path):
    """The line an artifact embeds, e.g. 'Matrix fingerprint: a1b2c3d4e5f6'."""
    return '%s: %s' % (LABEL, fingerprint(generator_path))


def stamp_for(generator_path, inputs):
    """As `stamp`, over an explicit input set."""
    return '%s: %s' % (LABEL, fingerprint_for(generator_path, inputs))
