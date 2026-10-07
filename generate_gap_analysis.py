"""Generate softhsm_ksp/docs/15-gap-analysis.md from the matrix.

Generated rather than written by hand, and that is the whole point: there
are thirty open rows, and a hand-maintained copy of thirty rows of detail
is a stale document waiting to happen. This project has paid for that
twice — a coverage figure quoted for two sessions after it stopped being
true, and CLAUDE.md stating the opposite of what the ECDSA code did.

The sources of truth are:

  docs/feature-matrix.csv     status, feature, remedy, effort
  docs/coverage_blockers.py   what class of thing blocks each open row
  docs/gap_detail.py          what works today, and what the blocker
                              rests on

All three are read here; nothing is restated. The narrative that is NOT
derived from them is the framing section, which is prose about how to read
the tables and is the one part a reader should expect a human to have
written.
"""
import csv
import os
import sys
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'softhsm_ksp', 'docs'))
from coverage_blockers import BLOCKER                       # noqa: E402
from gap_detail import GAP_DETAIL, OUT_OF_SCOPE_GAPS, validate  # noqa: E402
from matrix_fingerprint import stamp                         # noqa: E402

CSV_PATH = os.path.join(HERE, 'softhsm_ksp', 'docs', 'feature-matrix.csv')
OUT_PATH = os.path.join(HERE, 'softhsm_ksp', 'docs', '15-gap-analysis.md')

GROUPS = [
    ('Blocked: needs ncrypt_provider.h / Windows',
     'Waiting on `ncrypt_provider.h` and a Windows machine',
     'The header declares `NCRYPT_KEY_STORAGE_FUNCTION_TABLE`. A `dir /s /b` '
     'across both drives of a `windows-latest` runner returned exactly one '
     'copy — this repository\'s own test mock — and that was after a WDK '
     'install reported success. It is not in the Windows SDK. Where it does '
     'come from is still unestablished; it is associated with the '
     'Cryptographic Provider Development Kit, but that is unconfirmed and '
     'two guesses at its location were wrong. **These three rows close '
     'together, on one machine, and not before.**'),
    ('Blocked: CNG has no identifier or slot',
     'Waiting on Microsoft — CNG defines no identifier or no slot',
     '**All four of these work.** Three are verified end to end against an '
     'independent PKCS#11 token. They are open because CNG has no standard '
     'string for them, so they are reachable only from an application '
     'written against this provider by name, and cannot be BCrypt-verified '
     'end to end. Nothing in this repository can change that — the fix is a '
     'Microsoft decision.'),
    ('Blocked: no PKCS#11 mechanism',
     'Waiting on PKCS#11 — no mechanism exists to build on',
     'Each of these would need a primitive PKCS#11 does not define. Writing '
     'one anyway means inventing a facility the provider cannot actually '
     'deliver: a notification that is really a timer, an access-control '
     'model with no enforcement, a use count that is wrong under '
     'concurrency.'),
    ('Blocked: hardware / commercial',
     'Waiting on hardware, a purchase, or a validation programme',
     'None of these is an engineering task, and one is worth reading '
     'carefully: `OPS-03` is **fully tooled**. The signing script signs, '
     'timestamps and verifies, and CI signs automatically once the secret '
     'exists. What is missing is a code-signing certificate, which has to be '
     'bought by a verified legal entity.'),
    ('Deliberate position',
     'Decisions this project made — revisitable by definition',
     '**These are the only rows a reader can argue with**, and the only ones '
     'where "open" reflects a judgement rather than an obstacle. Each one\'s '
     '"rests on" has to survive a single question: *is that a fact about '
     'CNG, or a fact about our code?*'),
]


def md_escape(text):
    """Make prose safe inside a Markdown table cell.

    A pipe would end the cell. Angle brackets matter too: the detail text
    legitimately contains <ncrypt.h>, and a renderer that treats it as an
    HTML tag drops it silently — so the reader loses exactly the specific
    fact the column exists to carry.
    """
    return (text.replace('|', '\\|')
                .replace('<', '&lt;')
                .replace('>', '&gt;'))


def table(rows, cols):
    out = ['| ' + ' | '.join(c[0] for c in cols) + ' |',
           '|' + '|'.join('---' for _ in cols) + '|']
    for r in rows:
        out.append('| ' + ' | '.join(md_escape(str(c[1](r))) for c in cols)
                   + ' |')
    return out


def main():
    rows = list(csv.DictReader(open(CSV_PATH)))
    validate(rows, BLOCKER)

    open_rows = [r for r in rows if r['status'].strip() != 'Covered']
    ours = [r for r in open_rows
            if GAP_DETAIL[r['id']]['external'] is False]
    sized = [r for r in open_rows if r['effort'].strip() not in ('N/A', '')]
    startable = [r for r in sized
                 if GAP_DETAIL[r['id']]['external'] is False]
    blocked_sized = [r for r in sized
                     if GAP_DETAIL[r['id']]['external'] is True]
    covered = sum(1 for r in rows if r['status'].strip() == 'Covered')
    partial = sum(1 for r in rows if r['status'].strip() == 'Partial')
    nocov = sum(1 for r in rows if r['status'].strip() == 'Not covered')

    L = []
    w = L.append

    w('# Gap analysis')
    w('')
    w('**Generated — do not edit.** `python3 generate_gap_analysis.py`, from')
    w('`docs/feature-matrix.csv`, `docs/coverage_blockers.py` and')
    w('`docs/gap_detail.py`. Last generated %s.' % date.today().isoformat())
    w('')
    w('`%s` &mdash; of the data this was built from, so'
      % stamp(os.path.abspath(__file__)))
    w('`tests/check_generated_artifacts.py` can tell whether it is still in')
    w('step with the matrix. Regenerate if that check fails; do not edit the')
    w('stamp.')
    w('')
    w('The feature matrix answers *is it supported*, row by row. This answers')
    w('the question a reader asks next and cannot get from a status column:')
    w('**of everything still open, how much is waiting on somebody else, and')
    w('how much is a decision this project could revisit?**')
    w('')
    w('---')
    w('')
    w('## Where things stand')
    w('')
    w('%d capabilities assessed: **%d Covered · %d Partial · %d Not '
      'covered**.' % (len(rows), covered, partial, nocov))
    w('')
    w('Of the **%d open rows**, **%d are blocked outside this repository** — a'
      % (len(open_rows), len(open_rows) - len(ours)))
    w('CNG identifier Microsoft has not defined, a PKCS#11 mechanism that does')
    w('not exist, a header nobody here has, hardware, or a purchase. The')
    w('remaining **%d are decisions this project made**.' % len(ours))
    w('')
    w('Of those %d, **%d carry an effort estimate and could start today** —'
      % (len(ours), len(startable)))
    w('%s. The others have no estimate because no remedy is planned.'
      % ', '.join('`%s`' % r['id'] for r in startable))
    w('')
    w('> **The PDF reported "21 actionable gaps" until this was measured.**')
    w('> That count was any open row with a remedy and an effort other than')
    w('> N/A, a definition written before `gap_detail.py` existed. Eleven of')
    w('> the 21 were blocked outside this repository, so the most prominent')
    w('> number in the document overstated the backlog by more than twice.')
    w('> Effort answers *how big would it be*, which is not *can it start*:')
    w('> `TABLE-01` is S and needs a Windows machine. The two are now')
    w('> counted separately — **%d startable, %d sized but blocked**.'
      % (len(startable), len(blocked_sized)))
    w('')
    w('### Partial does not mean broken')
    w('')
    w('This is the most misread thing in the matrix. Most Partial rows')
    w('describe features that **work**, and several are verified against an')
    w('independent PKCS#11 token rather than against our own mock. They are')
    w('Partial because no stock Windows application can ask for them:')
    w('`EDDSA_ED25519`, `EDDSA_ED448`, `ChainingModeCTR` and `HMAC_SHA*` are')
    w('this provider\'s own identifiers, because CNG defines none. Reading the')
    w('status column alone gets that exactly backwards, which is why the')
    w('tables below carry a *What works today* column.')
    w('')
    w('### Why "deliberate position" needs a test')
    w('')
    w('Three rows were recorded as deliberate positions and have since been')
    w('closed: **`IFACE-04`** (token selection through `NCryptSetProperty`),')
    w('**`LIFE-08`** (machine/user isolation) and **`FMT-08`** (symmetric key')
    w('export). The error was identical each time — the "position" rested on')
    w('how the provider happened to work at that moment, not on anything in')
    w('CNG or PKCS#11:')
    w('')
    w('| Row | What the position rested on | Why that was not a constraint |')
    w('|---|---|---|')
    w('| `IFACE-04` | The session pool was already bound to a slot by the '
      'time a caller held a provider handle | Loading the module and calling '
      '`C_Initialize` need no token. Binding the slot lazily opened a window '
      'that had always been available |')
    w('| `LIFE-08` | Scoping was a `CKA_LABEL` prefix, and a prefix cannot '
      'isolate | PKCS#11 *does* have a boundary with a credential on it — '
      'the token. The scope can choose one instead of a prefix |')
    w('| `FMT-08` | Every key is `CKA_SENSITIVE=TRUE` / '
      '`CKA_EXTRACTABLE=FALSE` | That was a **default**, not a constraint. '
      'A policy property can relax it when, and only when, the caller asks |')
    w('')
    w('So every row below carries **what the blocker rests on**, named')
    w('specifically, and whether that thing is outside this repository. A')
    w('claim that something cannot be done has to rest on something external,')
    w('or it is a description masquerading as a constraint.')
    w('')
    w('`docs/gap_detail.py` enforces the pairing: a row classified as a')
    w('deliberate position must have `external=False` and vice versa, and')
    w('every generator that reads the module fails the build if they drift.')
    w('')
    w('---')
    w('')

    cols = [('ID', lambda r: '`%s`' % r['id']),
            ('Feature', lambda r: r['feature']),
            ('St', lambda r: 'P' if r['status'].strip() == 'Partial'
             else 'No'),
            ('Eff', lambda r: r['effort'] or '—'),
            ('What works today', lambda r: GAP_DETAIL[r['id']]['works']),
            ('What the blocker rests on',
             lambda r: GAP_DETAIL[r['id']]['rests_on'])]

    for blocker, heading, preamble in GROUPS:
        group = sorted((r for r in open_rows if BLOCKER[r['id']] == blocker),
                       key=lambda r: r['id'])
        if not group:
            continue
        w('## %s (%d)' % (heading, len(group)))
        w('')
        w(preamble)
        w('')
        L.extend(table(group, cols))
        w('')

    w('---')
    w('')
    w('## Gaps outside this matrix’s scope')
    w('')
    w('Every row above is a capability observed across shipping CNG KSPs —')
    w('the market. **A defect in this provider’s own conformance surface')
    w('is not such a capability**, so no row here would ever point at one.')
    w('')
    w('That blind spot has cost three findings: session 14’s two stubs,')
    w('found by reading the function table rather than the matrix, and the')
    w('first entry below, found by making a test repeatable. They are')
    w('recorded here rather than left in a commit message.')
    w('')
    for g in OUT_OF_SCOPE_GAPS:
        w('### %s' % g['what'])
        w('')
        w('%s' % g['detail'])
        w('')
        w('**How it was found.** %s' % g['found'])
        w('')
        w('**Status.** %s' % g['status'])
        w('')

    w('---')
    w('')
    w('## Maintaining this')
    w('')
    w('To record a gap as closed, set its row’s `status` to `Covered` and')
    w('clear its `gap_solution` in `docs/feature-matrix.csv`, then **delete')
    w('its entry from `docs/gap_detail.py`** — leaving it would keep')
    w('describing a gap that no longer exists, which is the same failure as a')
    w('stale coverage figure. Then regenerate:')
    w('')
    w('```bash')
    w('python3 generate_feature_matrix.py   # the PDF, including this analysis')
    w('python3 generate_cng_coverage_xlsx.py  # the workbook’s Open Items')
    w('python3 generate_gap_analysis.py     # this document')
    w('```')
    w('')
    w('All three call `gap_detail.validate()` first, so a row added to the')
    w('matrix without its detail, a stale entry, or a mismatch between')
    w('"deliberate position" and `external` fails the build instead of')
    w('producing an artifact with a silently blank column.')
    w('')
    w('**Forgetting to regenerate is now a CI failure.** Each artifact')
    w('embeds a fingerprint of the data it was built from, and')
    w('`tests/check_generated_artifacts.py` recomputes it. Editing the CSV')
    w('makes all three stale; editing one generator makes only its own')
    w('artifact stale. Byte-comparing a regenerated artifact against the')
    w('committed one cannot work — all three embed a generation date, and')
    w('two are binaries whose internal ordering is not stable.')

    open(OUT_PATH, 'w').write('\n'.join(L) + '\n')
    print('Wrote %s' % OUT_PATH)
    print('  %d open rows — %d outside this repository, %d our own decisions'
          % (len(open_rows), len(open_rows) - len(ours), len(ours)))
    print('  %d gaps recorded outside the matrix’s scope'
          % len(OUT_OF_SCOPE_GAPS))


if __name__ == '__main__':
    main()
