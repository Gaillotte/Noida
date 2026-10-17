#!/usr/bin/env python3
"""The test counts in docs/09-tests.md must match what the suite reports.

Why this exists. docs/09-tests.md's pyramid diagram said "22 test suites
1816 assertions" while the suite ran 25 binaries and reported 1886. Four
rows of its per-suite table were behind -- test_p11_session by 6,
test_ksp_key_ops by 19, test_ksp_key_props by 20 -- and test_rsa_lengths.c,
added three sessions earlier and built three times over, was missing
altogether. The 70-assertion gap accounted for exactly those four.

A figure nobody recomputes is a figure that stops being true, and this
repository has a long record of it: a coverage percentage quoted for two
sessions after it changed, a CLAUDE.md passage that documented the opposite
of what the ECDSA code did, and a feature matrix that counted one
capability twice. Those were all found by somebody happening to look.

What is checked:

  totals     The assertion total in the pyramid, the Total row of the
             per-suite table, and the sum the suite actually reports must
             all three be the same number.

  arithmetic The per-suite rows must sum to the Total row. This is what
             makes the individual rows self-verifying without this script
             having to map suite titles onto file names: a single wrong row
             breaks the sum. Two compensating errors would survive, which
             is a real hole and a small one.

  suites     The suite count in the pyramid must equal the number of
             binaries the runner reports.

NOTE on suites vs rows: the table has one row per SOURCE file and the
runner counts BINARIES, and those differ -- test_rsa_lengths.c is built
three times with different RSA floors, because what it checks is how the
reported default moves when the floor moves, and a floor is a compile-time
macro. So the row count is deliberately not compared against the suite
count; only the assertion arithmetic is.

Usage:
    python3 tests/check_test_counts.py [run-log]

With no argument it runs the suite itself, which takes a minute or two.
In CI the log from the existing unit-test step is passed in, so this costs
nothing and cannot disagree with the run that actually gated the build.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOC = os.path.join(ROOT, 'docs', '09-tests.md')
UNIT = os.path.join(HERE, 'unit')


def read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def run_suite():
    proc = subprocess.run(['make', '-s', 'run'], cwd=UNIT,
                          capture_output=True, text=True)
    return proc.stdout + proc.stderr


def from_log(log):
    """(suites, assertions) as the runner itself reports them."""
    per_suite = [int(m.group(1)) for m in
                 re.finditer(r'TOTAL\s*:\s*(\d+)\s+tests', log)]
    if not per_suite:
        sys.exit('check_test_counts: no suite totals in the run log -- was '
                 'the suite actually run? (make run, from tests/unit)')
    summary = re.search(r'Results:\s*PASS=(\d+)\s+FAIL=(\d+)', log)
    if not summary:
        sys.exit('check_test_counts: the run log has no final Results line')
    suites = int(summary.group(1)) + int(summary.group(2))
    if suites != len(per_suite):
        # Not pedantry: a suite that crashes before printing its total is
        # counted by the runner and absent here, and the difference is the
        # only sign of it.
        sys.exit('check_test_counts: the runner counted %d suites but %d '
                 'printed a total -- one ended early' % (suites,
                                                         len(per_suite)))
    return suites, sum(per_suite)


def from_doc(doc):
    """(suites, assertions, per-row sum) as docs/09-tests.md claims them."""
    pyramid = re.search(r'(\d+)\s+test suites\s*·\s*(\d+)\s+assertions', doc)
    if not pyramid:
        sys.exit('check_test_counts: the pyramid diagram in %s no longer '
                 'states "N test suites - N assertions"'
                 % os.path.basename(DOC))
    total = re.search(r'\|\s*\*\*Total\*\*\s*\|[^|]*\|\s*\*\*(\d+)\*\*',
                      doc)
    if not total:
        sys.exit('check_test_counts: no "**Total**" row in the per-suite '
                 'table')
    rows = [int(m.group(1)) for m in
            re.finditer(r'^\|[^|]*\|\s*`test_\w+\.c`\s*\|\s*(\d+)\s*\|',
                        doc, flags=re.M)]
    if not rows:
        sys.exit('check_test_counts: the per-suite table has no rows naming '
                 'a test_*.c file')
    return (int(pyramid.group(1)), int(pyramid.group(2)),
            int(total.group(1)), sum(rows), len(rows))


def main():
    log = read(sys.argv[1]) if len(sys.argv) > 1 else run_suite()
    suites, assertions = from_log(log)
    doc_suites, doc_assertions, doc_total, row_sum, rows = from_doc(read(DOC))

    problems = []
    if doc_suites != suites:
        problems.append('the pyramid says %d test suites; the runner ran %d'
                        % (doc_suites, suites))
    if doc_assertions != assertions:
        problems.append('the pyramid says %d assertions; the suite reported '
                        '%d' % (doc_assertions, assertions))
    if doc_total != assertions:
        problems.append('the table\'s Total row says %d; the suite reported '
                        '%d' % (doc_total, assertions))
    if row_sum != doc_total:
        problems.append('the %d per-suite rows sum to %d, but the Total row '
                        'says %d -- a row is out of date'
                        % (rows, row_sum, doc_total))

    if problems:
        print('docs/09-tests.md has drifted from the unit suite:')
        for p in problems:
            print('  - %s' % p)
        return 1

    print('docs/09-tests.md matches the unit suite: %d suites, %d assertions '
          'across %d source files.' % (suites, assertions, rows))
    return 0


if __name__ == '__main__':
    sys.exit(main())
