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


def read(path, strict=True):
    """Read a file. Documents are strict UTF-8; a run LOG is not.

    The log is program output and can carry whatever a suite printed —
    including bytes that are not valid UTF-8. Decoding it strictly made
    this checker crash with a UnicodeDecodeError instead of reporting on
    the counts, which is a checker failing for a reason that has nothing
    to do with what it checks.
    """
    with open(path, encoding='utf-8',
              errors='strict' if strict else 'replace') as fh:
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


def from_claude_md(text):
    """Every (suites, assertions) pair CLAUDE.md states about the unit suite.

    CLAUDE.md quotes the figures twice — the repository-layout tree and the
    `make run` comment — and neither was covered when this script was
    written. Both then went stale in the very session that added the
    checker: 26 suites and 2001 assertions everywhere else, 25 and 1886 in
    those two lines.

    That is the failure mode this file exists to stop, one file to the left
    of where it was looking. A checker that covers the document somebody
    thinks of as "the test doc" and not the one everybody actually reads is
    a checker with a hole in it.

    Matched loosely on purpose — "N test suites ... N assertions" and
    "N suites, N assertions" are different phrasings of the same claim, and
    requiring one spelling would just move the hole.

    THE SESSION LOG IS SKIPPED, and that exclusion is the whole subtlety.
    "Work Completed in Prior Sessions" is a historical record: session 4
    really did end at 14 suites and 676 assertions, and session 18's entry
    quotes the 22/1816 figures it found stale. Those sentences are true
    about the past and rewriting them to match today would destroy the
    record — the same reason the "22 functions" quotations were left alone.
    The first version of this function had no such exclusion and reported
    three historical entries as drift, which would have pressured the next
    reader into falsifying history to get a green build.
    """
    start = text.find('## Work Completed in Prior Sessions')
    if start != -1:
        end = text.find('\n## ', start + 1)
        if end == -1:
            end = len(text)
        text = text[:start] + text[end:]

    pairs = []
    for m in re.finditer(r'(\d+)\s+(?:test\s+)?suites?[^.\n]{0,40}?(\d+)\s+'
                         r'assertions', text):
        pairs.append((int(m.group(1)), int(m.group(2)), m.group(0).strip()))
    return pairs


def main():
    log = read(sys.argv[1], strict=False) if len(sys.argv) > 1 else run_suite()
    suites, assertions = from_log(log)
    doc_suites, doc_assertions, doc_total, row_sum, rows = from_doc(read(DOC))

    problems = []

    # CLAUDE.md is read at the start of every session, so a stale figure
    # there is read more often than one in docs/.
    claude = os.path.join(os.path.dirname(ROOT), 'CLAUDE.md')
    if os.path.exists(claude):
        pairs = from_claude_md(read(claude))
        if not pairs:
            problems.append('CLAUDE.md no longer states the suite counts in '
                            'a recognised form -- this check has gone blind')
        for s, a, where in pairs:
            if (s, a) != (suites, assertions):
                problems.append('CLAUDE.md says "%s"; the suite ran %d suites '
                                'with %d assertions' % (where, suites,
                                                        assertions))
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
        print('the documented test counts have drifted from the unit suite:')
        for p in problems:
            print('  - %s' % p)
        return 1

    print('docs/09-tests.md and CLAUDE.md match the unit suite: %d suites, '
          '%d assertions across %d source files.'
          % (suites, assertions, rows))
    return 0


if __name__ == '__main__':
    sys.exit(main())
