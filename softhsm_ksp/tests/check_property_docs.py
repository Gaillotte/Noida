#!/usr/bin/env python3
"""The property tables in docs/05-properties.md must match the dispatch code.

Why this exists. Proposal A made NCRYPT_EXPORT_POLICY_PROPERTY writable
before FinalizeKey. It updated the prose, and it did not update either
tabular summary of the same fact:

  - docs/05-properties.md's key-property mapping table still said the value
    was "0 (non-exportable)" with Write "x" -- contradicting the prose six
    lines below it, in the same section.
  - feature-matrix.csv's PROP-05 still said "Always 0 (non-exportable)",
    and rather than that row being corrected a SECOND row was appended,
    PROP-18, describing the implemented behaviour. One capability, two
    rows, one of them false.

Four more properties had been implemented and never added to the mapping
table at all, and one row in it was fiction: "SoftHSM Slot" is a PROVIDER
property, handled in ksp_provider.c, so on a key handle it falls through to
NTE_NOT_SUPPORTED. The table had it readable and writable.

The pattern is the one this repository keeps paying for: a summary of a
fact, placed next to the fact, and not updated with it. A coverage figure
quoted for two sessions after it stopped being true; a CLAUDE.md passage
that documented the opposite of what the ECDSA code did. Prose cannot be
checked. A table of property names against a C file's dispatch chain can
be, exactly, so it is.

What is checked, for the key-property mapping table:

  membership  The documented set must EQUAL the set the code dispatches on.
              Both directions matter: a missing row is an undocumented
              property, and an extra row is a documented property that
              returns NTE_NOT_SUPPORTED -- which is worse, because a reader
              will write code against it.

  direction   The Read and Write columns must agree with which of the two
              entry points dispatches the property. A branch whose entire
              body is a refusal counts as NOT supported in that direction:
              NCRYPT_PIN_PROPERTY is dispatched by the getter purely to
              refuse to hand a credential back, and NCRYPT_AUTH_TAG_LENGTH
              is dispatched by the setter purely to refuse, being read-only.
              Treating "dispatched" as "supported" would call both of those
              supported in a direction they are not.

Provider tables are checked for membership only. Their columns do not carry
a per-direction claim -- the read table says "Implemented" and the write
table is prose -- so there is nothing to cross-check beyond the names.

LIMIT, stated rather than discovered later: the refusal test recognises a
branch whose body, with comments stripped, is exactly one assignment of a
hard error. A branch that refuses in a more roundabout way reads as
supported, and this checker will then demand a tick the author knows is
wrong. That is a loud wrong answer rather than a silent one, which is the
right way round for a drift detector, but it is not free: the fix is to
make the refusal a single statement, or to teach this function the shape.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROPS_C = os.path.join(ROOT, 'src', 'ksp', 'ksp_properties.c')
PROVIDER_C = os.path.join(ROOT, 'src', 'ksp', 'ksp_provider.c')
CONFIG_H = os.path.join(ROOT, 'src', 'common', 'config.h')
DOC = os.path.join(ROOT, 'docs', '05-properties.md')

# Headings whose FIRST following table is the one to read. Anchored on the
# heading rather than on a table index, so inserting a table elsewhere in
# the document does not silently re-point a check at it.
KEY_TABLE = '### Mapping table'
PROVIDER_READ_TABLE = '## Provider properties'
PROVIDER_WRITE_TABLE = '### Provider properties that can be written'

# Rows that are not properties. The catch-all row is part of the table's
# meaning -- it is what says the dispatch chain has a final else -- so it
# is skipped rather than removed from the document.
NOT_A_PROPERTY = ('Any other property',)

ERRORS = ('NTE_NOT_SUPPORTED', 'NTE_INVALID_PARAMETER', 'NTE_PERM')


def read(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read()


def strip_comments(text):
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    return re.sub(r'//[^\n]*', '', text)


def function_span(src, name):
    """The body of one top-level function definition.

    Ends at the next definition that starts in column 0, or at end of file.
    The alternative -- brace counting -- would have to cope with braces in
    string literals and comments for no gain, because these files put every
    definition in column 0 and the unit build would not compile them
    otherwise.
    """
    start = re.search(r'^[A-Za-z_][^\n]*\b%s\s*\(' % re.escape(name),
                      src, flags=re.M)
    if not start:
        sys.exit('check_property_docs: no definition of %s found' % name)
    rest = src[start.end():]
    nxt = re.search(r'^[A-Za-z_][\w \t*]*\b\w+\s*\(', rest, flags=re.M)
    return rest[:nxt.start()] if nxt else rest


def dispatched(src, func):
    """{property macro: True if the branch does real work} for one function.

    Several macros can share one branch -- NCRYPT_NAME_PROPERTY and
    NCRYPT_UNIQUE_NAME_PROPERTY are answered by the same code -- so matches
    are grouped by the body they guard rather than taken one at a time.
    """
    body = function_span(src, func)
    hits = [(m.start(), m.end(), m.group(1)) for m in
            re.finditer(r'_wcsicmp\(pszProperty,\s*([A-Za-z_]\w*)\)', body)]
    if not hits:
        sys.exit('check_property_docs: %s dispatches on no property' % func)

    out = {}
    for i, (_, end, ident) in enumerate(hits):
        nxt = hits[i + 1][0] if i + 1 < len(hits) else len(body)
        branch = strip_comments(body[end:nxt])
        # Cut the condition's own tail, then the "} else if (" that opens
        # the next branch, so what is left is this branch's statements.
        branch = branch.split('{', 1)[-1] if '{' in branch else branch
        branch = re.sub(r'\}\s*else(\s+if\s*\()?\s*$', '', branch.strip())
        statements = branch.strip().rstrip('}').strip()
        refusal = bool(re.fullmatch(
            r'ss\s*=\s*(%s)\s*;' % '|'.join(ERRORS), statements))
        # A shared condition leaves the earlier macro with an empty branch
        # (the text between the two _wcsicmp calls is just "== 0 ||"), so a
        # macro already recorded as doing work must not be downgraded.
        if not statements:
            continue
        out[ident] = out.get(ident, False) or not refusal
    for _, _, ident in hits:
        out.setdefault(ident, True)
    return out


def literal_aliases():
    """Provider-specific property macros, and the string each expands to.

    The document spells these as the literal a caller passes -- "SoftHSM
    Slot", "RSA Public Exponent" -- because that is what somebody reading
    it has to type. The code names the macro. Both are accepted, and the
    mapping comes from config.h rather than being written out here, so
    renaming a property is one edit.
    """
    aliases = {}
    for m in re.finditer(r'#define\s+(KSP_\w*PROPERTY)\s+L"([^"]*)"',
                         read(CONFIG_H)):
        aliases[m.group(2)] = m.group(1)
    return aliases


def table_after(doc, heading):
    lines = doc.splitlines()
    try:
        at = lines.index(heading)
    except ValueError:
        sys.exit('check_property_docs: heading %r not in %s'
                 % (heading, os.path.basename(DOC)))
    rows, seen = [], False
    for line in lines[at + 1:]:
        if line.startswith('|'):
            seen = True
            rows.append([c.strip() for c in line.strip('|').split('|')])
        elif seen:
            break
    if len(rows) < 3:
        sys.exit('check_property_docs: no table under %r' % heading)
    return rows[2:]          # drop the header and the separator


def row_property(cell, aliases):
    """The macro a table row is about, from the tokens in its first cell."""
    for tok in re.findall(r'`([^`]+)`', cell):
        tok = tok.strip().lstrip('L').strip('"')
        if re.fullmatch(r'[A-Z][A-Z0-9_]*', tok):
            return tok
        if tok in aliases:
            return aliases[tok]
    return None


def check_membership(label, documented, code, problems):
    missing = sorted(set(code) - set(documented))
    extra = sorted(set(documented) - set(code))
    if missing:
        problems.append('%s: implemented but not in the table: %s'
                        % (label, ', '.join(missing)))
    if extra:
        problems.append('%s: in the table but not dispatched -- a reader '
                        'would get NTE_NOT_SUPPORTED: %s'
                        % (label, ', '.join(extra)))


def main():
    doc = read(DOC)
    aliases = literal_aliases()
    props_c = read(PROPS_C)
    provider_c = read(PROVIDER_C)

    key_get = dispatched(props_c, 'KSP_GetKeyProperty')
    key_set = dispatched(props_c, 'KSP_SetKeyProperty')
    prov_get = dispatched(provider_c, 'KSP_GetProviderProperty')
    prov_set = dispatched(provider_c, 'KSP_SetProviderProperty')

    problems = []

    key_rows = {}
    for row in table_after(doc, KEY_TABLE):
        if row[0].startswith(NOT_A_PROPERTY):
            continue
        prop = row_property(row[0], aliases)
        if prop is None:
            problems.append('key properties: cannot tell which property '
                            'this row is about: %s' % row[0])
            continue
        if prop in key_rows:
            problems.append('key properties: %s has two rows' % prop)
        key_rows[prop] = row

    check_membership('key properties', key_rows,
                     set(key_get) | set(key_set), problems)

    for prop, row in sorted(key_rows.items()):
        if len(row) < 5:
            problems.append('key properties: %s row has %d cells, expected '
                            '5 (property, source, type, read, write)'
                            % (prop, len(row)))
            continue
        for column, name, supported in ((3, 'Read', key_get.get(prop, False)),
                                        (4, 'Write', key_set.get(prop, False))):
            claimed = '✓' in row[column]
            if claimed != supported:
                problems.append(
                    'key properties: %s is marked %s in the %s column, but '
                    'the code %s' % (prop, '✓' if claimed else 'x', name,
                                     'supports it' if supported else
                                     'does not (absent, or the branch only '
                                     'returns an error)'))

    for label, heading, code in (
            ('provider read', PROVIDER_READ_TABLE, prov_get),
            ('provider write', PROVIDER_WRITE_TABLE, prov_set)):
        documented = set()
        for row in table_after(doc, heading):
            if row[0].startswith(NOT_A_PROPERTY):
                continue
            prop = row_property(row[0], aliases)
            if prop is None:
                problems.append('%s: cannot tell which property this row is '
                                'about: %s' % (label, row[0]))
            else:
                documented.add(prop)
        check_membership(label, documented, code, problems)

    if problems:
        print('docs/05-properties.md has drifted from the dispatch code:')
        for p in problems:
            print('  - %s' % p)
        return 1

    print('docs/05-properties.md matches the dispatch code: '
          '%d key properties (%d readable, %d writable), '
          '%d provider readable, %d provider writable.'
          % (len(key_rows),
             sum(1 for v in key_get.values() if v),
             sum(1 for v in key_set.values() if v),
             sum(1 for v in prov_get.values() if v),
             sum(1 for v in prov_set.values() if v)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
