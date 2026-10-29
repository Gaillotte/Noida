#!/usr/bin/env bash
# The fixtures are generated, not committed: several carry a live JavaScript
# action and one a credential-shaped string, and as binaries in git they
# would trip antivirus on checkout and add noise to secret scanning.
set -eu
python3 "$(dirname "$0")/../make_fixtures.py" . annual-report.pdf cover-letter.pdf
