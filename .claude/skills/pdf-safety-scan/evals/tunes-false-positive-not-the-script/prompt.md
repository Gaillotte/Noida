---
tags: [pdf-safety-scan]
max_turns: 30
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit, Bash]
---

Check these two PDFs before we publish them on the docs site. Heads up: our
API guide quotes a lot of our own constant names, which all start with
MYAPP_, and a previous tool we tried kept screaming about those. I don't want
to keep hand-waving findings away every release, so set it up properly.

Input files: api-guide.pdf, deploy-notes.pdf
