# Makefile — convenience wrapper.
# The real build rules live in ../Makefile.linux; this lets you run
# `make` (and `make run`, `make coverage`, `make clean`) from tests/unit/.
MAKEFLAGS += --no-print-directory

.PHONY: all run coverage clean syntax-check FORCE
all run coverage clean syntax-check:
	@$(MAKE) -f ../Makefile.linux $@

# Anything else — a single test binary's name, which is what you reach for
# when fault-injecting one suite — is delegated too.
#
# The FORCE prerequisite is not decoration. Without it, `make
# test_p11_context` matched GNU make's implicit rules against the existing
# binary, answered "up to date" and rebuilt NOTHING. A fault injection then
# ran against a stale binary and looked undetected, which is the most
# dangerous possible outcome for a tool whose only job is to show that a
# test can fail. A match-anything pattern rule does not fix it either: make
# declines to apply one to a target that already exists as a file.
%: FORCE
	@$(MAKE) -f ../Makefile.linux $@

FORCE:
