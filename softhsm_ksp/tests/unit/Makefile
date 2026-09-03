# Makefile — convenience wrapper.
# The real build rules live in ../Makefile.linux; this lets you run
# `make` (and `make run`, `make coverage`, `make clean`) from tests/unit/.
MAKEFLAGS += --no-print-directory

.PHONY: all run coverage clean
all run coverage clean:
	@$(MAKE) -f ../Makefile.linux $@
