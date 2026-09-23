# Makefile — run the provider against a real PKCS#11 module on Linux.
#
# Separate from tests/unit because the question is different. The unit
# suites pin down the provider's logic against a mock; this one asks whether
# the provider works against a module nobody here wrote, which is the claim
# the backend-portability architecture rests on and which a mock cannot
# answer.
#
#   make kryoptic      fetch and build Kryoptic (a PKCS#11 token in Rust)
#   make token         initialise a token in it
#   make run           run the provider against that token
#   make run-twice     run it twice against the SAME token — see below
#   make all           all four
#
# Kryoptic is built WITHOUT eddsa and WITHOUT the post-quantum mechanisms.
# That is deliberate: its mechanism list must differ from SoftHSM2's, or the
# test cannot tell a probe that read the token from one that replayed a list
# compiled into the provider.
#
# The post-quantum features additionally need OpenSSL 3.5+, which Ubuntu
# Noble does not ship. Reaching ML-DSA end to end means building OpenSSL
# from source — a separate piece of work, deliberately not attempted here.

CC      = gcc
CFLAGS  = -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -g \
          -I../mock -I../../src -I../unit
LDLIBS  = -ldl -lpthread

SRC  = ../../src
LINUX_DIR := $(abspath .)

# Where Kryoptic is fetched and built. Overridable so CI can cache it.
KRYOPTIC_DIR ?= $(LINUX_DIR)/.kryoptic
KRYOPTIC_REF ?= main
KRYOPTIC_SO  ?= $(KRYOPTIC_DIR)/target/release/libkryoptic_pkcs11.so

# Features OpenSSL 3.0 can satisfy. eddsa needs ossl320 and the PQC
# mechanisms need ossl350, so both are left out.
KRYOPTIC_FEATURES = kryoptic-lib/sqlitedb,kryoptic-lib/rsa,\
kryoptic-lib/ecc_min,kryoptic-lib/hash_all,kryoptic-lib/kdf_all,\
kryoptic-lib/aes,kryoptic-lib/dynamic

TOKEN_DIR   ?= $(LINUX_DIR)/.token
TOKEN_CONF  := $(TOKEN_DIR)/kryoptic.conf
TOKEN_DB    := $(TOKEN_DIR)/token.sql
TOKEN_LABEL ?= ksp-phase7
SO_PIN      ?= 12345678
USER_PIN    ?= 1234

PROVIDER_SRC = \
    $(SRC)/pkcs11/p11_context.c \
    $(SRC)/pkcs11/p11_caps.c \
    $(SRC)/pkcs11/p11_session.c \
    $(SRC)/pkcs11/p11_utils.c \
    $(SRC)/ksp/ksp_provider.c \
    $(SRC)/ksp/ksp_key.c \
    $(SRC)/ksp/ksp_crypto.c \
    $(SRC)/ksp/ksp_properties.c \
    $(SRC)/common/logging.c \
    $(SRC)/common/memory.c

.PHONY: all kryoptic token run clean distclean

all: kryoptic token run-twice

# ── Kryoptic ──────────────────────────────────────────────────────────────
$(KRYOPTIC_SO):
	@echo "══ Fetching and building Kryoptic ══"
	@test -d $(KRYOPTIC_DIR) || \
	    git clone --depth 1 -b $(KRYOPTIC_REF) \
	        https://github.com/latchset/kryoptic.git $(KRYOPTIC_DIR)
	cd $(KRYOPTIC_DIR) && cargo build --release -p kryoptic \
	    --no-default-features --features $(KRYOPTIC_FEATURES)
	@test -f $(KRYOPTIC_SO) || \
	    { echo "Kryoptic built but $(KRYOPTIC_SO) is missing"; exit 1; }

kryoptic: $(KRYOPTIC_SO)

# ── Token ─────────────────────────────────────────────────────────────────
p11_init_token: p11_init_token.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

token: p11_init_token $(KRYOPTIC_SO)
	@echo "══ Initialising a token ══"
	@rm -rf $(TOKEN_DIR)
	@mkdir -p $(TOKEN_DIR)
	@printf '[[slots]]\nslot = 0\ndbtype = "sqlite"\ndbargs = "%s"\n' \
	    "$(TOKEN_DB)" > $(TOKEN_CONF)
	KRYOPTIC_CONF=$(TOKEN_CONF) \
	    ./p11_init_token $(KRYOPTIC_SO) $(TOKEN_LABEL) $(SO_PIN) $(USER_PIN)

# ── The provider, against that token ──────────────────────────────────────
test_real_backend: test_real_backend.c p11_real_loader.c real_cert.c $(PROVIDER_SRC)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LDLIBS)

run: test_real_backend
	@echo "══ Running the provider against Kryoptic ══"
	KRYOPTIC_CONF=$(TOKEN_CONF) \
	KSP_PKCS11_LIB=$(KRYOPTIC_SO) \
	SOFTHSM2_PIN=$(USER_PIN) \
	    ./test_real_backend

# Run twice against the same token, without re-initialising between.
#
# This is not belt and braces. A whole class of defect is invisible to a
# single pass: anything the provider leaves behind on the token. The
# orphaned-certificate bug — KSP_DeleteKey destroying the key and not the
# CKO_CERTIFICATE beside it — was found exactly this way, by a second run
# reading back what the first had left. A single run passed it happily.
#
# The second pass costs a few seconds and makes "the token is as clean as we
# found it" an enforced property rather than a hope.
run-twice: test_real_backend
	@echo "══ Pass 1 of 2 ══"
	@$(MAKE) --no-print-directory run
	@echo ""
	@echo "══ Pass 2 of 2 — same token, nothing re-initialised ══"
	@echo "   (a failure here means the first pass left state behind)"
	@$(MAKE) --no-print-directory run

clean:
	rm -f test_real_backend p11_init_token
	rm -rf $(TOKEN_DIR)

# Leaves the Kryoptic checkout alone by default: re-cloning and rebuilding
# it is the slow part, and it is what a CI cache holds.
distclean: clean
	rm -rf $(KRYOPTIC_DIR)
