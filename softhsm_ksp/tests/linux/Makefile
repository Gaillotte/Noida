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
# There are two token configurations, and the suite passes against both.
#
#   make kryoptic       the base build: no eddsa, no post-quantum.
#   make kryoptic-pqc   builds OpenSSL 3.5 from source into .openssl, then
#                       Kryoptic with eddsa and pqc against it.
#
# Both are worth running, and not only for coverage. The base build has the
# Montgomery generator and NOT the Edwards one, which is what proved the two
# are separate mechanisms rather than one with a different curve OID. The
# pqc build is the only way to reach EdDSA and ML-DSA at all. A suite that
# asserted either feature set outright would be wrong against the other, so
# every capability-dependent assertion here asks the token and checks that
# the provider agrees — the gate closed and the gate open are both answers.
#
# Why OpenSSL has to be built: Kryoptic gates eddsa on ossl320 and the
# post-quantum mechanisms on ossl350. Ubuntu Noble ships 3.0.13, so nothing
# past ECDSA and ECDH is reachable against the system library.

CC      = gcc
# -Werror=implicit-function-declaration is not a style preference. A call
# with no prototype in scope is assumed to return int, so a function
# returning a pointer has its result truncated to 32 bits — which is a
# segfault at the call site and nothing at the definition. That cost a
# debugging session here. MSVC at /W3 /WX rejects it; this makes the Linux
# build agree.
CFLAGS  = -Wall -Wextra -Werror=implicit-function-declaration \
          -Wno-unused-parameter -Wno-unused-function -g \
          -I../mock -I../../src -I../unit
LDLIBS  = -ldl -lpthread

SRC  = ../../src
LINUX_DIR := $(abspath .)

# Where Kryoptic is fetched and built. Overridable so CI can cache it.
KRYOPTIC_DIR ?= $(LINUX_DIR)/.kryoptic
KRYOPTIC_REF ?= main
KRYOPTIC_SO  ?= $(KRYOPTIC_DIR)/target/release/libkryoptic_pkcs11.so

# Features OpenSSL 3.0 can satisfy.
#
# ec_montgomery (X25519) carries no version gate, so it is in — X25519 is
# implemented and advertised by this provider and had never met a real
# token. eddsa needs ossl320 and the PQC mechanisms need ossl350, so those
# wait for the OpenSSL build in steps 2b and 2c.
#
# One line on purpose. A backslash continuation inside a make variable
# becomes a SPACE, and cargo reads the feature list as several arguments and
# refuses it. That was not caught earlier because the first Kryoptic build
# was done by hand and its .so copied into place, so `make kryoptic` had
# never actually run — the CI job would have failed on a cold cache.
KRYOPTIC_FEATURES = kryoptic-lib/sqlitedb,kryoptic-lib/rsa,kryoptic-lib/ecc_min,kryoptic-lib/ec_montgomery,kryoptic-lib/hash_all,kryoptic-lib/kdf_all,kryoptic-lib/aes,kryoptic-lib/dynamic

# The pqc build adds eddsa (needs OpenSSL 3.2) and pqc (needs 3.5).
KRYOPTIC_PQC_FEATURES = $(KRYOPTIC_FEATURES),kryoptic-lib/eddsa,kryoptic-lib/pqc

# OpenSSL built from source, only for the pqc configuration.
OPENSSL_VERSION ?= openssl-3.5.8
OPENSSL_DIR     ?= $(LINUX_DIR)/.openssl
OPENSSL_SRC     ?= $(LINUX_DIR)/.openssl-src
OPENSSL_LIB     := $(OPENSSL_DIR)/lib64

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

.PHONY: all all-pqc kryoptic kryoptic-pqc openssl token run run-twice \
        clean distclean

all: kryoptic token run-twice

# The same thing against a token that can do EdDSA and ML-DSA. Slower by
# the OpenSSL build, which is why it is a separate target.
all-pqc: kryoptic-pqc token run-twice

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

# ── OpenSSL 3.5, for the pqc configuration ────────────────────────────────
$(OPENSSL_DIR)/lib64/libcrypto.so:
	@echo "══ Building OpenSSL $(OPENSSL_VERSION) ══"
	@test -d $(OPENSSL_SRC) || \
	    git clone --depth 1 -b $(OPENSSL_VERSION) \
	        https://github.com/openssl/openssl.git $(OPENSSL_SRC)
	cd $(OPENSSL_SRC) && ./Configure \
	    --prefix=$(OPENSSL_DIR) --openssldir=$(OPENSSL_DIR)/ssl \
	    shared no-docs
	cd $(OPENSSL_SRC) && $(MAKE) -j$$(nproc) && $(MAKE) install_sw

openssl: $(OPENSSL_DIR)/lib64/libcrypto.so

# Rebuild Kryoptic against that OpenSSL, with eddsa and the post-quantum
# mechanisms. The rpath is what makes the resulting .so load OUR libcrypto
# rather than the system 3.0 — without it the module loads, reports the
# mechanisms, and fails at the first operation.
kryoptic-pqc: openssl
	@echo "══ Building Kryoptic with eddsa + pqc ══"
	@test -d $(KRYOPTIC_DIR) || \
	    git clone --depth 1 -b $(KRYOPTIC_REF) \
	        https://github.com/latchset/kryoptic.git $(KRYOPTIC_DIR)
	cd $(KRYOPTIC_DIR) && \
	    PKG_CONFIG_PATH=$(OPENSSL_LIB)/pkgconfig \
	    LD_LIBRARY_PATH=$(OPENSSL_LIB) \
	    RUSTFLAGS="-C link-arg=-Wl,-rpath,$(OPENSSL_LIB)" \
	    cargo build --release -p kryoptic \
	        --no-default-features --features $(KRYOPTIC_PQC_FEATURES)
	@test -f $(KRYOPTIC_SO) || \
	    { echo "Kryoptic built but $(KRYOPTIC_SO) is missing"; exit 1; }

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
	rm -rf $(KRYOPTIC_DIR) $(OPENSSL_DIR) $(OPENSSL_SRC)
