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
#   make token-two     initialise TWO tokens behind the one module
#   make two-tokens    run the token-selection suite against both
#   make scope-tokens  run the per-scope isolation suite (LIFE-08)
#   make all           all of the above
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

# A SECOND token, for the suite that proves selecting a token selects one.
#
# Its own database, its own label and — on purpose — its own user PIN. The
# different PIN is not decoration: a case that asks for token B and is given
# token A fails to log in, so the wrong selection is caught by a second,
# independent mechanism as well as by the slot number.
TOKEN2_DIR   ?= $(LINUX_DIR)/.token2
TOKEN2_CONF  := $(TOKEN2_DIR)/kryoptic.conf
TOKEN2_DB_A  := $(TOKEN2_DIR)/token-a.sql
TOKEN2_DB_B  := $(TOKEN2_DIR)/token-b.sql
TOKEN2_LAB_A ?= ksp-first
TOKEN2_LAB_B ?= ksp-second
TOKEN2_PIN_A ?= 1111
TOKEN2_PIN_B ?= 2222

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

.PHONY: all all-pqc kryoptic kryoptic-pqc openssl token token-two run \
        run-twice two-tokens scope-tokens concurrent tsan clean distclean

all: kryoptic token run-twice concurrent token-two two-tokens \
     scope-tokens

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

# ── Two tokens on one module ──────────────────────────────────────────────
#
# Kryoptic takes one [[slots]] block per token, so two blocks with two
# databases give two tokens behind a single module — which is the
# configuration the token-selection code has to be tested against and the
# single-token setup above cannot provide.
token-two: p11_init_token $(KRYOPTIC_SO)
	@echo "══ Initialising two tokens ══"
	@rm -rf $(TOKEN2_DIR)
	@mkdir -p $(TOKEN2_DIR)
	@printf '[[slots]]\nslot = 0\ndbtype = "sqlite"\ndbargs = "%s"\n\n[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "%s"\n' \
	    "$(TOKEN2_DB_A)" "$(TOKEN2_DB_B)" > $(TOKEN2_CONF)
	KRYOPTIC_CONF=$(TOKEN2_CONF) ./p11_init_token \
	    $(KRYOPTIC_SO) $(TOKEN2_LAB_A) $(SO_PIN) $(TOKEN2_PIN_A) 0
	KRYOPTIC_CONF=$(TOKEN2_CONF) ./p11_init_token \
	    $(KRYOPTIC_SO) $(TOKEN2_LAB_B) $(SO_PIN) $(TOKEN2_PIN_B) 1

test_two_tokens: test_two_tokens.c p11_real_loader.c $(PROVIDER_SRC)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LDLIBS)

# One process per case. The PKCS#11 context is a per-process singleton and
# C_Initialize is not idempotent, so a case needs a process that has never
# touched the module — which is also the state a real application starts in.
#
# Order matters. 'isolated' reads back what 'default' and 'by-label' left on
# their respective tokens, so it runs after both, and 'cleanup' checks the
# same keys from the OTHER token before deleting them — absent from one and
# present on the other is the pair of facts that distinguishes two tokens
# from one token addressed twice. 'cleanup' also makes the suite repeatable.
# Each case is given the PIN of the token it is supposed to reach.
two-tokens: test_two_tokens
	@echo "══ Token selection, against two real tokens ══"
	@set -e; \
	KRYOPTIC_CONF=$(TOKEN2_CONF) KSP_PKCS11_LIB=$(KRYOPTIC_SO) \
	  KSP_TOKEN_A=$(TOKEN2_LAB_A) KSP_TOKEN_B=$(TOKEN2_LAB_B); \
	export KRYOPTIC_CONF KSP_PKCS11_LIB KSP_TOKEN_A KSP_TOKEN_B; \
	SOFTHSM2_PIN=$(TOKEN2_PIN_A) ./test_two_tokens default; \
	SOFTHSM2_PIN=$(TOKEN2_PIN_B) ./test_two_tokens by-label; \
	SOFTHSM2_PIN=$(TOKEN2_PIN_B) ./test_two_tokens by-slot; \
	SOFTHSM2_PIN=$(TOKEN2_PIN_A) ./test_two_tokens isolated; \
	SOFTHSM2_PIN=$(TOKEN2_PIN_B) ./test_two_tokens cleanup; \
	SOFTHSM2_PIN=$(TOKEN2_PIN_A) ./test_two_tokens too-late; \
	SOFTHSM2_PIN=$(TOKEN2_PIN_B) ./test_two_tokens no-such-label; \
	SOFTHSM2_PIN=$(TOKEN2_PIN_A) ./test_two_tokens no-such-slot

# Per-scope tokens (LIFE-08): the machine and user scopes on SEPARATE
# tokens with SEPARATE PINs.
#
# The machine token is slot 0 and the user token slot 1, which is on purpose
# the opposite of the obvious assignment: if the code quietly used the
# default slot for one of the scopes, putting the user scope on slot 0 would
# hide it. Here that mistake lands on the wrong token and is caught.
#
# 'scope-no-machine-pin' runs with KSP_MACHINE_PIN deliberately ABSENT.
# That is the case separating isolation from namespacing: without the
# machine credential the machine token cannot be opened at all, where a
# label prefix in one token would have been readable with the one PIN. The
# fallback PIN is given as the user PIN, so the machine token is reached
# with the wrong credential rather than with none — a provider that ignored
# the per-scope PIN would log in successfully and this case would pass.
scope-tokens: test_two_tokens
	@echo "══ Per-scope tokens: isolation by token boundary ══"
	@set -e; \
	export KRYOPTIC_CONF=$(TOKEN2_CONF); \
	export KSP_PKCS11_LIB=$(KRYOPTIC_SO); \
	export KSP_TOKEN_A=$(TOKEN2_LAB_A) KSP_TOKEN_B=$(TOKEN2_LAB_B); \
	export KSP_MACHINE_TOKEN_LABEL=$(TOKEN2_LAB_A); \
	export KSP_USER_TOKEN_LABEL=$(TOKEN2_LAB_B); \
	export KSP_MACHINE_PIN=$(TOKEN2_PIN_A) KSP_USER_PIN=$(TOKEN2_PIN_B); \
	./test_two_tokens scope-setup; \
	./test_two_tokens scope-isolated; \
	unset KSP_MACHINE_PIN; SOFTHSM2_PIN=$(TOKEN2_PIN_B) \
	    ./test_two_tokens scope-no-machine-pin; \
	export KSP_MACHINE_PIN=$(TOKEN2_PIN_A); \
	./test_two_tokens scope-cleanup
	@echo ""
	@echo "══ Misconfiguration must fail closed, not half-apply ══"
	@set -e; \
	export KRYOPTIC_CONF=$(TOKEN2_CONF); \
	export KSP_PKCS11_LIB=$(KRYOPTIC_SO); \
	export SOFTHSM2_PIN=$(TOKEN2_PIN_A); \
	KSP_MACHINE_TOKEN_LABEL=$(TOKEN2_LAB_A) \
	    ./test_two_tokens scope-half-configured; \
	KSP_MACHINE_SLOT=1 \
	    ./test_two_tokens scope-half-configured; \
	KSP_MACHINE_TOKEN_LABEL=$(TOKEN2_LAB_A) \
	KSP_USER_TOKEN_LABEL=$(TOKEN2_LAB_A) \
	    ./test_two_tokens scope-same-token

# ── The provider, against that token ──────────────────────────────────────
test_real_backend: test_real_backend.c p11_real_loader.c real_cert.c $(PROVIDER_SRC)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LDLIBS)

# ── Concurrency ───────────────────────────────────────────────────────────
#
# Separate binary, not another suite in test_real_backend, because it has
# to be built twice: once plain and once under ThreadSanitizer. The two
# answer different questions. TSan reports a race whether or not it
# corrupted anything on this particular run — races are timing-dependent
# and a clean run proves very little on its own. The value comparisons
# report corruption whether or not TSan happened to observe the race that
# caused it. Neither subsumes the other.
test_concurrent: test_concurrent.c p11_real_loader.c $(PROVIDER_SRC)
	$(CC) $(CFLAGS) -o $@ $(filter %.c,$^) $(LDLIBS)

test_concurrent_tsan: test_concurrent.c p11_real_loader.c $(PROVIDER_SRC)
	$(CC) $(CFLAGS) -fsanitize=thread -O1 -o $@ $(filter %.c,$^) $(LDLIBS)

concurrent: test_concurrent
	@echo "══ Concurrency against the token ══"
	KRYOPTIC_CONF=$(TOKEN_CONF) \
	KSP_PKCS11_LIB=$(KRYOPTIC_SO) \
	SOFTHSM2_PIN=$(USER_PIN) \
	    ./test_concurrent

tsan: test_concurrent_tsan
	@echo "══ Concurrency under ThreadSanitizer ══"
	KRYOPTIC_CONF=$(TOKEN_CONF) \
	KSP_PKCS11_LIB=$(KRYOPTIC_SO) \
	SOFTHSM2_PIN=$(USER_PIN) \
	TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1 suppressions=$(LINUX_DIR)/tsan.supp" \
	    ./test_concurrent_tsan

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
	rm -f test_real_backend test_concurrent test_concurrent_tsan \
	      test_two_tokens p11_init_token
	rm -rf $(TOKEN_DIR) $(TOKEN2_DIR)

# Leaves the Kryoptic checkout alone by default: re-cloning and rebuilding
# it is the slow part, and it is what a CI cache holds.
distclean: clean
	rm -rf $(KRYOPTIC_DIR) $(OPENSSL_DIR) $(OPENSSL_SRC)
