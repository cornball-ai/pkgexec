# pkgexec build. The static lib holds the logic that is testable without root:
# schema-1 digest (OpenSSL EVP), strict stdin parser (Jansson), process hygiene,
# broker redeem client, trusted-side policy, the non-committing plan step, and
# the authenticated broker transport (SO_PEERCRED before any byte). `check`
# runs all of it sanitized, against fakes — no broker, no lock, no root. The
# libapt-linking targets (`probe`, `plan`) are diagnostics whose runtime
# behaviour is VM-gated; CI treats them as compile+link proof only.

CC ?= gcc
CXX ?= g++

DPKG_CFLAGS   := $(shell dpkg-buildflags --get CFLAGS 2>/dev/null)
DPKG_CXXFLAGS := $(shell dpkg-buildflags --get CXXFLAGS 2>/dev/null)
DPKG_CPPFLAGS := $(shell dpkg-buildflags --get CPPFLAGS 2>/dev/null)
DPKG_LDFLAGS  := $(shell dpkg-buildflags --get LDFLAGS 2>/dev/null)

WARN := -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
CPPFLAGS := -D_GNU_SOURCE $(DPKG_CPPFLAGS)
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 $(WARN) $(DPKG_CFLAGS)
LDFLAGS += $(DPKG_LDFLAGS)

JSON_CFLAGS   := $(shell pkg-config --cflags jansson 2>/dev/null)
JSON_LIBS     := $(shell pkg-config --libs jansson 2>/dev/null)
CRYPTO_CFLAGS := $(shell pkg-config --cflags libcrypto 2>/dev/null)
CRYPTO_LIBS   := $(shell pkg-config --libs libcrypto 2>/dev/null)

SAN := -fsanitize=address,undefined -g

PREFIX ?= /usr
DOCDIR ?= $(PREFIX)/share/doc/pkgexec

.PHONY: all check test-digest test-request test-harden test-exec-child \
        test-redeem test-policy test-plan test-effect test-apt-outcome \
        test-spawn test-rapt test-transport fuzz probe plan effect clean install

all: libpkgexec.a

# The non-privileged production sources, compiled hardened into a static lib —
# a compile gate (no mutation-capable entrypoint yet).
libpkgexec.a: src/digest.c src/request.c src/harden.c src/redeem.c src/policy.c \
              src/plan.c src/effect.c src/transport.c src/spawn.c src/apt_status.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) $(CRYPTO_CFLAGS) -c $^
	ar rcs $@ digest.o request.o harden.o redeem.o policy.o plan.o effect.o \
	    transport.o spawn.o apt_status.o

check: test-digest test-request test-harden test-exec-child \
       test-redeem test-policy test-plan test-effect test-apt-outcome \
       test-spawn test-rapt test-transport

# Schema-1 digest encoder vs the shared golden corpus (Jansson + libcrypto).
test-digest: src/digest.c tests/test_digest.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) $(CRYPTO_CFLAGS) $(SAN) \
	    $^ -o build-test-digest $(JSON_LIBS) $(CRYPTO_LIBS)
	./build-test-digest

# Strict stdin-request parsing (Jansson).
test-request: src/request.c tests/test_request.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) $(SAN) \
	    $^ -o build-test-request $(JSON_LIBS)
	./build-test-request

# Environment/FD hygiene + PKEXEC_UID.
test-harden: src/harden.c tests/test_harden.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(SAN) $^ -o build-test-harden
	./build-test-harden

# Exec-child isolation: receipt/env/fd do not cross a fork+exec.
test-exec-child: src/harden.c tests/test_exec_child.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(SAN) $^ -o build-test-exec-child
	./build-test-exec-child

# Broker redeem client: strict reply validation + cid equality (fake transport).
test-redeem: src/redeem.c tests/test_redeem.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) $(SAN) \
	    $^ -o build-test-redeem $(JSON_LIBS)
	./build-test-redeem

# Trusted-side policy enforcement over resolved records.
test-policy: src/policy.c tests/test_policy.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(SAN) $^ -o build-test-policy
	./build-test-policy

# Non-committing plan step: policy -> resource -> digest -> redeem (fake transport).
test-plan: src/plan.c src/policy.c src/redeem.c src/digest.c tests/test_plan.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) $(CRYPTO_CFLAGS) $(SAN) \
	    $^ -o build-test-plan $(JSON_LIBS) $(CRYPTO_LIBS)
	./build-test-plan

# Commit gate + the four per-mechanism plan variants: the committer fires iff a
# validated redeem_ok, and the gate revalidates the cid via request.c's grammar
# (fake transport + fake committer; no libapt, no broker).
test-effect: src/effect.c src/plan.c src/policy.c src/redeem.c src/digest.c \
             src/request.c tests/test_effect.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) $(CRYPTO_CFLAGS) $(SAN) \
	    $^ -o build-test-effect $(JSON_LIBS) $(CRYPTO_LIBS)
	./build-test-effect

# Post-effect truth table: pre-effect failure vs interrupted-dpkg-after-effect.
test-apt-outcome: src/apt_status.c tests/test_apt_outcome.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(SAN) $^ -o build-test-apt-outcome
	./build-test-apt-outcome

# No-shell spawn helper: exit status, full-payload delivery, SIGPIPE-safe writes.
test-spawn: src/spawn.c tests/test_spawn.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(SAN) $^ -o build-test-spawn
	./build-test-spawn

# Cross-repo drift alarm: the pinned rapt ownership predicate still matches rapt's
# source (skips where rapt is not checked out, e.g. CI).
test-rapt: tests/test_rapt.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(SAN) $^ -o build-test-rapt
	./build-test-rapt

# Authenticated broker transport: SO_PEERCRED before any byte, framing,
# absolute deadlines — against fork'd fake unix-socket servers (no root).
test-transport: src/transport.c src/redeem.c tests/test_transport.c
	$(CC) $(CPPFLAGS) -std=c11 $(WARN) $(JSON_CFLAGS) $(SAN) \
	    $^ -o build-test-transport $(JSON_LIBS)
	./build-test-transport

# Request-parser fuzzing. Requires clang (libFuzzer): make fuzz CC=clang
fuzz: fuzz/fuzz_request.c src/request.c
	$(CC) $(CPPFLAGS) -std=c11 $(JSON_CFLAGS) \
	    -fsanitize=fuzzer,address,undefined -g $^ -o fuzz-request $(JSON_LIBS)

# Read-only libapt-pkg API spike (build-order step 0). Links the C++ library
# directly; a diagnostic, NOT a production entrypoint and NOT built by
# all/check. Requires libapt-pkg-dev.
probe: tools/probe.cc
	$(CXX) $(CPPFLAGS) $(DPKG_CXXFLAGS) -std=c++17 $(WARN) $< -o pkgexec-probe \
	    $(LDFLAGS) -lapt-pkg

# Locked libapt resolve diagnostic (slice 2). The C helpers are compiled as C
# and linked with the C++ resolve via g++; runtime is VM-gated (needs root for
# the lock), so CI builds it as the linkage proof and does not run it.
plan: tools/plan.cc src/digest.c src/policy.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(CRYPTO_CFLAGS) -c src/digest.c src/policy.c
	$(CXX) $(CPPFLAGS) $(DPKG_CXXFLAGS) -std=c++17 $(WARN) tools/plan.cc \
	    digest.o policy.o -o pkgexec-plan $(LDFLAGS) -lapt-pkg $(CRYPTO_LIBS)

# Commit effectors (activation, all four mechanisms): the C core
# (parse/policy/digest/redeem/gate/transport/spawn) linked with the C++ libapt
# commit paths via g++ — A transactions (GetArchives/DoInstall), B update
# (ListUpdate), C hold/unhold and D configure (dpkg via the spawn helper). Runtime
# is VM-only (root + the real broker + the dpkg lock); CI builds this as the
# mutation-path linkage proof and does not run it. Requires libapt-pkg-dev +
# libssl-dev + libjansson-dev.
effect: tools/effect.cc src/apt_common.cc src/apt_txn.cc src/apt_update.cc \
        src/apt_hold.cc src/apt_configure.cc src/digest.c src/policy.c \
        src/plan.c src/effect.c src/redeem.c src/request.c src/transport.c \
        src/harden.c src/apt_status.c src/spawn.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) $(CRYPTO_CFLAGS) -c \
	    src/digest.c src/policy.c src/plan.c src/effect.c src/redeem.c \
	    src/request.c src/transport.c src/harden.c src/apt_status.c src/spawn.c
	$(CXX) $(CPPFLAGS) $(DPKG_CXXFLAGS) -std=c++17 $(WARN) -c \
	    src/apt_common.cc src/apt_txn.cc src/apt_update.cc src/apt_hold.cc \
	    src/apt_configure.cc
	$(CXX) $(CPPFLAGS) $(DPKG_CXXFLAGS) -std=c++17 $(WARN) -c tools/effect.cc \
	    -o effect_diag.o
	$(CXX) $(CPPFLAGS) $(DPKG_CXXFLAGS) -std=c++17 -o pkgexec-effect \
	    effect_diag.o apt_common.o apt_txn.o apt_update.o apt_hold.o \
	    apt_configure.o digest.o policy.o plan.o effect.o redeem.o request.o \
	    transport.o harden.o apt_status.o spawn.o \
	    $(LDFLAGS) -lapt-pkg $(CRYPTO_LIBS) $(JSON_LIBS)

clean:
	rm -f libpkgexec.a digest.o request.o harden.o redeem.o policy.o plan.o \
	    effect.o transport.o spawn.o apt_status.o apt_common.o apt_txn.o \
	    apt_update.o apt_hold.o apt_configure.o \
	    effect_diag.o build-test-digest build-test-request \
	    build-test-harden build-test-exec-child build-test-redeem \
	    build-test-policy build-test-plan build-test-effect \
	    build-test-apt-outcome build-test-spawn build-test-rapt \
	    build-test-transport fuzz-request pkgexec-probe pkgexec-plan \
	    pkgexec-effect

# Slice 1 installs docs + the corpus only (no entrypoint yet), so the .deb has a
# meaningful build/install smoke while remaining incapable of mutation.
install: all
	install -D -m 0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -D -m 0644 tests/fixtures/plan-digest/vectors.json \
	    $(DESTDIR)$(DOCDIR)/plan-digest-vectors.json
