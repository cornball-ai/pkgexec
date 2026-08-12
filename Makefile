# pkgexec build. Slice 1 is incapable of mutation: it builds the schema-1
# plan-digest encoder (OpenSSL EVP), the strict stdin request parser (system
# Jansson), and process-hygiene primitives, plus their sanitized tests. There is
# no privileged entrypoint, no lock, and no libapt in the built product yet; the
# read-only `probe` target is an explicit spike, not built by `all`/`check`.

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
        test-redeem test-policy test-plan fuzz probe plan clean install

all: libpkgexec.a

# The non-privileged production sources, compiled hardened into a static lib —
# a compile gate (no mutation-capable entrypoint yet).
libpkgexec.a: src/digest.c src/request.c src/harden.c src/redeem.c src/policy.c \
              src/plan.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) $(CRYPTO_CFLAGS) -c $^
	ar rcs $@ digest.o request.o harden.o redeem.o policy.o plan.o

check: test-digest test-request test-harden test-exec-child \
       test-redeem test-policy test-plan

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

clean:
	rm -f libpkgexec.a digest.o request.o harden.o redeem.o policy.o plan.o \
	    build-test-digest build-test-request build-test-harden \
	    build-test-exec-child build-test-redeem build-test-policy \
	    build-test-plan fuzz-request pkgexec-probe pkgexec-plan

# Slice 1 installs docs + the corpus only (no entrypoint yet), so the .deb has a
# meaningful build/install smoke while remaining incapable of mutation.
install: all
	install -D -m 0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -D -m 0644 tests/fixtures/plan-digest/vectors.json \
	    $(DESTDIR)$(DOCDIR)/plan-digest-vectors.json
