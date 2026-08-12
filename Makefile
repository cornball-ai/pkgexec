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

.PHONY: all check test-digest test-request test-harden fuzz probe clean install

all: libpkgexec.a

# The non-privileged production sources, compiled hardened into a static lib —
# a compile gate (slice 1 ships no entrypoint yet).
libpkgexec.a: src/digest.c src/request.c src/harden.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(JSON_CFLAGS) $(CRYPTO_CFLAGS) -c $^
	ar rcs $@ digest.o request.o harden.o

check: test-digest test-request test-harden

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

clean:
	rm -f libpkgexec.a digest.o request.o harden.o build-test-digest \
	    build-test-request build-test-harden fuzz-request pkgexec-probe

# Slice 1 installs docs + the corpus only (no entrypoint yet), so the .deb has a
# meaningful build/install smoke while remaining incapable of mutation.
install: all
	install -D -m 0644 README.md $(DESTDIR)$(DOCDIR)/README.md
	install -D -m 0644 tests/fixtures/plan-digest/vectors.json \
	    $(DESTDIR)$(DOCDIR)/plan-digest-vectors.json
