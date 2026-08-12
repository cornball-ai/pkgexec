/* libFuzzer harness over the strict stdin-request parser — the untrusted-input
 * surface. Build with clang: `make fuzz CC=clang`, then e.g.
 *   ./fuzz-request -runs=200000 -max_total_time=30
 * The verb is fixed (a compile-time constant, as in a real entrypoint); the
 * fuzzer drives the request body. */
#include "../src/request.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pkgx_request req;
    const char *errcode = NULL;
    if (pkgx_parse_request("apt.install", (const char *) data, size, &req,
                           &errcode) == 0) {
        pkgx_request_free(&req);
    }
    return 0;
}
