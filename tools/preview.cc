/* runix-apt-preview: the unprivileged, read-only production planner for the
 * pkgops issuer. It reads a receipt-free request on stdin
 *   {"schema_version":1,"verb":"apt.install","packages":["nginx"]}
 * opens the package cache READ-ONLY (no lock), maps the current state to the
 * digest's record model through the SAME shared apt_common builders + policy +
 * digest the effectors use, and emits ONE newline-terminated JSON object on
 * stdout describing the plan and its schema-1 plan_hash. It mutates nothing:
 * no lock, no dpkg, no fetch, no shell, no receipt.
 *
 * It is an ORACLE, not an authority (pkgops-plan.md): its preview is advisory.
 * The locked pkgexec re-resolution at redeem remains authoritative; if the cache
 * shifts between preview and redeem the hashes differ and redemption fails closed
 * (no_intent), so a stale preview can never cause an unintended effect.
 *
 * What is SHARED with the effectors is the invariant that matters: the descriptor
 * construction (apt_common `pkgx_apt_map_*`), the policy, and the schema-1 digest.
 * A matching cache therefore yields the matching hash, so pkgops can drive a real
 * receipt from this hash. What is deliberately NOT shared is the transaction
 * RESOLVE: the lockless preview and the locked committer run in intentionally
 * different contexts, so each keeps its own resolve (this file mirrors apt_txn.cc
 * byte-for-byte in intent). Resolver drift is not a shared-code hazard here; it is
 * caught at receipt redemption and fails closed, so duplicating it costs nothing
 * the redeem gate does not already guarantee.
 *
 * Result contract (one uniform shape for every outcome; unavailable fields are
 * JSON null, but packages and records are always arrays):
 *   {"schema_version":1,"status":"ok","verb":"apt.install","packages":["nginx"],
 *    "plan_schema":1,"resource":"nginx","plan_hash":"<64 hex>","records":[...],
 *    "detail":null}
 * plan_schema/plan_hash are present exactly when a digest was computed (status ok
 * and the three policy refusals, which carry the full resolved records + hash +
 * offending package in detail). resource is present once the request parses.
 * Closed statuses: ok, no_op, schema_invalid, resolve_failed, package_not_owned,
 * held, protected_package, dpkg_broken, internal. Exit 0 iff ok or no_op.
 *
 * records mirror the hash input directly: they are decoded from the canonical
 * digest byte string the digest module returns, so they are automatically in
 * canonical (bytewise-sorted) digest order with flags/components sorted-unique and
 * update options limited to the digest's known keys — no second ordering or
 * enumeration implementation to drift from the hash.
 *
 * libapt diagnostics go to stderr only; stdout carries exactly the one JSON line.
 *
 *   make preview                                 # compile + link (the CI gate)
 *   echo '{"schema_version":1,"verb":"apt.install","packages":["nginx"]}' \
 *       | ./runix-apt-preview                    # unprivileged; read-only cache
 */
#include "../src/apt_common.hh" /* the shared apt_common descriptor builders */
#include "../src/digest.h"
#include "../src/policy.h"
#include "../src/request.h"

#include <apt-pkg/algorithms.h>
#include <apt-pkg/cachefile.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/depcache.h>
#include <apt-pkg/error.h>
#include <apt-pkg/init.h>
#include <apt-pkg/pkgcache.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/upgrade.h>

#include <jansson.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

namespace {

/* Byte separators of the canonical digest grammar (digest.h), reused here only to
 * DECODE the bytes the digest already produced — never to re-encode a plan. */
constexpr char RS = 0x1e; /* record separator */
constexpr char US = 0x1f; /* field separator */

/* Last-resort output when Jansson assembly itself fails: still one JSON line in
 * the uniform shape, so a reader never sees a truncated object. */
constexpr const char *FALLBACK =
    "{\"schema_version\":1,\"status\":\"internal\",\"verb\":null,\"packages\":[],"
    "\"plan_schema\":null,\"resource\":null,\"plan_hash\":null,\"records\":[],"
    "\"detail\":\"emit\"}\n";

/* ---- record decode from the canonical digest bytes -------------------- */

enum RecKind { REC_TXN, REC_CFG, REC_HOLD, REC_SRC };

/* Split on a single-byte delimiter. An empty input yields an empty vector (an
 * empty comma-list is zero elements); a trailing delimiter yields a trailing
 * empty element (so an empty final field is preserved). */
std::vector<std::string> split_on(const std::string &s, char d) {
    std::vector<std::string> out;
    if (s.empty()) {
        return out;
    }
    size_t start = 0;
    for (size_t i = 0; i <= s.size(); i++) {
        if (i == s.size() || s[i] == d) {
            out.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    return out;
}

std::string fld(const std::vector<std::string> &f, size_t i) {
    return i < f.size() ? f[i] : std::string(); /* well-formed canon never misses */
}

/* A comma-joined sub-list (flags / components) back to a JSON string array. */
json_t *csv_array(const std::string &field) {
    json_t *a = json_array();
    for (const std::string &x : split_on(field, ',')) {
        json_array_append_new(a, json_string(x.c_str()));
    }
    return a;
}

/* A comma-joined "k=v" option list back to a JSON object (keys already bytewise
 * sorted by the digest; Jansson preserves that insertion order). */
json_t *options_object(const std::string &field) {
    json_t *o = json_object();
    for (const std::string &kv : split_on(field, ',')) {
        size_t eq = kv.find('=');
        std::string k = (eq == std::string::npos) ? kv : kv.substr(0, eq);
        std::string v = (eq == std::string::npos) ? std::string() : kv.substr(eq + 1);
        json_object_set_new(o, k.c_str(), json_string(v.c_str()));
    }
    return o;
}

/* Decode the canonical byte string ("1" RS verb RS rec0 RS rec1 ...) into the
 * JSON records array. The records are already bytewise-sorted in the canon, so
 * this reproduces the exact hash input as structured JSON. */
json_t *decode_records(const unsigned char *canon, size_t len, RecKind kind) {
    std::string s(reinterpret_cast<const char *>(canon), len);
    std::vector<std::string> parts = split_on(s, RS); /* [0]="1", [1]=verb, [2..]=recs */
    json_t *arr = json_array();
    for (size_t i = 2; i < parts.size(); i++) {
        std::vector<std::string> f = split_on(parts[i], US);
        json_t *rec = json_object();
        switch (kind) {
        case REC_TXN:
            json_object_set_new(rec, "package", json_string(fld(f, 0).c_str()));
            json_object_set_new(rec, "architecture", json_string(fld(f, 1).c_str()));
            json_object_set_new(rec, "action", json_string(fld(f, 2).c_str()));
            json_object_set_new(rec, "from_version", json_string(fld(f, 3).c_str()));
            json_object_set_new(rec, "to_version", json_string(fld(f, 4).c_str()));
            json_object_set_new(rec, "flags", csv_array(fld(f, 5)));
            break;
        case REC_CFG:
            json_object_set_new(rec, "package", json_string(fld(f, 0).c_str()));
            json_object_set_new(rec, "architecture", json_string(fld(f, 1).c_str()));
            json_object_set_new(rec, "current_version",
                                json_string(fld(f, 2).c_str()));
            json_object_set_new(rec, "state", json_string(fld(f, 3).c_str()));
            break;
        case REC_HOLD:
            json_object_set_new(rec, "package", json_string(fld(f, 0).c_str()));
            json_object_set_new(rec, "from_state", json_string(fld(f, 1).c_str()));
            json_object_set_new(rec, "to_state", json_string(fld(f, 2).c_str()));
            break;
        case REC_SRC:
            json_object_set_new(rec, "uri", json_string(fld(f, 0).c_str()));
            json_object_set_new(rec, "suite", json_string(fld(f, 1).c_str()));
            json_object_set_new(rec, "components", csv_array(fld(f, 2)));
            json_object_set_new(rec, "options", options_object(fld(f, 3)));
            break;
        }
        json_array_append_new(arr, rec);
    }
    return arr;
}

/* ---- uniform result emission ------------------------------------------ */

int status_exit(const char *status) {
    return (strcmp(status, "ok") == 0 || strcmp(status, "no_op") == 0) ? 0 : 1;
}

/* Build and print the one JSON line, then return the process exit code. Takes
 * ownership of `records` (nullptr -> emit []). `verb`, `resource`, `plan_hash`,
 * and `detail` are emitted as JSON null when nullptr; plan_schema is 1 exactly
 * when plan_hash is present. */
int emit(const char *status, const char *verb,
         const std::vector<std::string> &packages, const char *resource,
         const char *plan_hash, json_t *records, const char *detail) {
    json_t *o = json_object();
    if (o == nullptr) {
        if (records != nullptr) {
            json_decref(records);
        }
        fputs(FALLBACK, stdout);
        return 1;
    }
    json_object_set_new(o, "schema_version", json_integer(1));
    json_object_set_new(o, "status", json_string(status));
    json_object_set_new(o, "verb", verb ? json_string(verb) : json_null());
    json_t *pk = json_array();
    for (const std::string &p : packages) {
        json_array_append_new(pk, json_string(p.c_str()));
    }
    json_object_set_new(o, "packages", pk);
    json_object_set_new(o, "plan_schema",
                        plan_hash ? json_integer(1) : json_null());
    json_object_set_new(o, "resource",
                        resource ? json_string(resource) : json_null());
    json_object_set_new(o, "plan_hash",
                        plan_hash ? json_string(plan_hash) : json_null());
    json_object_set_new(o, "records", records ? records : json_array());
    json_object_set_new(o, "detail", detail ? json_string(detail) : json_null());
    char *s = json_dumps(o, JSON_COMPACT);
    json_decref(o);
    if (s == nullptr) {
        fputs(FALLBACK, stdout);
        return 1;
    }
    fputs(s, stdout);
    fputc('\n', stdout);
    free(s);
    return status_exit(status);
}

/* The canonical resource token for a request's target names (bytewise-sorted,
 * comma-joined; "" for the zero-target verbs). 0 on success, -1 on failure. */
int compute_resource(const std::vector<std::string> &pkgs, std::string &out) {
    std::vector<const char *> tp;
    tp.reserve(pkgs.size());
    for (const std::string &p : pkgs) {
        tp.push_back(p.c_str());
    }
    char *r = nullptr;
    if (pkgx_resource(tp.data(), tp.size(), &r) != 0 || r == nullptr) {
        return -1;
    }
    out = r;
    free(r);
    return 0;
}

/* ---- per-verb previews (read-only; mirror the effectors' resolve/map) --- */

/* A. transactions (install/remove/purge/upgrade/dist_upgrade). The resolve
 * mirrors apt_txn.cc exactly (APT::Upgrade for the whole-system verbs, the
 * pkgProblemResolver for targeted ones) so the mapped record SET, and thus the
 * hash, matches the effector's. */
int preview_txn(pkgCacheFile &cache, const std::string &verb,
                const std::vector<std::string> &pkgs) {
    const bool removal = (verb == "apt.remove" || verb == "apt.purge");
    const bool purge = (verb == "apt.purge");
    const bool upgrade = (verb == "apt.upgrade");
    const bool dist = (verb == "apt.dist_upgrade");

    std::string resource;
    if (compute_resource(pkgs, resource) != 0) {
        return emit("internal", verb.c_str(), pkgs, nullptr, nullptr, nullptr,
                    "resource");
    }
    pkgCache *c = cache.GetPkgCache();
    pkgDepCache *dc = cache.GetDepCache();
    if (c == nullptr || dc == nullptr) {
        return emit("internal", verb.c_str(), pkgs, resource.c_str(), nullptr,
                    nullptr, "cache");
    }

    if (upgrade || dist) {
        const int mode = dist ? APT::Upgrade::ALLOW_EVERYTHING
                              : APT::Upgrade::FORBID_REMOVE_PACKAGES;
        if (!APT::Upgrade::Upgrade(*dc, mode)) {
            _error->DumpErrors();
            return emit("resolve_failed", verb.c_str(), pkgs, resource.c_str(),
                        nullptr, nullptr, "resolve");
        }
    } else {
        pkgProblemResolver resolver(dc);
        for (const std::string &t : pkgs) {
            pkgCache::PkgIterator P = c->FindPkg(t);
            if (P.end()) {
                return emit("resolve_failed", verb.c_str(), pkgs, resource.c_str(),
                            nullptr, nullptr, t.c_str()); /* unknown package */
            }
            resolver.Protect(P);
            if (removal) {
                dc->MarkDelete(P, purge);
                resolver.Remove(P);
            } else {
                dc->MarkInstall(P, true);
            }
        }
        if (!resolver.Resolve(true)) {
            _error->DumpErrors();
            return emit("resolve_failed", verb.c_str(), pkgs, resource.c_str(),
                        nullptr, nullptr, "resolve");
        }
    }

    std::deque<PkgxHolder> holders;
    std::vector<pkgx_txn_record> recs;
    pkgx_apt_map_txn(c, dc, holders, recs);
    if (recs.empty()) {
        return emit("no_op", verb.c_str(), pkgs, resource.c_str(), nullptr,
                    nullptr, nullptr);
    }

    const char *offender = nullptr;
    pkgx_policy_result pol = pkgx_policy_check(recs.data(), recs.size(), &offender);

    char hex[PKGEXEC_DIGEST_HEX + 1];
    unsigned char *canon = nullptr;
    size_t canon_len = 0;
    if (pkgx_digest_pkg_txn(verb.c_str(), recs.data(), recs.size(), hex, &canon,
                            &canon_len) != 0) {
        return emit("internal", verb.c_str(), pkgs, resource.c_str(), nullptr,
                    nullptr, "digest");
    }
    json_t *records = decode_records(canon, canon_len, REC_TXN);
    free(canon);

    switch (pol) {
    case PKGX_POLICY_OK:
        return emit("ok", verb.c_str(), pkgs, resource.c_str(), hex, records,
                    nullptr);
    case PKGX_POLICY_NOT_OWNED:
        return emit("package_not_owned", verb.c_str(), pkgs, resource.c_str(), hex,
                    records, offender);
    case PKGX_POLICY_HELD:
        return emit("held", verb.c_str(), pkgs, resource.c_str(), hex, records,
                    offender);
    case PKGX_POLICY_PROTECTED:
        return emit("protected_package", verb.c_str(), pkgs, resource.c_str(), hex,
                    records, offender);
    }
    json_decref(records); /* unreachable: pol is one of the four above */
    return emit("internal", verb.c_str(), pkgs, resource.c_str(), nullptr, nullptr,
                "policy");
}

/* B. update: the shared source-list enumeration. No package policy. resource is
 * the whole-source-list token "". */
int preview_update() {
    const std::vector<std::string> none;
    pkgSourceList list;
    if (!list.ReadMainList()) {
        _error->DumpErrors();
        return emit("internal", "apt.update", none, "", nullptr, nullptr, "sources");
    }
    std::deque<PkgxSrcHolder> holders;
    std::vector<pkgx_src_record> recs;
    pkgx_apt_map_sources(list, holders, recs);
    if (recs.empty()) {
        return emit("no_op", "apt.update", none, "", nullptr, nullptr, nullptr);
    }
    char hex[PKGEXEC_DIGEST_HEX + 1];
    unsigned char *canon = nullptr;
    size_t canon_len = 0;
    if (pkgx_digest_update(recs.data(), recs.size(), hex, &canon, &canon_len) != 0) {
        return emit("internal", "apt.update", none, "", nullptr, nullptr, "digest");
    }
    json_t *records = decode_records(canon, canon_len, REC_SRC);
    free(canon);
    return emit("ok", "apt.update", none, "", hex, records, nullptr);
}

/* C. hold / unhold: the shared selection read + change filter, then the same
 * ownership refusal the effector applies (never a rapt-owned package). */
int preview_hold(pkgCacheFile &cache, const std::string &verb,
                 const std::vector<std::string> &pkgs) {
    std::string resource;
    if (compute_resource(pkgs, resource) != 0) {
        return emit("internal", verb.c_str(), pkgs, nullptr, nullptr, nullptr,
                    "resource");
    }
    pkgCache *c = cache.GetPkgCache();
    if (c == nullptr) {
        return emit("internal", verb.c_str(), pkgs, resource.c_str(), nullptr,
                    nullptr, "cache");
    }
    const bool hold = (verb == "apt.hold");
    std::vector<const char *> tp;
    tp.reserve(pkgs.size());
    for (const std::string &p : pkgs) {
        tp.push_back(p.c_str());
    }
    std::deque<PkgxHoldHolder> changes;
    std::vector<pkgx_hold_record> holds;
    const char *offender = nullptr;
    pkgx_hold_map hm =
        pkgx_apt_map_hold(c, tp.data(), tp.size(), hold, changes, holds, &offender);
    if (hm == PKGX_HOLD_MAP_UNKNOWN || hm == PKGX_HOLD_MAP_INVALID) {
        return emit("resolve_failed", verb.c_str(), pkgs, resource.c_str(), nullptr,
                    nullptr, offender);
    }
    if (changes.empty()) {
        return emit("no_op", verb.c_str(), pkgs, resource.c_str(), nullptr, nullptr,
                    nullptr);
    }

    const char *own_off = nullptr;
    for (const PkgxHoldHolder &h : changes) {
        if (pkgx_is_rapt_owned(h.package.c_str())) {
            own_off = h.package.c_str();
            break;
        }
    }

    char hex[PKGEXEC_DIGEST_HEX + 1];
    unsigned char *canon = nullptr;
    size_t canon_len = 0;
    if (pkgx_digest_hold(verb.c_str(), holds.data(), holds.size(), hex, &canon,
                         &canon_len) != 0) {
        return emit("internal", verb.c_str(), pkgs, resource.c_str(), nullptr,
                    nullptr, "digest");
    }
    json_t *records = decode_records(canon, canon_len, REC_HOLD);
    free(canon);

    if (own_off != nullptr) {
        return emit("package_not_owned", verb.c_str(), pkgs, resource.c_str(), hex,
                    records, own_off);
    }
    return emit("ok", verb.c_str(), pkgs, resource.c_str(), hex, records, nullptr);
}

/* D. configure: the shared pending-configuration enumeration (with its
 * half-installed dpkg_broken refusal) and the same ownership refusal. resource is
 * the fixed "pending" token. */
int preview_configure(pkgCacheFile &cache) {
    const std::vector<std::string> none;
    pkgCache *c = cache.GetPkgCache();
    if (c == nullptr) {
        return emit("internal", "apt.configure", none, "pending", nullptr, nullptr,
                    "cache");
    }
    std::deque<PkgxCfgHolder> holders;
    std::vector<pkgx_cfg_record> cfgs;
    const char *half_installed = nullptr;
    if (pkgx_apt_map_configure(c, holders, cfgs, &half_installed) ==
        PKGX_CFG_MAP_HALF_INSTALLED) {
        return emit("dpkg_broken", "apt.configure", none, "pending", nullptr,
                    nullptr, half_installed);
    }
    if (cfgs.empty()) {
        return emit("no_op", "apt.configure", none, "pending", nullptr, nullptr,
                    nullptr);
    }

    const char *own_off = nullptr;
    for (const PkgxCfgHolder &h : holders) {
        if (pkgx_is_rapt_owned(h.package.c_str())) {
            own_off = h.package.c_str();
            break;
        }
    }

    char hex[PKGEXEC_DIGEST_HEX + 1];
    unsigned char *canon = nullptr;
    size_t canon_len = 0;
    if (pkgx_digest_configure(cfgs.data(), cfgs.size(), hex, &canon, &canon_len) !=
        0) {
        return emit("internal", "apt.configure", none, "pending", nullptr, nullptr,
                    "digest");
    }
    json_t *records = decode_records(canon, canon_len, REC_CFG);
    free(canon);

    if (own_off != nullptr) {
        return emit("package_not_owned", "apt.configure", none, "pending", hex,
                    records, own_off);
    }
    return emit("ok", "apt.configure", none, "pending", hex, records, nullptr);
}

} /* namespace */

int main() {
    /* Read the request with the helper's byte cap + absolute deadline. A read
     * failure has no request to echo: too_large/deadline are malformed input
     * (schema_invalid); a raw I/O error is internal. */
    char *body = nullptr;
    size_t len = 0;
    const char *rerr = nullptr;
    const std::vector<std::string> empty;
    if (pkgx_read_stdin(0, &body, &len, &rerr) != 0) {
        const char *status = (std::strcmp(rerr, "io") == 0) ? "internal"
                                                            : "schema_invalid";
        return emit(status, nullptr, empty, nullptr, nullptr, nullptr, rerr);
    }

    pkgx_preview_request req;
    const char *perr = nullptr;
    int pr = pkgx_parse_preview_request(body, len, &req, &perr);
    free(body);
    if (pr != 0) {
        return emit("schema_invalid", nullptr, empty, nullptr, nullptr, nullptr,
                    perr);
    }

    std::string verb = req.verb;
    std::vector<std::string> pkgs;
    pkgs.reserve(req.npackages);
    for (size_t i = 0; i < req.npackages; i++) {
        pkgs.push_back(req.packages[i]);
    }
    pkgx_preview_request_free(&req);

    if (!pkgInitConfig(*_config) || !pkgInitSystem(*_config, _system)) {
        _error->DumpErrors();
        return emit("internal", verb.c_str(), pkgs, nullptr, nullptr, nullptr,
                    "apt_init");
    }

    /* update reads the source list directly and needs no package cache. */
    if (verb == "apt.update") {
        return preview_update();
    }

    /* Every other verb reads the cache READ-ONLY (WithLock=false): no lock is
     * taken, so an ordinary user can preview without root and nothing is mutated. */
    pkgCacheFile cache;
    if (!cache.Open(nullptr, false)) {
        _error->DumpErrors();
        return emit("internal", verb.c_str(), pkgs, nullptr, nullptr, nullptr,
                    "cache_open");
    }
    if (verb == "apt.hold" || verb == "apt.unhold") {
        return preview_hold(cache, verb, pkgs);
    }
    if (verb == "apt.configure") {
        return preview_configure(cache);
    }
    return preview_txn(cache, verb, pkgs);
}
