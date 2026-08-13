/* Broker redeem client. See redeem.h. */
#include "redeem.h"

#include <jansson.h>
#include <stdlib.h>
#include <string.h>

/* The closed set of error codes a redeem reply may legitimately carry: the six
 * receipt_* verdicts plus the broker's operational refusals rate_limited and
 * persist_failed (runix-audit-broker src/broker.c, handle_redeem). Anything else
 * — a generic bad_json/schema_invalid/unknown_request that would mean our own
 * request was malformed — is a protocol violation; the helper refuses either
 * way, but only these are the contract's redeem errors. */
static const char *const REDEEM_ERRORS[] = {
    "receipt_invalid",       "receipt_expired",  "receipt_redeemed",
    "receipt_mismatch",      "receipt_unauthorized", "receipt_actor_mismatch",
    "rate_limited",          "persist_failed"};

static const char *known_error(const char *code) {
    for (size_t i = 0; i < sizeof REDEEM_ERRORS / sizeof *REDEEM_ERRORS; i++) {
        if (strcmp(code, REDEEM_ERRORS[i]) == 0) {
            return REDEEM_ERRORS[i];
        }
    }
    return NULL;
}

/* Reject a reply object carrying any key outside `allowed`. */
static int only_keys(json_t *o, const char *const *allowed, size_t n) {
    const char *k;
    json_t *v;
    json_object_foreach(o, k, v) {
        int ok = 0;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(k, allowed[i]) == 0) {
                ok = 1;
                break;
            }
        }
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

static char *build_request(const pkgx_redeem_req *r) {
    json_t *o = json_object();
    json_t *eff = json_object();
    if (o == NULL || eff == NULL) {
        json_decref(o);
        json_decref(eff);
        return NULL;
    }
    int bad = json_object_set_new(o, "type", json_string("redeem_receipt")) != 0 ||
              json_object_set_new(o, "effect_receipt",
                                  json_string(r->effect_receipt)) != 0 ||
              json_object_set_new(o, "principal_uid",
                                  json_integer((json_int_t) r->principal_uid)) != 0 ||
              json_object_set_new(eff, "operation", json_string(r->operation)) != 0 ||
              json_object_set_new(eff, "resource", json_string(r->resource)) != 0 ||
              json_object_set_new(eff, "plan_schema",
                                  json_integer(r->plan_schema)) != 0 ||
              json_object_set_new(eff, "plan_hash", json_string(r->plan_hash)) != 0;
    if (bad || json_object_set_new(o, "effect", eff) != 0) {
        if (bad) {
            json_decref(eff);
        }
        json_decref(o);
        return NULL;
    }
    char *s = json_dumps(o, JSON_COMPACT);
    json_decref(o);
    return s;
}

pkgx_redeem_status pkgx_redeem(const pkgx_redeem_req *req, const char *expected_cid,
                               pkgx_redeem_transport tx, void *ctx,
                               char out_cid[PKGX_CID_LEN + 1], const char **code) {
    *code = "protocol";
    char *reqbody = build_request(req);
    if (reqbody == NULL) {
        return PKGX_REDEEM_PROTOCOL;
    }
    char *resp = NULL;
    size_t resplen = 0;
    int trc = tx(ctx, reqbody, strlen(reqbody), &resp, &resplen);
    explicit_bzero(reqbody, strlen(reqbody)); /* the request body carries the token */
    free(reqbody);
    if (trc != 0 || resp == NULL) {
        free(resp);
        *code = "transport";
        return PKGX_REDEEM_PROTOCOL;
    }

    json_error_t jerr;
    json_t *root = json_loadb(resp, resplen, JSON_REJECT_DUPLICATES, &jerr);
    free(resp);
    if (root == NULL || !json_is_object(root)) {
        json_decref(root);
        return PKGX_REDEEM_PROTOCOL;
    }

    pkgx_redeem_status st = PKGX_REDEEM_PROTOCOL;
    json_t *jok = json_object_get(root, "ok");
    if (!json_is_boolean(jok)) {
        goto done;
    }
    if (json_is_true(jok)) {
        static const char *const OK_KEYS[] = {"ok", "correlation_id", "persisted"};
        json_t *jcid = json_object_get(root, "correlation_id");
        json_t *jp = json_object_get(root, "persisted");
        if (!only_keys(root, OK_KEYS, 3) || !json_is_string(jcid) ||
            !json_is_true(jp)) {
            goto done; /* ok reply must be exactly {ok, correlation_id, persisted:true} */
        }
        const char *cid = json_string_value(jcid);
        if (strlen(cid) != PKGX_CID_LEN || strcmp(cid, expected_cid) != 0) {
            *code = "cid_mismatch";
            st = PKGX_REDEEM_CID_MISMATCH;
            goto done;
        }
        memcpy(out_cid, cid, PKGX_CID_LEN + 1);
        *code = "ok";
        st = PKGX_REDEEM_OK;
    } else {
        static const char *const ERR_KEYS[] = {"ok", "error", "message"};
        json_t *jerrcode = json_object_get(root, "error");
        if (!only_keys(root, ERR_KEYS, 3) || !json_is_string(jerrcode) ||
            !json_is_string(json_object_get(root, "message"))) {
            goto done;
        }
        const char *known = known_error(json_string_value(jerrcode));
        if (known == NULL) {
            goto done; /* code outside the closed redeem set: protocol violation */
        }
        *code = known;
        st = PKGX_REDEEM_REFUSED;
    }

done:
    json_decref(root);
    return st;
}
