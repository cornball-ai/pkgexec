# pkgexec

The privileged apt effector for [Runix](https://github.com/cornball-ai/runix).
Nine tiny per-verb root binaries that link `libapt-pkg` and commit apt package
transactions, each gated by its own `pkexec`/polkit action and a broker-issued
**effect receipt** it redeems before committing.

Rung 2 of the apt-mutation arc, after the audit broker's effect-receipt
capability ([`runix-audit-broker`](https://github.com/cornball-ai/runix-audit-broker)).

## What it is, and is not

- **Effect only.** It mutates package state and nothing else. It writes **no
  audit** (the broker records; the unprivileged caller owns the two-phase write)
  and evaluates **no R**.
- **Verb fixed by executable path.** One immutable binary and one polkit action
  per verb — `update`, `install`, `remove`, `purge`, `upgrade`, `dist_upgrade`,
  `configure`, `hold`, `unhold` — never selected by `argv`.
- **No effect without a durable intent.** It redeems a broker effect receipt
  (bound to the caller, verb, resource, and the previewed plan hash) *before* it
  commits, under one held `libapt-pkg` lock so the validated plan is the executed
  plan. A missing / stale / mismatched / replayed receipt is a fail-closed
  refusal, before any effect.

## The unprivileged planner (`runix-apt-preview`)

A tenth binary, unlike the nine: **unprivileged, read-only, and installed on PATH**
(`/usr/bin/runix-apt-preview`). It reads the receipt-free stdin request
`{schema_version, verb, packages}`, opens the apt cache **without** the dpkg lock,
and prints one strict JSON object carrying the schema-1 `resource` and `plan_hash`.
It commits nothing (no lock, no dpkg, no fetch, no shell, no receipt), so it is safe
to run as any user any number of times.

It is the **single implementation** of the preview descriptor/digest the
[`pkgops`](https://github.com/cornball-ai/runix) issuer previews against: it shares
the effectors' `apt_common` descriptor builders, policy, and digest, so a matching
cache yields the matching hash. The preview is **advisory** — the effector's atomic
locked re-resolution at redeem stays authoritative, and any drift between preview
and redeem fails closed (`no_intent`). Distinct from `pkgexec-plan`, the root VM
diagnostic that holds the dpkg lock and is never installed.

## Design

Specified in [`cornball-ai/runix`](https://github.com/cornball-ai/runix) `docs/`:

- `apt-mutation-boundary-contract.md` — the boundary (authorization vs approval,
  package ownership, the dpkg lock, partial-failure recovery).
- `broker-effect-receipt-contract.md` — the receipt this effector redeems.
- `libapt-pkg-helper-plan.md` — this repo's implementation plan.

## Build

Build-deps: `libapt-pkg-dev`, `libjansson-dev`, `libssl-dev`, `pkg-config`.

Status: activated (0.0.3). The nine per-verb effectors commit behind the redeem
gate; proven on a disposable systemd/polkit/dpkg VM (23/23 polkit matrix, 37/37 §7
acceptance gates). Adds the unprivileged `runix-apt-preview` planner (above).
