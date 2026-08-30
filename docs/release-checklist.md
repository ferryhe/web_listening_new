# Phase 20 Release and Rollback Checklist

This checklist is read-only and non-production. It neither performs nor
authorizes a production switch.

## Release identities

- Old release: `ferryhe/web_listening@9fe9ea53104dd008086dfa0e86c35c50b75f4ce5`.
- New candidate basis: `ferryhe/web_listening_new@9450cb5968b3a24be50284a502c5adba696b20e6`
  plus the reviewed Phase 20 evidence diff. The release commit must replace this
  description before any real deployment decision.
- Live input snapshot: `tests/live/phase_20_site_targets.json`.

## GO / NO-GO gate

GO requires every box below. A missing result is NO-GO, not a waiver.

- [x] Frozen no-secret offline corpus covers success and rejection/failure.
- [x] Offline fixture-evidenced common semantics have no unexplained difference;
  unavailable legacy Artifact/Observation/Manifest/Usage fields are explicit `N/A`.
- [x] README §19 has 16 reproducible contract evidence rows.
- [x] Non-production rollback drill returns to the old healthy release and retains evidence.
- [x] Offline candidate-identity regressions freeze every Git-visible Issue file,
  bind both actual probe digests, and fail closed on scope, shape, read, or
  before/after byte drift.
- [ ] Fresh Live Test Subagent: with `WEB_LISTENING_LIVE_SITE` unset, the exact
  live command exits `0`; the ordered `soa`, `cas`, `iaa` parameters produce
  exactly `3 passed, 0 skipped` and zero live xfails; all three sites pass
  thresholds and parity. Ordinary warnings are allowed.
- [ ] Independent fresh I/O audit returns exactly `PASS`.
- [ ] Required CI/checks pass on the final release commit.
- [ ] A human with separate production authority explicitly authorizes the switch.

Current recommendation: **NO-GO** because the Live Test and I/O audit are pending.

## Read-only release procedure

1. Record immutable old and new release commits; reject a mutable branch name.
2. Verify the target snapshot against the base Git blob LF SHA-256
   `B13747A4516810BED5AB5FF164EFC3FD9F5F1C91B51FF3DCE5708A23724A0E6E`;
   CRLF checkout bytes must canonicalize to the same authority without editing
   either file.
3. Run the offline focused and unified quality gates on the new candidate.
   Before Live, require the current HEAD to descend from fixed prerequisite-sync
   base `9450cb5968b3a24be50284a502c5adba696b20e6`. The base-to-HEAD range must add
   exactly the 12 files integrated by #63, with no other path or status; the
   restored #21 worktree relative to HEAD must contain only the tracked
   `README.md` modification and no other tracked or non-ignored untracked path.
   Do not hard-code the future #63 merge SHA. Require
   `phase-20-candidate-identity.v2` to combine those boundaries into the exact
   sorted 13-file candidate set: README, these two documents, the target snapshot,
   the Live test, and all required `tests/parity/**` files. Each entry must record
   raw SHA-256 and size, with both the fixed prerequisite base revision and the
   separately measured current HEAD revision plus branch included in the canonical
   aggregate. Bind both probes to that identity; the old invocation remains fixed
   at `9fe9ea5...`, while all new success and boundary-failure evidence must name
   current HEAD rather than the prerequisite base. Missing, extra, unreadable,
   non-regular, renamed, deleted,
   conflicted, or out-of-whitelist paths are NO-GO. Git
   `ls-files --others --exclude-standard` is the sole untracked ignore authority;
   any returned path blocks and no cache-name filter may discard it. The external
   controlled runtime is outside the worktree and is not a candidate.
   Before each gate, audit and precisely remove verified caches because this repo
   does not currently ignore all of them. Set `PYTHONDONTWRITEBYTECODE=1`.
   Focused/combined runs explicitly use `-p no:cacheprovider`; run the exact full
   command `python -m pytest -q` with the disclosed environment
   `PYTEST_ADDOPTS=-p no:cacheprovider`.
4. In one authorized window, have a fresh tester run
   `python -m pytest -q -m live tests/live/test_phase_20_parity_live.py` with
   the disclosed environment `PYTEST_ADDOPTS=-p no:cacheprovider` and
   `PYTHONDONTWRITEBYTECODE=1`, after the same cache/path audit. The command text
   remains exact; the environment prevents pytest from writing a non-ignored root
   cache. Keep `WEB_LISTENING_LIVE_SITE` unset. The selector is diagnostic-only:
   when set,
   excluded parameters fail rather than skip and the selected evidence remains
   a release blocker, so that run is always NO-GO.
5. Record collected/passed/skipped/xfailed counts and all three site keys. The
   only accepted final summary is `3 passed, 0 skipped`, zero live xfails, and
   ordered `soa`, `cas`, `iaa`; ordinary warnings are allowed.
   Also require CPython 3.12.x, the fixed archive, and the frozen ten-distribution
   governed-read closure fingerprints to match before networking; any environment
   or either system subprocess failure is a blocker. Partial child evidence and
   a new Runtime job without a Result must produce complete blocker evidence
   rather than an incomplete report. Require real old/new process return codes;
   an in-process derived exit is not release evidence.
   Every site's old/new invocation and environment must bind the same frozen
   candidate aggregate and the actual digest/size of its respective probe. The
   outer harness must independently recompute the entire identity after both
   subprocess boundaries. Any path, digest, size, base, branch, probe binding,
   or read failure is `candidate_identity:drift` and NO-GO; child self-report is
   insufficient.
   The merged #61 HTTP-profile classifier and its tests are read-only base files,
   not Phase 20 candidate paths. Require the old-side setup to verify fixed commit
   `9fe9ea5` and blob SHAs `852c3776...`, `859a28d9...`, `46934a3f...`, and
   `d9e6262c...`, then construct the fixed `DiagnosticIdentity`,
   `AccessGatewayConfig`, `AccessGateway`, sealed `SafePinnedTransport`, and
   `GovernedReadGateway` directly. The incompatible fixed helper is forbidden.
   Require the new child to import `WEB_HTTP_REQUEST_PROFILE` and SHA
   `14450398...` directly from its actual transport module. Each real old/new
   transport call must emit its independently calculated, order-preserving
   descriptor/digest. Before any content comparison, the parent must call the
   #61 classifier. The only acceptable pair is
   `explained_fixed_difference` / `profile.fixed_old_accept_encoding` and only
   `Accept-Encoding: identity, gzip` → `identity`; provenance, identity, order,
   field, digest, authority/observation, or request-count drift is NO-GO.
   Boundary evidence must retain the same explicit profile shape and block.
   URL/status/MIME/size/content SHA and all existing Result evidence remain
   strict; `http.content_sha256` is never an accepted difference.
   Each system must also report finite nonnegative elapsed time within an exact
   30-second maximum; missing/invalid time evidence and numeric overruns are
   blockers even when another system failure is already present.
   Aggregate request/byte counts must be nonnegative exact integers before limit
   comparison. The normal legacy child budget must match the complete frozen
   limits, basis, robots-bound, deadline, concurrency, and retry contract;
   malformed count or child-budget evidence is a blocker.
   For every new-system case, require Result `usage.bytes_received` and the
   independently measured governed-transport byte delta to be nonnegative exact
   integers and equal. Their case sum must reconcile with both the declared case
   total and system transport total. Missing, malformed, negative, boolean, or
   mismatched byte evidence is NO-GO; legacy remains explicit `N/A` because its
   Result Usage measurement surface is unavailable.
   Independently validate every legacy case's complete Usage shape. Successful
   cases add the frozen robots allowance once to actual target wire/decoded
   bytes; conservative failures already include that allowance in their
   per-case upper bound. Exact case accounting must equal the system total, and
   missing/mistyped/out-of-range fields or any duplicate robots accounting are
   NO-GO.
   Apply the same fail-closed rule to requests: each new Result request count
   and independently measured governed-transport request delta must be
   nonnegative exact integers and equal, and all case deltas must reconcile with
   both the declared case total and system transport total. Legacy case gateway
   request counts (exact success or frozen failure upper bound) must reconcile
   with the legacy aggregate independently; do not compare the two systems'
   different counting bases. Unknown child/boundary counts remain explicit
   `N/A` and are NO-GO.
6. Require the independent I/O audit to reconcile README §19 and the independently
   constructed old/new Request descriptors and digests. The Request descriptor
   must include seeds, allowed origins, paths, content types, Site Skill presence,
   exploration, and budgets; the separate Site Skill snapshot digest must not be
   inserted into it. Also reconcile URL/redirect/status/MIME, Artifact/Observation/
   Manifest counts, SHA/size/MIME and identity relationships, tool id/version,
   explicit legacy `N/A` values, thresholds, budgets, and every difference
   classification. Any mismatch is NO-GO.
   Error comparison freezes availability, code, exact message, retryable,
   SafeError details, and error-type lists in normal and boundary evidence.
   Only the documented exact message, retryable, and details pairs are accepted;
   any missing, mistyped, or changed leaf is NO-GO. Offline A/O/M/Attempt
   evidence must come from actual ArtifactStore Observation/content readback and
   reconcile counts, SHA/size/MIME, identities, content, and tool id/version;
   caller fixture bytes alone are not evidence.
   Also retain the all-candidate identity emitted by the authorized Live run.
   A later evidence-only overlay may update only README and these two documents;
   the final I/O audit/PR must record the final commit identity and that exact
   overlay. Snapshot, Live test, and every `tests/parity/**` file are the
   runtime-critical subset and must still match their per-file Live digests. Any
   runtime-critical byte change requires rerunning Live. Do not embed a computed
   aggregate into a candidate file and create a self-reference.
7. Recommend the new release only when all contract and health gates pass.
8. Stop here unless separate production authorization is recorded. This Issue's
   tests and documents do not contain a deployment command.

## Reversible switch and rollback procedure

1. Preserve the old release and its data read path; do not overwrite it.
2. Select old/new by immutable release identity in the deployment system owned
   outside this repository.
3. Before switching, require the new candidate's contract and health gates.
4. After a separately authorized switch, check the same health/Result contract
   without broadening URLs, budgets, retries, or ignores.
5. On a failed health or contract check, select the preserved old release.
6. Re-run the old release health gate and retain both pre-switch and rollback
   evidence, including release identities and timestamps.
7. If the old release health gate fails, stop and escalate; do not improvise a
   third release or repair product functionality in Phase 20.

## Actual non-production rollback drill evidence

The offline test
[`test_nonproduction_rollback_drill_selects_switches_and_returns_to_old`](../tests/parity/test_phase_20_parity.py)
executed a pure simulation with no deployment or network authority:

| Evidence field | Observed |
|---|---|
| Selected release | `new` |
| Pre-switch health / contract | `pass` / `pass` |
| Switch recommendation | `go` |
| Injected post-switch health | `fail` |
| Rollback selection | `old` |
| Old release health after rollback | `pass` |
| Evidence retained | `true` |
| Production mutation | `false` |
| Drill result | `rollback-pass` |

Command: `python -m pytest -q tests/parity -m "not live"` → `211 passed`
(exit `0`). The scenario is frozen in
[`phase_20_offline_corpus.json`](../tests/parity/fixtures/phase_20_offline_corpus.json);
changing a pre-switch gate to failure prevents a switch recommendation.

## Evidence retention

Retain the final commit/PR, exact commands and exit codes, pytest counts, the
redacted JSON records printed by the live test, required-check results, the
independent I/O verdict, and the production authority record. Do not retain page
bodies, credentials, temporary checkouts, or pytest Artifact Stores.
