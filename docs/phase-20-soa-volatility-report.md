# Phase 20 SOA Volatility Attribution Report

## Status and scope

This report defines the auditable evidence contract for GitHub Issue #67. The
first authorized SOA Live run occurred on 2026-08-30 with this native pytest
result:

```text
exit 0; 1 passed in 3.72s
```

That pytest result is not an Issue PASS. The Issue evidence gate result is
**LIVE FAIL**: the emitted classification is `inconclusive`, and the supervised
worker result is `invalid-evidence` with a `SchemaError`. The parent replaced
all four sample slots with a fail-closed `not-observed` envelope. Consequently,
complete sample and system cap accounting, HTTP profile evidence,
authorization evidence, target/catalog evidence, and the original worker
samples were not retained. Phase 20 Issue #21 therefore remains `BLOCKED`, and
the first failed Live log must not be overwritten or reused as release
evidence.

The user authorized one additional diagnostic Live under the repaired evidence
gate. Its fresh diagnostic launcher exited `1` before pytest started because
`Set-Alias -Scope Process` is not valid PowerShell. This was a launcher failure,
not a Live Test execution or a content-diagnostic result. Native pytest exit and
all test counts are `N/A`: collected, passed, failed, skipped, and xfailed were
not produced. Network requests were `0`, and no authorization window was
generated. No diagnostic log was created, and zero JSON evidence records were
emitted. Consequently, classification, samples, caps, profile, digests, worker
validation, projection, and bundle evidence are all absent. No retry or rerun
occurred. At that aborted-launch point, bundle and staging directory counts were
both `0`.

The user subsequently classified this launcher attempt as `ABORTED`. It was not
an actual diagnostic and does not consume the authorized diagnostic Live. The
one authorized actual diagnostic then completed. Its native pytest result was
`exit 0; 1 passed`, but that diagnostic pytest result is not an evidence PASS.
The diagnostic evidence gate failed with classification `inconclusive`: only
`evidence.fixed_requested_url` and `evidence.allowed_final_origin` were false;
the other eleven predicates were true. The parent therefore replaced all four
worker samples with `not-observed` failure-envelope slots.

The unique diagnostic log is
`C:\Project\web_listening_new_delivery_state\issue-67-soa-diagnostic-actual.log`
(10,742 bytes; SHA-256
`50284f2ac6faac030684d67347c0821529c9c32cd186ec0771fcbc3453bfee99`).
The unique audit bundle is
`C:\Project\web_listening_new_delivery_state\issue-67-soa-audit-2c299f22a9b23b72dcc09cf6711e6baad1c2121cca61e26de1150be73dd33e5f`;
its manifest has SHA-256
`b985384aa9255130b639eb842864d1f0785fde6412b024bc4cca9806e3a75728`.
The fresh bundle audit passed, while the diagnostic evidence gate failed. Only
new-side artifact I/O is independently supported by that bundle. Old-side I/O,
cumulative caps, and profile evidence remain unknown.

The historical raw URL values were not retained, so the actual diagnostic
cannot establish which raw URL condition made the two predicates false. An
offline reproduction showed that a canonical `outcome == "failure"` case with
the complete safe N/A URL sentinel triggered exactly those reasons. The local
contract now permits that exact sentinel only for failure cases while preserving
all success URL requirements and rejecting every wrong or malformed URL. This
fix does not prove that condition was the historical root cause.

The first failed Live log remains immutable and must not be overwritten; the
actual diagnostic log and bundle use unique paths. At most one final Live
remained, and it could run only after a pre-final audit. The unique final
one-shot then completed. Its native pytest process returned `0`; the final
agent measured `4.73` seconds, while the log records `1 passed in 4.62s`.
The unique three-line, one-JSON-record log is
`C:\Project\web_listening_new_delivery_state\issue-67-soa-final-actual.log`
(12,017 bytes; SHA-256
`05f9a21c701ebfea0e4a0bad4c25a8a4a3f5cf7c3f0b381abfd7d69dab07510c`).

The final parent evidence has a valid fail-closed `inconclusive`
classification. Worker validation was valid, with all `13/13` predicates true
and no reason codes. Its audit bundle persisted at
`C:\Project\web_listening_new_delivery_state\issue-67-soa-audit-009744d9b5a8bbdb2c22e558057472d30ae6490cf82ae9aac60a52857a916a80`.
The bundle contains seven manifest-listed files, and its manifest SHA-256 is
`a13ff9e2ea8937d9ff2453572928b6b53761e7356c8a4f5813cb38be3ac197e5`.
The fresh final audit reported both **FINAL I/O AUDIT PASS** and
**ISSUE #67 EVIDENCE PASS**.

In that preserved evidence, old-1 and old-2 ended `environment-mismatch` /
`not-started`; their actual usage is `N/A`, not a fabricated zero. Their case
errors and unmet thresholds remain visible. New-1 used 4 requests, 648,431
bytes, and 1.542 seconds; new-2 used 4 requests, 648,431 bytes, and 0.885
seconds. The new-system total was 8 requests, 1,296,862 bytes, and 2.427
seconds, and the outer run used 4.411 of 65 seconds. New-side status, MIME,
size, and threshold evidence is complete, and the content SHA-256 values
changed between its two rounds.

Both profile rounds were outside authority: their monitor and document rows
reported `profile.old_provenance_mismatch`. The profile validation,
recomputation, and check-schema predicates were true. The independent audit
also passed the manifest, SQLite integrity, foreign-key, database-row-to-blob,
redaction, digest, and order checks. The first and diagnostic logs and the
diagnostic bundle remained unchanged.

Issue #67 evidence PASS means only that the attribution evidence contract is
complete and auditable; it is not an Issue #21 release PASS. Because the final
classification is not `stable_match`, Issue #21 remains `BLOCKED` until
complete fresh `stable_match` evidence. No normalization, ignore rule, or
comparison relaxation is warranted. Issue #67 may enter the publication
workflow. At the time this final evidence was captured, no commit or pull
request had yet been created.

The first failed Live log is
`C:\Project\web_listening_new_delivery_state\issue-67-soa-live-final.log`
(9,864 bytes; SHA-256
`8069843dd6e4f5b6340a456a52722b3eda4ebaa4a87037cff4f65db61901f43f`).
The original worker envelope was not saved. The exact failing child condition
inside the parent success-evidence validator is therefore unknown; this report
does not guess at a fix.

## Observed facts

The following facts describe the repository contract and the retained Live
results:

- Native pytest completed successfully in the first and diagnostic attempts,
  but their Issue evidence gates failed as described above. A test-process exit
  code cannot substitute for complete, valid Issue evidence.
- The first run's parent envelope records
  `old-1 -> new-1 -> old-2 -> new-2`, but all four slots are `not-observed`; it
  does not prove the child I/O, cumulative caps, profile compatibility, or
  content attribution for that run. The diagnostic preserved only new-side
  artifact evidence. The unique final record preserved all four ordered sample
  slots and the safe evidence required to explain its valid `inconclusive`
  result.

- The fixed site is `soa` from `tests/live/phase_20_site_targets.json`.
- The fixed cases are `monitor` and `document`; every child sample covers both.
- The old system remains pinned to
  `9fe9ea53104dd008086dfa0e86c35c50b75f4ce5`.
- Acquisition and HTTP profile behavior remain owned by the existing
  `legacy_live_probe.py`, `new_live_probe.py`, and
  `http_profile_compatibility.py` authorities. Issue #67 does not copy or
  modify them.
- The only permitted execution order is
  `old-1 -> new-1 -> old-2 -> new-2`, with concurrency `1` and retry `0`.
- Each child sample is capped at 4 requests, 2 MiB of response evidence, a
  13-second governed-network window, and a 15-second process limit. Therefore
  each system is capped at 8 requests, 4 MiB, and 30 seconds across its two
  samples. A separate worker contains legacy preparation, all four child
  probes, and the profile checks; the parent terminates that process tree at
  the whole-run 65-second hard deadline and emits only safe `inconclusive`
  deadline evidence.
- The fixed target thresholds are part of valid evidence: both cases require
  at least 150 words, and `document` additionally requires at least one
  document link. Each case records the expected counters, observed counters,
  and whether both requirements were met.
- Emitted evidence contains only process outcome, stable error code/type,
  status, MIME type, credential-free requested/final URL descriptors, strict
  content SHA-256 and size, and request/byte/time budget evidence. It never
  emits response bodies, credentials, raw authorization-window values,
  unredacted headers, error messages, or error details.
- URL descriptors retain scheme/origin plus irreversible path and query
  SHA-256 values. Raw query text is never emitted; absent and explicitly empty
  queries use the same empty-query digest but retain distinct query-delimiter
  flags. A URL containing any userinfo is invalid evidence rather than a
  credential-stripped alias of the fixed target. Query-value,
  explicit-empty-query, or userinfo drift therefore cannot collapse into a
  stable URL shape.
- The fixed old/new HTTP profiles differ at `Accept-Encoding`; the only valid
  non-blocking authority row is
  `explained_fixed_difference/profile.fixed_old_accept_encoding`. An
  `exact_match` row or any other non-blocking result is invalid worker
  evidence. Real authority blockers remain diagnostic `inconclusive`
  evidence.
- For each round, the worker supplies the parent only the exact, bounded HTTP
  profile evidence needed by the existing compatibility gate. The parent
  takes per-case request counts from the already canonical samples, reruns
  that gate, and requires its rows and blockers to equal the worker summary.
  JSON object order is not evidence: after validating the fixed old
  provenance and identity values, the parent rebuilds local copies in the
  authority's declared field order before invoking the gate.
  These validation-only profiles are removed before final evidence is
  printed, so a fabricated blocker code or altered validation input cannot be
  accepted or echoed.
- Successful worker output is treated as untrusted evidence. The parent
  requires the exact success envelope, regenerates the canonical samples,
  totals, limits, and classification, and checks fixed target/catalog digests,
  provenance, authorization digest, order, profile checks, and deadline shape.
  It also rebuilds each case's requested URL descriptor from the fixed SOA
  target and requires every final URL to remain in the target's fixed allowed
  origin. Missing, extra, inconsistent, off-target, or noncanonical fields
  become a sanitized `inconclusive` worker-output failure.
- The parent records a frozen allowlisted reason code and boolean result for
  every success-envelope predicate: top-level shape, schema, sample order,
  canonical core, fixed metadata, fixed digests, execution order, fixed
  requested URL, allowed final origin, outer budget, profile validation
  inputs, profile recomputation, and profile-check schema. These audit fields
  distinguish the failed predicate without echoing raw worker output or
  relaxing any validator.
- Before starting the diagnostic worker, the parent resolves and validates a
  unique checkout-external bundle destination beneath
  `C:\Project\web_listening_new_delivery_state`, derived from the authorization
  window SHA-256. An existing destination fails closed before any probe can
  start and is never overwritten.
- After the worker returns, the parent writes only a safe validation
  projection and any present `new-sample-1`/`new-sample-2` SQLite and blob
  artifacts through a temporary staging directory followed by an atomic
  rename. It never copies the legacy checkout, tar archive, unrelated files,
  raw worker envelope, bodies outside the governed blobs, raw URLs/queries,
  credentials, headers, or authorization-window value.
- The canonical bundle manifest records each copied relative path, size, and
  SHA-256. Final parent evidence records bundle outcome, path, manifest SHA-256,
  file count, and a stable failure reason when persistence is unavailable.
  Bundle failure remains `inconclusive` and never claims persistence success.
- If the supervised worker times out or fails, all four fixed sequence slots
  are emitted as `not-observed`. Actual request, byte, and elapsed totals are
  `N/A` with `within_budget=false`; no zero-use or successful-budget claim is
  fabricated from missing worker evidence.
- If parent-observed elapsed time crosses 65 seconds even though the worker
  reports success, the parent emits only the outer-deadline failure envelope;
  it cannot return a successful classification with a failed deadline flag.
- `http.content_sha256` remains a strict byte digest. Zero bytes require the
  SHA-256 of the empty byte string, and that digest requires zero bytes; the
  fixed positive word threshold also requires a nonempty body. No
  normalization, ignore rule, semantic comparison, or accepted difference is
  introduced.
- Every successful case requires at least one request. Per-case counts must
  still sum exactly to the sample and system totals and remain within the
  unchanged caps; zero-request success cannot be classified as stable.
- Sequence/sample identities, successful process return codes, fixed budget
  integers, and expected threshold counters require JSON integers and reject
  booleans or integral-valued floats. Measured elapsed seconds remain finite
  nonnegative real values as declared by the evidence contract.
- Error evidence uses a small frozen set of codes and types generated by this
  harness. Unknown probe values, including token-shaped strings, become
  `volatility.unsafe_error` with an unknown type rendered as `N/A`; regex shape
  alone never makes an error value safe to print.

The Issue #67 body records the earlier #21 observation that SOA monitor and
document lengths matched across the old/new serial run while their SHA-256
values differed. That earlier observation is insufficient to attribute the
difference and is not reclassified by this report.

### Offline forensic appendix

An earlier read-only implementation-worker inspection found two fixed URL
artifacts in each of `new-sample-1` and `new-sample-2`. In both rounds the
artifact sizes were 330,890 and 317,005 bytes. For each size, the SHA-256 value
differed between round 1 and round 2. At that time, both SQLite stores passed
their integrity and foreign-key checks, and their recorded blob SHA-256 values
and sizes matched the files.

Before deletion, a separate fresh I/O auditor confirmed that the temporary
artifact root existed with 501 files totaling 11,169,649 bytes and recorded the
sizes and SHA-256 values of the two SQLite files and four blob files. That
auditor did not independently repeat the SQLite integrity, foreign-key, or
database-row-to-blob checks. No immutable copy was made. A later offline pytest
temporary-directory rotation deleted that artifact root, so the stores are no
longer available for reinspection.

The historical hashes support only new-side time variation; they are not
complete Live evidence. The corresponding old-side samples and the request,
byte, time, profile, authorization, target, and catalog evidence were not
retained in the first run's final envelope. The deleted artifacts cannot establish
whole-run `site_dynamic` or any cross-system attribution. The final
classification remains `inconclusive`, and Issue #21 remains `BLOCKED`. The
later launcher attempt was `ABORTED` without producing Live evidence. The
subsequent actual diagnostic retained a separately audited bundle, but it
proved only new-side artifact I/O and also ended at the `inconclusive` evidence
gate described above. Neither event alters or replaces this historical record.
The later final bundle is a separate immutable record: it preserves the safe
old-side failures, complete new-side evidence, caps, profile diagnostics, and
validation result described in Status and scope. It does not convert the
historical artifacts into complete evidence or make Issue #21 release-ready.

## Evidence and classification contract

A complete Live record under this contract must contain four ordered samples.
The first 2026-08-30 run and the diagnostic did not satisfy this requirement;
the final one-shot preserved the four slots but correctly remained
`inconclusive` because both old samples failed before acquisition. Each valid
sample must have the exact `monitor` and `document` case set and record:

- system, sample number, and global sequence;
- child-process outcome and return code;
- status, MIME type, safe requested/final URL descriptors;
- content SHA-256 and byte size;
- fixed expected word/document-link thresholds, observed counts, and the
  derived `met` result;
- per-case and per-sample request/byte accounting;
- per-sample and per-system time accounting;
- stable, redacted error code/type pairs;
- the existing HTTP profile authority result for each old/new round; and
- one final whole-site classification.

The classifier is pure, offline, and deterministic. It produces only:

| Classification | Evidence required |
|---|---|
| `stable_match` | For both cases, all four valid sample SHA values are identical. |
| `stable_cross_system_mismatch` | Every case is either a stable match or is stable within each system but different across systems, and at least one case has the latter split. |
| `site_dynamic` | Every case is either a stable match or changes within both systems, and at least one case has the latter change. |
| `inconclusive` | Any missing sample/case, process or case error, zero-request success, missing or unmet fixed threshold, budget violation, whole-run deadline, schema drift, mixed status/MIME/URL shape, inconsistent size for one SHA, one-sided change, or mixed dynamic/system-split attribution. |

One safe case can never hide an unsafe shape in the other case. Mixed causal
evidence across monitor and document also fails closed to `inconclusive`.

## Allowed inference

Only the following inference is allowed from a complete fresh record:

- `stable_match`: the bounded interleaved SOA sample did not reproduce a byte
  mismatch under the fixed old/new profiles.
- `site_dynamic`: the bounded sample supports site-time variability because
  both systems changed internally.
- `stable_cross_system_mismatch`: the bounded sample supports a repeatable
  system-specific byte split for at least one fixed case.
- `inconclusive`: the bounded sample cannot safely attribute the earlier SOA
  mismatch.

These are bounded evidence statements. They do not establish behavior outside
the two samples or outside the fixed SOA monitor/document targets.

## What this cannot prove

This Issue cannot prove that:

- SOA is generally static or dynamic;
- a difference is harmless, semantically equivalent, or acceptable;
- a request header alone caused a content difference;
- either implementation is correct or defective;
- normalization, ignored fields, semantic comparison, or an accepted
  difference is justified;
- CAS or IAA still match in a later release run;
- Issue #21 is release-ready; or
- any production switch, deployment, or rollback should occur.

## Issue #21 follow-up conditions

| Fresh classification | Required next step for #21 |
|---|---|
| `stable_match` | Resume #21 from latest `main` and run a completely fresh three-site SOA/CAS/IAA Required Live. This Issue's run cannot be reused as release evidence. |
| `site_dynamic` | Keep #21 blocked until the user chooses a stable target, a shared capture/replay contract, or another explicit migration strategy. |
| `stable_cross_system_mismatch` | Keep #21 blocked and open a new, precise functional prerequisite Issue for the proven system split. |
| `inconclusive` | Keep #21 `BLOCKED`; do not infer a cause or relax the comparison. |

## README 1-2 and 18-20 alignment

This work improves the explanation of governed website-acquisition release
evidence: it makes strict content observations, failures, and budget use
traceable across the fixed old/new acquisition paths. Reusing the probes'
existing word and document-link counters only validates the fixed live target;
it does not add a new parser or content-analysis feature. This work belongs
only to the Phase 20 test and release-evidence layer described by README
section 18. It does not acquire authority from Request, Site Skill, Tool
Registry, Artifact, Result, Runtime, or Interfaces, and it does not alter their
contracts or execution.

The work preserves README sections 19-20: acquisition remains deterministic,
governed, repeatable, and independent of AI; strict observations remain byte
comparable. It adds no PDF/Word/Excel parsing, RAG, search, question answering,
content analysis, AI behavior, production switching, or deployment command.
