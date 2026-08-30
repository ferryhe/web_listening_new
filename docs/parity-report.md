# Phase 20 Parity Report

Status: **release blocker — fresh Live Test and independent I/O audit pending**.
No production switch has been performed or authorized.

## README 1–2 Alignment

This evidence advances README §1's governed website-acquisition goal by checking
that the fixed legacy baseline and the current system expose compatible success,
failure, Artifact, Observation, Manifest, Usage, and Error semantics. It is a
read-only validation/release layer across Request, Site Skill, Tool Registry,
Artifact, Result, Runtime, and Interfaces. It gains no authority owned by those
modules: it cannot expand scope, select production tools, access the Artifact
Store outside a test run, activate a Site Skill, or execute a release.

The change does not add PDF, Word, or Excel parsing, RAG, search, Q&A, content
analysis, or an AI dependency. Live inputs remain the three governed catalog
sites and two URLs per site.

## Frozen inputs and normalization

- Legacy source: `ferryhe/web_listening@9fe9ea53104dd008086dfa0e86c35c50b75f4ce5`.
- Offline corpus: [`tests/parity/fixtures/phase_20_offline_corpus.json`](../tests/parity/fixtures/phase_20_offline_corpus.json), with exact fixed-commit snapshots of
  [`capture-result-v1.sample.json`](../tests/parity/fixtures/legacy/capture-result-v1.sample.json)
  and [`access-rejection-error-v1.sample.json`](../tests/parity/fixtures/legacy/access-rejection-error-v1.sample.json).
- Live snapshot: [`tests/live/phase_20_site_targets.json`](../tests/live/phase_20_site_targets.json), projected only from the current three rows of [`dev_test_sites.json`](../tests/live/catalog/dev_test_sites.json).
- Catalog authority is the base Git blob's 3,610 LF bytes, SHA-256
  `B13747A4516810BED5AB5FF164EFC3FD9F5F1C91B51FF3DCE5708A23724A0E6E`.
  A CRLF checkout is canonicalized to the same LF Git-blob basis before both
  digest and three-row projection checks; the catalog itself is not changed.
- Before any run, the corpus freezes the only ignored fields: run, attempt,
  Artifact and Observation identities; start/finish timestamps; and runtime
  milliseconds. It freezes the sole value normalization `web_http` →
  `acquisition.web_http`. That exact rule projects the legacy success fixture's
  `/executor_id` onto the current Result Attempt `tool_id`; the legacy rejection
  fixture has an evidenced `N/A` identity. A run cannot add either an ignore or
  a normalization, and any other current tool identity is a blocker.
- Every remaining mismatch must match an exact old/new value pair and written
  rationale, or [`test_unexplained_semantic_difference_is_a_blocker`](../tests/parity/test_phase_20_parity.py)
  classifies it as `blocker`.

## Parity results

| Case | Artifact | Observation | Manifest | Success/failure | Usage | Error | Classification |
|---|---|---|---|---|---|---|---|
| Fixed `capture-result.v1` success | legacy every leaf `N/A`; current count/SHA/size/MIME from Result plus store readback | legacy every leaf `N/A`; current persisted identity/content relationship verified | legacy every leaf `N/A`; current content/Artifact/tool relationships verified | legacy state and normalized tool identity project to current success | legacy `N/A`; current exact values | availability `none`; empty code/message/retryable/details/error-type lists in both | `accepted`: every absent legacy A/O/M/Attempt leaf has one exact `N/A` → current rule; current values come from actual ArtifactStore readback, not caller body; legacy schema → current public schema remains an exact classified difference |
| Fixed `access-rejection-error.v1` | legacy every leaf `N/A`; current none/count zero | legacy every leaf `N/A`; current none/count zero | legacy every leaf `N/A`; current failure Manifest present with zero Artifacts | legacy error projects to failure and agrees; current failed Attempt tool/version are explicit | legacy `N/A`; current exact values | availability/code/error-type agree; exact message, retryable, and details surfaces are classified | `accepted`: message (`access failed closed while resolving robots policy` → `Acquisition did not complete.`), retryable (`true` → `N/A`), and details (`N/A` → `{}`) are separate exact rules; any Error or A/O/M/Attempt leaf drift is a blocker |
| SOA/CAS/IAA live monitor + document | pending | pending | pending | pending | pending | pending | `blocker`: required fresh Live Test has not run |

Offline evidence command: `python -m pytest -q tests/parity -m "not live"` →
`211 passed` (exit `0`). The larger offline governance check against the Live file
collects the additional failure, semantic-drift, and invocation-shape regressions
→ `219 passed, 3 deselected` (exit `0`). Neither result is a Live PASS.

The old projections are rebuilt during each offline run from the two snapshot
files above. Their LF SHA-256 values are respectively
`bf31d5bfb24a9f1ba27340d4331c1e52e5661585aa1f7071db74123d65d64231`
and `88a077f68536241583e06d564c435cc7faf9d5c3731821e42a505b3d59e2c169`.
Every projected leaf has a frozen JSON-pointer/derivation or explicit `N/A`
source. The legacy capture fixture's declared all-`a` content SHA is not the
digest of its `content.text`; it is excluded with a written reason, while the
compared digest is deterministically derived from those evidenced text bytes.
The current success projection does not reuse that caller fixture body as
persistence evidence. The helper reads the Observation and content back through
`ArtifactStore.get_observation`; the runner derives stored digest/size and checks
Artifact, Observation, Manifest, and Attempt counts, MIME, identities, tool
id/version, and content relationships from that readback. Each absent legacy
leaf is independently sourced as `N/A` and accepted only against its exact
current value.

The legacy live probe uses `git archive` at the fixed commit into a pytest
temporary directory. Its frozen source fingerprint is commit `9fe9ea5...` plus
archive SHA-256 `cb7a83f5979a852e27c4dc6f24b31850420c037470d1cd13eae01aaace775f74`.
Before extraction, the old-side setup verifies the four #61 Git objects that
prove the reachable HTTP path: identity contract `852c3776...`, pinned transport
`859a28d9...`, access gateway `46934a3f...`, and governed-read caller
`d9e6262c...`. It then constructs the fixed commit's real `DiagnosticIdentity`,
`AccessGatewayConfig`, `AccessGateway`, sealed `SafePinnedTransport`, and
`GovernedReadGateway` directly. It does not call the incompatible fixed
`build_runtime_read_gateway` helper and does not alter the archive.
The fixed metadata requires Python `>=3.12,<3.13`, its README requires Python
3.12.x and records verification with 3.12.3, and its CI rejects 3.11. The probe
therefore accepts only CPython 3.12.x. The current controlled evidence runtime is
3.12.13; evidence records the exact version, a redacted resolved executable,
executable-path SHA-256 `f22578e84bbcc711a4613ca74ce56cafae11c337d13d9f3fcb7dca537d7a2eab`,
and executable SHA-256 `560b9ef7d856608ab8da02ded2dc8a1951ad1f424c382c0ec6a698874165a18e`
without hard-coding a host path or making 3.12.13 the general policy.

The exact non-stdlib distribution closure observed while importing the fixed
governed-read path and constructing its gateway is frozen below. Each pair is
module SHA-256 / distribution `RECORD` SHA-256.

| Import / distribution | Version | Content fingerprints |
|---|---:|---|
| `annotated_types` / `annotated-types` | 0.8.0 | `a7104a4d439b27a9f74fc0be236b9ba1b7831e6044026802a205abc1298a9bc8` / `3999aa3e7cd1afa1ae67b55bf5b04bbc3ca55fdd6c7dcfe571b1aad05da849af` |
| `click` / `click` | 8.5.0 | `5abfc54d37d47cc788b7e7a05e9514787f8c5a0b7db429d0f24d748ac89964ca` / `4a523c0c5110a56f01ccedcea0dd40973a227083ead89333427baf414cb21c95` |
| `httpx` / `httpx` | 0.28.1 | `0ac6997bac998f4ac783adf6d8058a587193315afdb718047c3e4fdff46bcfad` / `167d3fdc01ae4df2c6f27edc08258417ed4fb89eed4eb7d5b1ef1242d31d3a72` |
| `idna` / `idna` | 3.19 | `8514c3ed53136a3596ebdf512fa487bbdd7da5a99adcaed82e0363d2c306d3af` / `3ff9f0b977f1c7619cdef69c72033d54d4ad8aaf5117b3df270e215647e33f45` |
| `pydantic` / `pydantic` | 2.13.4 | `e62127278c07bf5384cdd2903f368a69929f3b8a524000bae4e0eb608ebf4bc6` / `961389739a4b3e924d2da2248f92dcf035b3a0cb45168a1b2790be21dba19e6d` |
| `pydantic_core` / `pydantic_core` | 2.46.4 | `e644150a9eac4372c4ff826c8f614df288a561e39250e96c58e447f17806c6bf` / `3a804f1dcad67692d7faed9dbb37595678654a1cfccda37f9e2bd01aeef51b05` |
| `pygments` / `Pygments` | 2.21.0 | `83fe99688e06ed80d7d44d325f79027de83a434c60f249bceffd67fda3e7d2b1` / `149ba876dcb44ae7aaba8f805bd814a3e565317628e89e4c168b03b9cc97db83` |
| `typing_extensions` / `typing_extensions` | 4.16.0 | `4040ca1a1ecbee00d1385c12a93084d1c5bd46f0b774f07e5ae7e91c4f55e696` / `a346a921aa5be35b34ced3258614183d152887b954caaae5de2a94be72d5f2ec` |
| `typing_inspection` / `typing-inspection` | 0.4.4 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` / `06f60204c0b7d67df21f09681e2db4781ef463cad5fb7dfc7a749b232a0ec8ae` |
| `yaml` / `PyYAML` | 6.0.3 | `b19dfcc333d6a75dfd73073901164507252f271b41d3b5f7d85510033a0547a7` / `c55b91c92f924915927c027b1ffc40d102325d0ad29b4c89f0534ac977024f56` |

The fixed source imports PyYAML through `contracts.tool_result` and
`blocks.acquisition_profile`, so it remains required. The extracted
`web-listening` module is deliberately excluded from installed-distribution
metadata and is locked by commit/archive instead. Parent and child verify the
same closure before networking; any Python, module, version, `RECORD`, or source
mismatch produces two complete blocker records. `PYTHONPATH` points only at the
extracted fixed source; the old repository's current branch and `.venv` are
never read or copied. The new child uses the current Issue worktree and a pytest
temporary Artifact Store. Evidence prints redacted environment paths, the fixed
commit, Python versions, independently constructed Request descriptors and
digests, requested/final URLs, redirects,
status/MIME/hash/size, raw budgets, expected → observed thresholds, all Result
dimensions (or explicit `N/A` for the legacy gateway-only surface), and the
difference classification. The legacy probe hard-partitions both requests and
response bytes per case, so a failed first case cannot reuse or exceed the
second case's share of the per-system/per-site cap. Its governed network deadline
is 28 seconds, strictly inside the unchanged 30-second parent process cap.
Spawn, timeout, missing output, JSON parse, schema, setup, environment, and
unexpected outer old/new call-boundary failures all emit two complete
fail-closed case records, pass through threshold/difference
classification, and remain blockers. Both old and new systems run in separately
bounded subprocesses. Evidence distinguishes each redacted child command, cwd,
environment/revision identity, process outcome, and real return code from the
fixed outer pytest command whose actual return code is recorded by the Live Test
agent. A parseable child record must contain
every top-level and nested field consumed by comparison and threshold code;
partial dimensions or invalid nested shapes become `legacy.output_schema` or
`new.output_schema` blockers. A new Runtime job without a Result exits the child
and becomes complete two-case `new.no_output` blocker evidence.

Before either child starts for each site, the outer harness freezes a
`phase-20-candidate-identity.v2` record from two exact Git boundaries. First, the
current HEAD must descend from prerequisite-sync base
`9450cb5968b3a24be50284a502c5adba696b20e6`, and that base-to-HEAD range must add
exactly the 12 files integrated by #63, with no other status or path. No future
merge SHA is hard-coded. Second, the restored #21 worktree relative to that HEAD
must contain exactly one tracked modification, `README.md`, and no added,
deleted, renamed, conflicted, or non-ignored untracked path. Git's
`git ls-files --others --exclude-standard` remains the sole untracked ignore
authority; any path it returns blocks the run. There is no second cache-name or
suffix filter, so a returned `.pyc`, `.pytest_cache`, or `*.egg-info` path outside
the whitelist also blocks.

Those two boundaries form the exact sorted 13-path identity: the README overlay
plus the integrated documents, target snapshot, Live test, fixed fixture
snapshots, offline corpus, probes, runner, and both Phase 20 test files. The
merged #61 classifier/helper tests are read-only base files and do not enter the
identity. Any missing or extra integrated path, wrong Git status, ancestry or
branch drift, non-README overlay, or untracked path fails before networking.
Every candidate must be a regular readable file. Evidence contains only each
relative path, raw-byte SHA-256, byte size, the fixed prerequisite base revision,
the separately measured current HEAD revision, branch, and a SHA-256 over their
canonical JSON; it never contains file bodies, ignored caches, or the external
controlled runtime. Old and new invocation/environment evidence bind that same
aggregate, including current HEAD, to the independently measured digest and size
of their respective legacy/new probe. The old child still identifies fixed commit
`9fe9ea5...`; the new child and every new-side boundary-failure record identify
the measured current HEAD, never the prerequisite base. After both child
boundaries return, the outer
process reads and hashes every file again. Any path, digest, size, base, branch,
child binding, or readability drift adds `candidate_identity:drift`; child
self-report alone cannot satisfy the gate.

The authorized Live evidence will retain the complete candidate identity that was
true for that run. The only permitted post-Live change is an evidence overlay in
these two documents and README. Because those documentation bytes legitimately
change the all-candidate aggregate, the final I/O audit and PR must record the
final commit identity and identify that overlay. The runtime-critical subset —
`tests/live/phase_20_site_targets.json`,
`tests/live/test_phase_20_parity_live.py`, and all `tests/parity/**` files — must
remain byte-for-byte identical to the Live identity. Any runtime-critical byte
change invalidates the Live evidence and requires a fresh authorized Live run;
no self-referential digest is written into a candidate file.

This repository does not currently Git-ignore all interpreter/test caches, so
the evidence operator must audit and precisely remove verified cache artifacts
before every gate. Python runs use `PYTHONDONTWRITEBYTECODE=1`. Focused and
combined commands explicitly pass `-p no:cacheprovider`; the exact full command
remains `python -m pytest -q` with the disclosed environment
`PYTEST_ADDOPTS=-p no:cacheprovider`. The Live agent must disclose and use that
same environment while still invoking the required exact command
`python -m pytest -q -m live tests/live/test_phase_20_parity_live.py`.

Legacy missing-child records retain the frozen per-case upper bounds. New
missing-child and pre-spawn boundary records use the single new-probe failure
schema: Request/Result/transport request and byte counts are explicit `N/A`,
while limits, invocation, cwd/environment identity, process outcome, return
outcome, and stable error are retained; the unknown counts independently trip
the outer evidence gates.
Normal old/new child Error records have a strict shape covering availability at
projection time plus code, message, retryable, SafeError details, and error type.
Unavailable surfaces are explicit `N/A`; success is the exact `none`/empty-list
shape. Missing or mistyped leaves become child schema failures, while the outer
projection independently preserves every leaf so any drift remains a semantic
blocker.

At each actual gateway/Runtime call boundary, old and new independently project
the seed, allowed origins, include paths, content types, Site Skill presence,
exploration flag, and per-case Request budgets into the frozen
`phase-20-request-descriptor.v1` shape and hash their own canonical bytes. The
outer gate recomputes both hashes and blocks any descriptor or digest drift.
`site_skill_digest` is not a Request argument and therefore remains separate
snapshot provenance; it is not included in the Request digest.

The same call boundaries also record an order-preserving HTTP profile descriptor
and independently calculated digest for every governed transport request. The
old descriptor comes from the actual fixed transport call and the actual gateway
identity: `web-listening-runtime-v2`, product token `web-listening`, directly
aligned `web-listening/0.1` User-Agent, and identity SHA-256
`de7b07e47b4bb10246395f550e81ce66dabc9680747bbf8cb881109a194e70a5`.
The new probe directly imports `WEB_HTTP_REQUEST_PROFILE` and its
`14450398cbe8c3226505fad035a421c1c3b8a50e820c78b02d22a39888855377`
SHA from the actual in-process transport module; it does not copy a second
profile authority. Before any content semantic comparison, the parent invokes
the merged #61 `classify_http_profile_compatibility` authority. The only accepted
current result is `explained_fixed_difference` /
`profile.fixed_old_accept_encoding`, whose sole leaf is
`accept_encoding: identity, gzip` → `identity`. Provenance, identity, field
order, field value, descriptor digest, authority/observation agreement, or
per-call count drift is a blocker. Missing-child and outer-boundary evidence uses
the same profile shape with explicit `N/A`/zero observations and therefore fails
closed. Content URL/status/MIME/size/SHA comparison occurs only after this gate;
`http.content_sha256` remains strict and has no accepted-difference rule.

These are offline prerequisite-sync contracts only. No fresh Live request was
made, and SOA/CAS/IAA remain pending and NO-GO.

Artifact, Observation, and Manifest comparison freezes the new system's counts,
SHA/size/MIME agreement with the observed HTTP body, identity relationships,
and Manifest/Attempt tool id and version. Legacy first-class surfaces remain
exact `N/A`; the only accepted differences are the predeclared `N/A` to one
internally consistent new acquisition. A count, content field, relationship, or
tool identity drift changes the stable projection and is a blocker.

For each new-system case, the child snapshots governed transport response bytes
immediately before and after the Runtime call. Result `usage.bytes_received` and
that independent transport delta must both be nonnegative exact integers and
must be equal. The case deltas are summed and must equal both the declared case
total and the system transport `response_bytes`. Missing, boolean, float, string,
negative, mismatched, or unreconciled values become blocker evidence. The fixed
legacy gateway has no comparable Result Usage surface, so its value remains exact
`N/A`; only the predeclared `N/A` to valid-and-consistent evidence difference is
accepted, without equating legacy and new measurement bases.

Legacy per-case byte evidence is independently strict. Every normal record must
contain exact nonnegative request/response/target counts, exact upper bounds,
`tool_attempts=N/A`, one frozen byte basis, and `within_budget=true`, with actual
values inside their declared bounds. Success accounts target wire/decoded bytes
plus one frozen robots upper bound; conservative failure records already include
that robots allowance in their per-case upper bound, so it is not added twice.
The child and outer gate separately reconcile the resulting case sum with the
system response-byte total. Missing, boolean, float, string, negative, relation,
or aggregate drift is a blocker.

The child also snapshots governed transport request count immediately before
and after every new Runtime call. Both Result `usage.requests` and that delta
must be nonnegative exact integers and equal; case deltas must reconcile with
the declared case total and system transport request count. The legacy child
uses its gateway request count (exact on success, frozen per-case upper bound on
failure), and its case sum must independently reconcile with its aggregate
budget. These old/new numeric bases are retained in raw evidence and are not
compared to each other; parity accepts only the predeclared `N/A` → present,
exact, internally consistent new Result surface. Missing, malformed, negative,
boolean, per-case drift, or a schema-valid `2 + 2 != 5` aggregate is a blocker.

The aggregate gate independently requires each old/new budget to report a
finite, nonnegative numeric `elapsed_seconds`, a finite positive `max_seconds`
equal to the frozen 30-second limit, and `elapsed_seconds <= max_seconds <= 30`.
Missing, boolean, non-finite, string, or `N/A` time evidence adds a stable
`*_system:time_evidence` blocker; valid numeric overruns add
`*_system:time_budget`. These blockers remain present alongside any system
failure, including conservative boundary records whose elapsed time is `N/A`.
Offline Result projection reads the immutable public `result.schema_version`;
the corpus classifies each fixed legacy schema → `web-listening-result.v1`
difference explicitly and does not add contract normalization.

Before comparing aggregate counts, the outer gate requires `requests` and
`response_bytes` to be nonnegative exact integers and rejects booleans. Missing,
null, string, float, non-finite, negative, or boolean values add a stable
`*_system:count_evidence` blocker without preventing the two case comparisons;
only valid integers can reach the frozen 8-request / 4-MiB limit checks. A normal
legacy child budget must have its exact 13-field shape, nonempty basis strings,
declared limits equal to the payload, actual counts within those limits, the
frozen robots upper-bound formula, 28-second governed deadline inside the
30-second process cap, concurrency 1, and retry 0. Any parseable drift becomes
`legacy.output_schema`; conservative failure budgets are intentionally not
validated as normal child output.

`WEB_LISTENING_LIVE_SITE` is diagnostic-only. Setting it makes excluded site
parameters fail instead of skip and marks the selected site's evidence as a
release blocker, so the exact whole-module command cannot return a final PASS.
Final release evidence requires the selector to be unset, the exact ordered
`soa`, `cas`, and `iaa` parameter set, and outer summary `3 passed, 0 skipped`
with zero live xfails. Ordinary warnings do not change that frozen contract.

## README §19 production criteria

Each `PASS` below is limited to an existing reproducible offline contract. It
does not override the Phase 20 live and independent-audit release gates.

| # | Result | Reproducible evidence |
|---:|---|---|
| 1 | PASS | CLI/REST strict Result parity: [`test_acquire_parses_request_and_emits_the_unified_job_and_result_contract`](../tests/interfaces/test_cli.py), [`test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema`](../tests/interfaces/test_rest.py), and MCP [`test_complete_client_stdio_server_boundary`](../tests/interfaces/test_mcp.py). |
| 2 | PASS | No-AI acquisition: [`test_no_ai_fake_transport_completes_one_exact_acquisition`](../tests/runtime/test_service.py). |
| 3 | PASS | MCP calls the public Runtime boundary: [`test_source_calls_only_public_runtime_and_site_skill_boundaries`](../tests/interfaces/test_mcp.py). |
| 4 | PASS | Site Skill narrows and resolves without exploration/tool execution: [`test_resolution_intersects_scope_and_budgets_without_invoking_tool`](../tests/site_skill/test_resolve.py). |
| 5 | PASS | Candidate remains inactive: [`test_candidate_stays_inactive_until_explicit_activation`](../tests/site_skill/test_repository.py). |
| 6 | PASS | No switching when false: [`test_explore_false_never_switches_after_retryable_failure`](../tests/runtime/test_explore_all_tools.py). |
| 7 | PASS | Eligible ranked switching only: [`test_unqualified_tool_is_skipped_and_rank_does_not_use_registration_order`](../tests/runtime/test_explore_all_tools.py). |
| 8 | PASS | Policy/security/budget cannot be bypassed: [`test_policy_security_and_budget_rejections_stop_without_switching`](../tests/runtime/test_explore_all_tools.py). |
| 9 | PASS | Each success creates an Observation: [`test_first_store_and_same_bytes_keep_one_blob_two_observations`](../tests/artifact/test_store.py). |
| 10 | PASS | Same bytes reuse one Blob while retaining two Observations: the same Artifact test above. |
| 11 | PASS | Changed bytes add a Blob without overwrite: [`test_changed_bytes_add_blob_without_overwriting_history`](../tests/artifact/test_store.py). |
| 12 | PASS | Failed/rejected evidence has no success snapshot: [`test_failed_or_rejected_results_keep_evidence_without_snapshot`](../tests/result/test_result_manifest.py). |
| 13 | PASS | Transform failure preserves source and never falls back: [`test_transform_failure_preserves_original_and_never_falls_back`](../tests/runtime/test_transform_flow.py). |
| 14 | PASS | External protocol runner owns only attempt-local output and Runtime performs the final commit: [`test_output_path_must_be_portable_regular_content_inside_attempt`](../tests/tool_registry/test_subprocess_runner.py) plus [`test_success_stores_derived_markdown_lineage_and_tool_attempt`](../tests/runtime/test_transform_flow.py). |
| 15 | PASS | Side-by-side qualification/atomic preservation/rollback: [`test_failed_upgrade_keeps_old_active`](../tests/tool_registry/test_tool_lifecycle.py), [`test_activation_commit_failure_preserves_old_pointer`](../tests/tool_registry/test_tool_lifecycle.py), and [`test_explicit_rollback_switches_to_qualified_old_version`](../tests/tool_registry/test_tool_lifecycle.py). |
| 16 | PASS | Registration does not change the public Request shape: [`test_registration_does_not_change_public_request_shape_or_source`](../tests/tool_registry/test_registry.py). |

## README §18 and §20, plus merged follow-up evidence

- §18 final comparison step: frozen offline success and rejection paths are
  implemented; the required three-site live comparison remains a blocker.
- §20 positioning is unchanged: the runner compares deterministic governed
  acquisition evidence and does not turn Site Skill, AI, browser tools,
  Observation, Blob, Artifact, or Result into a new authority.
- Issue #38 / PR #56 incremental site refresh is covered by
  [`test_normal_refresh_uses_stored_recipe_and_builds_six_exclusive_sets`](../tests/runtime/test_site_refresh.py)
  and strict SiteRefresh Result tests in [`test_site_refresh_result.py`](../tests/result/test_site_refresh_result.py).
- Issue #54 / PR #55 Result URL safety is covered by
  [`test_public_long_slug_round_trips_across_result_url_siblings`](../tests/result/test_result_manifest.py)
  and the adjacent URL safety rejection vectors.

## Migration table

| Fixed `9fe9ea5` source | New test/runner | New location | Decision and reason |
|---|---|---|---|
| `web_listening/dev_targets.py` | exact three-row projection/digest checks | `tests/live/phase_20_site_targets.json`, `test_phase_20_parity_live.py` | Rewrite: retain fixed SOA/CAS/IAA selection; use the audited new catalog as runtime truth. |
| `web_listening/smoke_sites.py` | no product classification import | frozen target `historical_expectation` only | Discard executor/catalog truth; retain history only as expected → observed evidence. |
| `tools/run_dev_regression.py` | offline semantic runner and live thresholds | `tests/parity/phase_20_runner.py`, `test_phase_20_parity_live.py` | Rewrite: retain bounded regression/report structure; discard downloads, old JSON, and default networking. |
| `tools/run_dev_daily_monitor.py` | per-case evidence records | `test_phase_20_parity_live.py` | Rewrite: retain report shape; discard persistence, analysis summaries, and scheduled/default live behavior. |
| `tests/live/test_catalog_site_skills_live.py` | opt-in selector, redirect/scope and classification evidence | `test_phase_20_parity_live.py` | Retain opt-in/fixed canary pattern; narrow to the three frozen targets. |
| `tests/live/test_authorized_access_gateway_canary.py` | legacy fixed-commit probe and new governed Runtime | `tests/parity/legacy_live_probe.py`, `test_phase_20_parity_live.py` | Retain authorization, safe evidence, and fixed budgets; reject environment URL injection. |
| `docs/testing/fixtures/` | fixed snapshot-backed success/rejection corpus | `tests/parity/fixtures/legacy/`, `tests/parity/fixtures/phase_20_offline_corpus.json` | Retain only fields deterministically projected from fixed fixture bytes; mark absent contracts/Usage `N/A`; discard secrets, analysis/classification truth, and old internal JSON identity. |
| Old Artifact/Manifest/ToolResult contract tests | semantic projection and blocker classifier | `tests/parity/test_phase_20_parity.py` | Compare only fixture-evidenced common fields; make unavailable Artifact/Observation/Manifest/Usage surfaces explicit instead of inferring them. |

## Release decision

Current decision: **NO-GO**. The offline differences are explained and bounded,
but required fresh Live Test evidence and the separate I/O audit are absent.
Any live failure, threshold miss, budget violation, Request-digest mismatch, or
unexplained semantic difference remains a blocker and must not be converted to
PASS by changing URLs, budgets, ignores, or expectations in this Issue.
