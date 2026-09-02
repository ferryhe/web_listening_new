# Issue #72 Independent Site-Batch Delivery Development Report

## Outcome

The new-system-only offline implementation now uses exactly one production
`SiteBatchRequest` for FIRST and one for REFRESH. Their parent Request identities,
run IDs, and hashes differ. Within each phase, production creates a fresh
12-request, 52,428,800-byte, 60-second ledger for every frozen site, with
concurrency 1 and retry 0. The frozen
README evidence matrix remains complete. After prerequisites #75, #78, and #83, both
public batch calls retain their real ordered child target Results, including derived
Markdown, lineage, Transform Attempts, and goal-aware file evidence without
creating another Request or network budget. The one authorized multi-site Live
run and the different fresh independent I/O audit both passed. Required CI and
separate production-switch authorization remain, so the release decision is
still **NO-GO**. This change does not execute a production switch.

## Frozen README authority and matrix

Acceptance truth is the baseline Git object, not the working README:

| Field | Verified value |
|---|---|
| Baseline revision | `2fed958ee67d3c7d714fde40a372bc8b7389bf87` |
| README blob | `edcc24b4e09d69a316b28ed403f86107ef5dcb27` |
| Canonical CRLF SHA-256 | `8515EF08F2CB2C81A08DB89BA307A37D6D12FCD921782AD567E47B529BCFCB44` |
| Line count | 731 |
| Clause rows | 191 |
| Unique commands | 91 |
| Missing/duplicate/unexplained N/A | 0 / 0 / 0 |

`load_frozen_readme` reads the exact Git blob with `git cat-file`, verifies its
type, revision binding, canonical CRLF SHA-256, and line count. It never reads the
working README as acceptance truth. `extract_readme_clauses` then reconstructs
only verifiable normative prose, list, contract-table claims, five exact
independently normative colon-ending lead-ins, and three precisely bound
normative contract fences from §§1, 2, 4–17, and 19. The recognized fences
are §5's two forbidden public Request fields, §5's seven-member
`explore_all_tools` eligibility intersection, and §12's fixed first-version
Transform identifier. Other fences remain excluded examples, including Mermaid,
source trees, ASCII layouts, hard-coded fallback, CLI, REST, and MCP examples.
Table headings, explanatory layout text, and examples columns are also excluded.
The five retained colon-ending claims freeze the five-business-module and two
support-layer boundaries, the four-input Request shape, the common logical
Result, and the external-tool Adapter translation rule. Pure list introductions
such as `Example:` and `Rules:` remain excluded. Complete normative sentences
before another colon lead-in remain clauses; this includes §11's explicit
production-browser-read disable.
It expands the §2 module table into a responsibility and a prohibition for each
business module and treats Runtime and Interfaces as separate boundary clauses.
Section 19 must reconstruct exactly 16 ordered criteria.

Every non-§19 ID is
`README-<section>-<first-eight-SHA256-of-clause>`; §19 uses the frozen
ordered IDs `README-19-01` through `README-19-16`. Each `EvidenceRow` contains the
full clause text, exact pytest node IDs, an exact `py -3.14` command, actual
observable fields, `PASS`/`BLOCKED`, and an optional N/A reason. The final matrix
has only `PASS` and no N/A. Tests also prove the working README differs from the
immutable Issue-base object
`f43000ab0f170b376b5b19cd84ee3bb2f51f13f6:README.md` only at the status line;
the older `2fed958ee67d3c7d714fde40a372bc8b7389bf87` frozen object remains the clause
matrix acceptance authority.

Clause counts are:

| Section | Rows | Section | Rows | Section | Rows |
|---:|---:|---:|---:|---:|---:|
| 1 | 13 | 2 | 16 | 4 | 14 |
| 5 | 14 | 6 | 19 | 7 | 21 |
| 8 | 10 | 9 | 6 | 10 | 17 |
| 11 | 11 | 12 | 9 | 13 | 1 |
| 14 | 2 | 15 | 1 | 16 | 13 |
| 17 | 8 | 19 | 16 | Total | 191 |

The complete machine-readable matrix is returned by
`readme_evidence_matrix`; the independent auditor reconstructed and compared all
rows without trusting this report.

## Section 19 exact matrix

| ID | Exact test node(s) | Actual output fields | Result |
|---|---|---|---|
| README-19-01 | `tests/interfaces/test_cli.py::test_acquire_parses_request_and_emits_the_unified_job_and_result_contract`; `tests/interfaces/test_rest.py::test_acquire_maps_a_strict_request_to_runtime_and_returns_exact_result_schema`; `tests/interfaces/test_mcp.py::test_complete_client_stdio_server_boundary`; `tests/interfaces/test_mcp.py::test_source_calls_only_public_runtime_and_site_skill_boundaries` | normalized Request; logical Result; public Runtime calls; routes/tools | PASS |
| README-19-02 | `tests/runtime/test_service.py::test_no_ai_fake_transport_completes_one_exact_acquisition` | completed Result without model key | PASS |
| README-19-03 | `tests/interfaces/test_mcp.py::test_complete_client_stdio_server_boundary` | real MCP client; governed Result | PASS |
| README-19-04 | `tests/parity/test_phase_20_new_system_delivery.py::test_valid_site_skill_uses_preferred_tool_without_rediscovery_or_alternate` | `Result.site_skill_used`; unique preferred Acquisition Attempt; zero Discovery/alternate calls | PASS |
| README-19-05 | `tests/site_skill/test_repository.py::test_candidate_stays_inactive_until_explicit_activation` | candidate event; active value unchanged | PASS |
| README-19-06 | `tests/runtime/test_explore_all_tools.py::test_explore_false_never_switches_after_retryable_failure` | Attempt tool IDs; exploration false | PASS |
| README-19-07 | `tests/tool_registry/test_explore_all_tools_eligibility.py::test_selection_is_the_explicit_eligible_intersection_with_stable_reasons` | full eligible intersection; stable eligibility reasons | PASS |
| README-19-08 | `tests/runtime/test_explore_all_tools.py::test_policy_security_and_budget_rejections_stop_without_switching` | rejection code; single-tool Attempt evidence | PASS |
| README-19-09 | `tests/artifact/test_store.py::test_first_store_and_same_bytes_keep_one_blob_two_observations` | Observation count | PASS |
| README-19-10 | same node as README-19-09 | one Blob; two Observation IDs | PASS |
| README-19-11 | `tests/artifact/test_store.py::test_changed_bytes_add_blob_without_overwriting_history` | two Blob digests; prior Observation readable | PASS |
| README-19-12 | `tests/result/test_result_manifest.py::test_failed_or_rejected_results_keep_evidence_without_snapshot` | Attempt/Error evidence; zero Artifact/Observation snapshot | PASS |
| README-19-13 | `tests/runtime/test_transform_flow.py::test_transform_failure_preserves_original_and_never_falls_back` | source Artifact; Transform failure Attempt; no acquisition fallback | PASS |
| README-19-14 | `tests/tool_registry/test_subprocess_runner.py::test_output_path_must_be_portable_regular_content_inside_attempt`; `tests/runtime/test_transform_flow.py::test_success_stores_derived_markdown_lineage_and_tool_attempt` | attempt-local output; Runtime final Artifact commit | PASS |
| README-19-15 | `tests/tool_registry/test_tool_lifecycle.py::test_failed_upgrade_keeps_old_active`; `tests/tool_registry/test_tool_lifecycle.py::test_activation_commit_failure_preserves_old_pointer`; `tests/tool_registry/test_tool_lifecycle.py::test_explicit_rollback_switches_to_qualified_old_version` | side-by-side versions; atomic active pointer; rollback target | PASS |
| README-19-16 | `tests/tool_registry/test_registry.py::test_registration_does_not_change_public_request_shape_or_source`; real CLI, REST, and MCP acquisition contract nodes | registration before/after Request shape; CLI/REST/MCP Request contracts | PASS |

The exact command for any row is `py -3.14 -m pytest -q` followed by the node
IDs shown in that row. The exactly restored #69 evidence recorded all 91 unique
commands with `MATRIX END failed=0`. Issue #72 does not change the matrix helper;
its current full-suite run executes every named node and passes all 1,952 tests.

## Acceptance criteria evidence

### AC-1 — two independent batch Requests and per-site budgets

The runner creates exactly two top-level executions: one strict FIRST
`SiteBatchRequest` and one strict REFRESH `SiteBatchRequest`. Their
`request_id/run_id` and canonical request hashes differ. Production derives one
child Request for each frozen site in each phase. Every child starts at zero with
`max_requests=12`, `max_bytes=52,428,800`, `max_runtime_seconds=60`, concurrency
1, and retry 0; no site or phase inherits another ledger's usage or remainder.
The test-side phase ledger activates at the Acquisition invocation, before the
production resolver runs. The capped transport then uses that same active ledger
for robots, redirects, target requests, bytes, and deadline enforcement. Every
Acquisition constructs a fresh production `WebHttpAcquisitionTool` and transport
with that site's existing absolute phase deadline, then closes both after the
attempt. A later target on the same site cannot receive a new 60-second window.

Evidence reports the two batch identities, each child limit/usage ledger, and
per-site logical/physical reconciliation. Batch and combined totals are display
only, record `budget_gate=false`, and never grant or deny budget. A single site
can stop at its own request, byte, or deadline boundary while production retains
the other sites' real evidence. Offline regression also proves that multiple
responses for one site share that site's one 50 MiB phase ledger, so 50 MiB is
not granted separately to each HTTP response.

### AC-2 — governed new-system multi-site acquisition

The Issue-owned v3 snapshot is the sole target authorization authority. It
freezes SOA, CAS, IAA, and IPCC in that order, with exact URLs, allowed origins,
plans, limits, evidence thresholds, Site Skill identities, and tool facts. Its
strict loader validates only that operational schema and projection. It does not
open a catalog, compare catalog bytes or rows, or read historical provenance.

The Live runner makes exactly one public `run_site_batch` call for FIRST and one
for REFRESH. Its strict per-site declarations map CAS/IAA to the production
`required` file-discovery goal and SOA/IPCC to `not_required`; each child Scope is
derived from that site's exact snapshot seed, origins, and reviewed path scope.
The currently empty reviewed tree list retains that site's existing whole-origin
path authority without guessing a PDF URL. Production goal-aware
`html_file_links` prioritizes a real in-scope file even when alphabetically earlier
HTML links exist. The runner consumes factual `file_discovery_statuses`, each
production child `site_result`, and its real ordered `target_results`; it does not
rebuild Discovery, continuation context, choose a candidate, or perform candidate
acquisition in the test layer. The runner uses production
`usable_site_keys`, so one site's failure does not erase another site's evidence.

Live execution defaults to offline and additionally requires
`WEB_LISTENING_RUN_LIVE=1` plus a nonempty authorization-window reference. The
environment cannot supply a URL. The one authorized run set only those two
inputs, injected no URL, and returned exit 0 with all four frozen sites plus the
HTML, Markdown-lineage, and same-PDF refresh capabilities passing.

### AC-3 — complete content-free delivery

The delivery projection contains Result status, Site Skill used, an explicitly
inactive update candidate, Attempts, Usage, and safe Errors; hashed requested and
final URL identities; redirect/status/MIME facts; Manifest run/request identity,
Site Skill version/digest, and Usage; and Artifact ID, Observation ID, role, MIME,
size, SHA-256, tool/version, observed time, and lineage. Derived Markdown is
`text/markdown`, carries source lineage, and has a successful Transform Attempt.
PDF/download results contain only their original source Artifact and are not
parsed. The PDF gate first requires production `satisfied` file status in both
phases, audits the FIRST file Result obtained through real Discovery and
re-authorization, then requires REFRESH to return that same canonical URL
with a new Observation. Store metadata must prove same bytes reuse the Artifact/
Blob identity and changed bytes create a new identity. A different PDF URL does
not satisfy the gate. Every attempted discovered candidate also remains in `first_results` if
it fails, preserving status, Attempts, Usage, and safe Errors. Only successful
source Results enter SiteState/SiteSkill projection. First and refresh evidence
comes directly from the aggregate APIs' ordered `target_results`, including each
target Manifest, redirect/status/MIME facts, Artifact/Observation identities,
and Transform lineage; no test-side target Result is assembled or guessed.
Tests reject body text, raw URLs, authorization fields, and sensitive payloads
from delivered records.

### AC-4 — persisted first state, real refresh, and update feed

FIRST consumes only production `SiteBatchResult.next_refresh_contexts`. For each
usable site it persists both `previous_state` and the validated `site_skill` in
canonical form, strictly reloads both, constructs a strict
`SiteRefreshContext`, and checks its exact mapping round trip. REFRESH receives
only those reloaded contexts in its production `SiteBatchRequest`; there is no
candidate fallback or caller-side state projection. The child refresh Result
retains production state comparison and ordered target evidence.
Fixtures prove a new Observation on every successful refetch, same-byte Blob
reuse, changed-byte new Blob creation, and six mutually exclusive traceable
change sets.

#### Actionable update feed

The user feed contains only added, changed, missing, failed, and unresolved.
Unchanged is retained solely under audit with counts, previous/current
Observation IDs, Artifact ID, digest, `new_observation`, and `blob_reused`.
Deterministic fixtures prove an empty no-change feed; isolated HTML/PDF byte
changes; and added/missing/failed classifications that are never mislabeled as
unchanged.

### AC-5 — publication evidence

The 191-row frozen README matrix covers every scoped, verifiable normative clause
with a stable unique ID, exact node IDs, exact command, actual output fields, and
result. Non-§19 mapping uses an explicit clause-ID table with no section-wide
default or fallback; any newly extracted unmapped clause raises
`baseline_readme.unmapped_clause`. The current full suite passes every matrix
node, while the exact per-command run remains preserved as restored #69 input.

Direct evidence linkage is also fail-closed. The original-HTML/download clause
combines the real HTML Runtime path with the Issue-owned persisted PDF fixture;
§10 outcome and safe-error rows execute external success, failure, and rejection;
its URL/status/MIME/redirect/tool/time siblings assert the rebuilt successful
`AcquisitionOutput` fields directly;
the eligible-HTML rule executes the default HTML-to-Markdown Transform; and
§19 MCP, eligibility-intersection, and interface-shape rows execute their real
public contracts rather than relying on source scans or one negative example.

Live wrote outside the checkout to the fixed sibling audit root. Its unique
staging directory contained the real batch SQLite/blob store, per-site canonical
SiteStates, and content-free evidence, then received a size/SHA manifest and was
atomically renamed. The emitted locator includes the exact final path, run ID,
manifest SHA, and retention rule. A different fresh auditor reopened SQLite in
read-only immutable mode and returned `AUDIT PASS` after 1,944 atomic checks.
Required CI and separate production authorization remain, so release is not
recommended yet.

#### Authorized Live and independent audit

Immutable pre-Live candidate commit is
`40c5bf091a7c536e9985c719312156da670036d6`. A fresh tester used a temporary
Python 3.14 candidate runtime with
`-m pytest -q -m live tests/live/test_phase_20_new_system_delivery_live.py`.
The environment contained only `WEB_LISTENING_RUN_LIVE=1` and
`WEB_LISTENING_LIVE_AUTHORIZED_WINDOW=issue-72-authorized-2026-09-02`; no URL was
injected. The command returned exit 0 with
`1 passed, 7 deselected in 19.77s`.

Run ID is `phase-20-20260902T141716Z-00301780615b4f628e70454be9b778dc`.
The retained bundle locator is
`C:\Users\ferry\.codex\worktrees\eb2f\.web-listening-audit-bundles\issue-72\phase-20-20260902T141716Z-00301780615b4f628e70454be9b778dc`;
manifest SHA-256 is
`265bc3639582d93bd02d0c98662aba00459ec14502f74d20c0f0374be71b91c2`.
SOA, CAS, IAA, and IPCC were all `PASS`. HTML, Markdown lineage, and PDF
capabilities were all true. CAS and IAA each proved that the same canonical PDF
was refreshed with a new Observation and that unchanged content reused the
Artifact/Blob identity.

FIRST Request hash is
`42991abe5a968c1246aa475ba49b489c788b9091a444d63cefdd7ecdef829523`;
REFRESH Request hash is
`f19955f40fd16dca8cd90695efb4975479ed8fb6c701533a89215f4a4088b238`.
Every site in both phases started from zero with limits of 12 requests,
52,428,800 bytes, 60 seconds, concurrency 1, and retry 0. Every per-site budget
and reconciliation check passed. Audit-only totals were FIRST
`20 requests / 22,428,878 bytes`, REFRESH
`24 requests / 22,290,427 bytes`, and combined
`44 requests / 44,719,305 bytes / 19.133537 seconds`.

The different fresh auditor returned `AUDIT PASS` after 1,944 atomic checks. It
closed exactly 36 of 36 manifest payloads with no missing, extra, or escaping
path. Read-only SQLite inspection reconciled 26 Blobs, 26 Artifacts,
36 Observations, 43 FIRST child Results, 12 REFRESH child Results, and 16 Markdown
lineage records. It also closed four canonical SiteState/SiteSkill strict reloads
as the sole continuation authority, all six change sets and the feed, the
191-row README matrix, the `2fed958e...` baseline, the `f43000ab...` candidate
status guard, and all four runtime-critical hashes.

## Files changed

| File | Purpose |
|---|---|
| `tests/parity/phase_20_new_system_delivery.py` | Frozen README matrix, strict SiteState persistence/projection, content-free delivery/state/refresh/feed projections |
| `tests/parity/test_phase_20_new_system_delivery.py` | Deterministic real-public-API and ArtifactStore evidence for AC-2 through AC-5 |
| `tests/live/test_phase_20_new_system_delivery_live.py` | Offline snapshot/authorization contracts and authorized bounded multi-site runner |
| `tests/live/phase_20_new_system_delivery_targets.json` | Issue-owned exact reviewed target snapshot and frozen per-site/per-phase limits |
| `docs/new-system-delivery-report.md` | This AC/evidence/development report |
| `docs/release-checklist.md` | New-system release gates and non-executing rollback advice |
| `README.md` | Status line only |

No `src/**`, source catalog, project configuration, prior Phase 20 evidence file,
or another worktree/state file is modified.

## APIs and tests read

Implementation was based on the public Request/Scope/Budgets,
aggregate `run_site_batch`, its child site Results and ordered target Results,
Discovery and reauthorized candidate acquisition contracts,
`create_candidate`/`validate_site_skill`, strict SiteState mapping/canonical JSON,
ArtifactStore Observation readback, SiteRefreshResult change
sets, Result/Manifest/Attempt/Usage/ArtifactEvidence, built-in web HTTP,
HTML-links Discovery, and simple HTML-to-Markdown contracts.

Relevant test families read and executed include request/access policy, Site Skill
validation/resolution/repository, registry/protocol/eligibility/lifecycle and
subprocess runner, ArtifactStore/Observation/lineage, Result/Manifest, Runtime
service/discovery/exploration/transform, external transform and CloakBrowser
adapter, CLI/REST/MCP, package smoke, and site refresh contract patterns. The
Live snapshot contract reads only the Issue-owned operational target file.

## README §§1–2 alignment

- The implementation collects only governed websites and requested content types
  using normal Request scope, robots, redirects, MIME, budgets, and Site Skill
  validation.
- The new code is a test/evidence client. It does not gain acquisition, policy,
  tool-selection, storage, Result, or deployment authority and does not change
  the five business modules, Runtime, or Interfaces.
- It does not add PDF/Word/Excel parsing, RAG, search, Q&A, or content analysis.

## Assumptions

1. Production `SiteBatchResult.next_refresh_contexts` is the only FIRST-to-REFRESH
   continuation authority. The client may persist and strictly reload those
   public contexts, but does not recreate their SiteSkill or SiteState.
2. The Issue-owned operational snapshot is self-contained. Catalog digests, full
   catalog rows, old commits/paths/blobs/site keys, historical classifications,
   and historical expectations are outside target authorization and release
   evidence.
3. Extra snapshot sites may be unreachable and are reported `BLOCKED`; release
   still requires at least three distinct successful sites and all three required
   capabilities.
4. A download is delivered as its actual governed MIME and original Artifact; no
   document content parser is implied.
5. Matrix `PASS` records the actual successful command on this candidate. The
   different fresh auditor reconstructed all 191 rows; documentation alone is
   not evidence.
6. Candidate failures and policy rejections are delivery evidence, not SiteState
   pages. They remain content-free Results while only a successful source
   Artifact may enter the client-owned initial state projection.
7. The fixed checkout-sibling audit root is local operational evidence, not a
   business-authority input. Live accepted neither URLs nor a bundle path from
   the environment, and the emitted exact locator governed the completed audit
   and any later authorized cleanup.
8. A fenced block is normative only when the frozen README binds it through one
   of the three exact §5/§12 contract lead-ins. A colon-ending prose line is
   independently normative only when it is one of the five frozen claims named
   in the extraction contract. Other lead-ins and fenced material remain list
   introductions, examples, or layouts and are not silently promoted.
9. FIRST and REFRESH are separate parent batch Requests. Production creates a
   separate same-limit child Request per site in each phase; lower-level reads
   share that site's phase ledger and do not each receive 50 MiB.
10. The #75/#78 aggregate APIs perform the existing Transform within the same
    governed Request. Transform Attempts therefore count as tool attempts but
    contribute zero requests and zero response bytes; only source Artifacts enter
    Current SiteState and change classification.
11. The #83 per-site file goal is execution authority, not post-run scoring.
    `required` may prioritize an unknown discovered file URL only inside the
    frozen child Scope; `not_required` preserves ordinary HTML discovery. Both
    forms are strict Request/Result round-trippable public contracts.

## Sibling and exclusion audit

- Same-byte and changed-byte HTML/PDF shapes, a same-site PDF A→PDF B mismatch,
  plus added/missing/failed and unchanged-audit siblings, are covered by
  deterministic production-Result tests.
- README extraction includes ordinary prose/list/contract-table rules, the five
  exact independently normative colon lead-ins, §5's two forbidden Request
  fields and seven eligibility-intersection members, §12's fixed Transform ID,
  and the §11 browser-disable sentence. It continues to
  exclude §9 Mermaid/hard-coded fallback, §14 CLI/REST/MCP examples, and §15's
  source tree. Clause mappings have no section fallback, and any new extracted
  contract token fails closed.
- Default `RuntimeService.open` registers exactly `web_http` in the production
  Acquisition pool. The same pool feeds governed target reads and
  `explore_all_tools`; Playwright, CloakBrowser, and BrowserAct identities are
  absent. Existing external qualification/enable/disable/rollback evidence stays
  separate and unchanged.
- Offline candidate acquisition covers successful Discovery-provided candidates,
  a real acquisition-tool failure, and a scope-rejected candidate. Every returned
  Result is delivered; only the successful subset can become state pages.
- The completed bundle sibling audit covered unique staging/final names, same-parent atomic
  rename, exact relative-path containment, manifest file-set/size/SHA checks,
  blob size/SHA checks, and SQLite read-only immutable reopening. Completed
  evidence was retained through the different fresh auditor, not pytest cleanup.
- Goal-aware production tests include alphabetically earlier HTML siblings before
  a PDF, CAS/IAA `required`, SOA/IPCC `not_required`, strict child scopes, and
  factual Result status. Candidate choice and authorization remain entirely in
  the production workflow.
- Physical budget evidence covers request, response-byte, and elapsed-runtime
  limits independently for every site in FIRST and REFRESH. Each ledger begins at
  zero before that site's resolver and freezes when the next invoked site begins;
  DNS cannot leak into the prior site or escape the final site's runtime. The
  physical wall-clock includes pre-send and site-workflow time, while production
  logical runtime is attempt accounting, so both are emitted independently and
  are explicitly not compared for equality. Combined totals remain audit-only.
- The two aggregate Request siblings are both covered: one FIRST and one REFRESH
  `run_site_batch`, distinct parent request/run identities, strict batch Request
  and Result round trips, fresh per-site zero-start ledgers, fixed limits, and
  audit-only aggregate totals. Child target Manifest IDs remain subordinate
  evidence and never become extra top-level Request identities.
- Site Skill/State persistence siblings are covered together: every production
  FIRST continuation's validated SiteSkill and Current SiteState are written
  canonically, strictly reloaded, and those exact `SiteRefreshContext` objects
  are the only continuations supplied to REFRESH. Partial batches retain all
  child results while `usable_site_keys` controls continuation.
- FIRST and REFRESH child-result siblings consume production `site_results` and
  their ordered `target_results`. The safe projection preserves each real Manifest,
  redirect/status/MIME, Artifact/Observation identity, Markdown lineage,
  Transform Attempt, PDF metadata, Usage, and Error without rebuilding evidence.
- Same-shaped #72 call sites were all resolved: all four frozen target plans,
  FIRST/REFRESH parent construction, per-site ledgers, production continuation
  persistence/reload, partial-but-usable continuation, child-result projection,
  per-site reconciliation, aggregate audit, checklist, report, README status,
  and audit-root identity. No test-side candidate fallback, state projection, or
  target-result reconstruction remains in the Live path.
- Similar text was excluded with reasons: README's 100 MiB example is frozen
  product prose rather than this Issue's Live limit; the 1,024-byte serialization
  fixture tests a generic Request mapping; combined PDF capability requires one
  site to prove both PDF visits but is not a budget gate; combined Round labels
  describe historical test grouping; shared Blob wording describes content
  deduplication rather than usage accounting.
- The PDF release capability requires one site to prove that its discovered and
  re-authorized FIRST PDF canonical URL was actually refetched by REFRESH with a
  new Observation and valid same/changed Artifact identity. Another PDF at that
  site, or PDF evidence split across two sites, cannot satisfy the gate. Both CAS
  and IAA frozen plans use this rule.
- Redirected seeds retain the original seed path when narrowing the first
  successful SiteState scope; source refresh lookup is by canonical URL, not page
  ordering.
- Excluded: production feature changes, external tool installation, speculative
  safety frameworks, PDF parsing, RAG/search/Q&A/content analysis, deployment,
  and unrelated refactoring.

## Release-checklist retention audit

The prior checklist was larger because most of it specified a two-system
comparison that #69 removed and #72 continues to exclude. Its removal was not
used to remove general release control:

| Prior topic | Decision and reason |
|---|---|
| Fixed comparison-side revisions, probes, profiles, paired digests, and cross-side count/error/content rules | Deleted because they exist only to compare two systems; they are outside the new acceptance criteria |
| Immutable release identity | Retained as the final candidate commit/branch plus the currently approved release identity used only for reversible deployment control |
| Candidate path identity and cache discipline | Retained and rewritten as the seven-path base-to-HEAD/untracked audit, literal-path cache removal, and runtime-critical SHA/size freeze |
| Exact interpreter, environment, commands, and exit/count evidence | Retained for CPython 3.14, focused/full/matrix/Live commands, cache controls, and final report |
| Authorized Live window and bounded networking | Retained with both opt-ins, catalog-only URLs, fixed order, concurrency 1, retry 0, and independent first/refresh Request limits |
| Runtime-critical change after Live | Retained: any change to the snapshot, Live test, or two parity files invalidates Live evidence and forces a rerun |
| Independent I/O audit | Retained for one-system Result/ArtifactStore/SiteState/refresh/feed/budget reconciliation and frozen README reconstruction |
| Required CI and separate production authority | Retained as unchecked release gates |
| Rollback | Retained as non-executing advice to preserve the currently approved immutable release, check new-system health after an authorized switch, and revert on failure |
| Evidence retention and secret/body exclusion | Retained with exact required artifacts and prohibited content; the real bundle survived through the fresh I/O audit and is eligible for authorized exact-locator cleanup |

The rewritten checklist therefore removes comparison-only machinery while
preserving every generally applicable new-system release, audit, identity,
health, authorization, evidence-retention, and rollback control.

## Test evidence

Interpreter for every accepted result: CPython 3.14.3 at
`C:\Users\ferry\AppData\Local\Python\pythoncore-3.14-64\python.exe`.
The interpreter has no editable install, so accepted commands use `PYTHONPATH=src`.
`PYTHONDONTWRITEBYTECODE=1` and `PYTEST_ADDOPTS=-p no:cacheprovider` are set.

| Command/gate | Exact result |
|---|---|
| Four Round1 targeted nodes (F1/F2/F3 plus aggregate source scan) | `4 passed in 0.44s` |
| Four Round2 targeted nodes (two batch source contracts, strict batch execution, per-site budgets) | `4 passed in 0.56s` |
| Round3 same-PDF mismatch targeted node | `1 passed in 0.40s` |
| Round3 stable/changed PDF identity parameter cases | `2 passed in 1.17s` |
| Round4 catalog-independence and historical-evidence targeted nodes | `2 passed in 0.42s` |
| Round5 cross-site pre-send timing targeted node | `1 passed in 0.17s` |
| Round6 expired-before-resolver targeted node | `1 passed in 0.17s`; resolver calls `0` |
| Round7 production file-goal targeted node | `1 passed in 0.84s`; legacy shape produced four `not_requested` statuses and only seed/a.html/b.html before the production declaration supplied required file acquisition |
| Round8 immutable candidate README targeted node | pre-fix `1 failed in 0.45s` on the explicit moving-`HEAD` source guard; final behavior-only regression `1 passed in 0.33s` |
| `py -3.14 -m pytest -q tests/parity/test_phase_20_new_system_delivery.py -m "not live"` | `28 passed in 2.77s` |
| `py -3.14 -m pytest -q tests/request/test_site_batch_request.py tests/result/test_site_batch_result.py tests/runtime/test_site_batch.py tests/runtime/test_site_explore.py tests/runtime/test_site_refresh.py tests/tool_registry/test_html_links.py tests/runtime/test_service.py tests/runtime/test_transform_flow.py` | `287 passed in 12.69s` |
| `py -3.14 -m pytest -q tests/live/test_phase_20_new_system_delivery_live.py -m "not live"` | `7 passed, 1 deselected in 0.26s` |
| Restored #69 README matrix commands 01–91 | every exact command returned exit 0 with its named tests passing; no matrix-helper byte changed in #72 |
| Restored matrix aggregate | `91 commands`, `191 rows`, `MATRIX END commands=91 rows=191 failed=0`; current full suite passes every named node |
| `py -3.14 -m pytest -q` | `1952 passed, 7 skipped, 45 deselected, 1 warning in 63.48s` |
| `py -3.14 -m black --check src tests` | PASS; `151 files would be left unchanged` |
| `py -3.14 -m isort --check-only src tests` | PASS; exit 0, no output |
| `py -3.14 -m pylint src/web_listening tests` with `PYTHONPATH=src` | PASS; exit 0, `10.00/10` |
| `git diff --check` | PASS; exit 0; only Git line-ending notices |
| Authorized Live | PASS; exit 0, `1 passed, 7 deselected in 19.77s`; four of four sites and all HTML/Markdown/PDF capabilities passed |
| Independent I/O audit | `AUDIT PASS`; 1,944 atomic checks and 36/36 manifest payloads closed |

The host's default `python` resolves to Python 3.11, while this repository's
subprocess runner uses `Path.is_junction` and requires the documented Python 3.14
environment. Accepted `python -m ...` gates therefore prepend the Python 3.14
directory to `PATH` and set this checkout's `src` directory as `PYTHONPATH`.
Python 3.11 development feedback is not used as release evidence.

Twenty-six test/evidence-layer bug shapes were fixed with controlled RED→GREEN
evidence and no `src/**` change. The first three rows are the accepted Round1
findings, the next three cover Round2 and its directly exposed timing sibling,
and the following six are the accepted Round3 through Round8 findings. The
remaining rows are retained from the prior #72/#69 candidate:

| Shape | Pre-fix RED | Post-fix GREEN | Sibling audit |
|---|---|---|---|
| F1: first acquisition used multiple lower-level identities behind synthetic Request evidence | strict aggregate regression failed with `KeyError: _aggregate_usage_reconciliation` | targeted aggregate node passes; first and refresh have different aggregate request/run IDs, strict round trips, fixed limits, and zero-start usage | both aggregate calls, target Manifest IDs, physical/logical reconciliation, early first failure, and combined audit covered |
| F2: validated SiteSkill was not persisted/reloaded and first Current SiteState was not strictly reread before refresh | persistence regression failed because `current-site-state.json` did not exist | targeted persistence node passes; canonical SiteSkill and SiteState files strictly reload and refresh consumes the reloaded objects | validated candidate/fallback skill, state projection, persist/load pairs, refresh construction, and partial/failure exclusion covered |
| F3: refresh public evidence omitted real ordered per-target Manifest/redirect/MIME data | temporarily removing `refresh_record`'s direct `result.target_results` consumption made the unchanged refresh node fail on the expected three target records | unchanged refresh and aggregate source-scan nodes pass; projection uses `delivery_record(item)` directly on production `target_results` | first/refresh success and failure Results, target Manifest IDs, HTTP facts, Artifact/Observation, Markdown lineage/Transform Attempt, and PDF metadata covered |
| Round2 F1: the Live layer repeated one Request and workflow call per site instead of exactly two batch Requests | new source regression found zero `_batch_run` calls and failed as expected | FIRST and REFRESH are strict production `SiteBatchRequest` executions with different parent identities/hashes; focused Phase20 suite passes | all four frozen plans, both phases, per-site zero-start ledgers, partial availability, reconciliation, and aggregate-only totals covered |
| Round2 F2: the Live layer could create a fallback SiteSkill and project caller-owned continuation state | new source regression could not find `first.next_refresh_contexts` and failed as expected | FIRST persists/reloads production contexts and REFRESH consumes only those strict objects; child evidence comes directly from production `site_results/target_results` | usable/failed sites, SiteSkill/State round trips, HTML/Markdown/PDF child evidence, Manifest/redirect/status/MIME, and no fallback/reconstruction covered |
| Round2 F1 sibling: phase ledgers started together and FIRST evidence was sampled after REFRESH, so another site's or phase's elapsed time could contaminate the 60-second gate | ordering RED reported `3619 < 1392` false; serial-ledger RED rejected the new `clock` fixture argument | FIRST evidence freezes before persistence/REFRESH; each site's ledger activates on its first serial I/O and freezes when production advances sites; focused deadline/budget nodes pass | four frozen sites, both phases, unused ledgers, serial site transitions, first/refresh evidence timing, request/byte/deadline gates, and aggregate-only totals covered |
| Round3 F1: one site could PASS when FIRST acquired PDF A but REFRESH acquired only PDF B | production two-site SiteBatch fixture proved FIRST `{report.pdf}`, REFRESH `{replacement.pdf}`, both batches usable, then failed because the old record returned `PASS` instead of `BLOCKED` | same focused node passes; the gate now binds production FIRST discovery, child Results, State pages, Store metadata, new Observation, and same/changed Artifact identity to one canonical URL | mismatch A→B, same-byte reuse, changed-byte new identity, redirect-safe canonical final URL, aggregate capability, and both CAS/IAA PDF plans covered |
| Round4 F1: catalog digest/full-row and historical provenance could block the Issue-owned target authorization before new-system execution | changed catalog-only fixtures failed in `_load_snapshot` with `new-system delivery catalog digest drifted`; site evidence still exposed `historical_expectation` | the self-contained snapshot loader consumes only its strict operational projection and site evidence contains no historical expectation | SOA/CAS/IAA/IPCC order, exact URLs/origins/plans/limits, operational metadata shape, catalog independence, and all four site records covered |
| Round5 F1: cross-site DNS time was charged to the previously active site because the physical ledger switched only at transport send | fake clock reproduced `one=61s/BLOCKED`, `two=1s/PASS`, then the resolver-entry wrapper assertion failed | phase-aware Acquisition wrapper activates before the production resolver; corrected FIRST and REFRESH evidence is `one=2s`, `two=60s`, both PASS | all four ordered sites, both phases, same-site robots/target/redirect sends, skipped/no-I/O sites, failed attempts, unknown/backward hosts, physical runtime evidence, and audit-only aggregates covered |
| Round6 F1: each delegated production tool created a fresh target-level 60-second gateway deadline, allowing an expired phase ledger to enter robots/DNS before the transport stopped it | an already-expired site returned `robots.timeout`, and the real fake resolver recorded `[('one.test', 443)]` | each invocation passes the active ledger's absolute deadline to a fresh public `WebHttpAcquisitionTool`; expired evidence returns `budget.runtime` with zero resolver calls | FIRST/REFRESH registries, four sites, same-site seeds/candidates, expiry before robots/DNS, exact boundary, failed/zero-I/O sites, unknown/backward hosts, and one-tool/transport-per-attempt close lifecycle covered |
| Round7 F1: `try_discovered_pdf` was only post-run scoring and the claimed candidate cap was not a production input, so a/b HTML candidates displaced z-report.pdf | the real legacy SiteBatch produced four `not_requested` statuses and only seed/a.html/b.html, then the new regression failed with `KeyError: '_batch_sites'` | the same real batch test passes with snapshot-driven `SiteBatchSite` declarations; CAS/IAA return `satisfied` and production ordered Results contain the PDF | CAS/IAA required, SOA/IPCC not-required, FIRST/REFRESH, child Scope and Request/Result round trips, persisted SiteSkill scope, and goal-aware discovery covered |
| Round8 F1: the candidate README status-line guard compared with moving `HEAD`, so it would collapse to no difference after the candidate commit | the strengthened source contract rejected literal `HEAD:README.md` and failed on the existing command | the guard reads immutable `f43000ab0f170b376b5b19cd84ee3bb2f51f13f6:README.md`; the working README remains 751 lines and differs only at index 2 | candidate status guard and report/checklist wording covered; the separate `2fed958e...` README blob/revision continues to own clause-matrix acceptance |
| First acquisition and refresh shared one 8 MiB physical ledger and used the remainder as refresh authority | new focused regression against exact #69 payload failed with `KeyError: network_limits_per_request`; the restored payload exposed only `network_limits_per_site_first_and_refresh` with 8,388,608 bytes | focused command: `21 passed`; Live offline contract: `7 passed, 1 deselected` | exact7 search covered fixed limits, remaining-budget construction, physical reconciliation, request identities, combined totals, evidence/checklist text, and audit-root identity |
| Redirected discovery source was compared only with the original seed, which could drop a real discovered PDF | `test_phase_20_pdf_selection_uses_only_discovery_provenance`: `TypeError`, 1 failed | same node: `1 passed in 0.09s` | original-seed, redirected-source, out-of-scope, and wrong-provenance candidates |
| Remaining time was clamped to zero before the within-budget test, so a 61-second run could appear within 60 seconds | `test_phase_20_physical_budget_reports_a_real_deadline_overrun`: missing `runtime_seconds`, 1 failed | same node: `1 passed in 0.09s` | request, byte, exact elapsed runtime, and deadline predicates |
| Separate sites could contribute initial-PDF and refresh-PDF booleans to a misleading aggregate PASS | `test_phase_20_pdf_capability_requires_one_site_to_refresh_its_pdf`: missing combined capability, 1 failed | same node: `1 passed in 0.09s` | individual initial/refresh audit fields retained; combined same-site gate added |
| Frozen README extraction treated fenced examples as clauses and lost a complete colon lead-in rule | matrix identity node missed the §11 disable sentence, 1 failed | matrix identity plus exclusion assertions: `1 passed` | §9 Mermaid, §15 tree, CLI/REST/MCP examples, tables, and colon paragraphs audited |
| Non-§19 clauses inherited one section-wide evidence mapping | §12 non-HTML rule was bound to broad transform nodes, 1 failed | exact §12 node and fail-closed matrix: `2 passed in 0.30s` | every clause ID is explicit; no default/fallback/N/A/BLOCKED |
| Live evidence used pytest temporary storage with no usable fresh-auditor locator | bundle test raised `_finalize_audit_bundle` `NameError`, 1 failed | same node: `1 passed in 0.14s` | atomic rename, locator, manifest, containment, blob integrity, read-only SQLite, and retention |
| Failed discovered-candidate Results were filtered out of delivery and physical reconciliation | failure test raised `_partition_candidate_results` `NameError`, 1 failed | failure/rejection/reconciliation node passes | successful/failed/rejected candidates and same-site PDF initial+refresh gate |
| Offline first run rebuilt DiscoveryOutput from an independent candidates argument | real tool returned HTML but acquisition called the injected PDF, 1 failed | same node: `1 passed in 0.17s` | exact candidates/provenance/coverage from the just-returned DiscoveryOutput, including added/missing sequences |
| Normative fenced contracts were excluded with examples | exact §5 forbidden fields/intersection and §12 Transform-ID subset assertion failed, 1 failed | extractor node passed, then the combined Round2 targeted set returned `5 passed in 0.41s` | only three exact lead-ins accepted; §9 fallback/Mermaid, §14 interface examples, and §15 tree remain excluded |
| §11 browser-disable clause pointed only to external-adapter authorization evidence | matrix node-ID assertion showed the adapter node instead of default production composition, 1 failed | `RuntimeService.open` composition and exact clause mapping passed in the Round2 targeted set | `web_http` only in default Acquisition pool; three browser identities absent; external qualification/enable/rollback siblings unchanged |
| Five independently normative colon-ending prose claims were discarded as list introductions | exact five-claim subset assertion failed, 1 failed | Round3 targeted set: `3 passed in 0.35s` | every scoped colon-ending sibling audited; only the five complete standalone requirements retained; `Example:`, `Rules:`, list/fence introductions excluded |
| §19-04 pointed only to pure SiteSkill resolution rather than a real Runtime execution | exact node-ID assertion still showed the resolve-only node, 1 failed | real `run_single_target` regression and matrix binding passed in the Round3 targeted set | validated skill evidence, one preferred Acquisition Attempt, Discovery zero calls, eligible alternate zero calls; no production source change |
| Twelve matrix rows used related but non-direct evidence | exact direct-node/evidence contract failed first on the HTML-only mapping, then on the success-node field siblings | direct-link/PDF pair: `2 passed in 0.28s`; newly bound original nodes: `18 passed in 2.34s`; external-field sibling plus matrix contract: `2 passed in 0.28s` | remaining §19 rows audited; §10 URL/status/MIME/redirect/tool/time siblings now have direct field assertions; correct links unchanged |

## Path, cache, and Git audit

Branch is `codex/issue-72-independent-refresh-budget`. Immutable pre-Live
candidate `HEAD` is `40c5bf091a7c536e9985c719312156da670036d6`; its Issue base is
`f43000ab0f170b376b5b19cd84ee3bb2f51f13f6`. The candidate contains the exact
seven authorized Issue paths and the merged #75, #78, and #83 prerequisites.
Candidate cache cleanup was completed and independently re-enumerated as zero
before Live. This post-Live overlay modifies only README's status line and the
two Issue documentation files.

Immutable candidate runtime-critical identities used by Live and rechecked
unchanged after this documentation overlay are:

| Path | Bytes | SHA-256 |
|---|---:|---|
| `tests/parity/phase_20_new_system_delivery.py` | 75467 | `1D62A383D695F5921465C3DD4386B46E40B8BE33D5AF60DDA50DB262D50F5A09` |
| `tests/parity/test_phase_20_new_system_delivery.py` | 72291 | `55E1E6518827700CAEA227AD0CDC0A99915C6B9501990952009C1057EA8C9413` |
| `tests/live/test_phase_20_new_system_delivery_live.py` | 70124 | `C3184E9AE248EADDC7C45D60D88F51C6C9E73ECE97C326F5DB9AE383D800090B` |
| `tests/live/phase_20_new_system_delivery_targets.json` | 4512 | `571F6DEDA8A7D121415495DF62A058793DCC7E157A10A99D5D76E3B6CEE604A6` |

Any runtime-critical difference after this point invalidates the recorded Live
evidence and requires a new explicitly authorized run.

## Risks and blockers

- Required CI has not yet passed on the final documentation candidate.
- Separate production-switch authority has not authorized a switch. No
  production switch is recommended or executed.

## Current Git status

After this documentation overlay, `git status --short --untracked-files=all`
reports exactly these three authorized paths:

```text
 M README.md
 M docs/release-checklist.md
 M docs/new-system-delivery-report.md
```

This documentation overlay performed no commit, push, PR, merge,
branch/worktree deletion, production switch, bundle mutation, or Live network
call. The single authorized Live run and different fresh audit are the completed
external evidence recorded above.
