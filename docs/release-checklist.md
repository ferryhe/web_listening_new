# New-System Delivery Release and Rollback Checklist

This checklist is evidence-only. It does not perform or authorize a production
switch.

## Frozen acceptance authority

- Baseline revision: `2fed958ee67d3c7d714fde40a372bc8b7389bf87`.
- Baseline README Git blob: `edcc24b4e09d69a316b28ed403f86107ef5dcb27`.
- Canonical CRLF SHA-256:
  `8515EF08F2CB2C81A08DB89BA307A37D6D12FCD921782AD567E47B529BCFCB44`.
- Baseline README length: 731 lines.
- Live snapshot: `tests/live/phase_20_new_system_delivery_targets.json`.
- The v3 snapshot is the sole Issue-owned target authority. It contains only the
  frozen operational rows, plans, and limits; no catalog digest, copied catalog
  row, old commit/path/blob/site key, historical classification, or historical
  expectation participates in authorization or evidence.
- Runtime evidence: only the current `web_listening` public production APIs and
  the real `ArtifactStore`.

The post-Live documentation overlay changes only the working README status line.
Tests always reconstruct acceptance clauses from the older frozen Git object,
never from the working copy.

## GO / NO-GO gate

GO requires every item. A missing, skipped, failed, or `BLOCKED` item is NO-GO.

- [x] Python 3.14 focused offline delivery/refresh tests pass.
- [x] Live contract tests pass with the network test deselected.
- [x] The frozen README matrix has 191 stable, unique rows covering §§1, 2,
  4–17, and all 16 §19 criteria; every row contains exact node IDs, an exact
  command, observable fields, and `PASS`.
- [x] All 91 unique commands named by that matrix pass on this candidate.
- [x] Normative fenced contracts include the two forbidden public Request
  fields, all seven `explore_all_tools` eligibility checks, and the fixed
  `simple_html_markdown` identifier; diagram, fallback, interface, and source-tree
  examples remain excluded.
- [x] The five exact independently normative colon-ending claims cover the
  five-module/two-support-layer boundaries, four-input Request, common logical
  Result, and thin external Adapter; list/example lead-ins remain excluded.
- [x] The §11 browser-disable row is bound to default `RuntimeService.open`
  composition evidence: `web_http` is the sole production Acquisition tool and
  Playwright, CloakBrowser, and BrowserAct are absent from that pool.
- [x] The §19-04 row is bound to a real Runtime execution with a validated Site
  Skill: the preferred Acquisition tool runs once, while Discovery and the
  eligible alternate are not invoked.
- [x] Multi-line rows use direct contract evidence: real MCP client execution,
  the complete tool-eligibility intersection, registration plus CLI/REST/MCP
  Request contracts, external success/failure/rejection, executed default
  HTML-to-Markdown, and persisted HTML/PDF source Artifacts.
- [x] Deterministic evidence proves FIRST consumes production continuation
  contexts, strictly persists/reloads SiteState and SiteSkill, and REFRESH uses
  only those reloaded contexts; Observation/Blob and update-feed rules remain.
- [x] Exactly one FIRST and one REFRESH SiteBatch Request have different parent
  identities and hashes. Every site in each phase starts a fresh ledger with 12
  requests, 52,428,800 bytes, 60 seconds, concurrency 1, and retry 0. Aggregate
  totals are audit-only and never a budget gate.
- [x] Each phase ledger activates at the site's Acquisition invocation before the
  production resolver. Robots, DNS, redirects, target sends, and response bytes
  stay with that site until the next ordered site begins; skipped sites remain at
  zero and unknown or backward hosts fail safely.
- [x] Every target attempt receives the active site's existing absolute phase
  deadline through the public `WebHttpAcquisitionTool.runtime_deadline`; a fresh
  tool/transport is closed after each attempt, and later same-site targets never
  reset the 60-second phase window. Expired ledgers stop before resolver I/O.
- [x] The self-contained Issue snapshot strictly freezes all four sites in order,
  exact URLs/origins/plans/limits, and operational metadata shape without reading
  or comparing any catalog or historical provenance.
- [x] The snapshot maps CAS and IAA to the production `required` file-discovery
  goal and SOA/IPCC to `not_required`. FIRST and REFRESH pass strict per-site
  `SiteBatchSite` scopes into production; goal-aware HTML discovery, factual
  `file_discovery_statuses`, and real ordered `target_results` provide the file
  gate without a caller-selected candidate, guessed PDF URL, or private candidate
  cap.
- [x] Branch, base-to-working-tree name status, and exact untracked paths are
  recorded; only the seven Issue-authorized paths exist.
- [x] Immutable pre-Live candidate revision
  `40c5bf091a7c536e9985c719312156da670036d6` is recorded.
- [x] Candidate cache cleanup removed all worktree `__pycache__`, pytest/tool
  caches, and `.pyc` files and independently re-enumerated zero before Live.
- [x] Fresh authorized Live passed all four frozen sites and proved
  ordinary HTML, derived Markdown, and a discovered/re-authorized PDF or download
  whose same canonical URL is refetched on refresh with a new Observation and
  valid same-byte reuse or changed-byte Artifact/Blob identity.
- [x] A different fresh I/O auditor reconciled the emitted content-free evidence
  with the real `ArtifactStore`, Result, SiteState, and physical network budget:
  `AUDIT PASS`, 1,944 atomic checks.
- [ ] Required CI/checks pass on the final candidate.
- [ ] A human with separate production authority explicitly authorizes a switch.

Current recommendation: **NO-GO**. Required CI and separate production-switch
authorization are the only remaining gates.

## Candidate identity and path integrity

The candidate and Live preparation recorded:

1. Immutable candidate commit
   `40c5bf091a7c536e9985c719312156da670036d6` on
   `codex/issue-72-independent-refresh-budget`; a mutable branch name alone is
   not the release identity.
2. Treat `f43000ab0f170b376b5b19cd84ee3bb2f51f13f6:README.md` as the immutable
   candidate status-line guard, distinct from the older frozen clause-matrix
   object above. Run
   `git diff --name-status -M f43000ab0f170b376b5b19cd84ee3bb2f51f13f6`
   and `git ls-files --others --exclude-standard`. Reject missing, extra, deleted,
   conflicted, or out-of-scope paths. The only allowed paths are the two new
   parity files, two new Live files, this checklist, the delivery report, and the
   README status line.
3. Caches and bytecode under the resolved worktree were enumerated, removed by
   verified literal paths inside that worktree, and independently re-enumerated
   as zero before Live.
4. CPython version/executable and the disclosed `PYTHONPATH`,
   `PYTHONDONTWRITEBYTECODE`, and pytest cache configuration were recorded.
5. Raw SHA-256 and size for the snapshot, Live test, and both new parity files
   were recorded immediately before Live. Any later byte change to those
   runtime-critical files invalidates Live evidence and requires a fresh
   authorized rerun.

Documentation-only updates after Live must not rewrite runtime evidence. The
completed independent audit recorded the immutable runtime candidate; this
documentation-only overlay is tracked separately.

## Exact commands

Run from the repository root with Python 3.14, `PYTHONPATH=src`,
`PYTHONDONTWRITEBYTECODE=1`, and
`PYTEST_ADDOPTS=-p no:cacheprovider`.

```powershell
py -3.14 -m pytest -q tests/parity/test_phase_20_new_system_delivery.py -m "not live"
py -3.14 -m pytest -q tests/request/test_site_batch_request.py tests/result/test_site_batch_result.py tests/runtime/test_site_batch.py tests/runtime/test_site_explore.py tests/runtime/test_site_refresh.py tests/tool_registry/test_html_links.py tests/runtime/test_service.py tests/runtime/test_transform_flow.py
py -3.14 -m pytest -q tests/live/test_phase_20_new_system_delivery_live.py -m "not live"
```

The current commands return `28 passed`, `287 passed`, and
`7 passed, 1 deselected`, respectively. The middle command proves that the
merged #75/#78/#83 aggregate APIs retain real Markdown/lineage/Transform evidence,
per-site independent budgets, availability-first continuation, required-file
discovery/replay, and source-only SiteState. The machine-readable matrix in
`tests/parity/phase_20_new_system_delivery.py` supplies the 91 exact README
evidence commands. The exactly restored #69 input recorded
`MATRIX END failed=0` for all 191 rows; #72 leaves the matrix helper unchanged,
and its current full suite passes every named node. The development report
records the distinction.

Only a fresh Live tester may set both required environment inputs:

```powershell
$env:WEB_LISTENING_RUN_LIVE='1'
$env:WEB_LISTENING_LIVE_AUTHORIZED_WINDOW='<nonempty authorized window reference>'
python -m pytest -q -m live tests/live/test_phase_20_new_system_delivery_live.py
```

Without both inputs, the Live test must skip and does not count as PASS. The Live
runner must keep the frozen order and execute exactly one FIRST and one REFRESH
SiteBatch Request with separate parent identities. Production gives every site
in each phase a new ledger limited to 12 requests, 52,428,800 bytes, and 60
seconds, with concurrency 1 and retry 0. Batch and combined totals are retained
only for audit display and are not a budget gate. The 50 MiB limit is the total
for one site's complete phase, not an allowance for every lower-level response.
It must not accept a URL from the environment. Do not run this command outside
an authorized window.

CAS and IAA declare the production `required` file goal; SOA and IPCC declare
`not_required`. Each declaration carries its own strict snapshot-derived child
Scope. The current empty reviewed tree list retains the previously authorized
whole-origin path pattern for that site, while origins and seeds remain exact;
it does not prefill or guess a PDF URL. A required site passes only when both
FIRST and REFRESH return production `satisfied` status and the real child Results
also prove the same canonical PDF/download refresh semantics.

The one authorized run used a temporary Python 3.14 candidate runtime with
`-m pytest -q -m live tests/live/test_phase_20_new_system_delivery_live.py`.
Only `WEB_LISTENING_RUN_LIVE=1` and
`WEB_LISTENING_LIVE_AUTHORIZED_WINDOW=issue-72-authorized-2026-09-02` were set;
no URL was injected. It returned exit 0 with `1 passed, 7 deselected in 19.77s`.
Run ID is `phase-20-20260902T141716Z-00301780615b4f628e70454be9b778dc`.
The completed bundle is
`C:\Users\ferry\.codex\worktrees\eb2f\.web-listening-audit-bundles\issue-72\phase-20-20260902T141716Z-00301780615b4f628e70454be9b778dc`;
its manifest SHA-256 is
`265bc3639582d93bd02d0c98662aba00459ec14502f74d20c0f0374be71b91c2`.
SOA, CAS, IAA, and IPCC all passed. HTML, Markdown lineage, and PDF capabilities
were all true; CAS and IAA each proved the same canonical PDF on refresh, a new
Observation, and same-content Artifact/Blob reuse.

FIRST Request hash was
`42991abe5a968c1246aa475ba49b489c788b9091a444d63cefdd7ecdef829523`;
REFRESH Request hash was
`f19955f40fd16dca8cd90695efb4975479ed8fb6c701533a89215f4a4088b238`.
Every site in both phases started at zero with limits
`12 / 52,428,800 / 60 / concurrency 1 / retry 0`; all per-site budget and
logical/physical reconciliation gates passed. Audit-only phase totals were
FIRST `20 requests / 22,428,878 bytes`, REFRESH
`24 requests / 22,290,427 bytes`, and combined
`44 requests / 44,719,305 bytes / 19.133537 seconds`.

## Recorded Live evidence

Retain one redacted JSON packet containing:

- fixed snapshot identity and the ordered site keys;
- per-site production file goal and FIRST/REFRESH file-discovery status;
- per-site `PASS`/`BLOCKED`, plus honest reasons for extra unreachable sites;
- at least three successful distinct sites;
- ordinary HTML, derived `text/markdown` with lineage and Transform attempt, and
  a PDF/download found by real Discovery then rechecked by the governed gateway;
- the same canonical PDF/download target in FIRST and REFRESH, a new refresh
  Observation, and Store-backed same-byte reuse or changed-byte identity change;
- first Result/Manifest/Artifact/Observation records and strict persisted
  SiteState evidence;
- refresh Result, all six mutually exclusive change sets, and the user update
  feed containing only added/changed/missing/failed/unresolved;
- a new Observation for every successful refresh, with same-byte Blob reuse or
  changed-byte new Blob evidence;
- first and refresh physical request/byte/runtime counts within their respective
  frozen Request budgets, including resolver time, plus non-gating combined audit
  totals; logical attempt runtime and physical wall-clock remain separately
  auditable and are not asserted equal;
- every discovered-candidate Result, including failures with Attempts, Usage,
  and safe Errors, plus a logical-Result-to-physical-network reconciliation;
- an exact audit-bundle locator, run identity, manifest size, and manifest
  SHA-256.

Records must use URL hashes and safe error fields. Do not retain bodies, raw
sensitive queries, credentials, cookies, or authorization headers. PDF/download
evidence is the original Artifact only; do not parse its content.

The runner atomically renames a unique completed bundle under the checkout's
fixed sibling `.web-listening-audit-bundles/issue-72` directory. The bundle
contains each real ArtifactStore SQLite/blob repository, canonical persisted
SiteState files, the content-free packet, and a self-checking file manifest. It
does not accept a bundle path or target URL from the environment.

## Recorded independent I/O audit

The different fresh auditor independently reconstructed the 191 frozen README
clauses and checked every stable ID, test node, exact command, evidence field,
and result. It used the emitted locator and manifest digest to reopen each SQLite
database in read-only immutable mode, hashed the declared blobs without printing
bodies, and read each delivered Observation from the real ArtifactStore to
reconcile URL identity, Artifact/Observation IDs, MIME, size, SHA-256, lineage,
tool/version,
Site Skill version/digest, Usage, first Current SiteState, refresh Current
SiteState, six change sets, update feed, both independent physical budgets, and
the audit-only combined totals. Any mismatch or unexplained N/A would have been
`BLOCKED`. Its verdict was `AUDIT PASS` after 1,944 atomic
checks. The manifest closed exactly 36 of 36 payloads with no missing, extra, or
escaping path. Read-only SQLite inspection reconciled 26 Blobs, 26 Artifacts,
36 Observations, 43 FIRST and 12 REFRESH child Results, 16 Markdown lineage
records, and four canonical SiteState/SiteSkill strict
reloads that were the sole continuation authority. The six change sets, update
feed, 191-row README matrix, `2fed958e...` baseline, `f43000ab...` status guard,
and all four runtime-critical hashes also closed without mismatch.

## Evidence retention

Retain the immutable candidate identity, exact environment and commands, exit
codes/counts, per-file runtime-critical hashes/sizes, redacted Live JSON, the
complete audit bundle, physical budget evidence, independent audit verdict,
required CI results, and production authorization/switch/rollback timestamps.
The real SQLite/blob/State bundle remained intact through the different fresh I/O
auditor's completed verdict. It is now eligible for authorized cleanup using the
exact emitted locator. Never print page bodies, raw sensitive queries,
credentials, or authorization headers, and remove tool caches separately.

## Reversible release advice

This Issue does not execute the following drill:

1. Record immutable identities for the candidate and the currently approved
   release; keep the approved release and its data readable.
2. Validate the candidate with all gates above before selecting it.
3. Switch only through the deployment control owned outside this repository and
   only after separate authorization.
4. Immediately rerun the same new-system health and delivery contract without
   expanding scope, budgets, retries, or ignores.
5. If health or contract evidence fails, select the preserved approved release,
   verify its health, and retain both switch and rollback timestamps/evidence.
6. Stop and escalate if rollback health fails; do not improvise deployment repair
   in this evidence change.

No production command, compatibility layer, cross-system comparison, content
equality gate, PDF parser, RAG, search, Q&A, or content analysis is introduced.
