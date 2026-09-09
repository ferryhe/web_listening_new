# Governed browser acquisition

These versioned, self-contained adapters implement the existing external tool
protocol. Core Web Listening imports no browser SDK. `RuntimeService.open(data_dir)`
loads only active browser installations from that data directory; it never loads
test fixtures. Registry owns HTTP → Playwright → CloakBrowser ordering, with a
valid Site Skill preferred tool first. Exploration permission, eligibility and
remaining budgets still apply. Each tool runs once; retry is zero.

## Frozen runtime prerequisites

`runtime-lock.json` is the source of exact versions and digests. Linux AMD64 and
Python 3.12 are required. Provision runtimes separately, before qualification:

| Adapter | Runtime required by the lock |
| --- | --- |
| `playwright/1.0.0` | Playwright 1.62.0; Chromium 151.0.7922.34, revision 1234, chromium channel; SDK tree and executable SHA-256 in the lock |
| `cloakbrowser/0.5.9` | CloakBrowser 0.5.9; Chromium 146.0.7680.177, build 146.0.7680.177.5; the exact Linux AMD64 image digest inherited from #18 |

Playwright's provisioned layout under the Runtime data directory is:

```text
browser-runtimes/playwright/bin/python
browser-runtimes/playwright/lib/python3.12/site-packages/playwright/
browser-runtimes/playwright/browsers/chromium-1234/chrome-linux64/chrome
```

The installer verifies the SDK tree and browser executable digests. Its SDK tree
hash uses sorted relative paths, a NUL separator, then each file's binary SHA-256;
Python caches are excluded. The lock records provenance from existing provisioned
files, not a claim that the new adapter has passed real-browser validation.

For CloakBrowser, Docker must already contain the lock's exact image. The installer
uses `--pull=never --network=none` to measure SDK metadata and the executable in
that image. Actual adapter execution uses the same pinned image and a parent
loopback bridge. No install or Request implicitly downloads packages, binaries or
images. Missing engines or digest mismatches are BLOCKED.

## Install, qualify, activate and disable

Use a dedicated data directory and an explicitly authorized, valid single-target
Request JSON. Include HTML and, when authorized, file/resource content types, plus
the exact origins and paths needed for JS/XHR. The installer does not expand them.
The owned loopback fixture requires the test harness's explicit loopback policy;
the production Gateway continues to reject private network targets.

```bash
python tools/browser/install.py install --tool playwright \
  --data-dir "$BROWSER_DATA_DIR" \
  --runtime-root "$BROWSER_DATA_DIR/browser-runtimes/playwright" \
  --request "$QUALIFICATION_REQUEST" \
  --authorization-window "$AUTHORIZATION_WINDOW"

python tools/browser/install.py install --tool cloakbrowser \
  --data-dir "$BROWSER_DATA_DIR" --request "$QUALIFICATION_REQUEST" \
  --authorization-window "$AUTHORIZATION_WINDOW"
```

Each command prints qualification, binding, runtime identity, lock digest,
requests/bytes/time, parent robots decisions and output SHA. Qualification performs
one acquisition and reuses its output; it is not followed by a second fetch.
These reads consume the qualification Request's budget and belong in the
authorization window's ledger. Activation accepts only the issuing IsolatedRuntime's
live successful report for the exact installed identity and unchanged files, using
the existing lifecycle atomic writes. Failed qualification leaves the version
inactive. Existing same-version installations are never overwritten implicitly;
inspect their lifecycle state or use a fresh disposable validation data directory.

Every later Request gets fresh exact target/scope/budget/network binding and a
fresh acquisition result. Persistent activation never grants another target's
qualification. Reopen Runtime after lifecycle changes to refresh its catalog;
in-flight installed wrappers also reject disabled or broken versions.

```bash
python tools/browser/install.py disable --tool playwright --data-dir "$BROWSER_DATA_DIR"
python tools/browser/install.py disable --tool cloakbrowser --data-dir "$BROWSER_DATA_DIR"
```

Reopening Runtime after both commands restores HTTP-only operation. When a newer version is active and an older qualified, enabled version has
been retained, use the lifecycle rollback operation:

```bash
python tools/browser/install.py rollback --tool playwright --version 1.0.0 \
  --data-dir "$BROWSER_DATA_DIR"
```

Rollback still uses lifecycle validation/atomic state; execution still needs a
fresh Request binding. It cannot make a disabled, broken or unqualified version
executable, and requires a newer active version. Disabling both tools is the
HTTP-only rollback; reinstalling validation runtimes uses a fresh data directory.

## Network, output and cleanup contracts

The parent bridge runs the existing #101 Gateway for every navigation, script,
XHR and resource GET. Robots, per-hop redirects, DNS/network boundaries, origin,
path, content type, request count, bytes and one absolute deadline remain under
the original Request. Required resources outside that authority cause failure.
No CDN is implicitly authorized. Browser resource callbacks cannot issue writes.
Native HTTP proxy and CONNECT traffic are denied, service workers and WebSockets
are blocked, and browser DNS/background/UDP paths are constrained at launch.
Independent real-runtime I/O observation is still a release gate.

The subprocess runner retains the same wire fields. Only explicitly parent-bound
acquisition separates the manifest rendered-output limit from parent-measured
network bytes; ordinary external tools retain legacy inference and budget checks.
Parent output provenance, path/MIME/status/SHA checks and Registry limits remain
mandatory. Empty/only-script/error/challenge content cannot be committed as valid
content. Authentication and interactive challenges are terminal. HTML browsers
cannot receive a main-document file response.

Page/context/browser and SDK handles close in `finally`; cancellation/deadline
monitoring interrupts rendering. Parent bridge, transport, subprocess workspace
and temporary profile are closed for success and failure. Existing Runtime
commit/cancellation boundaries preserve earlier committed evidence and the
standard source/Markdown/Observation/Manifest/Result/handoff representation.

## Validation and evidence

The default suite is offline. `tests/integration/test_browser_acquisition.py`
explicitly uses a fake SDK for deterministic installed-runtime behavior. Its
separate subprocess/loopback case is skipped if the sandbox forbids sockets;
this is not real SDK evidence.

The manager's explicit real validation uses only the frozen fixture cases and
IPCC/TNFD snapshot, through actual `RuntimeService.open` installations:

```bash
WEB_LISTENING_RUN_LIVE=1 \
WEB_LISTENING_LIVE_AUTHORIZED_WINDOW="$AUTHORIZATION_WINDOW" \
WEB_LISTENING_BROWSER_DATA_DIR="$BROWSER_DATA_DIR" \
python -m pytest -q -m live tests/live/test_browser_chain_live.py
```

Each fixture case has at most 24 requests, 8 MiB and 60 seconds, including any
initial installation qualification reads. All public targets share 36 requests,
16 MiB and 120 seconds, concurrency one, retry zero. Public execution requires
both engines already active; it adds no separate public preflight fetches. URLs,
origins, catalog provenance and content expectations come only from the committed
snapshot; environment variables cannot inject replacement URLs.

Evidence is written below `data_dir/browser-validation`: lock/snapshot hashes,
installed environment, setup usage, ordered Attempts, parent network/robots
decisions, resource reads, Artifact digests, persisted Result and handoff checks.
Missing engines fail BLOCKED. Public failures record expected versus observed;
they are not converted into passing skips. A separate reviewer must audit native
egress, browser/child-process cleanup and real engine/build identity. This worker's
offline results do not satisfy either real-runtime gate.

## Migration mapping

Old repository reference: `89940fea711feb8fc98d7a4233e6cfb922fb8af1`, read-only.

| Reference | Disposition | Current implementation |
| --- | --- | --- |
| New #18/#44 CloakBrowser 0.5.9 `tool.py`/`tool.json`, IsolatedRuntime and recorded real TNFD evidence | Preserve protocol/control envelopes, identity, checks, output path/SHA and cleanup; preserve exact runtime image provenance | `cloakbrowser/0.5.9`, lifecycle activation bridge and fresh IsolatedRuntime binding |
| #18 controlled network observation | Extend | Parent Gateway bridge observes navigation and required resources, returns measured usage and robots evidence |
| Old `playwright_wrapper` first-document offline rendering | Rewrite | Versioned external Playwright with real routed navigation and JS/XHR; no offline-first-HTML substitute |
| Old `article_content` / `acquisition_fallback` observable stop/switch behavior | Preserve behavior, rewrite ownership | Registry order/quality classification; Request authority and shared Runtime budget |
| Old disabled Cloak wrapper and generic article-analysis logic | Discard | No disabled-wrapper import, semantic extraction or analysis platform |
| Old #68 login/subscription sessions and manual challenge continuation | Exclude | Explicit terminal authentication/interactive outcomes; no session continuation |

Same-shaped callers remain unified: acquire calls `run_single_target`; URL Fetch
and refresh call its bounded wrapper; site exploration calls it for seeds and
candidates; batch reuses exploration/refresh per site. CLI/REST/MCP call Runtime
and do not choose tools. No site orchestration, Request/Jobs/Store schema or
interface production path changes are needed. No production migration or climate
client cutover is implied by these adapters.

Runtime reopening verifies the installation's persisted `runtime-lock.json`
against the reviewed lock digest embedded in Runtime. It then checks the installed
adapter hashes and the complete locked runtime configuration. Playwright's SDK
tree and browser executable are rehashed; CloakBrowser is measured again inside
the exact digest-pinned image with `--pull=never --network=none`. Build/channel,
SDK and executable identity must agree before registration. Missing or mismatched
identity produces `eligibility.runtime_identity_mismatch` without changing
lifecycle activation. Installations made before lock persistence must be
reinstalled into a fresh data directory through this installer. Fresh exact
Request qualification still runs
for every actual acquisition; reopening performs no target fetches.

Offline fake-SDK tests explicitly substitute a test-owned lock digest and simulate
the container measurement. That test substitution is never a production runtime
source or qualification claim.
