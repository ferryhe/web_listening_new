"""One REST-worker FIRST/REFRESH batch with offline CLI/MCP read parity."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import anyio
import pytest

pytest.importorskip("fastapi", reason="install the optional REST extra")
pytest.importorskip("mcp", reason="install the optional MCP extra")
from fastapi.testclient import TestClient  # pylint: disable=wrong-import-position

from web_listening.interfaces import cli  # pylint: disable=wrong-import-position
from web_listening.interfaces.mcp import (  # pylint: disable=wrong-import-position
    _call_tool,
)
from web_listening.interfaces.server import (  # pylint: disable=wrong-import-position
    ServerConfig,
    build_app,
    write_token_file,
)
from web_listening.request.model import (  # pylint: disable=wrong-import-position
    Budgets,
    ContentType,
    Request,
    Scope,
)
from web_listening.request.site_batch import (  # pylint: disable=wrong-import-position
    SiteBatchPhase,
    SiteBatchRequest,
)
from web_listening.runtime.service import (  # pylint: disable=wrong-import-position
    RuntimeService,
)
from web_listening.runtime.site_batch import (  # pylint: disable=wrong-import-position
    site_batch_result_from_mapping,
)

TARGETS = Path(__file__).with_name("public_site_batch_targets.json")
CATALOG = Path(__file__).parent / "catalog" / "dev_test_sites.json"
TERMINAL = {"completed", "partial", "rejected", "failed"}


def _request(
    snapshot: dict[str, object], site_keys: tuple[str, ...] | None = None
) -> Request:
    targets = snapshot["targets"]
    limits = snapshot["limits_per_site_per_phase"]
    assert isinstance(targets, list) and isinstance(limits, dict)
    selected = [
        item
        for item in targets
        if site_keys is None or urlsplit(item["document_url"]).hostname in site_keys
    ]
    if site_keys is not None:
        assert (
            tuple(urlsplit(item["document_url"]).hostname for item in selected)
            == site_keys
        )
    return Request(
        Scope(
            tuple(item["document_url"] for item in selected),
            tuple(origin for item in selected for origin in item["allowed_origins"]),
            ("/**",),
            (ContentType.HTML, ContentType.FILE),
        ),
        None,
        True,
        Budgets(
            limits["max_requests"],
            limits["max_bytes"],
            limits["max_runtime_seconds"],
            limits["max_tool_attempts_per_target"],
        ),
    )


def _snapshot() -> dict[str, object]:
    snapshot = json.loads(TARGETS.read_text(encoding="utf-8"))
    assert snapshot["source_catalog_path"] == ("tests/live/catalog/dev_test_sites.json")
    digest = hashlib.sha256(CATALOG.read_bytes().replace(b"\r\n", b"\n"))
    assert snapshot["source_catalog_sha256"] == digest.hexdigest().upper()
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    by_key = {item["site_key"]: item for item in catalog["sites"]}
    for target in snapshot["targets"]:
        source = by_key[target["site_key"]]
        assert target["document_url"] == source["urls"]["document"]
        assert target["allowed_origins"] == source["allowed_origins"]
        assert target["provenance"] == source["provenance"]
    return snapshot


def _wait(client: TestClient, batch_id: str, headers: dict[str, str]) -> dict:
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        response = client.get(f"/v1/site-batches/{batch_id}", headers=headers)
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in TERMINAL:
            return payload
        time.sleep(0.05)
    pytest.fail("public batch did not become terminal")
    raise AssertionError("unreachable")


def _assert_evidence(
    payload: dict, limits: dict, expected_site_keys: tuple[str, ...]
) -> None:
    assert [item["order"] for item in payload["children"]] == list(
        range(1, len(expected_site_keys) + 1)
    )
    assert tuple(item["site_key"] for item in payload["children"]) == (
        expected_site_keys
    )
    result = payload["result"]
    assert result is not None
    assert result["run_id"] == payload["batch_id"]
    assert len(result["site_results"]) == len(expected_site_keys)
    for child in result["site_results"]:
        usage = child["usage"]
        assert usage["requests"] <= limits["max_requests"]
        assert usage["bytes_received"] <= limits["max_bytes"]
        for target in child["target_results"]:
            assert (
                target["usage"]["tool_attempts"]
                <= limits["max_tool_attempts_per_target"]
            )
            assert len(target["attempts"]) <= limits["max_tool_attempts_per_target"]
            for artifact in target["artifacts"]:
                assert artifact["artifact_id"]
                assert artifact["observation_id"]
                if artifact["role"] == "derived":
                    assert artifact["lineage"]
    assert site_batch_result_from_mapping(result).to_dict() == result


@pytest.mark.live
# pylint: disable-next=too-many-locals
def test_public_rest_worker_first_refresh_and_local_read_parity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run network work only through authenticated REST and the real worker."""
    snapshot = _snapshot()
    if os.environ.get("WEB_LISTENING_RUN_PUBLIC_BATCH_LIVE") != "1":
        pytest.skip("public batch live is offline by default")
    if not os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW"):
        pytest.skip("manager authorization window is required")
    limits = snapshot["limits_per_site_per_phase"]
    assert limits == {
        "max_requests": 12,
        "max_bytes": 52_428_800,
        "max_runtime_seconds": 60,
        "max_tool_attempts_per_target": 4,
        "concurrency": 1,
        "retry": 0,
    }
    data_root = tmp_path / "data"
    token = write_token_file(tmp_path / "token.json", "live-manager")
    config = ServerConfig(
        data_root,
        tmp_path / "token.json",
        concurrency=1,
        worker_poll_interval_seconds=0.05,
    )
    headers = {"Authorization": f"Bearer {token}"}
    parent = _request(snapshot)
    first_site_keys = ("www.soa.org", "www.casact.org", "actuaries.org")
    with TestClient(build_app(config)) as client:
        first_response = client.post(
            "/v1/site-batches",
            headers={**headers, "Idempotency-Key": "public-first"},
            json=SiteBatchRequest(SiteBatchPhase.FIRST, parent, ()).to_dict(),
        )
        assert first_response.status_code == 202
        first = _wait(client, first_response.json()["batch_id"], headers)
        _assert_evidence(first, limits, first_site_keys)
        first_result = site_batch_result_from_mapping(first["result"])
        context_site_keys = tuple(
            context.site_skill.site_key
            for context in first_result.next_refresh_contexts
        )
        assert context_site_keys == first_result.usable_site_keys
        assert context_site_keys, {
            "site_keys": first_result.site_keys,
            "site_modes": [item.value for item in first_result.site_modes],
            "file_discovery_statuses": [
                item.value for item in first_result.file_discovery_statuses
            ],
            "child_statuses": [item.status.value for item in first_result.site_results],
            "child_stop_reasons": [
                item.stop_reason for item in first_result.site_results
            ],
            "usable_site_keys": first_result.usable_site_keys,
        }
        refresh_parent = _request(snapshot, context_site_keys)
        refresh_response = client.post(
            "/v1/site-batches",
            headers={**headers, "Idempotency-Key": "public-refresh"},
            json=SiteBatchRequest(
                SiteBatchPhase.REFRESH,
                refresh_parent,
                first_result.next_refresh_contexts,
            ).to_dict(),
        )
        assert refresh_response.status_code == 202
        refresh = _wait(client, refresh_response.json()["batch_id"], headers)
        _assert_evidence(refresh, limits, context_site_keys)
        assert site_batch_result_from_mapping(refresh["result"]).next_refresh_contexts

    for expected in (first, refresh):
        assert (
            cli.main(
                [
                    "batch-get",
                    expected["batch_id"],
                    "--output",
                    str(data_root),
                    "--json",
                ]
            )
            == 0
        )
        cli_payload = json.loads(capsys.readouterr().out)
        runtime = RuntimeService.open(data_root)
        try:
            mcp_payload = anyio.run(
                _call_tool,
                lambda runtime=runtime: runtime,
                "web_listening_get_site_batch",
                {"batch_id": expected["batch_id"]},
            )
        finally:
            runtime.close()
        assert isinstance(mcp_payload, dict)
        assert cli_payload == mcp_payload == expected
