"""Authorized fixed-target URL-fetch REST/worker smoke test."""

# pylint: disable=missing-function-docstring

import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from web_listening.interfaces.rest import RestConfig, create_app
from web_listening.runtime.acquisition_service import AcquisitionService
from web_listening.runtime.service import RuntimeService

TARGETS = Path(__file__).with_name("url_fetch_targets.json")
WINDOW = "issue-53-20260905-authorized"


@pytest.mark.skipif(
    os.environ.get("WEB_LISTENING_RUN_LIVE") != "1"
    or os.environ.get("WEB_LISTENING_LIVE_AUTHORIZED_WINDOW") != WINDOW,
    reason="authorized URL-fetch Live is disabled",
)
@pytest.mark.live
def test_fixed_targets_through_authenticated_rest_and_persistent_worker(tmp_path):
    snapshot = json.loads(TARGETS.read_text(encoding="utf-8"))
    runtime = RuntimeService.open(tmp_path / "data")
    worker = AcquisitionService(
        runtime, runtime.job_repository, concurrency=1, clock=runtime.clock
    )
    token = "live-test-token"
    client = TestClient(
        create_app(
            lambda: runtime,
            RestConfig("live-auditor", hashlib.sha256(token.encode()).hexdigest()),
            wake=worker.wake,
        )
    )
    headers = {"Authorization": f"Bearer {token}"}
    try:
        for index, target in enumerate(snapshot["targets"]):
            response = client.post(
                "/v1/url-fetches",
                headers={**headers, "Idempotency-Key": f"fixed-{index}"},
                json={
                    "url": target["url"],
                    "explore_all_tools": False,
                    "follow_html_navigation": False,
                    "max_navigation_hops": 3,
                    "budgets": snapshot["budgets"],
                },
            )
            assert response.status_code == 202
            job_id = response.json()["job_id"]
            for _ in range(300):
                payload = client.get(
                    f"/v1/url-fetches/{job_id}", headers=headers
                ).json()
                if payload["status"] in {"completed", "partial", "failed", "rejected"}:
                    break
                time.sleep(0.01)
            assert payload["status"] == "completed"
            assert payload["result"]["resolved_content_type"] == target["kind"]
            assert "content" not in payload["result"]
    finally:
        worker.close()
        runtime.close()
