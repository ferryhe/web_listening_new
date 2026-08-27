"""Conforming lifecycle fixture version 2.0.0."""

# pylint: disable=duplicate-code

import hashlib
import json
import sys
from pathlib import Path

request = json.load(sys.stdin)
if request["protocol_version"] == "web-listening-external-tool.v1":
    tool_input = request["input"]
    BODY = b"x"
    Path("probe.txt").write_bytes(BODY)
    response = {
        "protocol_version": "web-listening-external-tool.v1",
        "category": "acquisition",
        "status": "success",
        "tool_id": "external.lifecycle",
        "tool_version": "2.0.0",
        "result": {
            "requested_url": tool_input["target_url"],
            "final_url": tool_input["target_url"],
            "status_code": 200,
            "mime_type": "text/plain",
            "output_path": "probe.txt",
            "size_bytes": len(BODY),
            "sha256": hashlib.sha256(BODY).hexdigest(),
            "redirects": [],
            "runtime_ms": 0,
        },
    }
else:
    operation = request["operation"]
    expected = {
        "protocol_version": "web-listening-tool-qualification.v1",
        "operation": operation,
        "tool_id": "external.lifecycle",
        "version": "2.0.0",
        "category": "acquisition",
    }
    if operation == "probe":
        expected["checks"] = ["governed_input", "bounded_output"]
    if request != expected:
        raise SystemExit("invalid qualification request")
    response = {
        "protocol_version": "web-listening-tool-qualification.v1",
        "operation": operation,
        "status": "ok",
    }
    if operation == "describe":
        response.update(
            tool_id="external.lifecycle", version="2.0.0", category="acquisition"
        )
    elif operation == "health":
        response["health"] = "healthy"
    elif operation == "probe":
        response.update(
            result="qualified",
            category="acquisition",
            checks=["governed_input", "bounded_output"],
        )
json.dump(response, sys.stdout, sort_keys=True)
