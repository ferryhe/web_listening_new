"""Conforming transform lifecycle fixture."""

# pylint: disable=duplicate-code

import hashlib
import json
import sys
from pathlib import Path

request = json.load(sys.stdin)
if request["protocol_version"] == "web-listening-external-tool.v1":
    source_artifact_id = request["input"]["source_artifact_id"]
    BODY = b"y"
    Path("probe.md").write_bytes(BODY)
    response = {
        "protocol_version": "web-listening-external-tool.v1",
        "category": "transform",
        "status": "success",
        "tool_id": "external.transform",
        "tool_version": "1.0.0",
        "result": {
            "source_artifact_id": source_artifact_id,
            "mime_type": "text/markdown",
            "output_path": "probe.md",
            "size_bytes": len(BODY),
            "sha256": hashlib.sha256(BODY).hexdigest(),
            "runtime_ms": 0,
        },
    }
else:
    operation = request["operation"]
    expected = {
        "protocol_version": "web-listening-tool-qualification.v1",
        "operation": operation,
        "tool_id": "external.transform",
        "version": "1.0.0",
        "category": "transform",
    }
    if operation == "probe":
        expected["checks"] = ["stored_source", "derived_output"]
    if request != expected:
        raise SystemExit("invalid qualification request")
    response = {
        "protocol_version": "web-listening-tool-qualification.v1",
        "operation": operation,
        "status": "ok",
    }
    if operation == "describe":
        response.update(
            tool_id="external.transform", version="1.0.0", category="transform"
        )
    elif operation == "health":
        response["health"] = "healthy"
    elif operation == "probe":
        response.update(
            result="qualified",
            category="transform",
            checks=["stored_source", "derived_output"],
        )
json.dump(response, sys.stdout, sort_keys=True)
