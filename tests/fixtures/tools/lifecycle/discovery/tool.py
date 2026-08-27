"""Conforming discovery lifecycle fixture."""

# pylint: disable=duplicate-code

import json
import sys

request = json.load(sys.stdin)
if request["protocol_version"] == "web-listening-external-tool.v1":
    source_url = request["input"]["source_url"]
    response = {
        "protocol_version": "web-listening-external-tool.v1",
        "category": "discovery",
        "status": "success",
        "tool_id": "external.discovery",
        "tool_version": "1.0.0",
        "result": {
            "candidates": ["https://example.test/item"],
            "discovered_from": [source_url],
        },
    }
else:
    operation = request["operation"]
    expected = {
        "protocol_version": "web-listening-tool-qualification.v1",
        "operation": operation,
        "tool_id": "external.discovery",
        "version": "1.0.0",
        "category": "discovery",
    }
    if operation == "probe":
        expected["checks"] = ["governed_input", "bounded_candidates"]
    if request != expected:
        raise SystemExit("invalid qualification request")
    response = {
        "protocol_version": "web-listening-tool-qualification.v1",
        "operation": operation,
        "status": "ok",
    }
    if operation == "describe":
        response.update(
            tool_id="external.discovery", version="1.0.0", category="discovery"
        )
    elif operation == "health":
        response["health"] = "healthy"
    elif operation == "probe":
        response.update(
            result="qualified",
            category="discovery",
            checks=["governed_input", "bounded_candidates"],
        )
json.dump(response, sys.stdout, sort_keys=True)
