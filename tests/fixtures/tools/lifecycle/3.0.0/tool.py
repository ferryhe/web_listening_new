"""Broken-health lifecycle fixture version 3.0.0."""

# pylint: disable=duplicate-code

import json
import sys

request = json.load(sys.stdin)
operation = request["operation"]
expected = {
    "protocol_version": "web-listening-tool-qualification.v1",
    "operation": operation,
    "tool_id": "external.lifecycle",
    "version": "3.0.0",
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
        tool_id="external.lifecycle", version="3.0.0", category="acquisition"
    )
elif operation == "health":
    response.update(status="failed", health="unhealthy")
elif operation == "probe":
    response.update(
        result="qualified",
        category="acquisition",
        checks=["governed_input", "bounded_output"],
    )
json.dump(response, sys.stdout, sort_keys=True)
