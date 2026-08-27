"""Fixture that self-reports qualification but lacks the category protocol."""

import json
import sys

request = json.load(sys.stdin)
operation = request["operation"]
response = {
    "protocol_version": "web-listening-tool-qualification.v1",
    "operation": operation,
    "status": "ok",
}
if operation == "describe":
    response.update(
        tool_id="external.lifecycle", version="5.0.0", category="acquisition"
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
