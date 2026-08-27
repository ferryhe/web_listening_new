"""Deliberately false external declarations for parent recheck tests."""

import hashlib
import json
import sys
from pathlib import Path

request = json.load(sys.stdin)
case = sys.argv[1]
tool_input = request["input"]
BODY = b"<html>x</html>"
Path("capture.html").write_bytes(BODY)
result = {
    "requested_url": tool_input["target_url"],
    "final_url": tool_input["target_url"],
    "status_code": 200,
    "mime_type": "text/html",
    "output_path": "capture.html",
    "size_bytes": len(BODY),
    "sha256": hashlib.sha256(BODY).hexdigest(),
    "redirects": [],
    "runtime_ms": 0,
}
if case == "url":
    result["requested_url"] = "https://outside.test/"
    result["final_url"] = "https://outside.test/"
elif case == "path":
    result["output_path"] = "../capture.html"
elif case == "mime":
    result["mime_type"] = "application/json"
elif case == "size":
    result["size_bytes"] += 1
elif case == "sha256":
    result["sha256"] = "0" * 64
json.dump(
    {
        "protocol_version": "web-listening-external-tool.v1",
        "category": "acquisition",
        "status": "success",
        "tool_id": "acquisition.cloakbrowser",
        "tool_version": "0.5.9",
        "result": result,
    },
    sys.stdout,
    sort_keys=True,
)
