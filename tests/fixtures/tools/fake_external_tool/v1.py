"""Version-one fake external tool used only by subprocess runner tests."""

# pylint: disable=missing-function-docstring,too-many-return-statements

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PROTOCOL_VERSION = "web-listening-external-tool.v1"
TOOL_ID = "external.fake"
TOOL_VERSION = "1.0.0"


def _write_json(value: object) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":")))
    sys.stdout.flush()


def _response(category: str, result: dict[str, object]) -> dict[str, object]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "category": category,
        "status": "success",
        "tool_id": TOOL_ID,
        "tool_version": TOOL_VERSION,
        "result": result,
    }


def _content_result(request: dict[str, object], category: str) -> dict[str, object]:
    if category == "acquisition":
        body = b"<!doctype html><html><body>captured</body></html>"
        output_path = "result.html"
        result = {
            "requested_url": request["input"]["target_url"],
            "final_url": request["input"]["target_url"],
            "status_code": 200,
            "mime_type": "text/html",
            "output_path": output_path,
            "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "redirects": [],
            "runtime_ms": 1,
        }
    else:
        body = b"# converted\n"
        output_path = "result.md"
        result = {
            "source_artifact_id": request["input"]["source_artifact_id"],
            "mime_type": "text/markdown",
            "output_path": output_path,
            "size_bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "runtime_ms": 1,
        }
    Path(output_path).write_bytes(body)
    return result


def main() -> int:  # pylint: disable=too-many-branches,too-many-statements
    behavior = sys.argv[1]
    if behavior == "timeout":
        time.sleep(30)
        return 0
    if behavior == "stdout_large":
        os.write(sys.stdout.fileno(), b"x" * 100_000)
        return 0
    if behavior == "stderr_large":
        os.write(sys.stderr.fileno(), b"x" * 100_000)
        time.sleep(30)
        return 0

    request = json.loads(sys.stdin.buffer.read())
    category = request["category"]
    if behavior == "nonzero":
        sys.stderr.write("Authorization: Bearer fixture-secret")
        return 7
    if behavior == "malformed_json":
        sys.stdout.write("not-json")
        return 0
    if behavior in {"failed", "rejected"}:
        _write_json(
            {
                "protocol_version": PROTOCOL_VERSION,
                "category": category,
                "status": behavior,
                "tool_id": TOOL_ID,
                "tool_version": TOOL_VERSION,
                "result": {
                    "code": (
                        "external.unavailable"
                        if behavior == "failed"
                        else "external.unsupported"
                    )
                },
            }
        )
        return 0
    if behavior == "discovery_success":
        source_url = request["input"]["source_url"]
        _write_json(
            _response(
                category,
                {
                    "candidates": ["https://example.test/report"],
                    "discovered_from": [source_url],
                },
            )
        )
        return 0

    result = _content_result(request, category)
    if behavior == "path_traversal":
        result["output_path"] = "../outside.html"
    elif behavior == "absolute_path":
        result["output_path"] = str((Path.cwd() / "result.html").resolve())
    elif behavior == "windows_absolute_path":
        result["output_path"] = "C:/outside.html"
    elif behavior == "symlink":
        target = Path(result["output_path"])
        link = Path("linked" + target.suffix)
        try:
            link.symlink_to(target.name)
        except OSError:
            if os.name != "nt":
                return 42
            target_directory = Path("target-directory")
            target_directory.mkdir()
            nested_target = target_directory / target.name
            target.replace(nested_target)
            linked_directory = Path("linked-directory")
            command = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
            completed = subprocess.run(
                (
                    str(command),
                    "/d",
                    "/c",
                    "mklink",
                    "/J",
                    str(linked_directory),
                    str(target_directory.resolve()),
                ),
                check=False,
                capture_output=True,
            )
            if completed.returncode:
                return 42
            result["output_path"] = f"{linked_directory.name}/{target.name}"
        else:
            result["output_path"] = link.name
    elif behavior == "hash_mismatch":
        result["sha256"] = "0" * 64
    elif behavior == "size_mismatch":
        result["size_bytes"] = int(result["size_bytes"]) + 1
    elif behavior == "mime_mismatch":
        result["mime_type"] = "application/pdf"
    elif behavior == "url_mismatch":
        result["requested_url"] = "https://example.test/unrelated"
        result["final_url"] = "https://example.test/unrelated"
    elif behavior == "identity_mismatch":
        payload = _response(category, result)
        payload["tool_version"] = "9.9.9"
        _write_json(payload)
        return 0
    elif behavior == "pdf_mime_mismatch":
        Path(result["output_path"]).unlink()
        body = b"%PDF-1.4\nfixture\n"
        result["output_path"] = "result.html"
        result["size_bytes"] = len(body)
        result["sha256"] = hashlib.sha256(body).hexdigest()
        result["mime_type"] = "text/html"
        Path(result["output_path"]).write_bytes(body)
    elif behavior == "non_pdf_claimed_pdf":
        Path(result["output_path"]).replace("result.bin")
        result["output_path"] = "result.bin"
        result["mime_type"] = "application/pdf"
    elif behavior != "content_success":
        raise RuntimeError("unknown fixture behavior")
    _write_json(_response(category, result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
