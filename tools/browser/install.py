"""Install frozen browser adapters using Lifecycle and live parent qualification.

This installer never downloads Python packages, browser binaries or images.
Operators provision the locked runtime first; qualification needs an explicit
Request and authorization window and reports all of its actual network usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from web_listening.request.validate import request_from_json
from web_listening.tool_registry.lifecycle import ToolLifecycle
from web_listening.tool_registry.manifest import ToolCategory, ToolRegistryError
from web_listening.tool_registry.protocols.acquisition import AcquisitionInput
from web_listening.tool_registry.runners.browser_acquisition import (
    FROZEN_RUNTIME_LOCK_SHA256,
    BrowserAcquisitionTool,
    cloak_runtime,
    host_runtime,
)


def install(args) -> dict:  # pylint: disable=too-many-locals
    """Install/qualify/activate without directly editing lifecycle state."""
    root = Path(__file__).resolve().parent
    lock_bytes = (root / "runtime-lock.json").read_bytes()
    if hashlib.sha256(lock_bytes).hexdigest() != FROZEN_RUNTIME_LOCK_SHA256:
        raise ValueError("browser.runtime_lock_mismatch")
    lock = json.loads(lock_bytes)
    entry = lock["tools"][args.tool]
    data_root = Path(args.data_dir).resolve()
    data_root.mkdir(parents=True, exist_ok=True)
    lifecycle = ToolLifecycle(data_root)
    identity = (
        ToolCategory.ACQUISITION,
        entry["tool_id"],
        args.version or entry["adapter_version"],
    )
    if args.action == "disable":
        state = lifecycle.disable(*identity)
        return {
            "tool_id": state.manifest.tool_id,
            "active": state.active,
            "disabled": state.disabled,
        }
    if args.action == "rollback":
        state = lifecycle.rollback(*identity)
        return {
            "tool_id": state.manifest.tool_id,
            "version": state.manifest.version,
            "active": state.active,
        }
    if not args.request or not args.authorization_window.strip():
        raise ValueError("browser.explicit_request_and_authorization_required")
    request = request_from_json(Path(args.request).read_text(encoding="utf-8"))
    if len(request.scope.seeds) != 1:
        raise ValueError("browser.single_qualification_target_required")
    source = root / args.tool / entry["adapter_version"]
    for filename, expected in entry["adapter_files_sha256"].items():
        if hashlib.sha256((source / filename).read_bytes()).hexdigest() != expected:
            raise ValueError("browser.adapter_digest_mismatch")
    if args.tool == "playwright":
        if not args.runtime_root:
            raise ValueError("browser.runtime_root_required")
        config = host_runtime(Path(args.runtime_root), data_root, entry)
    else:
        config = cloak_runtime(entry, args.docker)
    with tempfile.TemporaryDirectory(prefix="browser-install-") as temporary:
        staging = Path(temporary) / "source"
        shutil.copytree(source, staging)
        (staging / "runtime-lock.json").write_bytes(lock_bytes)
        (staging / "runtime.json").write_text(json.dumps(config, sort_keys=True) + "\n")
        state = lifecycle.install(staging)
    installed = (
        data_root / "tools/acquisition" / entry["tool_id"] / entry["adapter_version"]
    )
    tool = BrowserAcquisitionTool(
        state.manifest, (sys.executable, str(installed / "tool.py")), lifecycle
    )
    try:
        runtime, report = tool.qualify(
            AcquisitionInput(request, request.scope.seeds[0]), args.authorization_window
        )
        result = report.result
        evidence = {
            "tool_id": entry["tool_id"],
            "version": entry["adapter_version"],
            "qualified": report.qualified,
            "active": False,
            "failure_code": report.failure_code,
            "binding_sha256": report.binding_sha256,
            "runtime_lock_sha256": hashlib.sha256(
                (root / "runtime-lock.json").read_bytes()
            ).hexdigest(),
            "runtime": config,
            "requests": result.requests,
            "bytes_received": result.bytes_received,
            "runtime_ms": result.runtime_ms,
            "robots_decisions": [item.to_dict() for item in result.robots_decisions],
            "output_sha256": getattr(result, "sha256", None),
        }
        if report.qualified:
            evidence["active"] = lifecycle.activate_qualified(runtime, report).active
        return evidence
    finally:
        tool.close()


def main() -> int:
    """Execute one explicit lifecycle operation and print evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "disable", "rollback"))
    parser.add_argument("--tool", required=True, choices=("playwright", "cloakbrowser"))
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--runtime-root")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--version")
    parser.add_argument("--request")
    parser.add_argument("--authorization-window", default="")
    args = parser.parse_args()
    try:
        result = install(args)
    except (OSError, ValueError, ToolRegistryError, subprocess.SubprocessError) as exc:
        print(
            json.dumps(
                {
                    "active": False,
                    "status": "BLOCKED",
                    "code": getattr(exc, "code", "browser.runtime_unavailable"),
                }
            )
        )
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if args.action != "install" or result["active"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
