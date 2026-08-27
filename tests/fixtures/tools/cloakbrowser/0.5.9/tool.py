"""Thin pinned CloakBrowser 0.5.9 external Acquisition Adapter."""

# pylint: disable=broad-exception-caught,duplicate-code,missing-function-docstring
# pylint: disable=too-many-boolean-expressions,too-many-locals,too-many-return-statements
# pylint: disable=too-many-nested-blocks

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from importlib import import_module
from pathlib import Path
from urllib.parse import urlsplit

TOOL_ID = "acquisition.cloakbrowser"
VERSION = "0.5.9"
EXTERNAL_PROTOCOL = "web-listening-external-tool.v1"
QUALIFICATION_PROTOCOL = "web-listening-tool-qualification.v1"
BOUNDARY_SCHEMA = "web-listening-network-boundary.v1"
REQUIRED_CHECKS = [
    "health",
    "protocol",
    "scope",
    "redirect",
    "output_bound",
    "controlled_proxy_or_network_isolation",
]
BOUNDARY_KEYS = {
    "schema_version",
    "authorization_window_id",
    "kind",
    "allowed_origins",
    "proxy_server",
    "browser_profile_home",
    "target_url",
    "attempt_nonce",
    "attempt_directory",
    "limits",
}
MISSING = object()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _load_input():
    return json.load(sys.stdin, object_pairs_hook=_unique_object)


def _boundary():
    arguments = sys.argv[1:]
    if len(arguments) != 2 or arguments[0] != "--web-listening-boundary":
        return None
    try:
        raw = base64.urlsafe_b64decode(arguments[1].encode("ascii"))
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("schema_version") != BOUNDARY_SCHEMA:
        return None
    return value


def _network_is_controlled(boundary):
    if not isinstance(boundary, dict) or set(boundary) != BOUNDARY_KEYS:
        return False
    authorization = boundary.get("authorization_window_id")
    attempt_nonce = boundary.get("attempt_nonce")
    origins = boundary.get("allowed_origins")
    if (
        not isinstance(authorization, str)
        or len(authorization) != 64
        or any(character not in "0123456789abcdef" for character in authorization)
        or not isinstance(attempt_nonce, str)
        or len(attempt_nonce) != 64
        or any(character not in "0123456789abcdef" for character in attempt_nonce)
        or not isinstance(origins, list)
        or not origins
        or any(not isinstance(value, str) for value in origins)
    ):
        return False
    if boundary.get("kind") != "controlled_proxy":
        return False
    proxy = boundary.get("proxy_server")
    return (
        isinstance(proxy, str)
        and bool(proxy.strip())
        and _browser_profile_home(boundary) is not None
    )


def _browser_profile_home(boundary):
    if not isinstance(boundary, dict):
        return None
    raw = boundary.get("browser_profile_home")
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return None
    candidate = Path(raw)
    if (
        not candidate.is_absolute()
        or candidate.parent == candidate
        or candidate.as_posix() == "/root"
        or str(candidate) != raw
    ):
        return None
    try:
        resolved = candidate.resolve(strict=True)
        certificate_database = resolved / ".pki" / "nssdb" / "cert9.db"
        if resolved != candidate or not resolved.is_dir():
            return None
        if (
            not certificate_database.is_file()
            or certificate_database.stat().st_size <= 0
        ):
            return None
    except OSError:
        return None
    return str(resolved)


def _apply_browser_profile_home(boundary):
    profile_home = _browser_profile_home(boundary)
    if profile_home is None:
        raise RuntimeError("browser profile unavailable")
    os.environ["HOME"] = profile_home


def _control(request, boundary):
    expected = {
        "protocol_version": QUALIFICATION_PROTOCOL,
        "operation": request.get("operation"),
        "tool_id": TOOL_ID,
        "version": VERSION,
        "category": "acquisition",
    }
    if request.get("operation") == "probe":
        expected["checks"] = request.get("checks")
    if request != expected:
        return {
            "protocol_version": QUALIFICATION_PROTOCOL,
            "operation": request.get("operation"),
            "status": "error",
        }
    operation = request["operation"]
    if operation == "describe":
        return {
            "protocol_version": QUALIFICATION_PROTOCOL,
            "operation": "describe",
            "status": "ok",
            "tool_id": TOOL_ID,
            "version": VERSION,
            "category": "acquisition",
        }
    if operation == "health":
        try:
            _preflight(boundary)
        except Exception:
            return {
                "protocol_version": QUALIFICATION_PROTOCOL,
                "operation": "health",
                "status": "error",
            }
        return {
            "protocol_version": QUALIFICATION_PROTOCOL,
            "operation": "health",
            "status": "ok",
            "health": "healthy",
        }
    if operation == "probe":
        return {
            "protocol_version": QUALIFICATION_PROTOCOL,
            "operation": "probe",
            "status": "ok",
            "result": (
                "qualified" if _network_is_controlled(boundary) else "unqualified"
            ),
            "category": "acquisition",
            "checks": REQUIRED_CHECKS,
        }
    return {
        "protocol_version": QUALIFICATION_PROTOCOL,
        "operation": operation,
        "status": "error",
    }


def _load_sdk():
    sdk = import_module("cloakbrowser")
    if getattr(sdk, "__version__", None) != VERSION:
        raise RuntimeError("version mismatch")
    launch = getattr(sdk, "launch", None)
    if not callable(launch):
        raise RuntimeError("launch unavailable")
    return launch


def _preflight(boundary):
    if boundary is not None:
        if not _network_is_controlled(boundary):
            raise RuntimeError("network boundary unavailable")
        _apply_browser_profile_home(boundary)
    launch = _load_sdk()
    options = {"headless": True}
    if isinstance(boundary, dict) and boundary.get("kind") == "controlled_proxy":
        options["proxy"] = boundary.get("proxy_server")
    browser = launch(**options)
    close = getattr(browser, "close", None)
    if not callable(close):
        raise RuntimeError("close unavailable")
    close()


def _failure(code, *, rejected=False):
    return {
        "protocol_version": EXTERNAL_PROTOCOL,
        "category": "acquisition",
        "status": "rejected" if rejected else "failed",
        "tool_id": TOOL_ID,
        "tool_version": VERSION,
        "result": {"code": code},
    }


def _origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    default = (parsed.scheme == "https" and parsed.port in {None, 443}) or (
        parsed.scheme == "http" and parsed.port in {None, 80}
    )
    authority = parsed.hostname if default else parsed.netloc
    return f"{parsed.scheme}://{authority}"


def _path_allowed(url, include_paths):
    path = urlsplit(url).path or "/"
    for pattern in include_paths:
        if pattern == "/**":
            return True
        if pattern.endswith("/**"):
            base = pattern[:-3]
            if path == base or path.startswith(base + "/"):
                return True
        if path == pattern:
            return True
    return False


def _input_values(request):
    if not isinstance(request, dict) or set(request) != {
        "protocol_version",
        "category",
        "tool_id",
        "tool_version",
        "attempt_directory",
        "input",
    }:
        return None
    if (
        request["protocol_version"] != EXTERNAL_PROTOCOL
        or request["category"] != "acquisition"
        or request["tool_id"] != TOOL_ID
        or request["tool_version"] != VERSION
        or request["attempt_directory"] != "."
    ):
        return None
    value = request["input"]
    if not isinstance(value, dict) or set(value) != {
        "target_url",
        "allowed_origins",
        "include_paths",
        "content_types",
        "limits",
    }:
        return None
    limits = value["limits"]
    if not isinstance(limits, dict) or set(limits) != {
        "max_requests",
        "max_bytes",
        "max_runtime_seconds",
    }:
        return None
    if (
        not isinstance(value["target_url"], str)
        or not isinstance(value["allowed_origins"], list)
        or not value["allowed_origins"]
        or any(not isinstance(item, str) for item in value["allowed_origins"])
        or not isinstance(value["include_paths"], list)
        or any(not isinstance(item, str) for item in value["include_paths"])
        or value["content_types"] != ["html"]
        or not isinstance(limits["max_requests"], int)
        or isinstance(limits["max_requests"], bool)
        or limits["max_requests"] <= 0
        or not isinstance(limits["max_bytes"], int)
        or isinstance(limits["max_bytes"], bool)
        or limits["max_bytes"] <= 0
        or not isinstance(limits["max_runtime_seconds"], (int, float))
        or isinstance(limits["max_runtime_seconds"], bool)
        or limits["max_runtime_seconds"] <= 0
    ):
        return None
    return value


def _boundary_matches(boundary, value):
    if not _network_is_controlled(boundary):
        return False
    if boundary["allowed_origins"] != value["allowed_origins"]:
        return False
    invocation_keys = {"target_url", "attempt_directory", "limits"}
    if not invocation_keys.issubset(boundary):
        return False
    limits = value["limits"]
    return (
        boundary["target_url"] == value["target_url"]
        and boundary["attempt_directory"] == "."
        and boundary["limits"]
        == {
            "max_requests": limits["max_requests"],
            "max_response_bytes": limits["max_bytes"],
            "max_output_bytes": limits["max_bytes"],
            "max_runtime_seconds": limits["max_runtime_seconds"],
            "max_redirects": max(0, limits["max_requests"] - 1),
        }
    )


def _value(member):
    return member() if callable(member) else member


def _is_plain_subresource(request):
    try:
        navigation_member = getattr(request, "is_navigation_request", MISSING)
        resource_type = getattr(request, "resource_type", MISSING)
        redirected_from = getattr(request, "redirected_from", MISSING)
        navigation = (
            MISSING if navigation_member is MISSING else _value(navigation_member)
        )
    except Exception:  # pylint: disable=broad-exception-caught
        return False
    return (
        navigation is False
        and isinstance(resource_type, str)
        and bool(resource_type)
        and resource_type.casefold() != "document"
        and redirected_from is None
    )


def _redirects(response):
    current = _value(getattr(response, "request", None))
    reversed_items = []
    while current is not None:
        previous = _value(getattr(current, "redirected_from", None))
        if previous is None:
            break
        previous_response = _value(getattr(previous, "response", None))
        reversed_items.append(
            {
                "from_url": _value(getattr(previous, "url", "")),
                "to_url": _value(getattr(current, "url", "")),
                "status_code": _value(getattr(previous_response, "status", 0)),
            }
        )
        current = previous
    return list(reversed(reversed_items))


def _response_headers(response):
    headers = _value(getattr(response, "headers", {}))
    if not isinstance(headers, dict):
        return {}
    return {str(key).casefold(): str(value) for key, value in headers.items()}


def _acquire(
    request, boundary
):  # pylint: disable=too-many-branches,too-many-statements
    value = _input_values(request)
    if value is None:
        return _failure("cloakbrowser.protocol_error")
    target = value["target_url"]
    origins = value["allowed_origins"]
    include_paths = value["include_paths"]
    if _origin(target) not in origins or not _path_allowed(target, include_paths):
        return _failure("cloakbrowser.scope_rejected", rejected=True)
    if not _boundary_matches(boundary, value):
        return _failure("cloakbrowser.network_unrestricted", rejected=True)

    limits = value["limits"]
    launch = None
    browser = None
    result = None
    failure = None
    started = time.monotonic()
    blocked = {"code": None}
    request_count = {"value": 0}
    try:
        _apply_browser_profile_home(boundary)
        launch = _load_sdk()
        options = {"headless": True}
        if boundary["kind"] == "controlled_proxy":
            options["proxy"] = boundary["proxy_server"]
        browser = launch(**options)
        page = browser.new_page()
        page.set_extra_http_headers(
            {
                "X-Web-Listening-Attempt": boundary["attempt_nonce"],
                "X-Web-Listening-Max-Requests": str(limits["max_requests"]),
                "X-Web-Listening-Max-Response-Bytes": str(limits["max_bytes"]),
            }
        )

        def guard(route, intercepted=None):
            candidate = intercepted or _value(getattr(route, "request", None))
            url = _value(getattr(candidate, "url", ""))
            request_count["value"] += 1
            if request_count["value"] > limits["max_requests"]:
                route.abort()
                if not _is_plain_subresource(candidate):
                    blocked["code"] = "cloakbrowser.request_limit"
                return
            if _origin(url) not in origins or not _path_allowed(url, include_paths):
                blocked["code"] = "cloakbrowser.scope_rejected"
                route.abort()
                return
            route.continue_()

        page.route("**/*", guard)
        response = page.goto(
            target,
            wait_until="domcontentloaded",
            timeout=round(limits["max_runtime_seconds"] * 1000),
        )
        if blocked["code"] is not None:
            failure = _failure(blocked["code"], rejected=True)
        elif response is None:
            failure = _failure("cloakbrowser.no_response")
        else:
            redirects = _redirects(response)
            if len(redirects) > max(0, limits["max_requests"] - 1):
                failure = _failure("cloakbrowser.redirect_limit", rejected=True)
            elif any(
                _origin(item["from_url"]) not in origins
                or _origin(item["to_url"]) not in origins
                or not _path_allowed(item["from_url"], include_paths)
                or not _path_allowed(item["to_url"], include_paths)
                for item in redirects
            ):
                failure = _failure("cloakbrowser.scope_rejected", rejected=True)
            else:
                headers = _response_headers(response)
                length = headers.get("content-length")
                if length is not None and (
                    not length.isdecimal() or int(length) > limits["max_bytes"]
                ):
                    failure = _failure("cloakbrowser.response_limit")
                else:
                    content = page.content().encode("utf-8")
                    if len(content) > limits["max_bytes"]:
                        failure = _failure("cloakbrowser.output_limit")
                    else:
                        mime_type = headers.get("content-type", "text/html")
                        mime_type = mime_type.split(";", 1)[0].strip().casefold()
                        if mime_type != "text/html":
                            failure = _failure("cloakbrowser.mime_rejected")
                        else:
                            final_url = _value(getattr(page, "url", target))
                            if _origin(final_url) not in origins or not _path_allowed(
                                final_url, include_paths
                            ):
                                failure = _failure(
                                    "cloakbrowser.scope_rejected", rejected=True
                                )
                            else:
                                output = Path("capture.html")
                                output.write_bytes(content)
                                result = {
                                    "protocol_version": EXTERNAL_PROTOCOL,
                                    "category": "acquisition",
                                    "status": "success",
                                    "tool_id": TOOL_ID,
                                    "tool_version": VERSION,
                                    "result": {
                                        "requested_url": target,
                                        "final_url": final_url,
                                        "status_code": _value(
                                            getattr(response, "status", 0)
                                        ),
                                        "mime_type": mime_type,
                                        "output_path": output.as_posix(),
                                        "size_bytes": len(content),
                                        "sha256": hashlib.sha256(content).hexdigest(),
                                        "redirects": redirects,
                                        "runtime_ms": max(
                                            0,
                                            round((time.monotonic() - started) * 1000),
                                        ),
                                    },
                                }
    except Exception as exc:  # pylint: disable=broad-exception-caught
        if blocked["code"] is not None:
            failure = _failure(blocked["code"], rejected=True)
        elif "timeout" in type(exc).__name__.casefold():
            failure = _failure("cloakbrowser.timeout")
        else:
            failure = _failure("cloakbrowser.execution_failed")
    close_failed = False
    if browser is not None:
        close = getattr(browser, "close", None)
        if not callable(close):
            close_failed = True
        else:
            try:
                close()
            except Exception:  # pylint: disable=broad-exception-caught
                close_failed = True
    if close_failed:
        return _failure("cloakbrowser.close_failed")
    return result or failure or _failure("cloakbrowser.execution_failed")


def main():
    try:
        request = _load_input()
        boundary = _boundary()
        if request.get("protocol_version") == QUALIFICATION_PROTOCOL:
            response = _control(request, boundary)
        else:
            response = _acquire(request, boundary)
    except Exception:  # pylint: disable=broad-exception-caught
        response = _failure("cloakbrowser.protocol_error")
    json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
