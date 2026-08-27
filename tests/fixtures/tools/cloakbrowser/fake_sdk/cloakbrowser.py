"""Offline CloakBrowser 0.5.9 test double; it never opens a network."""

# pylint: disable=missing-function-docstring,protected-access
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-locals

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

__version__ = "0.5.9"
_ROOT = Path(__file__).parent
_SCENARIO = _ROOT / "fake_scenario.json"
_AUDIT = _ROOT / "fake_audit.jsonl"


def _scenario():
    if not _SCENARIO.is_file():
        return {
            "body": "<html>x</html>",
            "mime_type": "text/html",
            "status_code": 200,
            "redirects": [],
        }
    return json.loads(_SCENARIO.read_text(encoding="utf-8"))


def _record(event, **values):
    with _AUDIT.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"event": event, **values}, sort_keys=True) + "\n")


class _Route:
    def __init__(self, request):
        self.request = request
        self.aborted = False

    def continue_(self):
        _record("continue", url=self.request.url)
        nonce = self.request.headers.get("X-Web-Listening-Attempt", "")
        _record(
            "proxy_request",
            url=self.request.url,
            attempt_nonce_sha256=hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        )

    def abort(self):
        self.aborted = True
        _record("abort", url=self.request.url)


class _Request:
    def __init__(
        self,
        url,
        headers,
        redirected_from=None,
        *,
        resource_type="document",
        is_navigation_request=True,
        missing_fields=(),
        error_fields=(),
    ):
        object.__setattr__(self, "_missing_fields", frozenset(missing_fields))
        object.__setattr__(self, "_error_fields", frozenset(error_fields))
        self.url = url
        self.headers = headers
        self.redirected_from = redirected_from
        self.resource_type = resource_type
        self.frame = object()
        self._navigation = is_navigation_request
        self._response = None

    def __getattribute__(self, name):
        if name not in {"_missing_fields", "_error_fields"}:
            if name in object.__getattribute__(self, "_missing_fields"):
                raise AttributeError(name)
            if name in object.__getattribute__(self, "_error_fields"):
                raise RuntimeError(f"offline {name} access failure")
        return object.__getattribute__(self, name)

    def is_navigation_request(self):
        return self._navigation

    def response(self):
        return self._response


class _Response:
    def __init__(self, request, status, mime_type, body, *, omit_length=False):
        self.request = request
        self.status = status
        self.headers = {"content-type": mime_type}
        if not omit_length:
            self.headers["content-length"] = str(len(body.encode("utf-8")))


class _Page:
    def __init__(self):
        self._guard = None
        self._headers = {}
        self._proxy_response_bytes = 0
        self.url = ""

    def set_extra_http_headers(self, headers):
        self._headers = dict(headers)

    def route(self, pattern, guard):
        assert pattern == "**/*"
        self._guard = guard

    def goto(self, url, *, wait_until, timeout):
        scenario = _scenario()
        _record("goto", url=url, wait_until=wait_until, timeout=timeout)
        if scenario.get("timeout"):
            raise TimeoutError("offline timeout")
        current = _Request(url, self._headers)
        transitions = scenario.get("redirects", [])
        for transition in transitions:
            route = _Route(current)
            self._guard(route, current)
            if route.aborted:
                raise RuntimeError("aborted")
            redirect_body = str(transition.get("body", ""))
            current._response = _Response(
                current,
                transition["status_code"],
                "text/html",
                redirect_body,
            )
            self._proxy_response(current.url, len(redirect_body.encode("utf-8")))
            current = _Request(transition["to_url"], self._headers, current)
        route = _Route(current)
        self._guard(route, current)
        if route.aborted:
            raise RuntimeError("aborted")
        body = str(scenario.get("body", "<html>x</html>"))
        response = _Response(
            current,
            int(scenario.get("status_code", 200)),
            str(scenario.get("mime_type", "text/html")),
            body,
            omit_length=bool(scenario.get("omit_content_length")),
        )
        current._response = response
        self._proxy_response(current.url, len(body.encode("utf-8")))
        for item in scenario.get("subresponses", []):
            redirected_from = (
                _Request(str(item["url"]) + "?redirect-source", self._headers)
                if item.get("redirected_from")
                else None
            )
            subrequest = _Request(
                str(item["url"]),
                self._headers,
                redirected_from,
                resource_type=item.get("resource_type", "script"),
                is_navigation_request=item.get("is_navigation_request", False),
                missing_fields=item.get("missing_fields", ()),
                error_fields=item.get("error_fields", ()),
            )
            subroute = _Route(subrequest)
            self._guard(subroute, subrequest)
            if subroute.aborted:
                continue
            self._proxy_response(subrequest.url, int(item["response_bytes"]))
        self.url = current.url
        return response

    def _proxy_response(self, url, response_bytes):
        nonce = self._headers.get("X-Web-Listening-Attempt", "")
        maximum = int(self._headers.get("X-Web-Listening-Max-Response-Bytes", "0"))
        self._proxy_response_bytes += response_bytes
        cumulative = self._proxy_response_bytes
        nonce_sha256 = hashlib.sha256(nonce.encode("ascii")).hexdigest()
        _record(
            "proxy_response",
            url=url,
            attempt_nonce_sha256=nonce_sha256,
            response_bytes=response_bytes,
            cumulative_response_bytes=cumulative,
        )
        if cumulative > maximum:
            _record(
                "proxy_limit",
                attempt_nonce_sha256=nonce_sha256,
                limit="max_response_bytes",
                cumulative_response_bytes=cumulative,
            )
            raise _ProxyResponseLimitError("offline proxy response limit")

    def content(self):
        _record("content")
        return str(_scenario().get("body", "<html>x</html>"))


class _Browser:
    def new_page(self):
        _record("new_page")
        return _Page()

    def close(self):
        _record("close")
        if _scenario().get("close_error"):
            raise OSError("offline close failure")


def launch(*, headless=True, proxy=None):
    _record(
        "launch",
        headless=headless,
        proxy=proxy,
        home=os.environ.get("HOME"),
        environment_keys=sorted(os.environ),
    )
    return _Browser()


class _ProxyResponseLimitError(RuntimeError):
    pass
