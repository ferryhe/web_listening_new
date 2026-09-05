"""Thin command-line adapter over the public Runtime service."""

# pylint: disable=too-many-branches,too-many-statements

from __future__ import annotations

import argparse
import base64
import json
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

from web_listening.artifact.model import StoredArtifact
from web_listening.request.budgets import budgets_from_mapping
from web_listening.request.model import Request, RequestValidationError
from web_listening.request.site_batch import site_batch_request_from_json
from web_listening.request.site_refresh import site_refresh_request_from_json
from web_listening.request.url_fetch import UrlFetchRequest
from web_listening.request.validate import request_from_json
from web_listening.runtime.jobs import Job, JobStatus, SiteBatch, UrlFetchJob
from web_listening.runtime.service import RuntimeService
from web_listening.site_skill.model import SiteSkillError
from web_listening.site_skill.validate import site_skill_from_mapping

EXIT_SUCCESS = 0
EXIT_RUNTIME_ERROR = 1
EXIT_INPUT_ERROR = 2
EXIT_NOT_FOUND = 3


class _CliInputError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-listening",
        description="Run governed website acquisition through RuntimeService.",
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{acquire,site-explore,site-refresh,get-job,get-handoff,read-artifact}",
    )

    acquire = commands.add_parser("acquire", help="Submit one validated Request file.")
    acquire.add_argument("--request", required=True, type=Path)
    acquire.add_argument("--site-skill", type=Path)
    acquire.add_argument("--output", required=True, type=Path)
    acquire.add_argument("--json", action="store_true", help="Emit JSON.")

    site_explore = commands.add_parser(
        "site-explore", help="Explore one site with a validated Request file."
    )
    site_explore.add_argument("--request", required=True, type=Path)
    site_explore.add_argument("--output", required=True, type=Path)
    site_explore.add_argument("--json", action="store_true", help="Emit JSON.")

    site_refresh = commands.add_parser(
        "site-refresh", help="Refresh one site with a validated recipe and state."
    )
    site_refresh.add_argument("--request", required=True, type=Path)
    site_refresh.add_argument("--output", required=True, type=Path)
    site_refresh.add_argument("--json", action="store_true", help="Emit JSON.")

    get_job = commands.add_parser("get-job", help="Read one Runtime Job by ID.")
    get_job.add_argument("job_id")
    get_job.add_argument("--output", required=True, type=Path)
    get_job.add_argument("--json", action="store_true", help="Emit JSON.")

    get_handoff = commands.add_parser(
        "get-handoff", help="Export one terminal Runtime Job handoff."
    )
    get_handoff.add_argument("job_id")
    get_handoff.add_argument("--output", required=True, type=Path)
    get_handoff.add_argument("--json", action="store_true", help="Emit JSON.")

    read_artifact = commands.add_parser(
        "read-artifact", help="Read one stored Artifact by ID."
    )
    read_artifact.add_argument("artifact_id")
    read_artifact.add_argument("--output", required=True, type=Path)
    read_artifact.add_argument("--json", action="store_true", help="Emit JSON.")

    batch_submit = commands.add_parser(
        "batch-submit", help="Durably submit one strict site batch."
    )
    batch_submit.add_argument("--request", required=True, type=Path)
    batch_submit.add_argument("--caller-id", required=True)
    batch_submit.add_argument("--idempotency-key", required=True)
    batch_submit.add_argument("--output", required=True, type=Path)
    batch_submit.add_argument("--json", action="store_true", help="Emit JSON.")
    for name in ("batch-get", "batch-cancel"):
        command = commands.add_parser(
            name, help=f"{name.split('-')[1].title()} a site batch."
        )
        command.add_argument("batch_id")
        command.add_argument("--output", required=True, type=Path)
        command.add_argument("--json", action="store_true", help="Emit JSON.")
    fetch_url = commands.add_parser(
        "fetch-url", help="Submit a governed same-origin Smart URL Fetch."
    )
    fetch_url.add_argument("url")
    fetch_url.add_argument("--budgets", required=True, type=Path)
    fetch_url.add_argument("--explore-all-tools", action="store_true")
    fetch_url.add_argument("--max-navigation-hops", type=int, default=3)
    fetch_url.add_argument("--no-follow-html-navigation", action="store_true")
    fetch_url.add_argument("--caller-id", default="local-cli")
    fetch_url.add_argument("--idempotency-key", required=True)
    fetch_url.add_argument("--save-content", type=Path)
    fetch_url.add_argument("--output", required=True, type=Path)
    fetch_url.add_argument("--json", action="store_true", help="Emit JSON.")
    for name in ("url-fetch-get", "url-fetch-cancel"):
        command = commands.add_parser(
            name, help=f"{name.rsplit('-', maxsplit=1)[-1].title()} a URL fetch."
        )
        command.add_argument("job_id")
        command.add_argument("--output", required=True, type=Path)
        command.add_argument("--json", action="store_true", help="Emit JSON.")
        if name == "url-fetch-get":
            command.add_argument("--save-content", type=Path)
    return parser


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise _CliInputError("input.file_unreadable") from exc


def _unique_site_skill_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _CliInputError("site_skill.duplicate_key")
        result[key] = value
    return result


def _load_json(path: Path) -> object:
    try:
        return json.loads(_read_text(path), object_pairs_hook=_unique_site_skill_object)
    except json.JSONDecodeError as exc:
        raise _CliInputError("site_skill.invalid_json") from exc


def _load_request(request_path: Path, site_skill_path: Path | None) -> Request:
    request = request_from_json(_read_text(request_path))
    if request.site_skill is not None:
        request = replace(
            request, site_skill=site_skill_from_mapping(request.site_skill)
        )
    if site_skill_path is not None:
        request = replace(
            request, site_skill=site_skill_from_mapping(_load_json(site_skill_path))
        )
    return request


def _job_payload(job: Job) -> dict[str, object]:
    result = None if job.result is None else job.result.to_dict()
    return {
        "job_id": job.job_id,
        "status": job.status.value,
        "submitted_at": job.submitted_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "result": result,
        "failure_code": job.failure_code,
    }


def _batch_payload(batch: SiteBatch) -> dict[str, object]:
    return {
        "batch_id": batch.batch_id,
        "status": batch.status.value,
        "submitted_at": batch.submitted_at,
        "started_at": batch.started_at,
        "finished_at": batch.finished_at,
        "cancel_requested_at": batch.cancel_requested_at,
        "children": [
            {"site_key": item.site_key, "order": item.order, "status": item.status}
            for item in batch.children
        ],
        "result": None if batch.result is None else batch.result.to_dict(),
        "failure_code": batch.failure_code,
    }


def _url_fetch_payload(job: UrlFetchJob) -> dict[str, object]:
    return {
        "job_id": job.job_id,
        "status": job.status.value,
        "submitted_at": job.submitted_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "cancel_requested_at": job.cancel_requested_at,
        "result": None if job.result is None else job.result.to_dict(),
        "failure_code": job.failure_code,
    }


def _save_url_fetch_content(
    runtime: RuntimeService, job: UrlFetchJob, destination: Path
) -> None:
    if (
        job.status
        not in {
            JobStatus.COMPLETED,
            JobStatus.PARTIAL,
            JobStatus.REJECTED,
            JobStatus.FAILED,
        }
        or job.result is None
        or job.result.terminal_artifact is None
    ):
        raise RuntimeError("url_fetch.content_unavailable")
    destination.write_bytes(
        runtime.read_artifact(job.result.terminal_artifact.artifact_id).content
    )


def _wait_url_fetch(
    runtime: RuntimeService, job: UrlFetchJob, timeout_seconds: int
) -> UrlFetchJob:
    deadline = time.monotonic() + timeout_seconds
    while job.status in {JobStatus.SUBMITTED, JobStatus.RUNNING}:
        if time.monotonic() >= deadline:
            raise RuntimeError("url_fetch.not_terminal")
        time.sleep(0.05)
        job = runtime.get_url_fetch(job.job_id)
    return job


def _artifact_payload(artifact: StoredArtifact) -> dict[str, object]:
    return {
        "artifact_id": artifact.artifact_id,
        "blob_sha256": artifact.blob_sha256,
        "size_bytes": artifact.size_bytes,
        "mime_type": artifact.mime_type,
        "content_encoding": "base64",
        "content": base64.b64encode(artifact.content).decode("ascii"),
    }


def _run_with_runtime(
    output: Path, operation: Callable[[RuntimeService], dict[str, object]]
) -> dict[str, object]:
    runtime = RuntimeService.open(output)
    try:
        return operation(runtime)
    finally:
        runtime.close()


def _emit(payload: dict[str, object]) -> None:
    print(
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _diagnose(code: str) -> None:
    print(code, file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse CLI input, call one RuntimeService method, and emit its contract."""
    args = _parser().parse_args(argv)
    try:
        if args.command == "acquire":
            request = _load_request(args.request, args.site_skill)
            payload = _run_with_runtime(
                args.output, lambda runtime: _job_payload(runtime.run(request))
            )
        elif args.command == "site-explore":
            request = _load_request(args.request, None)
            payload = _run_with_runtime(
                args.output, lambda runtime: runtime.explore_site(request).to_dict()
            )
        elif args.command == "site-refresh":
            refresh_request = site_refresh_request_from_json(_read_text(args.request))
            payload = _run_with_runtime(
                args.output,
                lambda runtime: runtime.refresh_site(refresh_request).to_dict(),
            )
        elif args.command == "get-job":
            payload = _run_with_runtime(
                args.output,
                lambda runtime: _job_payload(runtime.get_job(args.job_id)),
            )
        elif args.command == "get-handoff":
            payload = _run_with_runtime(
                args.output,
                lambda runtime: runtime.get_handoff(args.job_id).to_dict(),
            )
        elif args.command == "batch-submit":
            batch_request = site_batch_request_from_json(_read_text(args.request))
            payload = _run_with_runtime(
                args.output,
                lambda runtime: _batch_payload(
                    runtime.submit_batch(
                        batch_request,
                        caller_id=args.caller_id,
                        idempotency_key=args.idempotency_key,
                    )
                ),
            )
        elif args.command == "batch-get":
            payload = _run_with_runtime(
                args.output,
                lambda runtime: _batch_payload(runtime.get_batch(args.batch_id)),
            )
        elif args.command == "batch-cancel":
            payload = _run_with_runtime(
                args.output,
                lambda runtime: _batch_payload(runtime.cancel_batch(args.batch_id)),
            )
        elif args.command == "fetch-url":
            budgets = budgets_from_mapping(_load_json(args.budgets))
            request = UrlFetchRequest(
                args.url,
                args.explore_all_tools,
                not args.no_follow_html_navigation,
                args.max_navigation_hops,
                budgets,
            )

            def submit_url(runtime):
                job = runtime.fetch_url(
                    request,
                    caller_id=args.caller_id,
                    idempotency_key=args.idempotency_key,
                )
                if args.save_content is not None:
                    job = _wait_url_fetch(
                        runtime, job, request.budgets.max_runtime_seconds
                    )
                    _save_url_fetch_content(runtime, job, args.save_content)
                return _url_fetch_payload(job)

            payload = _run_with_runtime(args.output, submit_url)
        elif args.command == "url-fetch-get":

            def get_url(runtime):
                job = runtime.get_url_fetch(args.job_id)
                if args.save_content is not None:
                    _save_url_fetch_content(runtime, job, args.save_content)
                return _url_fetch_payload(job)

            payload = _run_with_runtime(args.output, get_url)
        elif args.command == "url-fetch-cancel":
            payload = _run_with_runtime(
                args.output,
                lambda runtime: _url_fetch_payload(
                    runtime.cancel_url_fetch(args.job_id)
                ),
            )
        else:
            payload = _run_with_runtime(
                args.output,
                lambda runtime: _artifact_payload(
                    runtime.read_artifact(args.artifact_id)
                ),
            )
    except (_CliInputError, RequestValidationError, SiteSkillError) as exc:
        _diagnose(exc.code)
        return EXIT_INPUT_ERROR
    except Exception as exc:  # pylint: disable=broad-exception-caught
        code = getattr(exc, "code", "")
        if isinstance(code, str) and code.endswith(".not_found"):
            _diagnose(code)
            return EXIT_NOT_FOUND
        if code in {"job.id_invalid", "artifact.id_invalid"}:
            _diagnose(code)
            return EXIT_INPUT_ERROR
        if code in {"handoff.not_terminal", "handoff.result_unavailable"}:
            _diagnose(code)
            return EXIT_RUNTIME_ERROR
        _diagnose("runtime.failed")
        return EXIT_RUNTIME_ERROR
    _emit(payload)
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
