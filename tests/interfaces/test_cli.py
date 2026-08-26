"""Focused contract tests for the Phase 9 thin CLI adapter."""

# pylint: disable=consider-using-from-import,missing-function-docstring
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import web_listening.interfaces.cli as cli
from web_listening.artifact.model import ArtifactStoreError, StoredArtifact
from web_listening.request.model import Request
from web_listening.result.model import Result
from web_listening.runtime.jobs import Job, JobStateError, JobStatus
from web_listening.site_skill.model import SiteSkill

ROOT = Path(__file__).parents[2]
RESULT_FIXTURE = ROOT / "tests" / "result" / "fixtures" / "completed.v1.json"
SITE_SKILL_CATALOG = ROOT / "tests" / "live" / "catalog" / "site_skill_cases.json"


def _result() -> Result:
    return Result.from_dict(json.loads(RESULT_FIXTURE.read_text(encoding="utf-8")))


def _job() -> Job:
    return Job(
        job_id="job-one",
        status=JobStatus.COMPLETED,
        submitted_at="2026-08-26T12:00:00Z",
        started_at="2026-08-26T12:00:00Z",
        finished_at="2026-08-26T12:00:01Z",
        result=_result(),
    )


def _request_payload(site_skill: object = None) -> dict[str, object]:
    return {
        "scope": {
            "seeds": ["https://www.ipcc.ch/"],
            "allowed_origins": ["https://www.ipcc.ch"],
            "include_paths": ["/**"],
            "content_types": ["html"],
        },
        "site_skill": site_skill,
        "explore_all_tools": False,
        "budgets": {
            "max_requests": 1,
            "max_bytes": 2 * 1024 * 1024,
            "max_runtime_seconds": 30,
            "max_tool_attempts_per_target": 1,
        },
    }


def _site_skill(site_key: str) -> dict[str, object]:
    payload = json.loads(SITE_SKILL_CATALOG.read_text(encoding="utf-8"))
    return next(
        item["site_skill"] for item in payload["cases"] if item["site_key"] == site_key
    )


class FakeRuntime:
    """One programmable public RuntimeService test double."""

    opened_with: list[Path] = []
    instances: list["FakeRuntime"] = []
    open_error: Exception | None = None
    run_error: Exception | None = None
    get_error: Exception | None = None
    read_error: Exception | None = None

    def __init__(self) -> None:
        self.closed = False
        self.requests: list[Request] = []
        self.job_ids: list[str] = []
        self.artifact_ids: list[str] = []

    @classmethod
    def reset(cls) -> None:
        cls.opened_with = []
        cls.instances = []
        cls.open_error = None
        cls.run_error = None
        cls.get_error = None
        cls.read_error = None

    @classmethod
    def open(cls, data_dir: str | Path) -> "FakeRuntime":
        cls.opened_with.append(Path(data_dir))
        if cls.open_error is not None:
            raise cls.open_error
        instance = cls()
        cls.instances.append(instance)
        return instance

    def run(self, request: Request) -> Job:
        self.requests.append(request)
        if self.run_error is not None:
            raise self.run_error
        return _job()

    def get_job(self, job_id: str) -> Job:
        self.job_ids.append(job_id)
        if self.get_error is not None:
            raise self.get_error
        return _job()

    def read_artifact(self, artifact_id: str) -> StoredArtifact:
        self.artifact_ids.append(artifact_id)
        if self.read_error is not None:
            raise self.read_error
        content = b"\x00phase-9\xff"
        return StoredArtifact(
            artifact_id=artifact_id,
            blob_sha256="sha256:" + "a" * 64,
            size_bytes=len(content),
            mime_type="application/octet-stream",
            content=content,
        )

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _fake_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeRuntime.reset()
    monkeypatch.setattr(cli, "RuntimeService", FakeRuntime)


def _write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_help_lists_exactly_the_three_phase_9_commands(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["--help"])

    output = capsys.readouterr()
    assert caught.value.code == 0
    assert "{acquire,get-job,read-artifact}" in output.out
    assert output.err == ""
    for dropped in (
        "discover",
        "search",
        "parse",
        "rag",
        "ask",
        "list-tools",
        "validate-site-skill",
    ):
        assert dropped not in output.out.lower()


def test_acquire_parses_request_and_emits_the_unified_job_and_result_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request_path = _write_json(tmp_path / "request.json", _request_payload())
    output_dir = tmp_path / "runtime-data"

    exit_code = cli.main(
        [
            "acquire",
            "--request",
            str(request_path),
            "--output",
            str(output_dir),
            "--json",
        ]
    )

    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert exit_code == 0
    assert output.err == ""
    assert FakeRuntime.opened_with == [output_dir]
    assert len(FakeRuntime.instances) == 1
    runtime = FakeRuntime.instances[0]
    assert runtime.closed is True
    assert len(runtime.requests) == 1
    assert isinstance(runtime.requests[0], Request)
    assert payload["job_id"] == "job-one"
    assert payload["status"] == "completed"
    assert Result.from_dict(payload["result"]) == _result()


def test_acquire_validates_embedded_site_skill(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request_path = _write_json(
        tmp_path / "request.json", _request_payload(_site_skill("ipcc"))
    )

    assert (
        cli.main(
            [
                "acquire",
                "--request",
                str(request_path),
                "--output",
                str(tmp_path / "data"),
            ]
        )
        == 0
    )

    assert capsys.readouterr().err == ""
    parsed = FakeRuntime.instances[0].requests[0]
    assert isinstance(parsed.site_skill, SiteSkill)
    assert parsed.site_skill.site_key == "ipcc"


def test_separate_site_skill_replaces_only_the_request_site_skill(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    request_path = _write_json(
        tmp_path / "request.json", _request_payload(_site_skill("ipcc"))
    )
    skill_path = _write_json(tmp_path / "site-skill.json", _site_skill("a2ii"))

    assert (
        cli.main(
            [
                "acquire",
                "--request",
                str(request_path),
                "--site-skill",
                str(skill_path),
                "--output",
                str(tmp_path / "data"),
                "--json",
            ]
        )
        == 0
    )

    assert capsys.readouterr().err == ""
    parsed = FakeRuntime.instances[0].requests[0]
    expected = _request_payload(_site_skill("ipcc"))
    assert isinstance(parsed.site_skill, SiteSkill)
    assert parsed.site_skill.site_key == "a2ii"
    assert list(parsed.scope.seeds) == expected["scope"]["seeds"]
    assert parsed.explore_all_tools is expected["explore_all_tools"]
    assert parsed.budgets.max_requests == expected["budgets"]["max_requests"]


@pytest.mark.parametrize(
    ("original", "duplicate"),
    [
        (
            '"seeds": ["https://www.ipcc.ch/"]',
            '"seeds": ["https://www.ipcc.ch/"], '
            '"seeds": ["https://outside.invalid/"]',
        ),
        (
            '"max_requests": 12',
            '"max_requests": 12, "max_requests": 6',
        ),
    ],
)
def test_separate_site_skill_rejects_recursive_duplicate_authority_keys(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    original: str,
    duplicate: str,
) -> None:
    request_path = _write_json(tmp_path / "request.json", _request_payload())
    raw_skill = json.dumps(_site_skill("ipcc"))
    assert original in raw_skill
    skill_path = tmp_path / "private-site-skill.json"
    skill_path.write_text(raw_skill.replace(original, duplicate, 1), encoding="utf-8")

    exit_code = cli.main(
        [
            "acquire",
            "--request",
            str(request_path),
            "--site-skill",
            str(skill_path),
            "--output",
            str(tmp_path / "data"),
            "--json",
        ]
    )

    output = capsys.readouterr()
    assert exit_code == 2
    assert output.out == ""
    assert output.err == "site_skill.duplicate_key\n"
    assert "outside.invalid" not in output.err
    assert FakeRuntime.opened_with == []


@pytest.mark.parametrize(
    ("contents", "code"),
    [
        ("{not-json", "request.invalid_json"),
        (json.dumps({"scope": {}}), "request.missing"),
    ],
)
def test_invalid_request_is_stable_input_error_without_opening_runtime(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    contents: str,
    code: str,
) -> None:
    request_path = tmp_path / "private-request.json"
    request_path.write_text(contents, encoding="utf-8")

    exit_code = cli.main(
        [
            "acquire",
            "--request",
            str(request_path),
            "--output",
            str(tmp_path / "data"),
            "--json",
        ]
    )

    output = capsys.readouterr()
    assert exit_code == 2
    assert output.out == ""
    assert output.err == f"{code}\n"
    assert FakeRuntime.opened_with == []


def test_get_job_uses_public_runtime_and_emits_job_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"

    exit_code = cli.main(["get-job", "job-one", "--output", str(data_dir), "--json"])

    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert exit_code == 0
    assert output.err == ""
    assert FakeRuntime.opened_with == [data_dir]
    assert FakeRuntime.instances[0].job_ids == ["job-one"]
    assert FakeRuntime.instances[0].closed is True
    assert payload["job_id"] == "job-one"
    assert Result.from_dict(payload["result"]) == _result()


def test_read_artifact_emits_lossless_json_bytes_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"

    exit_code = cli.main(
        [
            "read-artifact",
            "artifact-one",
            "--output",
            str(data_dir),
            "--json",
        ]
    )

    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert exit_code == 0
    assert output.err == ""
    assert FakeRuntime.instances[0].artifact_ids == ["artifact-one"]
    assert FakeRuntime.instances[0].closed is True
    assert payload == {
        "artifact_id": "artifact-one",
        "blob_sha256": "sha256:" + "a" * 64,
        "size_bytes": 9,
        "mime_type": "application/octet-stream",
        "content_encoding": "base64",
        "content": base64.b64encode(b"\x00phase-9\xff").decode("ascii"),
    }


@pytest.mark.parametrize(
    ("args", "error", "diagnostic"),
    [
        (
            ["get-job", "missing", "--output", "data", "--json"],
            JobStateError("job.not_found"),
            "job.not_found",
        ),
        (
            ["read-artifact", "missing", "--output", "data", "--json"],
            ArtifactStoreError("artifact.not_found"),
            "artifact.not_found",
        ),
    ],
)
def test_not_found_has_stable_exit_code_and_closes_runtime(
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    error: Exception,
    diagnostic: str,
) -> None:
    if args[0] == "get-job":
        FakeRuntime.get_error = error
    else:
        FakeRuntime.read_error = error

    exit_code = cli.main(args)

    output = capsys.readouterr()
    assert exit_code == 3
    assert output.out == ""
    assert output.err == f"{diagnostic}\n"
    assert FakeRuntime.instances[0].closed is True


@pytest.mark.parametrize(
    ("args", "error", "diagnostic"),
    [
        (
            ["get-job", "bad id", "--output", "data", "--json"],
            JobStateError("job.id_invalid"),
            "job.id_invalid",
        ),
        (
            ["read-artifact", "bad", "--output", "data", "--json"],
            ArtifactStoreError("artifact.id_invalid"),
            "artifact.id_invalid",
        ),
    ],
)
def test_invalid_identifiers_use_the_stable_input_exit_code(
    capsys: pytest.CaptureFixture[str],
    args: list[str],
    error: Exception,
    diagnostic: str,
) -> None:
    if args[0] == "get-job":
        FakeRuntime.get_error = error
    else:
        FakeRuntime.read_error = error

    exit_code = cli.main(args)

    output = capsys.readouterr()
    assert exit_code == 2
    assert output.out == ""
    assert output.err == f"{diagnostic}\n"
    assert FakeRuntime.instances[0].closed is True


@pytest.mark.parametrize("stage", ["open", "run"])
def test_runtime_failures_are_redacted_stable_and_close_when_opened(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    stage: str,
) -> None:
    request_path = _write_json(tmp_path / "request.json", _request_payload())
    error = RuntimeError(f"PRIVATE:{tmp_path}")
    if stage == "open":
        FakeRuntime.open_error = error
    else:
        FakeRuntime.run_error = error

    exit_code = cli.main(
        [
            "acquire",
            "--request",
            str(request_path),
            "--output",
            str(tmp_path / "data"),
            "--json",
        ]
    )

    output = capsys.readouterr()
    assert exit_code == 1
    assert output.out == ""
    assert output.err == "runtime.failed\n"
    assert "PRIVATE" not in output.err
    if stage == "run":
        assert FakeRuntime.instances[0].closed is True
    else:
        assert FakeRuntime.instances == []


def test_cli_source_has_no_low_level_business_imports() -> None:
    source = Path(cli.__file__).read_text(encoding="utf-8")
    forbidden = (
        "tool_registry",
        "Registry",
        "Gateway",
        "ArtifactStore",
        "runtime.workflow",
        "acquisition.builtins",
        "sqlite",
    )

    assert "RuntimeService.open" in source
    assert all(name not in source for name in forbidden)


def _black_box(command: list[str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = (
        str(ROOT / "src") + os.pathsep + environment.get("PYTHONPATH", "")
    )
    return subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_python_module_entry_point_runs_the_real_cli(tmp_path: Path) -> None:
    result = _black_box(
        [
            sys.executable,
            "-m",
            "web_listening.interfaces.cli",
            "get-job",
            "job-missing",
            "--output",
            str(tmp_path / "module-data"),
            "--json",
        ]
    )

    assert result.returncode == 3
    assert result.stdout == ""
    assert result.stderr == "job.not_found\n"


def test_installed_console_script_runs_the_real_cli(tmp_path: Path) -> None:
    executable = shutil.which("web-listening")
    assert executable is not None

    result = _black_box(
        [
            executable,
            "get-job",
            "job-missing",
            "--output",
            str(tmp_path / "console-data"),
            "--json",
        ]
    )

    assert result.returncode == 3
    assert result.stdout == ""
    assert result.stderr == "job.not_found\n"


def test_pyproject_declares_only_the_requested_console_script() -> None:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert "[project.scripts]" in text
    assert 'web-listening = "web_listening.interfaces.cli:main"' in text
