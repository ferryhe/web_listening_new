"""Local install, qualification, activation, disable, and rollback for tools."""

# pylint: disable=too-many-lines,unidiomatic-typecheck

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

from web_listening.artifact.identity import artifact_id, blob_relative_path
from web_listening.artifact.model import (
    Artifact,
    ArtifactRole,
    Blob,
    Observation,
    StoredObservation,
)
from web_listening.request.model import Budgets, ContentType, Request, Scope
from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
    ToolRegistryError,
    validate_tool_id,
    validate_tool_version,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionInput,
    AcquisitionOutput,
)
from web_listening.tool_registry.protocols.discovery import (
    DiscoveryInput,
    DiscoveryOutput,
)
from web_listening.tool_registry.protocols.transform import (
    TransformInput,
    TransformOutput,
)
from web_listening.tool_registry.runners.subprocess import SubprocessRunner

_EXTERNAL_PROTOCOL = "web-listening-external-tool.v1"
_QUALIFICATION_PROTOCOL = "web-listening-tool-qualification.v1"
_STATE_SCHEMA = "web-listening-tool-state.v1"
_ACTIVE_SCHEMA = "web-listening-tool-active.v1"
_MAX_CONTROL_BYTES = 64 * 1024
_DECLARATION_KEYS = {"source", "protocol_version", "entrypoint", "manifest"}
_SOURCE_KEYS = {"name", "category", "tool_id", "version"}
_MANIFEST_KEYS = {
    "tool_id",
    "version",
    "category",
    "distribution",
    "capabilities",
    "limits",
    "health",
    "qualification",
}
_LIMIT_KEYS = {"max_runtime_seconds", "max_input_bytes", "max_output_bytes"}
_STATE_KEYS = {
    "schema_version",
    "qualified",
    "disabled",
    "broken",
    "failure_code",
}
_PROBE_CHECKS = {
    ToolCategory.DISCOVERY: ("governed_input", "bounded_candidates"),
    ToolCategory.ACQUISITION: ("governed_input", "bounded_output"),
    ToolCategory.TRANSFORM: ("stored_source", "derived_output"),
}


class ToolLifecycleError(ToolRegistryError):
    """A stable local tool-lifecycle failure."""


@dataclass(frozen=True, slots=True)
class ToolVersionState:
    """One installed version's restart-safe lifecycle view."""

    manifest: ToolManifest
    installed: bool
    qualified: bool
    active: bool
    disabled: bool
    broken: bool
    failure_code: str | None


@dataclass(frozen=True, slots=True)
class _InstalledTool:
    manifest: ToolManifest
    entrypoint: str
    directory: Path


class ToolLifecycle:  # pylint: disable=too-many-public-methods
    """Manage external versions under one caller-provided data root."""

    def __init__(self, data_root: str | Path) -> None:
        try:
            candidate = Path(data_root).absolute()
        except (TypeError, ValueError, OSError) as exc:
            raise ToolLifecycleError("lifecycle.data_root_invalid") from exc
        _reject_link_components(candidate, "lifecycle.data_root_invalid")
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ToolLifecycleError("lifecycle.data_root_invalid") from exc
        if _is_link(candidate) or not candidate.is_dir():
            raise ToolLifecycleError("lifecycle.data_root_invalid")
        self._root = candidate.resolve(strict=True)

    @property
    def data_root(self) -> Path:
        """Return the caller-owned absolute data root."""
        return self._root

    def install(self, source: str | Path) -> ToolVersionState:
        """Validate and atomically install one version as unqualified."""
        files = _read_source(source, self._root)
        declaration = _parse_declaration(files)
        manifest = declaration.manifest
        parent = self._tool_parent(manifest.category, manifest.tool_id, create=True)
        destination = parent / manifest.version
        if _path_exists(destination):
            raise ToolLifecycleError("lifecycle.already_installed")
        staging = parent / f".install-{uuid.uuid4().hex}"
        try:
            staging.mkdir()
            for relative, content in files:
                target = staging.joinpath(*PurePosixPath(relative).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            _write_json_direct(staging / "state.json", _initial_state())
            os.replace(staging, destination)
        except ToolLifecycleError:
            _remove_staging(staging)
            raise
        except OSError as exc:
            _remove_staging(staging)
            raise ToolLifecycleError("lifecycle.install_failed") from exc
        return self.inspect(manifest.category, manifest.tool_id, manifest.version)

    def qualify(
        self, category: ToolCategory, tool_id: str, version: str
    ) -> ToolVersionState:
        """Run describe, health, then the category's minimum local probe."""
        installed = self._read_installed(category, tool_id, version)
        state = self._read_state(installed.directory)
        try:
            self._run_describe(installed)
            self._run_health(installed)
            self._run_probe(installed)
        except _ContractFailure as exc:
            state.update(qualified=False, broken=False, failure_code=exc.code)
        except _BrokenTool as exc:
            state.update(qualified=False, broken=True, failure_code=exc.code)
        else:
            state.update(qualified=True, broken=False, failure_code=None)
        self._write_state(installed.directory, state)
        return self.inspect(category, tool_id, version)

    def activate(
        self, category: ToolCategory, tool_id: str, version: str
    ) -> ToolVersionState:
        """Atomically select one explicitly qualified usable version."""
        installed = self._read_installed(category, tool_id, version)
        state = self._read_state(installed.directory)
        if not state["qualified"] or state["disabled"] or state["broken"]:
            raise ToolLifecycleError("lifecycle.not_activatable")
        self._write_active(category, tool_id, version)
        return self.inspect(category, tool_id, version)

    def disable(
        self, category: ToolCategory, tool_id: str, version: str
    ) -> ToolVersionState:
        """Disable a version and make an active disabled version unusable."""
        installed = self._read_installed(category, tool_id, version)
        state = self._read_state(installed.directory)
        state["disabled"] = True
        self._write_state(installed.directory, state)
        if self._read_active(category, tool_id) == version:
            self._write_active(category, tool_id, None)
        return self.inspect(category, tool_id, version)

    def rollback(
        self, category: ToolCategory, tool_id: str, version: str
    ) -> ToolVersionState:
        """Explicitly switch from the active version to an older usable version."""
        current = self.active(category, tool_id)
        if current is None or _version_key(version) >= _version_key(
            current.manifest.version
        ):
            raise ToolLifecycleError("lifecycle.rollback_invalid")
        return self.activate(category, tool_id, version)

    def inspect(
        self, category: ToolCategory, tool_id: str, version: str
    ) -> ToolVersionState:
        """Read one installed version without changing lifecycle state."""
        installed = self._read_installed(category, tool_id, version)
        state = self._read_state(installed.directory)
        active = (
            self._read_active(category, tool_id) == version
            and bool(state["qualified"])
            and not bool(state["disabled"])
            and not bool(state["broken"])
        )
        manifest = ToolManifest(
            installed.manifest.tool_id,
            installed.manifest.version,
            installed.manifest.category,
            installed.manifest.distribution,
            installed.manifest.capabilities,
            installed.manifest.limits,
            HealthStatus.UNHEALTHY if state["broken"] else HealthStatus.HEALTHY,
            (
                QualificationStatus.QUALIFIED
                if state["qualified"]
                else QualificationStatus.UNQUALIFIED
            ),
        )
        return ToolVersionState(
            manifest=manifest,
            installed=True,
            qualified=bool(state["qualified"]),
            active=active,
            disabled=bool(state["disabled"]),
            broken=bool(state["broken"]),
            failure_code=state["failure_code"],  # type: ignore[arg-type]
        )

    def list_versions(
        self, category: ToolCategory, tool_id: str
    ) -> tuple[ToolVersionState, ...]:
        """Return installed versions in strict semantic-version order."""
        parent = self._tool_parent(category, tool_id, create=False)
        if not parent.exists():
            return ()
        _require_real_directory(parent)
        versions: list[str] = []
        try:
            entries = list(parent.iterdir())
        except OSError as exc:
            raise ToolLifecycleError("lifecycle.state_invalid") from exc
        for entry in entries:
            if entry.name.startswith(".install-") or entry.name == "active.json":
                continue
            if _is_link(entry) or not entry.is_dir():
                raise ToolLifecycleError("lifecycle.path_invalid")
            try:
                versions.append(validate_tool_version(entry.name))
            except ToolRegistryError as exc:
                raise ToolLifecycleError("lifecycle.path_invalid") from exc
        return tuple(
            self.inspect(category, tool_id, version)
            for version in sorted(versions, key=_version_key)
        )

    def active(self, category: ToolCategory, tool_id: str) -> ToolVersionState | None:
        """Return the currently usable active version, if any."""
        version = self._read_active(category, tool_id)
        if version is None:
            return None
        state = self.inspect(category, tool_id, version)
        return state if state.active else None

    def _tool_parent(
        self, category: ToolCategory, tool_id: str, *, create: bool
    ) -> Path:
        category, tool_id = _validate_identity(category, tool_id)
        parent = self._root / "tools" / category.value / tool_id
        if create:
            _make_real_directories(self._root, parent)
        else:
            _reject_link_components(parent, "lifecycle.path_invalid")
        return parent

    def _read_installed(
        self, category: ToolCategory, tool_id: str, version: str
    ) -> _InstalledTool:
        category, tool_id = _validate_identity(category, tool_id)
        try:
            version = validate_tool_version(version)
        except ToolRegistryError as exc:
            raise ToolLifecycleError("lifecycle.selector_invalid") from exc
        directory = self._tool_parent(category, tool_id, create=False) / version
        if not directory.exists():
            raise ToolLifecycleError("lifecycle.not_installed")
        files = _read_installed_tree(directory)
        declaration = _parse_declaration(files)
        if declaration.manifest.category is not category or (
            declaration.manifest.tool_id,
            declaration.manifest.version,
        ) != (tool_id, version):
            raise ToolLifecycleError("lifecycle.manifest_invalid")
        return _InstalledTool(declaration.manifest, declaration.entrypoint, directory)

    def _run_describe(self, installed: _InstalledTool) -> None:
        response = self._run_qualification(installed, "describe")
        expected = {
            "protocol_version": _QUALIFICATION_PROTOCOL,
            "operation": "describe",
            "status": "ok",
            "tool_id": installed.manifest.tool_id,
            "version": installed.manifest.version,
            "category": installed.manifest.category.value,
        }
        if response != expected:
            raise _BrokenTool("lifecycle.describe_failed")

    def _run_health(self, installed: _InstalledTool) -> None:
        response = self._run_qualification(installed, "health")
        expected = {
            "protocol_version": _QUALIFICATION_PROTOCOL,
            "operation": "health",
            "status": "ok",
            "health": "healthy",
        }
        if response != expected:
            raise _BrokenTool("lifecycle.health_failed")

    def _run_probe(self, installed: _InstalledTool) -> None:
        response = self._run_qualification(installed, "probe")
        expected = {
            "protocol_version": _QUALIFICATION_PROTOCOL,
            "operation": "probe",
            "status": "ok",
            "result": "qualified",
            "category": installed.manifest.category.value,
            "checks": list(_PROBE_CHECKS[installed.manifest.category]),
        }
        if response != expected:
            raise _ContractFailure("lifecycle.contract_failed")
        tool_input, output_type = _category_contract_vector(installed.manifest.category)
        try:
            result = SubprocessRunner(
                installed.manifest, _installed_command(installed)
            ).invoke(tool_input)
        except (OSError, ToolRegistryError) as exc:
            raise _BrokenTool("lifecycle.qualification_failed") from exc
        if type(result) is not output_type:
            raise _ContractFailure("lifecycle.contract_failed")

    def _run_qualification(
        self, installed: _InstalledTool, operation: str
    ) -> dict[str, object]:
        request = {
            "protocol_version": _QUALIFICATION_PROTOCOL,
            "operation": operation,
            "tool_id": installed.manifest.tool_id,
            "version": installed.manifest.version,
            "category": installed.manifest.category.value,
        }
        if operation == "probe":
            request["checks"] = list(_PROBE_CHECKS[installed.manifest.category])
        command = _installed_command(installed)
        try:
            completed = subprocess.run(  # pylint: disable=subprocess-run-check
                command,
                input=json.dumps(request, separators=(",", ":")).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=installed.directory,
                env=_minimal_environment(),
                timeout=installed.manifest.limits.max_runtime_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise _BrokenTool("lifecycle.qualification_failed") from exc
        if completed.returncode != 0 or len(completed.stdout) > _MAX_CONTROL_BYTES:
            raise _BrokenTool("lifecycle.qualification_failed")
        try:
            response = _load_json(completed.stdout)
        except ToolLifecycleError as exc:
            raise _BrokenTool("lifecycle.qualification_failed") from exc
        if type(response) is not dict:
            raise _BrokenTool("lifecycle.qualification_failed")
        return response

    def _read_state(self, directory: Path) -> dict[str, object]:
        path = directory / "state.json"
        if _is_link(path) or not path.is_file():
            raise ToolLifecycleError("lifecycle.state_invalid")
        try:
            value = _load_json(path.read_bytes())
        except (OSError, ToolLifecycleError) as exc:
            raise ToolLifecycleError("lifecycle.state_invalid") from exc
        valid = (
            type(value) is dict
            and set(value) == _STATE_KEYS
            and value.get("schema_version") == _STATE_SCHEMA
            and all(
                type(value.get(name)) is bool
                for name in ("qualified", "disabled", "broken")
            )
            and (
                value.get("failure_code") is None
                or type(value.get("failure_code")) is str
            )
        )
        if not valid:
            raise ToolLifecycleError("lifecycle.state_invalid")
        return value

    @staticmethod
    def _write_state(directory: Path, state: dict[str, object]) -> None:
        _atomic_json(directory / "state.json", state)

    def _read_active(self, category: ToolCategory, tool_id: str) -> str | None:
        path = self._tool_parent(category, tool_id, create=False) / "active.json"
        if not _path_exists(path):
            return None
        if _is_link(path) or not path.is_file():
            raise ToolLifecycleError("lifecycle.state_invalid")
        try:
            value = _load_json(path.read_bytes())
        except (OSError, ToolLifecycleError) as exc:
            raise ToolLifecycleError("lifecycle.state_invalid") from exc
        if type(value) is not dict or set(value) != {"schema_version", "version"}:
            raise ToolLifecycleError("lifecycle.state_invalid")
        if value["schema_version"] != _ACTIVE_SCHEMA:
            raise ToolLifecycleError("lifecycle.state_invalid")
        version = value["version"]
        if version is None:
            return None
        try:
            return validate_tool_version(version)  # type: ignore[arg-type]
        except ToolRegistryError as exc:
            raise ToolLifecycleError("lifecycle.state_invalid") from exc

    def _write_active(
        self, category: ToolCategory, tool_id: str, version: str | None
    ) -> None:
        parent = self._tool_parent(category, tool_id, create=False)
        _atomic_json(
            parent / "active.json",
            {"schema_version": _ACTIVE_SCHEMA, "version": version},
        )


@dataclass(frozen=True, slots=True)
class _Declaration:
    manifest: ToolManifest
    entrypoint: str


class _BrokenTool(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ContractFailure(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _parse_declaration(  # pylint: disable=too-many-branches
    files: list[tuple[str, bytes]],
) -> _Declaration:
    contents = dict(files)
    try:
        value = _load_json(contents["tool.json"])
        if type(value) is not dict or set(value) != _DECLARATION_KEYS:
            raise ValueError
        source = value["source"]
        raw_manifest = value["manifest"]
        if type(source) is not dict or set(source) != _SOURCE_KEYS:
            raise ValueError
        if type(raw_manifest) is not dict or set(raw_manifest) != _MANIFEST_KEYS:
            raise ValueError
        limits = raw_manifest["limits"]
        if type(limits) is not dict or set(limits) != _LIMIT_KEYS:
            raise ValueError
        capabilities = raw_manifest["capabilities"]
        if type(capabilities) is not list or any(
            type(item) is not str for item in capabilities
        ):
            raise ValueError
        manifest = ToolManifest(
            tool_id=raw_manifest["tool_id"],
            version=raw_manifest["version"],
            category=ToolCategory(raw_manifest["category"]),
            distribution=ToolDistribution(raw_manifest["distribution"]),
            capabilities=frozenset(capabilities),
            limits=ToolLimits(**limits),
            health=HealthStatus(raw_manifest["health"]),
            qualification=QualificationStatus(raw_manifest["qualification"]),
        )
        validate_tool_id(source["name"])
        source_identity = (
            ToolCategory(source["category"]),
            source["tool_id"],
            source["version"],
        )
        if source_identity != (
            manifest.category,
            manifest.tool_id,
            manifest.version,
        ):
            raise ValueError
        if value["protocol_version"] != _EXTERNAL_PROTOCOL:
            raise ValueError
        if manifest.distribution is not ToolDistribution.INSTALLED:
            raise ValueError
        if manifest.health is not HealthStatus.HEALTHY:
            raise ValueError
        if manifest.qualification is not QualificationStatus.UNQUALIFIED:
            raise ValueError
        entrypoint = _portable_relative(value["entrypoint"])
        if entrypoint not in contents or entrypoint == "tool.json":
            raise ToolLifecycleError("lifecycle.path_invalid")
    except ToolLifecycleError:
        raise
    except (KeyError, TypeError, ValueError, ToolRegistryError) as exc:
        raise ToolLifecycleError("lifecycle.manifest_invalid") from exc
    return _Declaration(manifest, entrypoint)


def _read_source(source: str | Path, data_root: Path) -> list[tuple[str, bytes]]:
    try:
        path = Path(source).absolute()
    except (TypeError, ValueError, OSError) as exc:
        raise ToolLifecycleError("lifecycle.path_invalid") from exc
    _reject_link_components(path, "lifecycle.path_invalid")
    if _is_link(path) or not path.is_dir():
        raise ToolLifecycleError("lifecycle.path_invalid")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ToolLifecycleError("lifecycle.path_invalid") from exc
    if resolved.is_relative_to(data_root) or data_root.is_relative_to(resolved):
        raise ToolLifecycleError("lifecycle.path_invalid")
    return _read_real_tree(resolved, include_state=False)


def _read_installed_tree(directory: Path) -> list[tuple[str, bytes]]:
    _reject_link_components(directory, "lifecycle.path_invalid")
    _require_real_directory(directory)
    return _read_real_tree(directory, include_state=False)


def _read_real_tree(root: Path, *, include_state: bool) -> list[tuple[str, bytes]]:
    files: list[tuple[str, bytes]] = []
    try:
        before_root = root.stat(follow_symlinks=False)
        stack = [(root, "")]
        while stack:
            directory, prefix = stack.pop()
            before = directory.stat(follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ToolLifecycleError("lifecycle.path_invalid")
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
            for entry in entries:
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                if not include_state and relative == "state.json":
                    continue
                _portable_relative(relative)
                info = entry.stat(follow_symlinks=False)
                if _is_link(Path(entry.path)):
                    raise ToolLifecycleError("lifecycle.path_invalid")
                if stat.S_ISDIR(info.st_mode):
                    stack.append((Path(entry.path), relative))
                elif stat.S_ISREG(info.st_mode):
                    files.append((relative, _stable_read(Path(entry.path), info)))
                else:
                    raise ToolLifecycleError("lifecycle.path_invalid")
            if not _same_identity(before, directory.stat(follow_symlinks=False)):
                raise ToolLifecycleError("lifecycle.path_changed")
        if not _same_identity(before_root, root.stat(follow_symlinks=False)):
            raise ToolLifecycleError("lifecycle.path_changed")
    except OSError as exc:
        raise ToolLifecycleError("lifecycle.path_invalid") from exc
    return sorted(files)


def _stable_read(path: Path, expected: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_identity(opened, expected):
            raise ToolLifecycleError("lifecycle.path_changed")
        chunks = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        if not _same_identity(opened, os.fstat(descriptor)) or not _same_identity(
            opened, path.stat(follow_symlinks=False)
        ):
            raise ToolLifecycleError("lifecycle.path_changed")
        return b"".join(chunks)
    except OSError as exc:
        raise ToolLifecycleError("lifecycle.path_invalid") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    stable = (first.st_mode, first.st_size, first.st_mtime_ns) == (
        second.st_mode,
        second.st_size,
        second.st_mtime_ns,
    )
    if not stable:
        return False
    first_identity = (first.st_dev, first.st_ino)
    second_identity = (second.st_dev, second.st_ino)
    return 0 in first_identity + second_identity or first_identity == second_identity


def _portable_relative(value: object) -> str:
    if type(value) is not str or not value or "\\" in value:
        raise ToolLifecycleError("lifecycle.path_invalid")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or windows.drive
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise ToolLifecycleError("lifecycle.path_invalid")
    return posix.as_posix()


def _validate_identity(
    category: ToolCategory, tool_id: str
) -> tuple[ToolCategory, str]:
    if type(category) is not ToolCategory:
        raise ToolLifecycleError("lifecycle.selector_invalid")
    try:
        return category, validate_tool_id(tool_id)
    except ToolRegistryError as exc:
        raise ToolLifecycleError("lifecycle.selector_invalid") from exc


def _version_key(version: str) -> tuple[int, int, int]:
    try:
        validated = validate_tool_version(version)
    except ToolRegistryError as exc:
        raise ToolLifecycleError("lifecycle.selector_invalid") from exc
    return tuple(int(part) for part in validated.split("."))  # type: ignore[return-value]


def _initial_state() -> dict[str, object]:
    return {
        "schema_version": _STATE_SCHEMA,
        "qualified": False,
        "disabled": False,
        "broken": False,
        "failure_code": None,
    }


def _load_json(content: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ToolLifecycleError("lifecycle.json_invalid") from exc


def _write_json_direct(path: Path, value: dict[str, object]) -> None:
    try:
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
    except OSError as exc:
        raise ToolLifecycleError("lifecycle.state_write_failed") from exc


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".state-", dir=path.parent)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError as exc:
        raise ToolLifecycleError("lifecycle.state_write_failed") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _minimal_environment() -> dict[str, str]:
    environment = {"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}
    for name in ("PATH", "SystemRoot", "WINDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _installed_command(installed: _InstalledTool) -> tuple[str, ...]:
    entrypoint = installed.directory.joinpath(
        *PurePosixPath(installed.entrypoint).parts
    )
    if entrypoint.suffix.casefold() == ".py":
        return (sys.executable, str(entrypoint))
    return (str(entrypoint),)


def _category_contract_vector(
    category: ToolCategory,
) -> tuple[
    DiscoveryInput | AcquisitionInput | TransformInput,
    type[DiscoveryOutput] | type[AcquisitionOutput] | type[TransformOutput],
]:
    scope = Scope(
        seeds=("https://example.test/",),
        allowed_origins=("https://example.test",),
        include_paths=("/**",),
        content_types=(ContentType.HTML, ContentType.FILE),
    )
    if category is ToolCategory.DISCOVERY:
        return DiscoveryInput(scope), DiscoveryOutput
    if category is ToolCategory.ACQUISITION:
        request = Request(scope, None, False, Budgets(1, 1, 1, 1))
        return AcquisitionInput(request, "https://example.test/"), AcquisitionOutput
    content = b"x"
    digest = hashlib.sha256(content).hexdigest()
    identifier = artifact_id(digest, "text/plain", ArtifactRole.SOURCE)
    stored = StoredObservation(
        Blob(digest, 1, blob_relative_path(digest)),
        Artifact(identifier, digest, "text/plain", ArtifactRole.SOURCE),
        Observation(
            "observation-00000000000000000000000000000000",
            identifier,
            "https://example.test/",
            "2026-08-27T00:00:00Z",
        ),
        (),
        content,
    )
    return TransformInput(stored), TransformOutput


def _make_real_directories(root: Path, destination: Path) -> None:
    current = root
    for part in destination.relative_to(root).parts:
        current = current / part
        if _path_exists(current):
            _require_real_directory(current)
            continue
        try:
            current.mkdir()
        except OSError as exc:
            raise ToolLifecycleError("lifecycle.data_root_invalid") from exc


def _require_real_directory(path: Path) -> None:
    if _is_link(path) or not path.is_dir():
        raise ToolLifecycleError("lifecycle.path_invalid")


def _reject_link_components(path: Path, code: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if _path_exists(current) and _is_link(current):
            raise ToolLifecycleError(code)


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ToolLifecycleError("lifecycle.path_invalid") from exc
    return True


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _remove_staging(path: Path) -> None:
    try:
        if _path_exists(path) and not _is_link(path):
            shutil.rmtree(path)
    except (OSError, ToolLifecycleError):
        pass


__all__ = ["ToolLifecycle", "ToolLifecycleError", "ToolVersionState"]
