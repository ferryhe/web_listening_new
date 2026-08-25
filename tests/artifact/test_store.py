"""Offline contract tests for the minimal immutable Artifact repository."""

# pylint: disable=protected-access,redefined-outer-name,too-many-arguments,too-many-lines

from __future__ import annotations

import ast
import hashlib
import json
import sqlite3
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import web_listening.artifact.store as artifact_store_module
from web_listening.artifact.identity import (
    artifact_id,
    blob_relative_path,
    validate_relative_path,
)
from web_listening.artifact.lineage import lineage_id
from web_listening.artifact.model import ArtifactRole, ArtifactStoreError
from web_listening.artifact.observation import ObservationProposal
from web_listening.artifact.store import ArtifactStore

HTML = b"<!doctype html><html><body>offline annual report</body></html>"
CHANGED_HTML = b"<!doctype html><html><body>changed offline report</body></html>"
MARKDOWN = b"# Offline annual report\n"
SOURCE_URL = "https://www.soa.org/research/annual/"
OBSERVED_AT = "2026-08-25T12:00:00Z"


class InjectedPublicationFailure(BaseException):
    """A non-Exception interruption after a filesystem side effect."""


@pytest.fixture
def store(tmp_path: Path) -> ArtifactStore:
    """Return one repository and close its SQLite handle after the test."""
    repository = ArtifactStore(tmp_path / "repository")
    try:
        yield repository
    finally:
        repository.close()


def proposal(
    content: bytes = HTML,
    *,
    mime_type: str = "text/html",
    source_url: str = SOURCE_URL,
    observed_at: str = OBSERVED_AT,
    role: ArtifactRole = ArtifactRole.SOURCE,
    derived_from_observation_id: str | None = None,
    declared_sha256: str | None = None,
    declared_size: int | None = None,
) -> ObservationProposal:
    """Build a complete caller declaration over fixed local bytes."""
    return ObservationProposal(
        content=content,
        sha256=(
            hashlib.sha256(content).hexdigest()
            if declared_sha256 is None
            else declared_sha256
        ),
        size_bytes=len(content) if declared_size is None else declared_size,
        mime_type=mime_type,
        source_url=source_url,
        observed_at=observed_at,
        role=role,
        derived_from_observation_id=derived_from_observation_id,
    )


def row_counts(repository: ArtifactStore) -> dict[str, int]:
    """Read committed row counts through an independent SQLite connection."""
    with sqlite3.connect(repository.database_path) as connection:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("blobs", "artifacts", "observations", "lineage")
        }


def repository_files(repository: ArtifactStore) -> dict[str, bytes]:
    """Snapshot repository files other than SQLite's durable database file."""
    return {
        path.relative_to(repository.root).as_posix(): path.read_bytes()
        for path in repository.root.rglob("*")
        if path.is_file() and path != repository.database_path
    }


def make_symlink(link: Path, target: Path, *, directory: bool) -> None:
    """Create a test symlink or skip where the host denies that capability."""
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")


def test_first_store_and_same_bytes_keep_one_blob_two_observations(
    store: ArtifactStore,
) -> None:
    """Blob and Artifact deduplicate, but every successful visit is retained."""
    first = store.commit_observation(proposal())
    second = store.commit_observation(proposal(observed_at="2026-08-25T12:01:00Z"))

    digest = hashlib.sha256(HTML).hexdigest()
    assert first.blob.sha256 == second.blob.sha256 == digest
    assert first.artifact == second.artifact
    assert first.observation.observation_id != second.observation.observation_id
    assert first.content == second.content == HTML
    assert first.blob.relative_path == blob_relative_path(digest)
    assert row_counts(store) == {
        "blobs": 1,
        "artifacts": 1,
        "observations": 2,
        "lineage": 0,
    }


def test_changed_bytes_add_blob_without_overwriting_history(
    store: ArtifactStore,
) -> None:
    """A later changed response remains readable beside the first snapshot."""
    first = store.commit_observation(proposal())
    second = store.commit_observation(
        proposal(CHANGED_HTML, observed_at="2026-08-25T12:02:00Z")
    )

    assert first.blob.sha256 != second.blob.sha256
    assert store.get_observation(first.observation.observation_id).content == HTML
    assert (
        store.get_observation(second.observation.observation_id).content == CHANGED_HTML
    )
    assert row_counts(store) == {
        "blobs": 2,
        "artifacts": 2,
        "observations": 2,
        "lineage": 0,
    }


def test_artifact_and_lineage_identity_are_deterministic(store: ArtifactStore) -> None:
    """Immutable payloads and edges have canonical repeatable identities."""
    source = store.commit_observation(proposal())
    derived = store.commit_observation(
        proposal(
            MARKDOWN,
            mime_type="text/markdown",
            source_url="urn:web-listening:derived:markdown",
            observed_at="2026-08-25T12:03:00Z",
            role=ArtifactRole.DERIVED,
            derived_from_observation_id=source.observation.observation_id,
        )
    )
    edge = derived.lineage[0]

    assert derived.artifact.artifact_id == artifact_id(
        derived.blob.sha256, "text/markdown", ArtifactRole.DERIVED
    )
    assert edge.lineage_id == lineage_id(
        observation_id=derived.observation.observation_id,
        artifact_id=derived.artifact.artifact_id,
        source_observation_id=source.observation.observation_id,
        source_artifact_id=source.artifact.artifact_id,
    )
    assert edge.relation == "derived_from"
    assert edge.source_artifact_id == source.artifact.artifact_id
    assert row_counts(store)["lineage"] == 1


@pytest.mark.parametrize(
    ("role", "related", "expected_code"),
    [
        (ArtifactRole.SOURCE, "observation-" + "0" * 32, "lineage.forbidden"),
        (ArtifactRole.DERIVED, None, "lineage.required"),
        (
            ArtifactRole.DERIVED,
            "observation-" + "0" * 32,
            "lineage.missing_reference",
        ),
    ],
)
def test_lineage_role_and_reference_rules_fail_before_mutation(
    store: ArtifactStore,
    role: ArtifactRole,
    related: str | None,
    expected_code: str,
) -> None:
    """Source/derived roles cannot create forbidden or dangling relations."""
    before = row_counts(store)

    with pytest.raises(ArtifactStoreError) as caught:
        store.commit_observation(
            proposal(
                MARKDOWN,
                mime_type="text/markdown",
                source_url="urn:web-listening:derived:markdown",
                role=role,
                derived_from_observation_id=related,
            )
        )

    assert caught.value.code == expected_code
    assert row_counts(store) == before
    assert repository_files(store) == {}


@pytest.mark.parametrize(
    ("overrides", "expected_code"),
    [
        ({"mime_type": "Text/HTML"}, "mime.invalid"),
        ({"mime_type": "text/html; charset=utf-8"}, "mime.invalid"),
        ({"mime_type": "text/html\nprivate"}, "mime.invalid"),
        ({"declared_sha256": "0" * 63}, "blob.sha256_invalid"),
        ({"declared_sha256": "0" * 64}, "blob.sha256_mismatch"),
        ({"declared_size": True}, "blob.size_invalid"),
        ({"declared_size": len(HTML) + 1}, "blob.size_mismatch"),
        ({"source_url": "offline\x00private"}, "observation.source_invalid"),
        ({"observed_at": "2026-08-25"}, "observation.time_invalid"),
    ],
)
def test_invalid_declarations_fail_without_state(
    store: ArtifactStore, overrides: dict[str, object], expected_code: str
) -> None:
    """Caller claims are strict and checked before files or rows exist."""
    before = row_counts(store)

    with pytest.raises(ArtifactStoreError) as caught:
        store.commit_observation(proposal(**overrides))  # type: ignore[arg-type]

    assert caught.value.code == expected_code
    assert row_counts(store) == before
    assert repository_files(store) == {}


@pytest.mark.parametrize(
    "value",
    [
        "",
        "/absolute/blob",
        "C:/absolute/blob",
        "../escape",
        "blobs/../escape",
        "blobs\\escape",
        "blobs//escape",
        "blobs/control\x00leaf",
    ],
)
def test_portable_relative_path_rejects_unsafe_shapes(value: str) -> None:
    """No exposed relative path can escape or change meaning by platform."""
    with pytest.raises(ArtifactStoreError) as caught:
        validate_relative_path(value)

    assert caught.value.code == "path.invalid"


@pytest.mark.parametrize("tampered", [b"X" * len(HTML), HTML + b"extra"])
def test_reads_revalidate_stored_size_and_hash(
    store: ArtifactStore, tampered: bytes
) -> None:
    """File tampering never returns unverified content."""
    stored = store.commit_observation(proposal())
    target = store.root.joinpath(*stored.blob.relative_path.split("/"))
    target.write_bytes(tampered)

    with pytest.raises(ArtifactStoreError) as caught:
        store.read_blob(stored.blob.sha256)
    assert caught.value.code == "blob.corrupt"
    with pytest.raises(ArtifactStoreError):
        store.get_observation(stored.observation.observation_id)


def test_loaded_relative_path_tamper_fails_closed(store: ArtifactStore) -> None:
    """A database path escape is rejected before filesystem access."""
    stored = store.commit_observation(proposal())
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE blobs SET relative_path = ? WHERE sha256 = ?",
            ("../escape", stored.blob.sha256),
        )

    with pytest.raises(ArtifactStoreError) as caught:
        store.read_blob(stored.blob.sha256)

    assert caught.value.code == "path.invalid"


def test_returned_models_are_frozen(store: ArtifactStore) -> None:
    """Repository values cannot be mutated into contradictory identities."""
    stored = store.commit_observation(proposal())

    with pytest.raises(FrozenInstanceError):
        stored.blob.size_bytes = 0  # type: ignore[misc]


def test_root_symlink_is_rejected_without_touching_target(tmp_path: Path) -> None:
    """The repository root itself is never followed through a symlink."""
    victim = tmp_path / "victim"
    victim.mkdir()
    link = tmp_path / "repository-link"
    make_symlink(link, victim, directory=True)

    with pytest.raises(ArtifactStoreError) as caught:
        ArtifactStore(link)

    assert caught.value.code == "path.symlink"
    assert not list(victim.iterdir())


def test_simulated_junction_root_is_rejected_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Windows-style junction is treated as a link on every host."""
    repository = tmp_path / "repository"
    repository.mkdir()
    sentinel = repository / "victim-content"
    sentinel.write_bytes(b"preserve")

    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda candidate: candidate == repository,
        raising=False,
    )

    with pytest.raises(ArtifactStoreError) as caught:
        ArtifactStore(repository)

    assert caught.value.code == "path.symlink"
    assert sentinel.read_bytes() == b"preserve"
    assert list(repository.iterdir()) == [sentinel]


def test_database_leaf_symlink_is_rejected_before_sqlite_open(tmp_path: Path) -> None:
    """Repository initialization never follows a pre-existing database link."""
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "blobs").mkdir()
    victim = tmp_path / "database-victim"
    original = b"not a database and must stay unchanged"
    victim.write_bytes(original)
    make_symlink(repository / "artifact.sqlite3", victim, directory=False)

    with pytest.raises(ArtifactStoreError) as caught:
        ArtifactStore(repository)

    assert caught.value.code == "path.symlink"
    assert victim.read_bytes() == original


def test_blob_parent_symlink_is_rejected_without_escape(store: ArtifactStore) -> None:
    """A symlinked CAS shard cannot redirect publication outside the root."""
    digest = hashlib.sha256(HTML).hexdigest()
    shard = store.root / "blobs" / digest[:2]
    escape = store.root.parent / "escape-parent"
    escape.mkdir()
    make_symlink(shard, escape, directory=True)

    with pytest.raises(ArtifactStoreError) as caught:
        store.commit_observation(proposal())

    assert caught.value.code == "path.symlink"
    assert not list(escape.iterdir())
    assert row_counts(store) == {
        "blobs": 0,
        "artifacts": 0,
        "observations": 0,
        "lineage": 0,
    }


def test_blob_leaf_symlink_is_rejected_and_victim_preserved(
    store: ArtifactStore,
) -> None:
    """A pre-existing leaf symlink is neither followed nor removed."""
    digest = hashlib.sha256(HTML).hexdigest()
    target = store.root.joinpath(*blob_relative_path(digest).split("/"))
    target.parent.mkdir()
    victim = store.root.parent / "leaf-victim"
    victim.write_bytes(b"victim")
    make_symlink(target, victim, directory=False)

    with pytest.raises(ArtifactStoreError) as caught:
        store.commit_observation(proposal())

    assert caught.value.code == "path.symlink"
    assert victim.read_bytes() == b"victim"
    assert target.is_symlink()
    assert row_counts(store)["observations"] == 0


def test_injected_mid_commit_failure_rolls_back_rows_files_and_temps(
    store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure after all inserts leaves the initialized repository unchanged."""
    before_rows = row_counts(store)
    before_files = repository_files(store)

    def fail(stage: str, _observation: object) -> None:
        if stage == "after_rows":
            raise RuntimeError("injected mid-commit failure")

    monkeypatch.setattr(store, "_commit_checkpoint", fail)

    with pytest.raises(RuntimeError, match="injected mid-commit failure"):
        store.commit_observation(proposal())

    assert row_counts(store) == before_rows
    assert repository_files(store) == before_files
    assert not list(store.root.rglob("*.tmp"))


def test_post_parent_mkdir_checkpoint_removes_only_owned_shard(
    store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-mkdir interruption removes its shard and preserves the repository."""
    digest = hashlib.sha256(HTML).hexdigest()
    blobs = store.root / "blobs"
    shard = blobs / digest[:2]
    target = shard / f"{digest}.blob"
    sentinel = blobs / "preexisting-sentinel"
    sentinel.write_bytes(b"preserve")

    def interrupt(stage: str) -> None:
        if stage == "after_parent_mkdir":
            raise InjectedPublicationFailure("interrupt after parent mkdir")

    monkeypatch.setattr(store, "_publication_checkpoint", interrupt)

    with pytest.raises(InjectedPublicationFailure, match="after parent mkdir"):
        store.commit_observation(proposal())

    assert row_counts(store) == {
        "blobs": 0,
        "artifacts": 0,
        "observations": 0,
        "lineage": 0,
    }
    assert store.root.is_dir()
    assert blobs.is_dir()
    assert sentinel.read_bytes() == b"preserve"
    assert not shard.exists()
    assert not target.exists()
    assert not list(store.root.rglob("*.tmp"))


def test_temp_identity_capture_interruption_removes_exact_temp(
    store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An opened exclusive temp is recovered and removed if fstat interrupts."""
    target = store.root.joinpath(
        *blob_relative_path(hashlib.sha256(HTML).hexdigest()).split("/")
    )

    def interrupt_fstat(_descriptor: int) -> object:
        raise InjectedPublicationFailure("interrupt temp identity capture")

    monkeypatch.setattr(artifact_store_module.os, "fstat", interrupt_fstat)

    with pytest.raises(InjectedPublicationFailure, match="temp identity capture"):
        store.commit_observation(proposal())

    assert row_counts(store) == {
        "blobs": 0,
        "artifacts": 0,
        "observations": 0,
        "lineage": 0,
    }
    assert not list(store.root.rglob("*.tmp"))
    assert not target.exists()


def test_post_fstat_checkpoint_interruption_removes_exact_temp(
    store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-fstat interruption cannot precede recoverable temp ownership."""
    target = store.root.joinpath(
        *blob_relative_path(hashlib.sha256(HTML).hexdigest()).split("/")
    )

    def interrupt(stage: str) -> None:
        if stage == "after_temp_stat":
            raise InjectedPublicationFailure("interrupt after temp fstat")

    monkeypatch.setattr(store, "_publication_checkpoint", interrupt)

    with pytest.raises(InjectedPublicationFailure, match="after temp fstat"):
        store.commit_observation(proposal())

    assert row_counts(store) == {
        "blobs": 0,
        "artifacts": 0,
        "observations": 0,
        "lineage": 0,
    }
    assert not list(store.root.rglob("*.tmp"))
    assert not target.exists()


def test_hardlink_effect_then_interruption_removes_exact_new_leaf(
    store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A linked CAS target is claimed before an interruption can orphan it."""
    digest = hashlib.sha256(HTML).hexdigest()
    target = store.root.joinpath(*blob_relative_path(digest).split("/"))
    real_link = artifact_store_module.os.link

    def link_then_interrupt(
        source: Path, destination: Path, *, follow_symlinks: bool
    ) -> None:
        real_link(source, destination, follow_symlinks=follow_symlinks)
        raise InjectedPublicationFailure("interrupt after hardlink effect")

    monkeypatch.setattr(artifact_store_module.os, "link", link_then_interrupt)

    with pytest.raises(InjectedPublicationFailure, match="hardlink effect"):
        store.commit_observation(proposal())

    assert row_counts(store) == {
        "blobs": 0,
        "artifacts": 0,
        "observations": 0,
        "lineage": 0,
    }
    assert not list(store.root.rglob("*.tmp"))
    assert not target.exists()


def test_post_hardlink_checkpoint_interruption_removes_exact_new_leaf(
    store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-link interruption cannot precede recoverable target ownership."""
    digest = hashlib.sha256(HTML).hexdigest()
    target = store.root.joinpath(*blob_relative_path(digest).split("/"))

    def interrupt(stage: str) -> None:
        if stage == "after_target_link":
            raise InjectedPublicationFailure("interrupt after target link")

    monkeypatch.setattr(store, "_publication_checkpoint", interrupt)

    with pytest.raises(InjectedPublicationFailure, match="after target link"):
        store.commit_observation(proposal())

    assert row_counts(store) == {
        "blobs": 0,
        "artifacts": 0,
        "observations": 0,
        "lineage": 0,
    }
    assert not list(store.root.rglob("*.tmp"))
    assert not target.exists()


def test_failed_commit_never_removes_preexisting_valid_or_conflicting_leaf(
    store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rollback owns only the exact CAS leaf created by that commit."""
    digest = hashlib.sha256(HTML).hexdigest()
    target = store.root.joinpath(*blob_relative_path(digest).split("/"))
    target.parent.mkdir()
    target.write_bytes(HTML)

    def fail(stage: str, _observation: object) -> None:
        if stage == "after_rows":
            raise InjectedPublicationFailure("fail after adopting valid leaf")

    monkeypatch.setattr(store, "_commit_checkpoint", fail)
    with pytest.raises(InjectedPublicationFailure, match="adopting valid leaf"):
        store.commit_observation(proposal())
    assert target.read_bytes() == HTML
    assert row_counts(store)["blobs"] == 0

    target.write_bytes(b"preexisting conflict")
    with pytest.raises(ArtifactStoreError) as caught:
        store.commit_observation(proposal())
    assert caught.value.code == "blob.conflict"
    assert target.read_bytes() == b"preexisting conflict"
    assert not list(store.root.rglob("*.tmp"))


def test_concurrent_identical_writes_make_one_blob_and_two_observations(
    store: ArtifactStore,
) -> None:
    """Thread submissions serialize without collapsing visit history."""
    barrier = threading.Barrier(2)
    results = []
    failures: list[BaseException] = []

    def submit(index: int) -> None:
        try:
            barrier.wait(timeout=5)
            results.append(
                store.commit_observation(
                    proposal(observed_at=f"2026-08-25T12:0{index}:00Z")
                )
            )
        except BaseException as exc:  # pylint: disable=broad-exception-caught
            failures.append(exc)

    threads = [threading.Thread(target=submit, args=(index,)) for index in (4, 5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert not any(thread.is_alive() for thread in threads)
    assert not failures
    assert len({item.observation.observation_id for item in results}) == 2
    assert row_counts(store) == {
        "blobs": 1,
        "artifacts": 1,
        "observations": 2,
        "lineage": 0,
    }


def test_concurrent_failure_cannot_rollback_another_writer(
    store: ArtifactStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A queued failing transaction cannot remove an earlier durable commit."""
    success_at_checkpoint = threading.Event()
    release_success = threading.Event()
    results = []
    failures: list[BaseException] = []

    def checkpoint(stage: str, observation: object) -> None:
        if stage != "after_rows":
            return
        source_url = observation.source_url  # type: ignore[attr-defined]
        if source_url.endswith("success"):
            success_at_checkpoint.set()
            if not release_success.wait(timeout=5):
                raise TimeoutError("success writer was not released")
            return
        raise RuntimeError("injected failing writer")

    monkeypatch.setattr(store, "_commit_checkpoint", checkpoint)

    def submit(source_url: str) -> None:
        try:
            results.append(store.commit_observation(proposal(source_url=source_url)))
        except BaseException as exc:  # pylint: disable=broad-exception-caught
            failures.append(exc)

    successful = threading.Thread(target=submit, args=("offline:success",))
    failing = threading.Thread(target=submit, args=("offline:failure",))
    successful.start()
    assert success_at_checkpoint.wait(timeout=5)
    failing.start()
    release_success.set()
    successful.join(timeout=5)
    failing.join(timeout=5)

    assert not successful.is_alive() and not failing.is_alive()
    assert len(results) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], RuntimeError)
    assert results[0].content == HTML
    assert store.read_blob(results[0].blob.sha256) == HTML
    assert row_counts(store) == {
        "blobs": 1,
        "artifacts": 1,
        "observations": 1,
        "lineage": 0,
    }


def test_artifact_modules_have_zero_network_or_tool_authority() -> None:
    """Artifact source imports contain no acquisition or networking dependency."""
    root = Path(__file__).parents[2] / "src" / "web_listening" / "artifact"
    forbidden_roots = {
        "http",
        "httpx",
        "requests",
        "socket",
        "urllib",
        "web_listening.interfaces",
        "web_listening.request",
        "web_listening.result",
        "web_listening.runtime",
        "web_listening.site_skill",
        "web_listening.tool_registry",
    }
    observed: set[str] = set()
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                observed.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                observed.add(node.module)

    assert not {
        name
        for name in observed
        if any(
            name == root_name or name.startswith(f"{root_name}.")
            for root_name in forbidden_roots
        )
    }


def test_identity_payload_is_canonical_json() -> None:
    """Artifact identity matches the documented sorted compact JSON payload."""
    digest = hashlib.sha256(HTML).hexdigest()
    payload = {
        "blob_sha256": digest,
        "mime_type": "text/html",
        "role": "source",
    }
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    assert artifact_id(digest, "text/html", ArtifactRole.SOURCE) == (
        f"artifact-{expected}"
    )
