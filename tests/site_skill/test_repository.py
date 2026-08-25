"""Explicit candidate, activation, conflict, and rollback tests."""

# pylint: disable=duplicate-code,missing-function-docstring,protected-access

from __future__ import annotations

import threading
import traceback

import pytest

from web_listening.request.model import Budgets, ContentType, Scope
from web_listening.site_skill.model import SiteSkillError, SuccessChecks, ToolReference
from web_listening.site_skill.repository import SiteSkillRepository
from web_listening.site_skill.update import create_candidate
from web_listening.tool_registry.manifest import ToolCategory


class _BarrierDict(dict):
    """Pause the first two worker reads at the old check/write race boundary."""

    def __init__(self, value: dict) -> None:
        super().__init__(value)
        self._barrier = threading.Barrier(2)
        self._remaining = 2
        self._counter_lock = threading.Lock()

    def get(self, key, default=None):
        value = super().get(key, default)
        with self._counter_lock:
            wait = (
                self._remaining > 0
                and threading.current_thread() is not threading.main_thread()
            )
            if wait:
                self._remaining -= 1
        if wait:
            try:
                self._barrier.wait(timeout=0.25)
            except threading.BrokenBarrierError:
                pass
        return value


def _run_together(*calls):
    start = threading.Barrier(len(calls))
    outcomes: list[str] = []

    def run(call) -> None:
        start.wait()
        try:
            call()
            outcomes.append("success")
        except SiteSkillError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=run, args=(call,)) for call in calls]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
        assert not thread.is_alive()
    return outcomes


def _candidate(*, previous=None, version: int = 1, site_key: str = "example"):
    return create_candidate(
        site_key=site_key,
        version=version,
        previous=previous,
        scope=Scope(
            seeds=("https://example.test/",),
            allowed_origins=("https://example.test",),
            include_paths=("/**",),
            content_types=(ContentType.HTML,),
        ),
        budgets=Budgets(4, 4096, 20, 1),
        tool=ToolReference(
            "acquisition.web_http",
            "1.0.0",
            ToolCategory.ACQUISITION,
            frozenset({"http_get"}),
        ),
        success_checks=SuccessChecks(("text/html",), 100),
        verified_at="2026-08-25T00:00:00Z",
    )


def test_candidate_stays_inactive_until_explicit_activation() -> None:
    repository = SiteSkillRepository()
    first = _candidate()

    repository.submit(first)

    assert repository.active("example") is None
    assert repository.candidate("example", first.skill.digest) == first.skill
    activated = repository.activate(
        "example", first.skill.digest, expected_active_digest=None
    )
    assert activated == first.skill
    assert repository.active("example") == first.skill
    assert repository.events[-1].action == "activate"


def test_activation_is_conflict_safe_and_preserves_active_value() -> None:
    repository = SiteSkillRepository()
    first = _candidate()
    repository.submit(first)
    repository.activate("example", first.skill.digest, expected_active_digest=None)
    second = _candidate(previous=first.skill, version=2)
    repository.submit(second)

    with pytest.raises(SiteSkillError, match="repository.conflict"):
        repository.activate("example", second.skill.digest, expected_active_digest=None)

    assert repository.active("example") == first.skill


def test_activation_validates_lineage_and_rollback_records_provenance() -> None:
    repository = SiteSkillRepository()
    first = _candidate()
    repository.submit(first)
    repository.activate("example", first.skill.digest, expected_active_digest=None)
    second = _candidate(previous=first.skill, version=2)
    repository.submit(second)
    repository.activate(
        "example", second.skill.digest, expected_active_digest=first.skill.digest
    )

    rolled_back = repository.rollback(
        "example", first.skill.digest, expected_active_digest=second.skill.digest
    )

    assert rolled_back == first.skill
    assert repository.active("example") == first.skill
    assert repository.events[-1].action == "rollback"
    assert repository.events[-1].from_digest == second.skill.digest
    assert repository.events[-1].to_digest == first.skill.digest


def test_missing_previous_candidate_is_rejected_without_state_change() -> None:
    repository = SiteSkillRepository()
    untracked_parent = _candidate().skill
    second = _candidate(previous=untracked_parent, version=2)

    with pytest.raises(SiteSkillError, match="repository.previous_missing"):
        repository.submit(second)

    assert repository.active("example") is None
    assert not repository.events


def test_rollback_cannot_jump_to_unrelated_candidate() -> None:
    repository = SiteSkillRepository()
    first = _candidate()
    unrelated = _candidate(site_key="other")
    repository.submit(first)
    repository.submit(unrelated)
    repository.activate("example", first.skill.digest, expected_active_digest=None)

    with pytest.raises(SiteSkillError, match="repository.candidate_missing"):
        repository.rollback(
            "example",
            unrelated.skill.digest,
            expected_active_digest=first.skill.digest,
        )

    assert repository.active("example") == first.skill


def test_rollback_uses_compare_and_set_without_mutating_on_conflict() -> None:
    repository = SiteSkillRepository()
    first = _candidate()
    repository.submit(first)
    repository.activate("example", first.skill.digest, expected_active_digest=None)
    second = _candidate(previous=first.skill, version=2)
    repository.submit(second)
    repository.activate(
        "example", second.skill.digest, expected_active_digest=first.skill.digest
    )

    with pytest.raises(SiteSkillError, match="repository.conflict"):
        repository.rollback(
            "example", first.skill.digest, expected_active_digest=first.skill.digest
        )

    assert repository.active("example") == second.skill


def test_concurrent_conflicting_activation_has_one_atomic_winner() -> None:
    repository = SiteSkillRepository()
    left = _candidate()
    right = create_candidate(
        site_key="example",
        version=1,
        previous=None,
        scope=left.skill.scope,
        budgets=Budgets(3, 4096, 20, 1),
        tool=left.skill.tool,
        success_checks=left.skill.success_checks,
        verified_at=left.skill.verified_at,
    )
    repository.submit(left)
    repository.submit(right)
    repository._active = _BarrierDict(
        repository._active
    )  # pylint: disable=protected-access

    outcomes = _run_together(
        lambda: repository.activate(
            "example", left.skill.digest, expected_active_digest=None
        ),
        lambda: repository.activate(
            "example", right.skill.digest, expected_active_digest=None
        ),
    )

    assert sorted(outcomes) == ["repository.conflict", "success"]
    assert sum(event.action == "activate" for event in repository.events) == 1


def test_concurrent_identical_submit_records_one_candidate_event() -> None:
    repository = SiteSkillRepository()
    candidate = _candidate()
    repository._candidates = _BarrierDict(  # pylint: disable=protected-access
        repository._candidates  # pylint: disable=protected-access
    )

    outcomes = _run_together(
        lambda: repository.submit(candidate),
        lambda: repository.submit(candidate),
    )

    assert outcomes == ["success", "success"]
    assert sum(event.action == "candidate" for event in repository.events) == 1


def test_concurrent_rollback_and_activation_share_one_cas_boundary() -> None:
    repository = SiteSkillRepository()
    first = _candidate()
    repository.submit(first)
    repository.activate("example", first.skill.digest, expected_active_digest=None)
    second = _candidate(previous=first.skill, version=2)
    repository.submit(second)
    repository.activate(
        "example", second.skill.digest, expected_active_digest=first.skill.digest
    )
    third = _candidate(previous=second.skill, version=3)
    repository.submit(third)
    repository._active = _BarrierDict(
        repository._active
    )  # pylint: disable=protected-access
    before = len(repository.events)

    outcomes = _run_together(
        lambda: repository.rollback(
            "example", first.skill.digest, expected_active_digest=second.skill.digest
        ),
        lambda: repository.activate(
            "example", third.skill.digest, expected_active_digest=second.skill.digest
        ),
    )

    assert sorted(outcomes) == ["repository.conflict", "success"]
    assert len(repository.events) == before + 1


def test_every_returned_value_and_event_is_detached_from_repository_state() -> None:
    repository = SiteSkillRepository()
    first = _candidate()
    original_digest = first.skill.digest
    returned = repository.submit(first)
    object.__setattr__(returned, "digest", "sha256:" + "f" * 64)
    assert repository.candidate("example", original_digest).digest == original_digest

    returned = repository.candidate("example", original_digest)
    object.__setattr__(returned, "digest", "sha256:" + "e" * 64)
    returned = repository.activate(
        "example", original_digest, expected_active_digest=None
    )
    object.__setattr__(returned, "digest", "sha256:" + "d" * 64)
    returned = repository.active("example")
    object.__setattr__(returned, "digest", "sha256:" + "c" * 64)

    second = _candidate(previous=first.skill, version=2)
    repository.submit(second)
    repository.activate(
        "example", second.skill.digest, expected_active_digest=original_digest
    )
    returned = repository.rollback(
        "example", original_digest, expected_active_digest=second.skill.digest
    )
    object.__setattr__(returned, "digest", "sha256:" + "b" * 64)
    before = len(repository.events)
    returned_event = repository.events[0]
    original_action = returned_event.action
    object.__setattr__(returned_event, "action", "CORRUPTED")

    assert repository.active("example").digest == original_digest
    assert repository.candidate("example", original_digest).digest == original_digest
    assert repository.events[0].action == original_action
    assert len(repository.events) == before


class _HostileKey(str):
    def __hash__(self):
        raise RuntimeError("PRIVATE-KEY-CANARY")


@pytest.mark.parametrize(
    "call",
    [
        lambda repository, digest: repository.candidate([], digest),
        lambda repository, digest: repository.active({}),
        lambda repository, digest: repository.activate(
            "example", [], expected_active_digest=None
        ),
        lambda repository, digest: repository.candidate(_HostileKey("example"), digest),
    ],
)
def test_malformed_public_keys_are_context_free_and_do_not_mutate(call) -> None:
    repository = SiteSkillRepository()
    candidate = _candidate()
    repository.submit(candidate)
    before = repository.events

    with pytest.raises(SiteSkillError) as caught:
        call(repository, candidate.skill.digest)

    assert caught.value.code == "repository.key_invalid"
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert "PRIVATE-KEY-CANARY" not in "".join(traceback.format_exception(caught.value))
    assert repository.events == before
