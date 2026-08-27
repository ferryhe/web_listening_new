"""Immutable, explicitly ordered acquisition-attempt evidence."""

from __future__ import annotations

from dataclasses import dataclass

from web_listening.result.errors import (
    ResultValidationError,
    SafeError,
    parse_utc_time,
    require_exact_fields,
    require_mapping,
    validate_nonnegative_int,
    validate_text,
    validate_url,
    validate_utc_time,
)

ATTEMPT_SCHEMA_VERSION = "web-listening-attempt.v1"
_OUTCOMES = {"succeeded", "failed", "skipped"}


@dataclass(frozen=True, slots=True)
class Attempt:  # pylint: disable=too-many-instance-attributes
    """One immutable tool attempt, including failures and skipped candidates."""

    order: int
    attempt_id: str
    outcome: str
    tool_id: str
    tool_version: str
    started_at: str
    finished_at: str
    requested_url: str
    final_url: str | None
    http_status: int | None
    error: SafeError | None
    requests: int
    bytes_received: int
    runtime_ms: int
    schema_version: str = ATTEMPT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ATTEMPT_SCHEMA_VERSION:
            raise ResultValidationError("schema.version_invalid")
        validate_nonnegative_int(self.order, code="attempt.order_invalid")
        validate_text(self.attempt_id, code="attempt.id_invalid", maximum=128)
        if not isinstance(self.outcome, str) or self.outcome not in _OUTCOMES:
            raise ResultValidationError("attempt.outcome_invalid")
        validate_text(self.tool_id, code="attempt.tool_invalid", maximum=128)
        validate_text(self.tool_version, code="attempt.tool_invalid", maximum=128)
        validate_utc_time(self.started_at)
        validate_utc_time(self.finished_at)
        if parse_utc_time(self.finished_at) < parse_utc_time(self.started_at):
            raise ResultValidationError("attempt.time_invalid")
        validate_url(self.requested_url)
        if self.final_url is not None:
            validate_url(self.final_url)
        if self.http_status is not None and (
            isinstance(self.http_status, bool)
            or not isinstance(self.http_status, int)
            or not 100 <= self.http_status <= 599
        ):
            raise ResultValidationError("attempt.http_status_invalid")
        validate_nonnegative_int(self.requests, code="attempt.usage_invalid")
        validate_nonnegative_int(self.bytes_received, code="attempt.usage_invalid")
        validate_nonnegative_int(self.runtime_ms, code="attempt.usage_invalid")
        if self.error is not None and not isinstance(self.error, SafeError):
            raise ResultValidationError("attempt.error_invalid")

        if self.outcome == "succeeded":
            network_effect = any(
                value is not None and value != 0
                for value in (
                    self.final_url,
                    self.http_status,
                    self.requests,
                    self.bytes_received,
                )
            )
            network_success = (
                self.final_url is not None
                and self.http_status is not None
                and self.requests > 0
            )
            local_success = (
                self.final_url is None
                and self.http_status is None
                and self.requests == 0
                and self.bytes_received == 0
            )
            if self.error is not None or not (
                network_success if network_effect else local_success
            ):
                raise ResultValidationError("attempt.success_invalid")
        elif self.error is None:
            raise ResultValidationError("attempt.error_required")
        skipped_effects = (
            self.final_url,
            self.http_status,
            self.requests,
            self.bytes_received,
            self.runtime_ms,
        )
        if self.outcome == "skipped" and any(
            value is not None and value != 0 for value in skipped_effects
        ):
            raise ResultValidationError("attempt.skipped_invalid")

    @classmethod
    def from_dict(cls, value: object) -> Attempt:
        """Parse one strict versioned attempt."""
        payload = require_mapping(value)
        require_exact_fields(
            payload,
            {
                "schema_version",
                "order",
                "attempt_id",
                "outcome",
                "tool_id",
                "tool_version",
                "started_at",
                "finished_at",
                "requested_url",
                "final_url",
                "http_status",
                "error",
                "requests",
                "bytes_received",
                "runtime_ms",
            },
        )
        error = (
            None if payload["error"] is None else SafeError.from_dict(payload["error"])
        )
        return cls(
            schema_version=payload["schema_version"],
            order=payload["order"],
            attempt_id=payload["attempt_id"],
            outcome=payload["outcome"],
            tool_id=payload["tool_id"],
            tool_version=payload["tool_version"],
            started_at=payload["started_at"],
            finished_at=payload["finished_at"],
            requested_url=payload["requested_url"],
            final_url=payload["final_url"],
            http_status=payload["http_status"],
            error=error,
            requests=payload["requests"],
            bytes_received=payload["bytes_received"],
            runtime_ms=payload["runtime_ms"],
        )

    def to_dict(self) -> dict[str, object]:
        """Return the complete attempt as a plain JSON value."""
        return {
            "schema_version": self.schema_version,
            "order": self.order,
            "attempt_id": self.attempt_id,
            "outcome": self.outcome,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "http_status": self.http_status,
            "error": None if self.error is None else self.error.to_dict(),
            "requests": self.requests,
            "bytes_received": self.bytes_received,
            "runtime_ms": self.runtime_ms,
        }


def validate_attempts(attempts: tuple[Attempt, ...]) -> tuple[Attempt, ...]:
    """Require unique identities and caller-provided contiguous ordering."""
    if not isinstance(attempts, tuple) or not all(
        isinstance(attempt, Attempt) for attempt in attempts
    ):
        raise ResultValidationError("attempt.invalid")
    if [attempt.order for attempt in attempts] != list(range(len(attempts))):
        raise ResultValidationError("attempt.order_invalid")
    identities = [attempt.attempt_id for attempt in attempts]
    if len(identities) != len(set(identities)):
        raise ResultValidationError("attempt.duplicate")
    return attempts
