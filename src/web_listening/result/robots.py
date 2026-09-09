"""Inert, strict evidence of a Gateway-owned robots decision."""

# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, replace

from web_listening.result.errors import (
    ResultValidationError,
    require_exact_fields,
    require_mapping,
    validate_url,
)

ROBOTS_POLICY_ID = "robots-unknown-allow.v1"
_FIELDS = {
    "origin",
    "robots_url",
    "target_url",
    "status_code",
    "decision",
    "reason_code",
    "policy_id",
}


@dataclass(frozen=True, slots=True)
class RobotsDecision:
    """Serializable facts; this value never evaluates access policy."""

    origin: str
    robots_url: str
    target_url: str
    status_code: int | None
    decision: str
    reason_code: str
    policy_id: str = ROBOTS_POLICY_ID

    def __post_init__(self) -> None:
        for value in (self.origin, self.robots_url, self.target_url):
            validate_url(value)
            query = value.partition("?")[2]
            if "#" in value or (
                query and re.fullmatch(r"query-sha256=[0-9a-f]{64}", query) is None
            ):
                raise ResultValidationError("robots.url_invalid")
        if re.fullmatch(r"https?://[^/?#]+", self.origin) is None:
            raise ResultValidationError("robots.origin_invalid")
        if self.status_code is not None and (
            type(self.status_code) is not int or not 100 <= self.status_code <= 599
        ):
            raise ResultValidationError("robots.status_invalid")
        if not isinstance(self.decision, str) or self.decision not in {
            "allowed",
            "denied",
            "absent",
            "unknown_allow",
        }:
            raise ResultValidationError("robots.decision_invalid")
        if (
            not isinstance(self.reason_code, str)
            or re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", self.reason_code)
            is None
        ):
            raise ResultValidationError("robots.reason_invalid")
        if self.policy_id != ROBOTS_POLICY_ID:
            raise ResultValidationError("robots.policy_invalid")

    @property
    def code(self) -> str:
        """Keep the existing in-process evidence accessor."""
        return self.reason_code

    @property
    def allowed(self) -> bool:
        """Expose the already-recorded outcome, without evaluating rules."""
        return self.decision != "denied"

    def to_dict(self) -> dict[str, object]:
        """Return exactly the frozen JSON fields."""
        return asdict(self)

    @classmethod
    def from_dict(cls, value: object) -> RobotsDecision:
        """Read strict evidence without inventing defaults for missing fields."""
        payload = require_mapping(value)
        require_exact_fields(payload, _FIELDS)
        return cls(**payload)


def validate_robots_decisions(value: object) -> tuple[RobotsDecision, ...]:
    """Revalidate even frozen objects at receiving trust boundaries."""
    if not isinstance(value, tuple) or any(
        type(item) is not RobotsDecision for item in value
    ):
        raise ResultValidationError("robots.decisions_invalid")
    return tuple(replace(item) for item in value)
