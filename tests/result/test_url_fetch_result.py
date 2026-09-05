"""Strict URL-fetch result tests."""

# pylint: disable=missing-function-docstring

from web_listening.result.manifest import Usage
from web_listening.result.model import ResultStatus
from web_listening.result.url_fetch import ResolutionKind, UrlFetchResult


def test_empty_failed_result_round_trips_strictly() -> None:
    result = UrlFetchResult(
        ResultStatus.FAILED,
        "https://example.test/",
        None,
        None,
        ResolutionKind.UNRESOLVED,
        None,
        (),
        None,
        (),
        Usage(0, 0, 0, 0),
        "acquisition_failed",
        (),
    )
    assert UrlFetchResult.from_dict(result.to_dict()) == result
