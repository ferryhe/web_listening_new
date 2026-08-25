"""Built-in acquisition adapter for the governed HTTP gateway."""

from __future__ import annotations

from collections.abc import Callable

from web_listening.tool_registry.manifest import (
    HealthStatus,
    QualificationStatus,
    ToolCategory,
    ToolDistribution,
    ToolLimits,
    ToolManifest,
)
from web_listening.tool_registry.protocols.acquisition import (
    AcquisitionFailure,
    AcquisitionInput,
    AcquisitionOutput,
    AcquisitionRedirect,
)
from web_listening.tool_registry.runners.in_process import (
    GatewayFailure,
    GovernedAccessGateway,
    Transport,
)

WEB_HTTP_MANIFEST = ToolManifest(
    tool_id="acquisition.web_http",
    version="1.0.0",
    category=ToolCategory.ACQUISITION,
    distribution=ToolDistribution.BUILTIN,
    capabilities=frozenset({"http_get"}),
    limits=ToolLimits(
        max_runtime_seconds=30,
        max_input_bytes=2 * 1024 * 1024,
        max_output_bytes=2 * 1024 * 1024,
    ),
    health=HealthStatus.HEALTHY,
    qualification=QualificationStatus.QUALIFIED,
)


class WebHttpAcquisitionTool:
    """Normalize one gateway-owned read as an Acquisition result."""

    manifest = WEB_HTTP_MANIFEST

    def __init__(
        self,
        transport_factory: Callable[[], Transport],
        *,
        resolver: Callable[[str, int], tuple[str, ...]] | None = None,
    ) -> None:
        self._transport_factory = transport_factory
        self._resolver = resolver
        self._closed = False

    def acquire(
        self, tool_input: AcquisitionInput
    ) -> AcquisitionOutput | AcquisitionFailure:
        """Return governed original bytes or one stable safe failure code."""
        if self._closed:
            return self._failure("gateway.closed")
        transport: Transport | None = None
        gateway: GovernedAccessGateway | None = None
        try:
            transport = self._transport_factory()
            gateway = GovernedAccessGateway(
                tool_input.request,
                transport,
                resolver=self._resolver,
            )
            result = gateway.read(tool_input.target_url)
            redirects = tuple(
                AcquisitionRedirect(
                    from_url=redirect.source_url,
                    to_url=redirect.target_url,
                    status_code=redirect.status_code,
                )
                for redirect in result.evidence.redirects
                if redirect.kind == "target"
            )
            return AcquisitionOutput(
                tool_id=self.manifest.tool_id,
                tool_version=self.manifest.version,
                requested_url=result.requested_url,
                final_url=result.final_url,
                status_code=result.status_code,
                mime_type=result.mime_type,
                body=result.body,
                sha256=result.sha256,
                redirects=redirects,
                runtime_ms=round(result.evidence.usage.elapsed_seconds * 1000),
            )
        except GatewayFailure as exc:
            try:
                return self._failure(exc.code)
            except Exception:  # pylint: disable=broad-exception-caught
                return self._failure("web_http.failure")
        except Exception:  # pylint: disable=broad-exception-caught
            return self._failure("web_http.failure")
        finally:
            if gateway is not None:
                self._close_resource(gateway)
            elif transport is not None:
                self._close_resource(transport)

    def close(self) -> None:
        """Reject future work; each completed attempt already released resources."""
        if self._closed:
            return
        self._closed = True

    @staticmethod
    def _close_resource(resource: GovernedAccessGateway | Transport) -> None:
        try:
            resource.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def _failure(self, code: str) -> AcquisitionFailure:
        return AcquisitionFailure(
            tool_id=self.manifest.tool_id,
            tool_version=self.manifest.version,
            code=code,
        )


__all__ = ["WEB_HTTP_MANIFEST", "WebHttpAcquisitionTool"]
