"""Smoke tests for the Phase 0 package and quality configuration."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import importlib
import importlib.metadata
import tomllib
from pathlib import Path

import web_listening

ROOT = Path(__file__).resolve().parents[1]
PROJECT_CONFIG = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_project_metadata_matches_imported_package() -> None:
    """The installed package and project metadata share one release version."""
    project = PROJECT_CONFIG["project"]

    assert project["name"] == "web-listening"
    assert project["requires-python"] == ">=3.12"
    assert project["dependencies"] == []
    assert importlib.metadata.version("web-listening") == project["version"]
    assert web_listening.__version__ == project["version"]


def test_readme_module_boundaries_are_importable() -> None:
    """README business modules and thin support layers exist as packages."""
    module_names = (
        "request",
        "site_skill",
        "tool_registry",
        "tool_registry.protocols",
        "tool_registry.runners",
        "tool_registry.discovery",
        "tool_registry.discovery.builtins",
        "tool_registry.acquisition",
        "tool_registry.acquisition.builtins",
        "tool_registry.transform",
        "tool_registry.transform.builtins",
        "artifact",
        "result",
        "runtime",
        "interfaces",
    )

    for module_name in module_names:
        assert importlib.import_module(f"web_listening.{module_name}") is not None


def test_quality_tool_configuration_is_minimal_and_consistent() -> None:
    """Only the requested quality tools are configured for development."""
    dev_dependencies = PROJECT_CONFIG["project"]["optional-dependencies"]["dev"]
    dependency_names = {item.split(">=", maxsplit=1)[0] for item in dev_dependencies}

    assert dependency_names == {
        "black",
        "isort",
        "jsonschema[format]",
        "pylint",
        "pytest",
    }
    assert PROJECT_CONFIG["tool"]["isort"]["profile"] == "black"
    assert PROJECT_CONFIG["tool"]["black"]["target-version"] == ["py312"]
    assert PROJECT_CONFIG["tool"]["pytest"]["ini_options"]["markers"] == [
        "live: opt-in tests that access external runtimes or networks"
    ]
    assert PROJECT_CONFIG["tool"]["pytest"]["ini_options"]["addopts"] == [
        "-m",
        "not live",
    ]


def test_server_entrypoint_is_packaged_in_rest_extra() -> None:
    assert PROJECT_CONFIG["project"]["scripts"]["web-listening-server"] == (
        "web_listening.interfaces.server:main"
    )
    assert any(
        dependency.startswith("uvicorn>=")
        for dependency in PROJECT_CONFIG["project"]["optional-dependencies"]["rest"]
    )
