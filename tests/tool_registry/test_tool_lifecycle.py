"""Focused tests for local external-tool lifecycle management."""

# pylint: disable=missing-function-docstring,protected-access

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from web_listening.tool_registry import lifecycle as lifecycle_module
from web_listening.tool_registry.lifecycle import ToolLifecycle, ToolLifecycleError
from web_listening.tool_registry.manifest import ToolCategory

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests/fixtures/tools/lifecycle"
TOOL_ID = "external.lifecycle"
TRANSFORM_SOURCE = ROOT / "tests/fixtures/tools/external_transform/1.0.0"


def _source(version: str) -> Path:
    return FIXTURES / version


def _installed_path(root: Path, version: str) -> Path:
    return root / "tools/acquisition" / TOOL_ID / version


def test_install_is_versioned_unqualified_and_restart_safe(tmp_path: Path) -> None:
    lifecycle = ToolLifecycle(tmp_path / "data")

    first = lifecycle.install(_source("1.0.0"))
    second = lifecycle.install(_source("2.0.0"))

    assert first.manifest.version == "1.0.0"
    assert first.installed is True
    assert first.qualified is False
    assert first.active is False
    assert first.disabled is False
    assert first.broken is False
    assert second.manifest.version == "2.0.0"
    assert _installed_path(tmp_path / "data", "1.0.0").is_dir()
    assert _installed_path(tmp_path / "data", "2.0.0").is_dir()
    restarted = ToolLifecycle(tmp_path / "data")
    assert [
        item.manifest.version
        for item in restarted.list_versions(ToolCategory.ACQUISITION, TOOL_ID)
    ] == ["1.0.0", "2.0.0"]
    assert restarted.active(ToolCategory.ACQUISITION, TOOL_ID) is None


def test_invalid_install_is_stable_and_leaves_no_usable_version(tmp_path: Path) -> None:
    lifecycle = ToolLifecycle(tmp_path / "data")

    with pytest.raises(ToolLifecycleError) as caught:
        lifecycle.install(_source("invalid"))

    assert caught.value.code == "lifecycle.manifest_invalid"
    assert not _installed_path(tmp_path / "data", "9.0.0").exists()
    assert not list((tmp_path / "data").rglob(".install-*"))


@pytest.mark.parametrize(
    "case",
    [
        "protocol",
        "source_identity",
        "distribution",
        "capabilities",
        "limits",
        "health",
        "qualification",
    ],
)
def test_install_validates_source_protocol_and_manifest_claims(
    tmp_path: Path, case: str
) -> None:
    source = tmp_path / "source"
    shutil.copytree(_source("1.0.0"), source)
    declaration = json.loads((source / "tool.json").read_text(encoding="utf-8"))
    if case == "protocol":
        declaration["protocol_version"] = "external.v2"
    elif case == "source_identity":
        declaration["source"]["tool_id"] = "external.other"
    elif case == "distribution":
        declaration["manifest"]["distribution"] = "builtin"
    elif case == "capabilities":
        declaration["manifest"]["capabilities"] = []
    elif case == "limits":
        declaration["manifest"]["limits"]["max_output_bytes"] = 0
    elif case == "health":
        declaration["manifest"]["health"] = "unhealthy"
    else:
        declaration["manifest"]["qualification"] = "qualified"
    (source / "tool.json").write_text(json.dumps(declaration), encoding="utf-8")

    with pytest.raises(ToolLifecycleError) as caught:
        ToolLifecycle(tmp_path / "data").install(source)

    assert caught.value.code == "lifecycle.manifest_invalid"


def test_declared_entrypoint_must_be_a_regular_source_file(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(_source("1.0.0"), source)
    (source / "tool.py").unlink()
    (source / "tool.py").mkdir()

    with pytest.raises(ToolLifecycleError) as caught:
        ToolLifecycle(tmp_path / "data").install(source)

    assert caught.value.code == "lifecycle.path_invalid"


@pytest.mark.parametrize(
    "entrypoint", ["../outside.py", "/outside.py", "C:/outside.py"]
)
def test_entrypoint_escape_is_rejected(tmp_path: Path, entrypoint: str) -> None:
    source = tmp_path / "source"
    shutil.copytree(_source("1.0.0"), source)
    declaration = json.loads((source / "tool.json").read_text(encoding="utf-8"))
    declaration["entrypoint"] = entrypoint
    (source / "tool.json").write_text(json.dumps(declaration), encoding="utf-8")

    with pytest.raises(ToolLifecycleError) as caught:
        ToolLifecycle(tmp_path / "data").install(source)

    assert caught.value.code == "lifecycle.path_invalid"


def test_source_inside_data_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "data"
    source = root / "incoming"
    shutil.copytree(_source("1.0.0"), source)

    with pytest.raises(ToolLifecycleError) as caught:
        ToolLifecycle(root).install(source)

    assert caught.value.code == "lifecycle.path_invalid"


def test_source_symlink_is_rejected_when_supported(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(_source("1.0.0"), source)
    try:
        (source / "linked.py").symlink_to(source / "tool.py")
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ToolLifecycleError) as caught:
        ToolLifecycle(tmp_path / "data").install(source)

    assert caught.value.code == "lifecycle.path_invalid"


@pytest.mark.skipif(os.name != "nt", reason="directory junctions are Windows links")
def test_source_directory_junction_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    target = tmp_path / "linked-target"
    shutil.copytree(_source("1.0.0"), source)
    target.mkdir()
    link = source / "linked"
    created = subprocess.run(
        ("cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if created.returncode:
        pytest.skip("directory junction creation is unavailable")

    with pytest.raises(ToolLifecycleError) as caught:
        ToolLifecycle(tmp_path / "data").install(source)

    assert caught.value.code == "lifecycle.path_invalid"


def test_qualification_and_activation_are_distinct_and_restart_safe(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    lifecycle = ToolLifecycle(root)
    lifecycle.install(_source("1.0.0"))

    qualified = lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    assert qualified.qualified is True
    assert qualified.active is False
    activated = lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    assert activated.active is True

    restarted = ToolLifecycle(root)
    current = restarted.active(ToolCategory.ACQUISITION, TOOL_ID)
    assert current is not None
    assert current.manifest.version == "1.0.0"
    assert restarted.inspect(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0").active is True


def test_active_versions_discovers_usable_transforms_without_known_ids(
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    lifecycle = ToolLifecycle(root)
    lifecycle.install(TRANSFORM_SOURCE)
    lifecycle.qualify(ToolCategory.TRANSFORM, "external.basic_html_markdown", "1.0.0")
    lifecycle.activate(ToolCategory.TRANSFORM, "external.basic_html_markdown", "1.0.0")

    descriptions = ToolLifecycle(root).active_versions(ToolCategory.TRANSFORM)

    assert tuple(item.manifest.tool_id for item in descriptions) == (
        "external.basic_html_markdown",
    )
    assert Path(descriptions[0].command[-1]).name == "tool.py"
    assert not lifecycle.active_versions(ToolCategory.DISCOVERY)


def test_active_versions_are_stably_sorted_by_tool_identity(tmp_path: Path) -> None:
    root = tmp_path / "data"
    lifecycle = ToolLifecycle(root)
    for tool_id in ("external.zeta_transform", "external.alpha_transform"):
        source = tmp_path / tool_id
        shutil.copytree(TRANSFORM_SOURCE, source)
        for name in ("tool.json", "tool.py"):
            path = source / name
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "external.basic_html_markdown", tool_id
                ),
                encoding="utf-8",
            )
        lifecycle.install(source)
        lifecycle.qualify(ToolCategory.TRANSFORM, tool_id, "1.0.0")
        lifecycle.activate(ToolCategory.TRANSFORM, tool_id, "1.0.0")

    assert tuple(
        item.manifest.tool_id
        for item in lifecycle.active_versions(ToolCategory.TRANSFORM)
    ) == ("external.alpha_transform", "external.zeta_transform")


def test_active_versions_fails_closed_on_corrupt_transform_tree(tmp_path: Path) -> None:
    root = tmp_path / "data"
    lifecycle = ToolLifecycle(root)
    lifecycle.install(TRANSFORM_SOURCE)
    installed = root / "tools/transform/external.basic_html_markdown/1.0.0/state.json"
    installed.write_text("not-json", encoding="utf-8")

    with pytest.raises(ToolLifecycleError) as caught:
        lifecycle.active_versions(ToolCategory.TRANSFORM)

    assert caught.value.code == "lifecycle.state_invalid"


@pytest.mark.parametrize("link", ("tools", "tools/transform"))
def test_active_versions_rejects_dangling_tree_link(tmp_path: Path, link: str) -> None:
    root = tmp_path / "data"
    root.mkdir()
    path = root / link
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.symlink_to(tmp_path / "missing", target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(ToolLifecycleError) as caught:
        ToolLifecycle(root).active_versions(ToolCategory.TRANSFORM)

    assert caught.value.code == "lifecycle.path_invalid"


def test_restart_rejects_a_dangling_active_pointer_link(tmp_path: Path) -> None:
    root = tmp_path / "data"
    lifecycle = ToolLifecycle(root)
    lifecycle.install(_source("1.0.0"))
    lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    pointer = root / "tools/acquisition" / TOOL_ID / "active.json"
    pointer.unlink()
    target = tmp_path / "pointer-target"
    target.mkdir()
    try:
        pointer.symlink_to(target, target_is_directory=True)
    except OSError:
        created = subprocess.run(
            ("cmd.exe", "/d", "/c", "mklink", "/J", str(pointer), str(target)),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if created.returncode:
            pytest.skip("dangling link creation is unavailable")
    target.rmdir()
    assert pointer.exists() is False

    with pytest.raises(ToolLifecycleError) as caught:
        ToolLifecycle(root).active(ToolCategory.ACQUISITION, TOOL_ID)

    assert caught.value.code == "lifecycle.state_invalid"


def test_broken_health_and_failed_contract_remain_inspectable(
    tmp_path: Path,
) -> None:
    lifecycle = ToolLifecycle(tmp_path / "data")
    lifecycle.install(_source("3.0.0"))
    lifecycle.install(_source("4.0.0"))

    broken = lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, "3.0.0")
    excluded = lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, "4.0.0")

    assert (broken.qualified, broken.broken, broken.failure_code) == (
        False,
        True,
        "lifecycle.health_failed",
    )
    assert (excluded.qualified, excluded.broken, excluded.failure_code) == (
        False,
        False,
        "lifecycle.contract_failed",
    )
    for version in ("3.0.0", "4.0.0"):
        with pytest.raises(ToolLifecycleError) as caught:
            lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, version)
        assert caught.value.code == "lifecycle.not_activatable"


def test_self_report_probe_cannot_qualify_a_broken_category_protocol(
    tmp_path: Path,
) -> None:
    lifecycle = ToolLifecycle(tmp_path / "data")
    lifecycle.install(_source("self-report-only"))

    excluded = lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, "5.0.0")

    assert (excluded.qualified, excluded.broken, excluded.failure_code) == (
        False,
        False,
        "lifecycle.contract_failed",
    )
    with pytest.raises(ToolLifecycleError) as caught:
        lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "5.0.0")
    assert caught.value.code == "lifecycle.not_activatable"


@pytest.mark.parametrize(
    ("fixture", "category", "tool_id"),
    [
        ("1.0.0", ToolCategory.ACQUISITION, "external.lifecycle"),
        ("discovery", ToolCategory.DISCOVERY, "external.discovery"),
        ("transform", ToolCategory.TRANSFORM, "external.transform"),
    ],
)
def test_each_category_must_pass_its_real_external_protocol_vector(
    tmp_path: Path, fixture: str, category: ToolCategory, tool_id: str
) -> None:
    lifecycle = ToolLifecycle(tmp_path / "data")
    lifecycle.install(_source(fixture))

    qualified = lifecycle.qualify(category, tool_id, "1.0.0")
    activated = lifecycle.activate(category, tool_id, "1.0.0")

    assert qualified.qualified is True
    assert qualified.active is False
    assert activated.active is True


def test_failed_upgrade_keeps_old_active(tmp_path: Path) -> None:
    lifecycle = ToolLifecycle(tmp_path / "data")
    lifecycle.install(_source("1.0.0"))
    lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    lifecycle.install(_source("3.0.0"))
    lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, "3.0.0")

    with pytest.raises(ToolLifecycleError):
        lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "3.0.0")

    current = lifecycle.active(ToolCategory.ACQUISITION, TOOL_ID)
    assert current is not None and current.manifest.version == "1.0.0"


def test_activation_commit_failure_preserves_old_pointer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lifecycle = ToolLifecycle(tmp_path / "data")
    for version in ("1.0.0", "2.0.0"):
        lifecycle.install(_source(version))
        lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, version)
    lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    original = lifecycle_module.os.replace

    def fail_active(source: str | Path, target: str | Path) -> None:
        if Path(target).name == "active.json":
            raise OSError("simulated commit failure")
        original(source, target)

    monkeypatch.setattr(lifecycle_module.os, "replace", fail_active)
    with pytest.raises(ToolLifecycleError) as caught:
        lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "2.0.0")

    assert caught.value.code == "lifecycle.state_write_failed"
    current = lifecycle.active(ToolCategory.ACQUISITION, TOOL_ID)
    assert current is not None and current.manifest.version == "1.0.0"


def test_disable_active_version_clears_active_status(tmp_path: Path) -> None:
    lifecycle = ToolLifecycle(tmp_path / "data")
    lifecycle.install(_source("1.0.0"))
    lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")

    disabled = lifecycle.disable(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")

    assert disabled.disabled is True
    assert disabled.active is False
    assert (
        ToolLifecycle(tmp_path / "data").active(ToolCategory.ACQUISITION, TOOL_ID)
        is None
    )
    with pytest.raises(ToolLifecycleError) as caught:
        lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")
    assert caught.value.code == "lifecycle.not_activatable"


def test_explicit_rollback_switches_to_qualified_old_version(tmp_path: Path) -> None:
    root = tmp_path / "data"
    lifecycle = ToolLifecycle(root)
    for version in ("1.0.0", "2.0.0"):
        lifecycle.install(_source(version))
        lifecycle.qualify(ToolCategory.ACQUISITION, TOOL_ID, version)
    lifecycle.activate(ToolCategory.ACQUISITION, TOOL_ID, "2.0.0")

    rolled_back = lifecycle.rollback(ToolCategory.ACQUISITION, TOOL_ID, "1.0.0")

    assert rolled_back.active is True
    assert rolled_back.manifest.version == "1.0.0"
    current = ToolLifecycle(root).active(ToolCategory.ACQUISITION, TOOL_ID)
    assert current is not None and current.manifest.version == "1.0.0"


def test_fixture_and_lifecycle_have_no_network_or_cross_module_authority() -> None:
    sources = [path.read_text(encoding="utf-8") for path in FIXTURES.rglob("*.py")]
    lifecycle_path = ROOT / "src/web_listening/tool_registry/lifecycle.py"
    tree = ast.parse(
        lifecycle_path.read_text(encoding="utf-8"), filename=str(lifecycle_path)
    )
    imports = {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }

    for token in ("socket", "requests", "httpx", "urlopen"):
        assert all(token not in source for source in sources)
    assert imports.isdisjoint(
        {
            "web_listening.result",
            "web_listening.runtime",
            "web_listening.artifact.store",
            "web_listening.site_skill",
            "web_listening.tool_registry.registry",
        }
    )
