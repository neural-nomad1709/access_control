"""Packaging — a plain install never depends on AgentLighthouse.

`uv sync` and `uv run` validate every declared source, not only the ones being
installed. A source that points at a sibling checkout therefore makes the
standalone tool depend on that checkout existing and matching, which is how a
package rename inside AgentLighthouse once stopped `uv run ac` from starting.

These tests read pyproject.toml and pin the contract: AgentLighthouse is named
only by the opt-in `lighthouse` extra and `lighthouse-test` group, and is taken
from one released tag rather than from a path outside this repository.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

PYPROJECT = tomllib.loads(
    (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text("utf-8"))
SOURCES = PYPROJECT["tool"]["uv"]["sources"]
LIGHTHOUSE_PACKAGES = (
    "agentlighthouse-core",
    "agentlighthouse-verify",
    "agentlighthouse-governance",
)


def _names_lighthouse(requirements: list[str]) -> list[str]:
    return [r for r in requirements if r.startswith(("agentlighthouse", "al-"))]


@pytest.mark.parametrize("requirements", [
    PYPROJECT["project"]["dependencies"],
    PYPROJECT["project"]["optional-dependencies"]["dev"],
    PYPROJECT["dependency-groups"]["dev"],
], ids=["runtime", "dev-extra", "dev-group"])
def test_the_default_install_names_no_lighthouse_package(requirements) -> None:
    assert _names_lighthouse(requirements) == []


def test_lighthouse_is_reachable_only_through_the_opt_in_extra_and_group() -> None:
    assert PYPROJECT["project"]["optional-dependencies"]["lighthouse"] == [
        "agentlighthouse-core"]
    assert PYPROJECT["dependency-groups"]["lighthouse-test"] == [
        "agentlighthouse-governance"]


def test_every_lighthouse_package_has_a_source() -> None:
    assert sorted(SOURCES) == sorted(LIGHTHOUSE_PACKAGES)


@pytest.mark.parametrize("package", LIGHTHOUSE_PACKAGES)
def test_no_source_points_outside_this_repository(package) -> None:
    source = SOURCES[package]
    assert "path" not in source
    assert source["git"].startswith("https://")
    assert source["tag"]


def test_all_lighthouse_packages_come_from_the_same_release() -> None:
    assert len({SOURCES[p]["tag"] for p in LIGHTHOUSE_PACKAGES}) == 1
