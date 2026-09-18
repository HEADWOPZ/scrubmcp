from __future__ import annotations

from pathlib import Path

from scrubmcp.cli import skills_root


def _frontmatter(text: str) -> dict[str, str]:
    assert text.startswith("---\n")
    body = text.split("---\n", 2)[1]
    data: dict[str, str] = {}
    for line in body.splitlines():
        if ":" in line and not line.startswith(" "):
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip()
    return data


def test_skills_exist_and_are_named() -> None:
    root = skills_root()
    for name in ("pre-cloud-scrub", "footprint-audit"):
        skill = (root / name / "SKILL.md").read_text(encoding="utf-8")
        meta = _frontmatter(skill)
        assert meta["name"] == name
        assert meta["description"]
        assert "MIT" in skill


def test_pre_cloud_scrub_is_local_only() -> None:
    text = (skills_root() / "pre-cloud-scrub" / "SKILL.md").read_text(encoding="utf-8")
    assert "Never uploads" in text
    assert "scrub_text" in text
    assert "remote LLM" in text or "remote / cloud" in text


def test_footprint_audit_is_opt_out_only() -> None:
    text = (skills_root() / "footprint-audit" / "SKILL.md").read_text(encoding="utf-8").lower()
    assert "opt-out" in text or "opt out" in text
    assert "checklist" in text
    assert "no doxxing" in text or "dox" in text
    # Mentions of banned verbs must be prohibitions, not instructions.
    assert "hard bans" in text
    bans = text.split("## allowed outcome", 1)[0]
    assert "scrape people-search" in bans
    assert "build harassment" in bans


def test_repo_root_skills_match_package() -> None:
    packaged = skills_root()
    repo = Path(__file__).resolve().parents[1] / "skills"
    for name in ("pre-cloud-scrub", "footprint-audit"):
        left = (packaged / name / "SKILL.md").read_text(encoding="utf-8")
        right = (repo / name / "SKILL.md").read_text(encoding="utf-8")
        assert left == right
