from pathlib import Path

import pytest

from coverage_map.parser import parse_markdown_rule_file, parse_markdown_rules_directory


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_happy_path_single_technique(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-001\nname: My Rule\nmitre_technique: T1078.004\nmitre_tactic: Initial Access\n---\n\nBody ignored.")
    rule = parse_markdown_rule_file(p)
    assert rule is not None
    assert rule.techniques == ["T1078.004"]
    assert rule.tactics == ["initial-access"]
    assert rule.title == "My Rule"
    assert rule.rule_id == "CT-001"


def test_multi_technique_comma_split(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-002\nname: Multi\nmitre_technique: T1078.004, T1552.001\nmitre_tactic: Initial Access\n---")
    rule = parse_markdown_rule_file(p)
    assert rule.techniques == ["T1078.004", "T1552.001"]


def test_em_dash_description_strip(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-003\nname: Strip\nmitre_technique: T1552.004 — Unsecured Credentials\n---")
    rule = parse_markdown_rule_file(p)
    assert rule.techniques == ["T1552.004"]


def test_hyphen_dash_description_strip(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-004\nname: Strip2\nmitre_technique: T1552.004 - Unsecured Credentials\n---")
    rule = parse_markdown_rule_file(p)
    assert rule.techniques == ["T1552.004"]


def test_na_skipped(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-005\nname: NA\nmitre_technique: N/A\n---")
    assert parse_markdown_rule_file(p) is None


def test_na_case_insensitive(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-006\nname: NA2\nmitre_technique: n/a\n---")
    assert parse_markdown_rule_file(p) is None


def test_missing_technique_field_skipped(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-007\nname: NoTech\n---")
    assert parse_markdown_rule_file(p) is None


def test_invalid_technique_id_skipped(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-008\nname: Bad\nmitre_technique: TXXX\n---")
    assert parse_markdown_rule_file(p) is None


def test_invalid_mixed_with_valid(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-009\nname: Mixed\nmitre_technique: TXXX, T1078.004\n---")
    rule = parse_markdown_rule_file(p)
    assert rule is not None
    assert rule.techniques == ["T1078.004"]


def test_multi_tactic_slash(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-010\nname: MultiTactic\nmitre_technique: T1078.004\nmitre_tactic: Initial Access / Defense Evasion\n---")
    rule = parse_markdown_rule_file(p)
    assert "initial-access" in rule.tactics
    assert "defense-evasion" in rule.tactics


def test_missing_frontmatter_skipped(tmp_path):
    p = _write(tmp_path, "rule.md", "No frontmatter here at all.")
    assert parse_markdown_rule_file(p) is None


def test_title_fallback_to_id(tmp_path):
    p = _write(tmp_path, "rule.md", "---\nid: CT-011\nmitre_technique: T1078.004\n---")
    rule = parse_markdown_rule_file(p)
    assert rule.title == "CT-011"


def test_title_fallback_to_stem(tmp_path):
    p = _write(tmp_path, "my-detection.md", "---\nmitre_technique: T1078.004\n---")
    rule = parse_markdown_rule_file(p)
    assert rule.title == "my-detection"


def test_directory_parse(tmp_path):
    _write(tmp_path, "a.md", "---\nid: CT-020\nname: A\nmitre_technique: T1078.004\n---")
    _write(tmp_path, "b.md", "---\nid: CT-021\nname: B\nmitre_technique: N/A\n---")
    _write(tmp_path, "c.md", "---\nid: CT-022\nname: C\nmitre_technique: T1059.001\n---")
    rules = parse_markdown_rules_directory(tmp_path)
    assert len(rules) == 2
    ids = {r.rule_id for r in rules}
    assert ids == {"CT-020", "CT-022"}
