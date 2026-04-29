from pathlib import Path

from coverage_map.parser import parse_rules_directory
from coverage_map.navigator import build_layer, render_summary

SIGMA_TO_SPL_RULES = Path(__file__).parent.parent.parent / "sigma-to-spl" / "rules"


def _get_rules_dir() -> Path:
    if SIGMA_TO_SPL_RULES.exists():
        return SIGMA_TO_SPL_RULES
    return Path(__file__).parent / "fixtures"


def test_parse_finds_techniques():
    rules_dir = _get_rules_dir()
    if not rules_dir.exists():
        return
    rules = parse_rules_directory(rules_dir)
    assert len(rules) > 0
    assert all(r.techniques for r in rules)


def test_layer_structure():
    rules_dir = _get_rules_dir()
    if not rules_dir.exists():
        return
    rules = parse_rules_directory(rules_dir)
    layer = build_layer(rules)

    assert layer["domain"] == "enterprise-attack"
    assert "techniques" in layer
    assert len(layer["techniques"]) > 0
    for t in layer["techniques"]:
        assert t["techniqueID"].startswith("T")
        assert t["score"] >= 1


def test_summary_output():
    rules_dir = _get_rules_dir()
    if not rules_dir.exists():
        return
    rules = parse_rules_directory(rules_dir)
    summary = render_summary(rules)
    assert "Techniques covered" in summary
