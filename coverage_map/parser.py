import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
TACTIC_RE = re.compile(r"attack\.([a-z\-]+)$", re.IGNORECASE)

TACTIC_SLUGS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}


@dataclass
class ParsedRule:
    title: str
    rule_id: str
    techniques: list[str]
    tactics: list[str]
    source_file: Path


def parse_rule_file(path: Path) -> ParsedRule | None:
    try:
        with open(path) as f:
            raw = yaml.safe_load(f)
    except Exception:
        return None

    if not isinstance(raw, dict):
        return None

    tags = raw.get("tags") or []
    techniques = []
    tactics = []

    for tag in tags:
        tech_match = TECHNIQUE_RE.match(tag)
        if tech_match:
            techniques.append(tech_match.group(1).upper())
            continue
        tactic_match = TACTIC_RE.match(tag)
        if tactic_match and tactic_match.group(1).lower() in TACTIC_SLUGS:
            tactics.append(tactic_match.group(1).lower())

    return ParsedRule(
        title=raw.get("title", path.stem),
        rule_id=str(raw.get("id", "")),
        techniques=techniques,
        tactics=tactics,
        source_file=path,
    )


def parse_rules_directory(rules_dir: Path) -> list[ParsedRule]:
    rules = []
    for path in sorted(rules_dir.rglob("*.yml")):
        rule = parse_rule_file(path)
        if rule and rule.techniques:
            rules.append(rule)
    return rules
