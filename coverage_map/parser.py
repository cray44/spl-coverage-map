import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

TECHNIQUE_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)", re.IGNORECASE)
TACTIC_RE = re.compile(r"attack\.([a-z_\-]+)$", re.IGNORECASE)
MD_TECHNIQUE_RE = re.compile(r"T\d{4}(\.\d{3})?$")

TACTIC_SLUGS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}

TACTIC_SLUG_MAP = {
    "reconnaissance": "reconnaissance",
    "resource development": "resource-development",
    "initial access": "initial-access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege escalation": "privilege-escalation",
    "defense evasion": "defense-evasion",
    "credential access": "credential-access",
    "discovery": "discovery",
    "lateral movement": "lateral-movement",
    "collection": "collection",
    "command and control": "command-and-control",
    "exfiltration": "exfiltration",
    "impact": "impact",
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
        if tactic_match:
            slug = tactic_match.group(1).lower().replace("_", "-")
            if slug in TACTIC_SLUGS:
                tactics.append(slug)

    return ParsedRule(
        title=raw.get("title", path.stem),
        rule_id=str(raw.get("id", "")),
        techniques=techniques,
        tactics=tactics,
        source_file=path,
    )


def parse_markdown_rule_file(path: Path) -> ParsedRule | None:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return None

    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None

    end = next((i for i, l in enumerate(lines[1:], 1) if l.strip() == "---"), None)
    if end is None:
        return None

    try:
        raw = yaml.safe_load("\n".join(lines[1:end]))
    except Exception:
        return None

    if not isinstance(raw, dict):
        return None

    tech_raw = raw.get("mitre_technique")
    if not tech_raw or str(tech_raw).strip().upper() == "N/A":
        return None

    techniques = []
    for part in str(tech_raw).split(","):
        part = part.strip()
        # strip trailing " — description" or " - description"
        part = re.split(r"\s+[—\-]", part)[0].strip()
        if MD_TECHNIQUE_RE.match(part):
            techniques.append(part)

    if not techniques:
        return None

    tactics = []
    tactic_raw = raw.get("mitre_tactic", "")
    if tactic_raw:
        for part in re.split(r"[/,]", str(tactic_raw)):
            slug = TACTIC_SLUG_MAP.get(part.strip().lower())
            if slug:
                tactics.append(slug)

    title = raw.get("name") or raw.get("id") or path.stem

    return ParsedRule(
        title=str(title),
        rule_id=str(raw.get("id", "")),
        techniques=techniques,
        tactics=tactics,
        source_file=path,
    )


def parse_markdown_rules_directory(rules_dir: Path) -> list[ParsedRule]:
    rules = []
    for path in sorted(rules_dir.rglob("*.md")):
        rule = parse_markdown_rule_file(path)
        if rule:
            rules.append(rule)
    return rules


def parse_rules_directory(rules_dir: Path) -> list[ParsedRule]:
    rules = []
    for path in sorted(rules_dir.rglob("*.yml")):
        rule = parse_rule_file(path)
        if rule and rule.techniques:
            rules.append(rule)
    return rules
