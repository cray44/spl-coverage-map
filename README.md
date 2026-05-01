# spl-coverage-map

Generates [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) JSON coverage layers from a directory of Sigma rules or Markdown detection writeups.

The practical use case: you have a library of Sigma rules (or ADS-format writeups with MITRE frontmatter) and want to know at a glance which techniques you're covering, where the gaps are, and which tactics have zero coverage. Drop the JSON output into Navigator and you have a visual coverage map.

Pairs with [sigma-to-spl](https://github.com/cray44/sigma-to-spl) — the same `rules/` directory is the input for both.

---

## Installation

```bash
pip install -r requirements.txt
pip install -e .
```

Requires Python 3.10+.

---

## Usage

**Generate a Navigator layer from a Sigma rule directory:**
```bash
python -m coverage_map generate ../sigma-to-spl/rules/ --output output/coverage.json
```

**Print a coverage summary:**
```bash
python -m coverage_map generate ../sigma-to-spl/rules/ --summary
```

Output:
```
Techniques covered: 12
  T1003.001    LSASS Process Access for Credential Dumping
  T1021.002    SMB Lateral Movement via Admin Share Access
  T1071        Statistical Beaconing via Zeek Connection Log
  T1071.001    TLS C2 via JA4 Fingerprint and Certificate Anomalies
  T1071.004    DNS Tunneling via High-Entropy Subdomains
  T1078.004    AWS IAM Privilege Escalation via Policy Attachment
  T1098.001    Entra ID Service Principal Credential Addition
  T1528        Azure Illicit OAuth Application Consent Grant
  T1558.003    Kerberoasting via RC4 Encryption Downgrade
  T1566.002    OAuth Device Code Phishing
  T1573.002    TLS C2 via JA4 Fingerprint and Certificate Anomalies

Tactics with no coverage:
  defense-evasion
  discovery
  execution
  impact
  reconnaissance
  resource-development
```

**Open in ATT&CK Navigator:**
1. Go to [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
2. Open Existing Layer → Upload from local
3. Select `output/coverage.json`

Covered techniques are highlighted green; score reflects the number of rules covering that technique.

---

## Markdown format (`--format markdown`)

Reads MITRE data from YAML frontmatter in `.md` files instead of Sigma rule `tags:` blocks. Useful for coverage maps derived from detection writeup libraries.

```bash
python -m coverage_map generate detections/ --format markdown --output coverage.json --summary
```

Expected frontmatter fields:

```yaml
---
mitre_technique: T1078.004
mitre_tactic: Initial Access / Defense Evasion
---
```

- `mitre_technique` — single ID, comma-separated list, or `ID — Description` (description stripped automatically)
- `mitre_tactic` — human-readable string, slash- or comma-separated for multiple tactics
- Files with `mitre_technique: N/A` or no `mitre_technique` field are silently skipped

---

## Output format

Standard ATT&CK Navigator layer (v4.9). Each covered technique is highlighted green; score = number of rules covering that technique. Compatible with Navigator's "layer comparison" feature for gap analysis against other team layers.

---

## Architecture

`parser.parse_rules_directory()` walks a Sigma rule directory, extracts `attack.TXXXX` and `attack.<tactic>` tags from each rule's `tags:` list → returns `list[ParsedRule]`.

`navigator.build_layer()` aggregates by technique ID, scores by rule count, returns ATT&CK Navigator 4.9 layer dict. `write_layer()` dumps JSON. `render_summary()` prints the gap analysis.

Both parsers (Sigma and Markdown) feed the same `build_layer()` pipeline.
