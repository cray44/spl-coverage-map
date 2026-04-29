# spl-coverage-map

Generates [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) JSON coverage layers from a directory of Sigma rules. Drop the output into Navigator to visualize which techniques you have detections for and where your gaps are.

Pairs with [sigma-to-spl](https://github.com/cray44/sigma-to-spl) — use the same `rules/` directory as input for both.

---

## Usage

**Generate a Navigator layer from a Sigma rule directory:**
```bash
python -m coverage_map generate ../sigma-to-spl/rules/ --output output/coverage.json
```

**Open in ATT&CK Navigator:**
1. Go to [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/)
2. Open Existing Layer → Upload from local
3. Select `output/coverage.json`

**Print a coverage summary to stdout:**
```bash
python -m coverage_map generate ../sigma-to-spl/rules/ --summary
```

Example output:
```
Techniques covered: 3
  T1071.004  Command and Control  dns-tunneling-high-entropy-subdomains
  T1078.004  Persistence          okta-impossible-travel
  T1110.003  Credential Access    password-spray-entra

Tactics with no coverage:
  Discovery, Lateral Movement, Impact, ...
```

---

## Output format

Produces a standard ATT&CK Navigator layer (v4.5). Each covered technique is highlighted green; score reflects the number of rules covering that technique.

---

## Installation

```bash
pip install -r requirements.txt
```

Requires Python 3.10+.
