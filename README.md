# PerimeterWatch

A modular security toolkit combining cloud config auditing, log parsing, anomaly detection, and vulnerability scanning — with CI/CD-driven security checks and a unified findings dashboard.

## Status
🚧 Under active development

## Architecture
- `config_checker/` — scans cloud configs against security baselines
- `log_parser/` — ingests and parses log files into structured findings
- `anomaly_detector/` — flags unusual patterns from parsed logs
- `vuln_scanner/` — wraps dependency/package vulnerability checks
- `dashboard/` — reads the shared findings store and displays results

All modules emit a common finding schema:
```json
{
  "source": "module_name",
  "severity": "low | medium | high | critical",
  "finding": "description",
  "timestamp": "ISO 8601"
}
```

## Setup
```bash
pip install -r requirements.txt
```

## Running tests
```bash
pytest -v
```

## CI/CD
GitHub Actions runs pytest, bandit, and pip-audit on every push and pull request.