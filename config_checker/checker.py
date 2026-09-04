"""CLI entry point: runs all config checks and prints findings as JSON."""
import json
import sys

from config_checker.s3_checks import check_buckets
from config_checker.sg_checks import check_security_groups


def run_all_checks():
    findings = []
    findings.extend(check_buckets())
    findings.extend(check_security_groups())
    return findings


if __name__ == "__main__":
    results = run_all_checks()
    print(json.dumps([f.to_dict() for f in results], indent=2))
    sys.exit(1 if results else 0)