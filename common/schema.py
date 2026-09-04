"""Shared finding schema used across all PerimeterWatch modules."""
from dataclasses import dataclass, asdict
from datetime import datetime, timezone


@dataclass
class Finding:
    source: str        # which module produced this, e.g. "config_checker.s3"
    severity: str       # "low" | "medium" | "high" | "critical"
    finding: str         # human-readable description
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self):
        return asdict(self)