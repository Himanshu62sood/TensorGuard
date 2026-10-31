from dataclasses import dataclass
from typing import Optional

@dataclass
class Vulnerability:
    file_path: str
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW
    rule_id: str         # e.g., TG-001-PICKLE-RCE
    message: str
    evidence: Optional[str] = None