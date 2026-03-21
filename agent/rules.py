from dataclasses import dataclass
from typing import List

@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str

def run_rules(code: str) -> List[Finding]:
    findings = []

    if '"Action": "*"' in code or "Action = \"*\"" in code:
        findings.append(Finding(
            rule_id="IAM_WILDCARD_ACTION",
            severity="HIGH",
            message="IAM policy allows wildcard actions (*)"
        ))

    if "public-read" in code or "acl = \"public\"" in code:
        findings.append(Finding(
            rule_id="S3_PUBLIC_ACCESS",
            severity="CRITICAL",
            message="S3 bucket may be publicly accessible"
        ))

    return findings
