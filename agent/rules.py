from dataclasses import dataclass
from typing import List


@dataclass
class Finding:
    technique_id: str
    technique_name: str
    severity: str
    message: str


def build_technique_reference(techniques: List[dict]) -> str:
    lines = []
    for t in techniques:
        lines.append(f"- {t['id']} ({t['name']}): {t['description']}")
        if t.get("cloud_examples"):
            lines.append(f"  Cloud indicators: {t['cloud_examples']}")
    return "\n".join(lines)
