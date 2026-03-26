import json
import re
from typing import List
import requests

from agent.rules import Finding, build_technique_reference
from agent.vector_store import retrieve_techniques

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "deepseek-r1:1.5b"

PROMPT_TEMPLATE = """You are a cloud security analyst specializing in MITRE ATT&CK for Cloud.
Analyze the given infrastructure code for security misconfigurations.

Map each issue to one of these MITRE ATT&CK techniques (retrieved based on relevance to the code):
{technique_ref}

Respond ONLY with JSON in this exact format (no other text):
{{
  "findings": [
    {{
      "technique_id": "T1530",
      "technique_name": "Data from Cloud Storage",
      "severity": "CRITICAL",
      "message": "Description of the issue and how to fix it"
    }}
  ]
}}

If no issues found, respond: {{"findings": []}}

Rules:
- Only report real security issues visible in the code
- severity must be CRITICAL, HIGH, MEDIUM, or LOW
- technique_id must be from the list above
- message must explain the risk AND suggest a fix
"""


def _parse_findings(raw: str) -> List[Finding]:
    # Try direct JSON parse
    try:
        data = json.loads(raw)
        if "findings" in data:
            return [
                Finding(
                    technique_id=f["technique_id"],
                    technique_name=f["technique_name"],
                    severity=f["severity"],
                    message=f["message"],
                )
                for f in data["findings"]
            ]
    except (json.JSONDecodeError, KeyError, TypeError):
        pass

    # Fallback: extract JSON block from LLM response
    match = re.search(r"\{.*\"findings\".*\}", raw, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group())
            return [
                Finding(
                    technique_id=f["technique_id"],
                    technique_name=f["technique_name"],
                    severity=f["severity"],
                    message=f["message"],
                )
                for f in data["findings"]
            ]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # Last resort: return raw text as a single finding
    if raw.strip():
        return [
            Finding(
                technique_id="UNKNOWN",
                technique_name="Manual Review Needed",
                severity="MEDIUM",
                message=raw.strip(),
            )
        ]
    return []


def _format_findings(findings: List[Finding]) -> str:
    if not findings:
        return "No security issues detected."

    lines = []
    for f in findings:
        lines.append(f"[{f.severity}] {f.technique_id} - {f.technique_name}")
        lines.append(f"  {f.message}")
        lines.append("")
    return "\n".join(lines).strip()


def analyze_security(code: str, filename: str) -> str:
    # RAG: retrieve only the most relevant techniques for this code
    techniques = retrieve_techniques(code, top_k=5)
    technique_ref = build_technique_reference(techniques)

    system_prompt = PROMPT_TEMPLATE.format(technique_ref=technique_ref)

    prompt = f"""{system_prompt}

File: {filename}

Code:
{code}
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False,
        },
        timeout=120,
    )
    response.raise_for_status()

    raw = response.json()["response"]
    findings = _parse_findings(raw)
    return _format_findings(findings)
