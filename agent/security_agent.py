# import ollama

# def analyze_security(code: str, filename: str) -> str:
#     prompt = f"""
# You are a cloud security engineer.
# Analyze the given infrastructure code.
# Identify security risks, explain impact, and suggest fixes.
# Be concise and actionable.

# File: {filename}

# {code}
# """

#     response = ollama.generate(
#         model="deepseek-r1:1.5b",
#         prompt=prompt
#     )

#     return response["response"]


from typing import List
from agent.rules import run_rules, Finding
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "deepseek-r1:1.5b"

SYSTEM_PROMPT = """
You are a cloud security engineer.
You will be given infrastructure code and rule-based findings.
Explain why each finding matters and how to fix it.
"""

def analyze_security(code: str, filename: str) -> str:
    # 1️⃣ Run deterministic rules
    findings: List[Finding] = run_rules(code)

    if not findings:
        return "✅ No obvious security issues found by static rules."

    # 2️⃣ Prepare findings for the LLM
    findings_text = "\n".join(
        f"- [{f.severity}] {f.rule_id}: {f.message}"
        for f in findings
    )

    prompt = f"""
File: {filename}

Detected findings:
{findings_text}

Code:
{code}

Explain each finding and suggest remediations.
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=60
    )

    response.raise_for_status()
    return response.json()["response"]
