"""Cloud security analyst agent.

Uses the OpenAI Agents SDK to drive a real model<->tool loop with a local
Ollama model (via LiteLLM). Tools come from two sources:
  1. A local function_tool wrapping the project's ChromaDB retriever.
  2. The mitre-attack MCP server (mcp_server/mitre_attack_server.py),
     auto-discovered via MCPServerStdio.
"""

import json
import os
import re
from typing import List

from pydantic import BaseModel, ValidationError

from agents import Agent, Runner, function_tool
from agents.extensions.models.litellm_model import LitellmModel
from agents.mcp import MCPServerStdio, create_static_tool_filter

from agent.vector_store import retrieve_techniques


# Ollama via LiteLLM. Must be a model that supports tool calling
# (llama3.1, qwen2.5, mistral-nemo, etc — NOT deepseek-r1:1.5b).
MODEL = "ollama_chat/qwen2.5:7b"
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


class FindingModel(BaseModel):
    technique_id: str
    technique_name: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    message: str


class FindingsReport(BaseModel):
    findings: List[FindingModel]


@function_tool
def retrieve_relevant_techniques(query: str, top_k: int = 5) -> str:
    """Search the local ChromaDB index for MITRE ATT&CK cloud techniques
    most relevant to a snippet of infrastructure code or a description of
    a misconfiguration."""
    print(f"[RAG] retrieve_relevant_techniques called with: {query!r}", flush=True)
    techniques = retrieve_techniques(query, top_k=top_k)
    if not techniques:
        return "No relevant techniques found."
    lines = []
    for t in techniques:
        lines.append(
            f"{t['id']} - {t['name']} [{t.get('platform','')}]\n"
            f"  {t.get('description','')}"
        )
    return "\n\n".join(lines)


INSTRUCTIONS = """You are a cloud security analyst specializing in MITRE ATT&CK for Cloud.

You will be given a piece of infrastructure-as-code (Terraform, CloudFormation, etc).
Your job is to find real security misconfigurations and map each one to a MITRE
ATT&CK cloud technique.

You have exactly TWO tools. You MUST use them — do not rely on your own memory
of MITRE ATT&CK technique IDs, as it is unreliable.

1. retrieve_relevant_techniques(query): semantic search over the indexed
   cloud-only MITRE ATT&CK techniques. This is your ONLY way to discover
   candidate techniques. Call it with short natural-language descriptions of
   what you see in the code (e.g. "public S3 bucket", "overly permissive
   IAM policy", "unencrypted EBS volume").

2. get_technique(technique_id): fetch the full official details for a single
   technique by its T-id. Use this to VERIFY a candidate from RAG before
   committing to it as a finding.

Required workflow:
1. Read the code carefully.
2. For each suspicious pattern, call retrieve_relevant_techniques with a
   short query describing the pattern.
3. From the candidates RAG returns, call get_technique on the most likely
   match to verify the description fits.
4. Only report a finding if RAG surfaced the technique AND get_technique
   confirms the mapping. Never invent or recall technique IDs from memory.
5. Each finding must include severity (CRITICAL/HIGH/MEDIUM/LOW), the
   technique id+name (exactly as returned by the tools), and a message
   that explains the risk AND a concrete fix.

When you are completely done investigating, your FINAL message must contain
ONLY a JSON object in this exact shape (no prose, no markdown fences):

{
  "findings": [
    {
      "technique_id": "T1530",
      "technique_name": "Data from Cloud Storage",
      "severity": "HIGH",
      "message": "Description of the issue and how to fix it"
    }
  ]
}

If there are no issues, return {"findings": []}.
"""


def _build_agent(mcp_server: MCPServerStdio) -> Agent:
    # NOTE: output_type is intentionally NOT set. With LiteLLM + Ollama, passing
    # a structured output schema puts llama3.1 into "emit JSON immediately" mode
    # and bypasses the tool-call loop entirely. Instead we ask for JSON in the
    # final message via the prompt and parse it ourselves below.
    return Agent(
        name="CloudSecurityAgent",
        instructions=INSTRUCTIONS,
        model=LitellmModel(model=MODEL, base_url=OLLAMA_BASE_URL),
        tools=[retrieve_relevant_techniques],
        mcp_servers=[mcp_server],
    )


def _parse_report(raw: str) -> FindingsReport:
    """Best-effort parse of the model's final message into a FindingsReport.
    Tries direct JSON first, then a regex fallback to extract a JSON object."""
    try:
        return FindingsReport.model_validate_json(raw)
    except (ValidationError, ValueError):
        pass

    match = re.search(r"\{[\s\S]*\"findings\"[\s\S]*\}", raw)
    if match:
        try:
            return FindingsReport.model_validate(json.loads(match.group()))
        except (ValidationError, ValueError, json.JSONDecodeError):
            pass

    # Last resort: surface the raw text as a single advisory finding so the
    # user sees something rather than a silent empty list.
    return FindingsReport(
        findings=[
            FindingModel(
                technique_id="UNKNOWN",
                technique_name="Manual Review Needed",
                severity="MEDIUM",
                message=raw.strip() or "Model returned no parseable output.",
            )
        ]
    )


def _format_findings(findings: List[FindingModel]) -> str:
    if not findings:
        return "No security issues detected."
    lines = []
    for f in findings:
        lines.append(f"[{f.severity}] {f.technique_id} - {f.technique_name}")
        lines.append(f"  {f.message}")
        lines.append("")
    return "\n".join(lines).strip()


async def analyze_security(code: str, filename: str) -> str:
    async with MCPServerStdio(
        params={
            "command": "python",
            "args": ["mcp_server/mitre_attack_server.py"],
        },
        # Force the agent to use RAG for discovery; MCP is verification only.
        # This is important because the model's internal knowledge of MITRE IDs is very unreliable,
        # and we want to ensure all findings are grounded in the indexed techniques.
        # Also, other mcp tools could interfere with the RAG process if allowed, so we restrict to just get_technique.
        tool_filter=create_static_tool_filter(allowed_tool_names=["get_technique"]),
    ) as mcp_server:
        agent = _build_agent(mcp_server)
        user_msg = f"File: {filename}\n\nCode:\n{code}"
        result = await Runner.run(agent, user_msg)
        report = _parse_report(str(result.final_output))
        return _format_findings(report.findings)
