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
from agents.exceptions import MaxTurnsExceeded
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


# Per-request cache to stop the model from looping on the same RAG query.
# Cleared at the start of each analyze_security() call.
_rag_cache: dict[str, str] = {}


@function_tool
def retrieve_relevant_techniques(query: str, top_k: int = 5) -> str:
    """Search the local ChromaDB index for MITRE ATT&CK cloud techniques
    most relevant to a snippet of infrastructure code or a description of
    a misconfiguration."""
    print(f"[RAG] retrieve_relevant_techniques called with: {query!r}", flush=True)

    # If we already answered this exact query, return a short-circuit message
    # that nudges the model to stop calling tools and produce its final answer.
    if query in _rag_cache:
        print("[RAG] DUPLICATE query — returning cached result", flush=True)
        return (
            "You already retrieved these results. DO NOT call this tool again. "
            "Use the techniques below to produce your final JSON answer now.\n\n"
            + _rag_cache[query]
        )

    techniques = retrieve_techniques(query, top_k=top_k)
    if not techniques:
        _rag_cache[query] = "No relevant techniques found."
        return "No relevant techniques found."
    lines = []
    for t in techniques:
        lines.append(
            f"{t['id']} - {t['name']} [{t.get('platform','')}]\n"
            f"  {t.get('description','')}"
        )
    result = "\n\n".join(lines)
    _rag_cache[query] = result
    return result


INSTRUCTIONS = """You are a cloud security analyst. You analyze infrastructure-as-code for security misconfigurations and map them to MITRE ATT&CK techniques.

IMPORTANT: You have a STRICT BUDGET of 5 tool calls total. Do NOT call the same tool with the same arguments more than once.

Steps:
1. Read the code and identify ALL security issues at once.
2. Call retrieve_relevant_techniques ONCE with a combined query covering all issues you found (e.g. "public S3 bucket, overly permissive IAM policy, unencrypted storage").
3. Optionally call get_technique on 1-2 technique IDs from the results to verify.
4. STOP calling tools and output your final JSON answer.

NEVER call retrieve_relevant_techniques more than twice. After your tool calls, you MUST respond with ONLY this JSON (no other text):

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
    """Main entry point for the security agent. Analyzes the given code and returns a formatted report of findings."""
    _rag_cache.clear()
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
        try:
            result = await Runner.run(agent, user_msg, max_turns=6)
        except MaxTurnsExceeded:
            # The model looped without producing a final answer.
            # Return a graceful fallback instead of a 500 error.
            return (
                "[MEDIUM] UNKNOWN - Manual Review Needed\n"
                "  Agent exceeded its turn budget. The code may contain "
                "security issues that require manual review."
            )
        report = _parse_report(str(result.final_output))
        return _format_findings(report.findings)
