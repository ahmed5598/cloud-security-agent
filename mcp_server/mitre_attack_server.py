import json
import re
import sys
from pathlib import Path

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mitre-attack", host="0.0.0.0", port=8000)

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CLOUD_PLATFORMS = {
    "IaaS",
    "AWS",
    "Azure",
    "GCP",
    "SaaS",
    "Office 365",
    "Google Workspace",
}
PROJECT_DIR = Path(__file__).parent.parent
DATA_FILE = PROJECT_DIR / "data" / "mitre_techniques.json"

_stix_data = None


def _load_stix_bundle() -> dict:
    """Download and cache the Enterprise ATT&CK STIX bundle from GitHub."""
    global _stix_data
    if _stix_data is not None:
        return _stix_data

    resp = requests.get(STIX_URL, timeout=60)
    resp.raise_for_status()
    _stix_data = resp.json()
    return _stix_data


def _extract_attack_id(technique: dict) -> str:
    """Extract the T-number (e.g. T1078.004) from STIX external_references."""
    for ref in technique.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _extract_tactics(technique: dict) -> str:
    """Extract tactic names from kill_chain_phases."""
    phases = technique.get("kill_chain_phases", [])
    tactics = [p["phase_name"].replace("-", " ").title() for p in phases]
    return ", ".join(tactics)


def _extract_detection_keywords(technique: dict) -> str:
    """Extract keywords from the detection field for vector search."""
    detection = technique.get("x_mitre_detection", "")
    if not detection:
        return ""
    # Pull out notable terms: resource names, API calls, services
    words = set()
    for match in re.findall(r"[A-Z][a-zA-Z]+(?:[A-Z][a-zA-Z]+)+", detection):
        words.add(match)
    for match in re.findall(r"[a-z_]+:[A-Za-z*]+", detection):
        words.add(match)
    return ", ".join(sorted(words)[:20]) if words else ""


def _get_cloud_techniques() -> list:
    """Fetch and filter cloud-relevant techniques from the STIX bundle."""
    bundle = _load_stix_bundle()
    techniques = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        platforms = set(obj.get("x_mitre_platforms", []))
        if not platforms & CLOUD_PLATFORMS:
            continue

        attack_id = _extract_attack_id(obj)
        if not attack_id:
            continue

        techniques.append(
            {
                "id": attack_id,
                "name": obj.get("name", ""),
                "tactic": _extract_tactics(obj),
                "platform": ", ".join(sorted(platforms & CLOUD_PLATFORMS)),
                "description": obj.get("description", ""),
                "detection": obj.get("x_mitre_detection", ""),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }
        )

    techniques.sort(key=lambda t: t["id"])
    return techniques


def _transform_for_vectorstore(techniques: list) -> list:
    """Transform STIX techniques into the project's JSON format for ChromaDB."""
    result = []
    for t in techniques:
        desc = t["description"]
        # Truncate very long descriptions for the LLM prompt
        if len(desc) > 500:
            desc = desc[:497] + "..."

        detection_patterns = _extract_detection_keywords(
            {"x_mitre_detection": t.get("detection", "")}
        )

        result.append(
            {
                "id": t["id"],
                "name": t["name"],
                "tactic": t["tactic"],
                "platform": t["platform"],
                "description": desc,
                "cloud_examples": "",
                "detection_patterns": detection_patterns,
            }
        )
    return result


@mcp.tool()
def fetch_cloud_techniques() -> str:
    """Fetch all cloud-relevant MITRE ATT&CK techniques from the official STIX data. Returns a summary of available techniques."""
    techniques = _get_cloud_techniques()
    summary_lines = [f"Found {len(techniques)} cloud-relevant techniques:\n"]
    for t in techniques:
        summary_lines.append(f"  {t['id']} - {t['name']} [{t['platform']}]")
    return "\n".join(summary_lines)


@mcp.tool()
def get_technique(technique_id: str) -> str:
    """Get full details of a MITRE ATT&CK cloud technique by its ID (e.g. T1078.004).
    Only returns techniques tagged for cloud platforms — non-cloud techniques are
    intentionally excluded."""
    print(
        f"[MCP] get_technique called with: {technique_id!r}",
        file=sys.stderr,
        flush=True,
    )
    techniques = _get_cloud_techniques()
    for t in techniques:
        if t["id"] == technique_id:
            return json.dumps(t, indent=2)
    return (
        f"Technique {technique_id} not found in the cloud technique set. "
        f"This project only handles cloud-tagged techniques."
    )


@mcp.tool()
def search_techniques(query: str) -> str:
    """Search cloud MITRE ATT&CK techniques by keyword in name or description."""
    techniques = _get_cloud_techniques()
    query_lower = query.lower()
    matches = [
        t
        for t in techniques
        if query_lower in t["name"].lower() or query_lower in t["description"].lower()
    ]
    if not matches:
        return f"No cloud techniques found matching '{query}'."

    lines = [f"Found {len(matches)} matching techniques:\n"]
    for t in matches:
        lines.append(f"  {t['id']} - {t['name']} [{t['platform']}]")
    return "\n".join(lines)


@mcp.tool()
def retrieve_relevant_techniques(query: str) -> str:
    """Semantic search over the local ChromaDB index for the 5 MITRE ATT&CK
    cloud techniques most relevant to the given query (e.g. a snippet of
    infrastructure code or a description of a misconfiguration)."""
    sys.path.insert(0, str(PROJECT_DIR))
    from agent.vector_store import retrieve_techniques

    results = retrieve_techniques(query, top_k=5)
    if not results:
        return "No relevant techniques found."

    lines = []
    for t in results:
        lines.append(
            f"{t['id']} - {t['name']} [tactic: {t.get('tactic','')}]\n"
            f"  {t.get('description','')}"
        )
    return "\n\n".join(lines)


@mcp.tool()
def sync_to_vectorstore() -> str:
    """Fetch cloud techniques from MITRE ATT&CK and sync them to the project's vector store.

    This updates data/mitre_techniques.json and triggers ChromaDB re-indexing.
    """
    techniques = _get_cloud_techniques()
    transformed = _transform_for_vectorstore(techniques)

    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump({"techniques": transformed}, f, indent=2)

    # Trigger ChromaDB re-index by resetting the cached collection
    try:
        sys.path.insert(0, str(PROJECT_DIR))
        from agent.vector_store import get_collection, _collection
        import agent.vector_store as vs

        vs._collection = None  # Reset cache to force re-index
        collection = get_collection()
        count = collection.count()
        return (
            f"Synced {len(transformed)} techniques to {DATA_FILE}\n"
            f"ChromaDB re-indexed: {count} techniques in vector store."
        )
    except Exception as e:
        return (
            f"Synced {len(transformed)} techniques to {DATA_FILE}\n"
            f"ChromaDB re-index failed (run start.sh to re-index): {e}"
        )


def _auto_sync_on_startup():
    """Auto-sync MITRE ATT&CK data to the vector store on server startup."""
    try:
        result = sync_to_vectorstore()
        print(f"[mitre-attack] Auto-sync complete: {result}", file=sys.stderr)
    except Exception as e:
        print(f"[mitre-attack] Auto-sync failed: {e}", file=sys.stderr)


_auto_sync_on_startup()

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
