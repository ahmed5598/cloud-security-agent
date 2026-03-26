import json
import chromadb
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
TECHNIQUES_FILE = DATA_DIR / "mitre_techniques.json"
CHROMA_DIR = DATA_DIR / "chroma_db"
COLLECTION_NAME = "mitre_attack_techniques"

_collection = None


def _load_techniques_json() -> list:
    """Load MITRE ATT&CK techniques from the JSON data file."""
    with open(TECHNIQUES_FILE) as f:
        return json.load(f)["techniques"]


def _build_document_text(technique: dict) -> str:
    """Concatenate technique fields into a single string for embedding."""
    return (
        f"{technique['name']}: {technique['description']} "
        f"Examples: {technique['cloud_examples']} "
        f"Patterns: {technique['detection_patterns']}"
    )


def get_collection() -> chromadb.Collection:
    """Get or create the ChromaDB collection, populating from JSON if needed."""
    global _collection
    if _collection is not None:
        return _collection

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    techniques = _load_techniques_json()

    if collection.count() != len(techniques):
        # Clear and rebuild
        if collection.count() > 0:
            existing_ids = collection.get()["ids"]
            collection.delete(ids=existing_ids)

        documents = []
        metadatas = []
        ids = []
        for t in techniques:
            documents.append(_build_document_text(t))
            metadatas.append({
                "id": t["id"],
                "name": t["name"],
                "tactic": t["tactic"],
                "platform": t.get("platform", ""),
                "description": t["description"],
                "cloud_examples": t["cloud_examples"],
            })
            ids.append(t["id"])

        collection.add(documents=documents, metadatas=metadatas, ids=ids)

    _collection = collection
    return _collection


def retrieve_techniques(code: str, top_k: int = 5) -> list:
    """Semantic search for the top-k most relevant MITRE techniques for the given code."""
    collection = get_collection()
    results = collection.query(query_texts=[code], n_results=top_k)

    techniques = []
    for i in range(len(results["ids"][0])):
        meta = results["metadatas"][0][i]
        techniques.append({
            "id": meta["id"],
            "name": meta["name"],
            "tactic": meta["tactic"],
            "description": meta["description"],
            "cloud_examples": meta["cloud_examples"],
            "distance": results["distances"][0][i] if results.get("distances") else None,
        })
    return techniques
