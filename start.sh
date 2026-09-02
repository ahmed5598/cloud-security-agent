#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$PROJECT_DIR/venv"
PY="$VENV/bin/python"
MODEL="qwen2.5:7b"

# 1. Create virtual environment
echo "==> Checking Python virtual environment..."
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi

# 2. Install dependencies
echo "==> Installing Python dependencies... (skipped — uncomment to enable)"
"$VENV/bin/pip" install -r "$PROJECT_DIR/requirements.txt"

# 3. Check Ollama is installed
echo "==> Checking Ollama..."
if ! command -v ollama &>/dev/null; then
  echo "ERROR: Ollama is not installed."
  echo "       Install it with: brew install ollama"
  exit 1
fi

# 4. Start Ollama if it isn't already running
if ! curl -s --max-time 2 http://localhost:11434/api/tags &>/dev/null; then
  echo "    Ollama not running — starting it..."
  nohup ollama serve >/tmp/ollama.log 2>&1 &

  echo "    Waiting for Ollama to be ready..."
  for i in $(seq 1 20); do
    if curl -s --max-time 2 http://localhost:11434/api/tags &>/dev/null; then
      break
    fi
    sleep 1
    if [ "$i" -eq 20 ]; then
      echo "ERROR: Ollama did not start in time. Check /tmp/ollama.log"
      exit 1
    fi
  done
else
  echo "    Ollama is already running."
fi

# 5. Pull the model only if it isn't already present locally
echo "==> Checking model '$MODEL'..."
if ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Fxq "$MODEL"; then
  echo "    Model already present — skipping pull."
else
  echo "    Model not found locally — pulling (this can take several minutes)..."
  ollama pull "$MODEL"
fi

# 6. Initialize MITRE ATT&CK vector database
# NOTE: chromadb import is heavy (~30s cold). We print before AND after so it
# doesn't look like a hang.
echo "==> Initializing MITRE ATT&CK vector database (importing chromadb is slow, ~30s)..."
"$PY" -u -c "from agent.vector_store import get_collection; c = get_collection(); print(f'    Loaded {c.count()} techniques into ChromaDB')"

# 7. Start FastAPI server
# Only watch source dirs — NOT data/chroma_db, whose sqlite file changes on
# every request and would cause reload loops.
echo ""
echo "==> Starting FastAPI server at http://127.0.0.1:8000"
echo "    Docs: http://127.0.0.1:8000/docs"
cd "$PROJECT_DIR"
exec "$VENV/bin/uvicorn" main:app \
  --host 127.0.0.1 \
  --port 8000 \
  --reload \
  --reload-dir "$PROJECT_DIR/agent" \
  --reload-include "main.py"
