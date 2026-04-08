#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$PROJECT_DIR/venv"
MODEL="qwen2.5:7b"

# 1. Create virtual environment
echo "==> Checking Python virtual environment..."
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"

# 2. Install dependencies
echo "==> Installing Python dependencies..."
pip install -r "$PROJECT_DIR/requirements.txt"

# 3. Initialize MITRE ATT&CK vector database
echo "==> Initializing MITRE ATT&CK vector database..."
python3 -c "from agent.vector_store import get_collection; c = get_collection(); print(f'    Loaded {c.count()} techniques into ChromaDB')"

# 4. Check Ollama is installed
echo "==> Checking Ollama..."
if ! command -v ollama &>/dev/null; then
  echo "ERROR: Ollama is not installed."
  echo "       Install it with: brew install ollama"
  exit 1
fi

# 5. Start Ollama if it isn't already running
if ! curl -s http://localhost:11434/api/tags &>/dev/null; then
  echo "    Ollama not running — starting it..."
  if command -v brew &>/dev/null && brew services list 2>/dev/null | grep -q "^ollama"; then
    brew services start ollama
  else
    # Fall back to running ollama serve in the background
    nohup ollama serve >/tmp/ollama.log 2>&1 &
  fi

  echo "    Waiting for Ollama to be ready..."
  for i in $(seq 1 20); do
    if curl -s http://localhost:11434/api/tags &>/dev/null; then
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

# 6. Pull the model (must support tool calling for the agent loop)
echo "==> Pulling model '$MODEL' (skipped if already present)..."
ollama pull "$MODEL"

# 7. Start FastAPI server
echo ""
echo "==> Starting FastAPI server at http://127.0.0.1:8000"
echo "    Docs: http://127.0.0.1:8000/docs"
cd "$PROJECT_DIR"
uvicorn main:app --reload --reload-dir "$PROJECT_DIR/agent" --reload-dir "$PROJECT_DIR/data" --reload-include "main.py"
