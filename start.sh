#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$PROJECT_DIR/venv"
MODEL="deepseek-r1:1.5b"

# 1. Create virtual environment
echo "==> Checking Python virtual environment..."
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"

# 2. Install dependencies
echo "==> Installing Python dependencies..."
pip install -q -r "$PROJECT_DIR/requirements.txt"

# 3. Check Docker is available
echo "==> Checking Docker..."
if ! command -v docker &>/dev/null; then
  echo "ERROR: Docker is not installed. Install Docker Desktop from https://www.docker.com/products/docker-desktop"
  exit 1
fi

if ! docker info &>/dev/null; then
  echo "ERROR: Docker is not running. Please start Docker Desktop."
  exit 1
fi

# 4. Start Ollama container
echo "==> Setting up Ollama Docker container..."
if docker container inspect ollama &>/dev/null; then
  if [ "$(docker container inspect -f '{{.State.Running}}' ollama)" != "true" ]; then
    echo "    Restarting existing Ollama container..."
    docker container start ollama
  else
    echo "    Ollama container is already running."
  fi
else
  echo "    Creating Ollama container..."
  docker run -d \
    --name ollama \
    -p 11434:11434 \
    -v ollama:/root/.ollama \
    ollama/ollama
fi

# 5. Wait for Ollama to be ready
echo "==> Waiting for Ollama to be ready..."
for i in $(seq 1 15); do
  if curl -s http://localhost:11434/api/tags &>/dev/null; then
    break
  fi
  sleep 1
  if [ "$i" -eq 15 ]; then
    echo "ERROR: Ollama did not start in time."
    exit 1
  fi
done

# 6. Pull the model
echo "==> Pulling model '$MODEL' (skipped if already present)..."
docker exec -it ollama ollama pull "$MODEL"

# 7. Verify Ollama
echo "==> Verifying Ollama..."
curl -s http://localhost:11434/api/tags

# 8. Start FastAPI server
echo ""
echo "==> Starting FastAPI server at http://127.0.0.1:8000"
echo "    Docs: http://127.0.0.1:8000/docs"
cd "$PROJECT_DIR"
uvicorn main:app --reload
