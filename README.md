# Cloud Security Agent

A FastAPI-based security analysis agent for analyzing code and detecting security vulnerabilities.

## Setup

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd cloud-security-agent
   ```

2. **Create a virtual environment** (optional but recommended)

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   - Copy or create a `.env` file in the root directory with your configuration

### Setup Ollama with Docker

This project uses **Ollama** with the **deepseek-r1:1.5b** model for LLM-based security analysis.

#### Option 1: Using Docker (Recommended)

1. **Install Docker**
   - Download and install [Docker Desktop](https://www.docker.com/products/docker-desktop) for your OS

2. **Run Ollama container**

   ```bash
   docker run -d \
     --name ollama \
     -p 11434:11434 \
     -v ollama:/root/.ollama \
     ollama/ollama
   ```

   > **Note:** If you get a "container name already in use" error, the container may exist but be stopped. Run `docker container ls -a` to see all containers, then either:
   > - Remove it: `docker container rm ollama` (then run the command above again)
   > - Or restart it: `docker container start ollama`

3. **Pull the deepseek-r1:1.5b model**

   ```bash
   docker exec -it ollama ollama pull deepseek-r1:1.5b
   ```

   This will download the model (approximately 1-2 GB depending on the version)

4. **Verify Ollama is running**

   ```bash
   curl http://localhost:11434/api/tags
   ```

#### Option 2: Direct Installation

If you prefer to install Ollama directly without Docker:

1. **Download and install Ollama**
   - Visit [ollama.ai](https://ollama.ai) and download the installer for your OS

2. **Start Ollama**

   ```bash
   ollama serve
   ```

3. **In a new terminal, pull the model**

   ```bash
   ollama pull deepseek-r1:1.5b
   ```

4. **Verify it's working**

   ```bash
   ollama list
   ```

## Running the App

1. **Start the server**

   ```bash
   uvicorn main:app --reload
   ```

   The API will be available at `http://127.0.0.1:8000`

2. **Access the API documentation**
   - Swagger UI: `http://127.0.0.1:8000/docs`
   - ReDoc: `http://127.0.0.1:8000/redoc`

3. **Test the security analyzer**
   - Send a POST request to `/analyze` with your code:

   ```bash
   curl -X POST "http://127.0.0.1:8000/analyze" \
     -H "Content-Type: application/json" \
     -d '{
       "code": "import os; password = os.environ.get(\"PASSWORD\")",
       "filename": "example.py"
     }'
   ```

## MITRE ATT&CK MCP Server

This project includes an MCP (Model Context Protocol) server that connects to the official MITRE ATT&CK STIX data and keeps the security agent's knowledge base up to date.

### How It Works

The MCP server (`mcp_server/mitre_attack_server.py`) fetches cloud-relevant MITRE ATT&CK techniques from GitHub's `mitre/cti` repository and syncs them into the project's ChromaDB vector store.

**Important:** The `data/mitre_techniques.json` file is **auto-populated when Claude Code starts**, not when `start.sh` is executed. Claude Code reads `.mcp.json`, spawns the MCP server, and the server automatically downloads the latest MITRE ATT&CK data, writes it to `data/mitre_techniques.json`, and re-indexes ChromaDB. If you run `start.sh` without Claude Code, the vector store will use whatever data is already in the JSON file.

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `fetch_cloud_techniques()` | Fetch all cloud-relevant techniques from MITRE ATT&CK |
| `get_technique(technique_id)` | Get full details of a technique by ID (e.g. `T1078`) |
| `search_techniques(query)` | Search techniques by keyword |
| `sync_to_vectorstore()` | Manually sync techniques to `mitre_techniques.json` and re-index ChromaDB |

### Setup

1. Install the MCP server dependencies:

   ```bash
   pip install -r mcp_server/requirements.txt
   ```

2. The `.mcp.json` file at the project root registers the server with Claude Code. On next Claude Code startup, the server will launch automatically and sync the MITRE ATT&CK data.

## RAG Pipeline

The security agent uses a RAG (Retrieval-Augmented Generation) pipeline to analyze infrastructure code:

1. **Indexing** -- MITRE ATT&CK techniques are embedded into ChromaDB using the all-MiniLM-L6-v2 model
2. **Retrieval** -- When code is submitted, ChromaDB finds the 5 most semantically similar techniques via cosine similarity
3. **Generation** -- Only those 5 relevant techniques are injected into the LLM prompt, and the model maps findings to MITRE ATT&CK technique IDs

The vector store is persisted at `data/chroma_db/` and re-indexes automatically when the technique count in `data/mitre_techniques.json` changes.

## Project Structure

```
cloud-security-agent/
├── agent/
│   ├── __init__.py
│   ├── security_agent.py      # LLM-based security analysis with RAG
│   ├── rules.py               # Finding dataclass and prompt formatting
│   └── vector_store.py        # ChromaDB vector store for MITRE techniques
├── mcp_server/
│   ├── mitre_attack_server.py # MCP server for MITRE ATT&CK data
│   └── requirements.txt       # MCP server dependencies
├── data/
│   ├── mitre_techniques.json  # MITRE ATT&CK techniques (auto-populated)
│   └── chroma_db/             # ChromaDB persistent storage (gitignored)
├── main.py                    # FastAPI application entry point
├── .mcp.json                  # MCP server registration for Claude Code
└── .env                       # Environment configuration
```

## VS Code Extension

### What This Extension Does

This is a Cloud Security Agent extension that analyzes code for security vulnerabilities. It sends code to a FastAPI backend (running on localhost:8000) and displays security analysis results in VS Code.

### How to Use It

#### 1. Build the Extension

First, compile the TypeScript to JavaScript:

```bash
npm run compile
```

#### 2. Run It in Development Mode

Press F5 or go to Run > Start Debugging to launch the extension in a new VS Code window. This opens an "Extension Development Host" where you can test the extension.

#### 3. Start the Backend Server

The extension requires a FastAPI backend running on <http://localhost:8000>. You need to have this set up separately. The backend should have an `/analyze` endpoint that accepts:

```json
{
  "code": "string",
  "filename": "string"
}
```

#### 4. Use the Command

1. Open a code file in VS Code
2. Open the Command Palette (Cmd+Shift+P)
3. Search for and run "Analyze Cloud Security"
4. The analysis results will appear in a new tab

### How to Add It as a Permanent Extension

Once you're ready to package and install it permanently:

1. **Install the packaging tool**

   ```bash
   npm install -g @vscode/vsce
   ```

2. **Create the extension package**

   ```bash
   vsce package
   ```

   This creates a `.vsix` file.

3. **Install in VS Code**

   Go to Extensions (Cmd+Shift+X), click the three-dot menu, select "Install from VSIX...", and select the `.vsix` file you just created.

   Or install it directly:

   ```bash
   code --install-extension cloud-security-agent-0.0.1.vsix
   ```
