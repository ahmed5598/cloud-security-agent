# Cloud Security Agent

An AI-powered VS Code extension that analyzes code for security vulnerabilities in cloud infrastructure using rule-based detection and LLM-driven insights.

## Features

- **Security Analysis**: Analyzes your code files for cloud infrastructure security risks
- **AI-Powered Insights**: Uses LLM-driven analysis to identify vulnerabilities
- **Quick Feedback**: Get detailed security reports directly in VS Code
- **Easy Integration**: Simple command to analyze any open file

## Requirements

- VS Code 1.108.0 or higher
- A running FastAPI backend server on `http://localhost:8000` with an `/analyze` endpoint

## Usage

1. Open a code file in VS Code
2. Open the Command Palette (`Cmd+Shift+P` on macOS)
3. Search for and run **"Analyze Cloud Security"**
4. View the security analysis results in a new markdown document

## Extension Settings

This extension does not currently contribute any settings.

## Backend Setup

The extension requires a FastAPI backend running on `localhost:8000`. Make sure the backend has a POST endpoint at `/analyze` that accepts:

```json
{
  "code": "string",
  "filename": "string"
}
```

## Known Issues

- Backend server must be running on `localhost:8000` for the extension to work
- Ensure your backend properly handles the analyze endpoint

## Release Notes

### 0.0.1

Initial release of the Cloud Security Agent extension.

---

For more information about VS Code extensions, see the [Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines).
