#!/bin/bash
set -e

EXT_DIR="$(cd "$(dirname "$0")" && pwd)/cloud-security-agent"

cd "$EXT_DIR"

# 1. Install dependencies
echo "==> Installing npm dependencies..."
npm install

# 2. Compile TypeScript
echo "==> Compiling extension..."
npm run compile

# 3. Package the extension
echo "==> Packaging .vsix..."
if ! command -v vsce &>/dev/null; then
  echo "    Installing @vscode/vsce..."
  npm install -g @vscode/vsce
fi
vsce package --no-dependencies

# 4. Install into VS Code
VSIX=$(ls -t *.vsix | head -1)
echo "==> Installing $VSIX into VS Code..."
code --install-extension "$VSIX" --force

echo ""
echo "Done. Reload VS Code to use the updated extension."
