import * as vscode from 'vscode';

export async function activate(context: vscode.ExtensionContext) {

  const disposable = vscode.commands.registerCommand(
    'cloudSecurity.analyzeFile',
    async () => {

      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showErrorMessage('No active file');
        return;
      }

      const code = editor.document.getText();
      const filename = editor.document.fileName;

      const fetch = (await import('node-fetch')).default;
      const response = await fetch('http://localhost:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, filename })
      });

      const data = (await response.json()) as { result: string };

      vscode.window.showInformationMessage(
        'Cloud Security Analysis Complete'
      );

      const doc = await vscode.workspace.openTextDocument({
        content: data.result,
        language: 'markdown'
      });

      vscode.window.showTextDocument(doc, { preview: false });
    }
  );

  context.subscriptions.push(disposable);
}
