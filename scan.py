"""Run the security agent against files from the command line.

Used by the CI pipeline to scan IaC files and print the agent's findings.
Also appends the report to the GitHub Actions step summary when available.
"""

import asyncio
import os
import sys
from pathlib import Path

from agent.security_agent import analyze_security


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: python scan.py <file> [<file> ...]", file=sys.stderr)
        raise SystemExit(2)

    for path_str in sys.argv[1:]:
        path = Path(path_str)
        code = path.read_text()

        print(f"=== Scanning {path} ===", flush=True)
        report = asyncio.run(analyze_security(code, path.name))
        print(report, flush=True)

        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a") as f:
                f.write(f"## Security scan: `{path}`\n\n```text\n{report}\n```\n\n")


if __name__ == "__main__":
    main()
