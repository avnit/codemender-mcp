"""CodeMender MCP server.

Exposes CodeMender `find`, `validate` (cm verify) and `fix` as MCP tools. Each
tool call stages the repository snapshot in Cloud Storage and launches a new
Cloud Run Job execution of the sandboxed `cm-runner` image. Results (findings,
verification verdicts, patches) are written to BigQuery, and fixes can be
pushed back to the repository as a branch / pull request.
"""

__version__ = "0.1.0"
