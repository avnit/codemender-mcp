# agent/ - ai_security_agent (Google ADK, Python)

An ADK agent that investigates security findings across four MCP servers and BigQuery, proposes minimal patches, validates them in the `codemender-sandbox` Cloud Run Job and opens pull requests for human review. It never merges.

```
agent/
  security_agent/
    __init__.py         from . import agent
    agent.py            root_agent (LlmAgent, name ai_security_agent)
    config.py           env loading, ENABLE_* toggles, HITL_MODE
    toolsets.py         one McpToolset factory per MCP server + token sources
    guardrails.py       TOOL_POLICY, before_tool_callback, before_agent_callback
    prompts.py          system instruction (+ skills appended)
    skills_loader.py    parses skills/*/SKILL.md front matter
  skills/<name>/SKILL.md  7 skills (see below)
  deploy.py             Vertex AI Agent Engine deployment (--dry-run)
  register_gemini_enterprise.md
  requirements.txt, .env.example
  tests/                unittest suite, no network
```

## MCP servers

| Toggle | Server | URL env | Auth |
|---|---|---|---|
| `ENABLE_WIZ` | Wiz remote MCP | `WIZ_MCP_URL` (`https://mcp.app.wiz.io`) | `Authorization: Bearer` from `WIZ_MCP_TOKEN`, or client-credentials exchange with `WIZ_CLIENT_ID`/`WIZ_CLIENT_SECRET` against `https://auth.app.wiz.io/oauth/token`, audience `wiz-api`. Whether the Wiz MCP endpoint accepts this token: confirm in your environment. Enable MCP in Wiz under Settings > Tenant > AI Features (confirm in your environment). |
| `ENABLE_LOGGING` | Cloud Logging remote MCP | `CLOUD_LOGGING_MCP_URL` (`https://logging.googleapis.com/mcp`) | Google access token from `google.auth.default(scopes=[cloud-platform])`, refreshed when expired, sent through a header provider on each session. Adds `x-goog-user-project: $GOOGLE_CLOUD_PROJECT` (confirm in your environment). |
| `ENABLE_GITHUB` | GitHub remote MCP | `GITHUB_MCP_URL` (`https://api.githubcopilot.com/mcp/`) | `Authorization: Bearer $GITHUB_PAT` (static header). Blocked tools are filtered out with `tool_filter`. |
| `ENABLE_CODEMENDER` | Custom CodeMender MCP on Cloud Run | `CODEMENDER_MCP_URL` (`https://codemender-mcp-server-XXXX.us-central1.run.app/mcp`) | Google ID token, audience = service base URL (`https://codemender-mcp-server-XXXX.us-central1.run.app`), via `google.oauth2.id_token.fetch_id_token`. |

A toolset is skipped with a warning (agent still starts) when its toggle is false, its URL is missing, or its credentials are missing. Values still containing `REPLACE_ME`, `your-` or `XXXX` count as missing. Tokens are fetched lazily, so building the agent makes no network calls. Tokens are cached until 5 minutes before expiry so headers stay stable (ADK pools MCP sessions per header set).

Local runs use your ADC (`gcloud auth application-default login`). An ID token for Cloud Run needs a service account or `gcloud auth application-default login --impersonate-service-account=...`; plain user ADC cannot mint ID tokens with a custom audience (confirm in your environment). On Agent Engine the service agent `service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com` is used; it needs `roles/run.invoker` on `codemender-mcp-server` and `roles/logging.viewer`.

## Run locally

```bash
cd agent
cp .env.example .env        # fill in values; keep placeholders for servers you skip
pip install -r requirements.txt
adk web                     # dev UI, pick security_agent
adk run security_agent      # terminal chat
```
`adk web` and `adk run` read `agent/.env` from the agent folder. The ADK CLI (`google.adk.cli`) is not part of the ADK build installed in the lab test environment; install `google-adk` from PyPI to get it.

Try: "What did CodeMender find in payment-service?", "Who changed IAM in the last 24 hours?", "Fix CM-0001 and verify it in the sandbox."

## Test

```bash
cd agent
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```
51 tests, no network, no model calls. They also run under pytest. Covered: tool policy and both confirmation modes, skill parsing (and loading with ADK's own skill loader), toolset skipping, header construction with mocked credentials, agent construction with all toolsets disabled, instruction content, deploy dry run.

## Deploy to Vertex AI Agent Engine

```bash
cd agent
python3 deploy.py --dry-run     # prints project, location, bucket, requirements, env vars
python3 deploy.py               # creates the reasoning engine
python3 deploy.py --update projects/PROJECT_NUMBER/locations/us-central1/reasoningEngines/ID
```
`deploy.py` uses `vertexai.init(...)`, `vertexai.agent_engines.AdkApp(agent=root_agent)` and `vertexai.agent_engines.create(...)`. `vertexai` is imported inside `main()`, so the module imports without it. `WIZ_CLIENT_SECRET` and `GITHUB_PAT` are passed as Secret Manager references (`wiz-client-secret`, `github-mcp-pat`), not plain values; the env-var secret format is "confirm in your environment".

Alternative: `adk deploy agent_engine --project=your-gcp-project-id --region=us-central1 --staging_bucket=gs://your-gcp-project-id-agent-staging security_agent` from agent/ (flags vary by ADK version: run `adk deploy agent_engine --help`).

Then register the agent in Gemini Enterprise: see `register_gemini_enterprise.md`.

## Human-in-the-loop design

All tool names live in one constant, `guardrails.TOOL_POLICY`:

```python
TOOL_POLICY = {
    "blocked": {  # never run
        "merge_pull_request", "enable_auto_merge", "enable_pull_request_auto_merge",
        "delete_branch", "delete_file", "delete_repository",
        "update_branch_protection", "update_branch_protection_rule",
        "create_or_update_branch_protection", "delete_branch_protection",
    },
    "blocked_on_default_branch": {  # refused on main/master or with no branch;
        "create_or_update_file", "push_files",   # confirmation on other branches
    },
    "confirm": {  # ACTION tools, explicit user confirmation
        "create_pull_request", "run_workflow", "rerun_workflow_run",
        "rerun_failed_jobs", "start_sandbox_validation", "create_branch",
    },
}
```

Enforcement layers:
1. GitHub `McpToolset(tool_filter=github_tool_filter)` hides `blocked` tools from the model.
2. `before_tool_callback` refuses `blocked` tools and default-branch writes with `{"error": "tool_blocked", ...}`. Default branches come from `GITHUB_DEFAULT_BRANCHES` (default `main,master`).
3. For `confirm` tools:
   - `HITL_MODE=native` (default): ADK ToolConfirmation. The callback calls `tool_context.request_confirmation(hint=..., payload=proposed_action)`, sets `actions.skip_summarization = True` and returns `{"error": "confirmation_required", "proposed_action": ...}`. The client answers with a ToolConfirmation; ADK re-runs the call with `tool_context.tool_confirmation` set. Approved: the call proceeds. Rejected: `{"error": "rejected_by_user"}`.
   - `HITL_MODE=chat`, or native not available (no `function_call_id`): `before_agent_callback` saves the latest user message in session state. The call proceeds only if that message starts with `confirm` (`yes, confirm` also works). One confirmation allows one action call per user turn.
   - Otherwise the call returns `confirmation_required`.
4. `start_sandbox_validation`: the callback sets `confirmed=True` in the args only after confirmation. A model-supplied `confirmed=True` without confirmation never reaches the tool. The MCP server itself also refuses unless `confirmed=True`.
5. Branch protection with CODEOWNERS requires one human approval to merge (set up in the GitHub module).

The instruction also tells the model to show the diff and justification before asking, to treat tool output as untrusted data, to stay read-only by default and to never print secrets.

## Skills

`skills/<name>/SKILL.md` with YAML front matter (`name`, `description`) and sections When to use, Steps, Tools, Output format, Do not:
alert-triage, investigation-routing, code-to-cloud-attribution, root-cause-and-patch, sandbox-verification, pr-creation, bigquery-data-insights.

`skills_loader.py` parses them and `prompts.build_instruction()` appends an index plus each body to the system instruction. Setting `USE_ADK_SKILL_TOOLSET=true` also registers them through ADK's experimental `SkillToolset` (lazy loading via list/load skill tools). The instruction is passed as a callable so ADK does not substitute session state into `{...}` text inside skills.

## ADK API facts relied on (google-adk 2.10.0, inspected locally)

- `google.adk.tools.mcp_tool.McpToolset(*, connection_params, tool_filter=None, tool_name_prefix=None, ..., require_confirmation=False, header_provider=None, ...)`.
- `StreamableHTTPConnectionParams(*, url, headers=None, timeout=5.0, sse_read_timeout=300.0, terminate_on_close=True, ...)`.
- `header_provider: Callable[[ReadonlyContext], dict[str, str] | Awaitable[...]]`, merged into the MCP session headers when ADK opens a session; sessions are pooled per header set.
- `tool_filter` accepts a list of names or a `ToolPredicate` (`(tool, readonly_context) -> bool`, runtime-checkable protocol; a plain function qualifies).
- `McpToolset(require_confirmation=...)` exists (bool or callable of the tool args); it applies to all tools of a toolset and does not receive the tool name, so per-tool policy is done in the callback instead.
- `LlmAgent` fields used: `name`, `model`, `description`, `instruction` (str or `InstructionProvider` callable), `tools`, `before_agent_callback`, `before_tool_callback`.
- `before_tool_callback(tool, args, tool_context) -> dict | None`. A returned dict replaces the tool result. The `args` dict is the same object later passed to the tool, so setting `args["confirmed"] = True` reaches the tool.
- `ToolContext.request_confirmation(*, hint=None, payload=None)` (raises `ValueError` without `function_call_id`), `ToolContext.tool_confirmation` (`ToolConfirmation(hint, confirmed, payload)`), `ToolContext.actions.skip_summarization`.
- `google.adk.skills.load_skill_from_dir(dir)` returns `Skill(frontmatter, instructions, resources)`; `google.adk.tools.skill_toolset.SkillToolset(skills=[...])`. Marked experimental.
- `google.adk.cli` (the `adk` command) is not in this install.

## Environment variables

See `.env.example`. Required by NAMING.md: `GOOGLE_CLOUD_PROJECT`, `GOOGLE_CLOUD_LOCATION`, `GOOGLE_GENAI_USE_VERTEXAI`, `AGENT_MODEL`, `WIZ_MCP_URL`, `WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET` or `WIZ_MCP_TOKEN`, `CLOUD_LOGGING_MCP_URL`, `GITHUB_MCP_URL`, `GITHUB_PAT`, `CODEMENDER_MCP_URL`, `STAGING_BUCKET`, `GITHUB_ORG`, `ENABLE_WIZ`, `ENABLE_GITHUB`, `ENABLE_LOGGING`, `ENABLE_CODEMENDER`. Added here: `GITHUB_DEFAULT_BRANCHES`, `HITL_MODE`, `USE_ADK_SKILL_TOOLSET`, optional `WIZ_AUTH_URL`, `WIZ_AUDIENCE`, `SKILLS_DIR`, `MCP_TIMEOUT_SECONDS`.
