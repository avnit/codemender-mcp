# Register ai_security_agent in Gemini Enterprise

Prerequisites:
- The agent is deployed to Vertex AI Agent Engine (`python3 deploy.py`). Note the resource name printed at the end: `projects/PROJECT_NUMBER/locations/us-central1/reasoningEngines/ENGINE_ID`.
- A Gemini Enterprise app exists (Days 1-3). Note its app ID (engine ID) from the app's URL or the Apps list.
- You have `roles/discoveryengine.admin` on the project.
- The Agent Engine service agent `service-<PROJECT_NUMBER>@gcp-sa-aiplatform-re.iam.gserviceaccount.com` has `roles/run.invoker` on `codemender-mcp-server` and `roles/logging.viewer` (done by Terraform).

UI labels below change between releases. Treat every exact label as "confirm in your environment".

## Option A: console
1. Google Cloud console > Gemini Enterprise > Apps > select your app.
2. Open Agents > Add agent.
3. Choose Custom agent via Agent Engine.
4. Fill in:
   - Name: `AI Security Agent`
   - Description: `Investigates Wiz, Cloud Logging, GitHub, CodeMender and BigQuery findings, proposes patches, validates them in a sandbox and opens PRs for human review.`
   - Agent Engine reasoning engine: the resource name from `deploy.py`.
   - Authorization: add the authorization resource from the OAuth section if you use user-delegated tools.
5. Save. Open the Gemini Enterprise web app, pick the agent from the agent list, and ask: "What did CodeMender find in payment-service?"

## Option B: Discovery Engine REST API
```bash
PROJECT_ID=your-gcp-project-id
PROJECT_NUMBER=123456789012
APP_ID=your-gemini-enterprise-app-id
ENGINE=projects/${PROJECT_NUMBER}/locations/us-central1/reasoningEngines/ENGINE_ID

curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT_NUMBER}/locations/global/collections/default_collection/engines/${APP_ID}/assistants/default_assistant/agents" \
  -d '{
    "displayName": "AI Security Agent",
    "description": "Security investigation and remediation agent (Wiz, Cloud Logging, GitHub, CodeMender, BigQuery). Never merges.",
    "adkAgentDefinition": {
      "toolSettings": {
        "toolDescription": "Use for security findings, vulnerabilities, IAM changes, code fixes, sandbox validation and security PRs."
      },
      "provisionedReasoningEngine": {
        "reasoningEngine": "'"${ENGINE}"'"
      }
    }
  }'
```
- Use the `global` location unless your app is in a multi-region (`us` or `eu`); then use that location and the matching endpoint `https://us-discoveryengine.googleapis.com` (confirm in your environment).
- The API version (`v1alpha`) and field names are from current docs; confirm in your environment.
- List agents to verify: `GET .../assistants/default_assistant/agents`.

## OAuth authorization resource (user-delegated tools)
Use this when tools should act as the signed-in user (for example GitHub OAuth instead of a shared PAT, or Google APIs with the user's identity). The lab default uses service credentials (ADC, ID token, PAT), so this section is optional.

1. Create an OAuth 2.0 client (Web application). Redirect URI: `https://vertexaisearch.cloud.google.com/oauth-redirect`.
2. Create the authorization resource:
```bash
AUTH_ID=security-agent-google-auth
curl -X POST \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "Content-Type: application/json" \
  -H "X-Goog-User-Project: ${PROJECT_ID}" \
  "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT_NUMBER}/locations/global/authorizations?authorizationId=${AUTH_ID}" \
  -d '{
    "name": "projects/'"${PROJECT_NUMBER}"'/locations/global/authorizations/'"${AUTH_ID}"'",
    "serverSideOauth2": {
      "clientId": "your-oauth-client-id.apps.googleusercontent.com",
      "clientSecret": "REPLACE_ME",
      "authorizationUri": "https://accounts.google.com/o/oauth2/v2/auth?client_id=your-oauth-client-id.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fvertexaisearch.cloud.google.com%2Foauth-redirect&scope=openid%20email%20profile%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform&include_granted_scopes=true&response_type=code&access_type=offline&prompt=consent",
      "tokenUri": "https://oauth2.googleapis.com/token"
    }
  }'
```
3. Add it to the agent: include `"authorizationConfig": {"toolAuthorizations": ["projects/${PROJECT_NUMBER}/locations/global/authorizations/${AUTH_ID}"]}` in the agent create (or PATCH) body.
4. At runtime Gemini Enterprise asks the user to authorize and passes the access token to the agent in session state under the key `AUTH_ID` (confirm in your environment). Reading that token requires a code change in `toolsets.py`: a header provider that reads `readonly_context.state[AUTH_ID]` instead of ADC.

## Human-in-the-loop in Gemini Enterprise
- `HITL_MODE=native` uses ADK ToolConfirmation. Whether the Gemini Enterprise UI shows an approve/reject card for Agent Engine agents is "confirm in your environment".
- If it does not, deploy with `HITL_MODE=chat`. The agent then shows the proposed action and waits for a message that starts with `confirm`. One confirmation allows one action.
- The GitHub merge, delete and branch-protection tools are blocked in code in both modes.

## Agent Designer (no-code alternative)
Agent Designer in Gemini Enterprise builds agents from a prompt, instructions and connected tools without writing code.

What it can do:
- Write instructions and conversation starters in the UI.
- Use Gemini Enterprise data stores and connectors the app already has, and approved MCP connectors (subject to org policy `discoveryengine.managed.disableCustomMcpServerConnector`).
- Be shared with users of the app quickly; good for read-only Q&A over the same sources.

What it cannot do compared with this agent (confirm in your environment, features change):
- No `before_tool_callback`: you cannot block `merge_pull_request` in code or force confirmation for specific tools; you rely on tool scopes and connector permissions.
- No custom auth logic (Wiz client-credentials exchange, Cloud Run ID tokens per request).
- No version-controlled skills folder, unit tests or CI for the agent's behavior.
- No Agent Engine features such as custom Python dependencies and tracing configuration.

Use Agent Designer for a read-only "ask about findings" assistant. Use this code-based agent when it must take actions (PRs, sandbox runs) under enforced guardrails.
