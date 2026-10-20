---
name: pr-creation
description: Open a pull request with a verified security patch on a security/<finding-id>-<slug> branch, using the repository PR template, after explicit user confirmation. Never merge.
---

## When to use
- The patch has a `PATCH_VERIFIED` sandbox verdict, or the user explicitly accepts opening a PR without one (say so in the PR body).

## Steps
1. Build the branch name: `security/<finding-id>-<slug>`, lowercase, slug of 2-5 words. Examples: `security/cm-0001-parameterize-transaction-query`, `security/cm-0004-update-base-image`.
2. Show the user, in one message: repository, base branch (default branch), new branch name, the full diff, PR title and PR body. Ask them to confirm.
3. After confirmation:
   a. `create_branch` from the base branch at the finding's commit or the current head.
   b. `push_files` (or `create_or_update_file`) to the new branch only. The guardrail refuses writes to `main`/`master` or calls without a branch.
   c. `create_pull_request` with head = new branch, base = default branch, title `fix(security): <short description> (<finding-id>)`.
4. Return the PR URL. Tell the user that CODEOWNERS review and branch protection require one human approval and that a human merges.

## PR body template
Keep these section headings; they match `sample-app/.github/pull_request_template.md`.
```
## Summary
<What changed and why, 2-4 sentences.>

## Linked finding
- CodeMender: <CM-000N>
- Wiz: <wiz-issue-000N or n/a>
- CWE: <CWE-NNN>
- File: <path:line> at <commit_sha>

## Security justification
<Root cause, why the fix removes it, what behavior is unchanged.>

## Sandbox verification
- Run: <run_id> / <execution_name>
- PoC before: <EXPLOITABLE>  PoC after: <NOT_EXPLOITABLE>
- Unit tests: <passed>/<total>
- Verdict: <PATCH_VERIFIED | not run - reason>

## Human review checklist
- [ ] Diff is minimal and limited to the finding
- [ ] Sandbox verdict is PATCH_VERIFIED
- [ ] No secrets, credentials or debug code added
- [ ] Unit tests pass in CI
- [ ] Reviewer from CODEOWNERS approved
```

## Tools
- GitHub MCP: `create_branch`, `push_files`, `create_or_update_file`, `create_pull_request` (all require confirmation), `get_file_contents`, `list_pull_requests`.
- CodeMender MCP: `get_sandbox_result` to fill the verification section.

## Output format
`PR opened: <url> (branch <name> -> <base>). Waiting for human review; the agent will not merge.`

## Do not
- Never merge, enable auto-merge, approve the PR, or delete branches. These tools are blocked.
- Never push to the default branch.
- Do not open more than one PR per finding; check `list_pull_requests` for an existing one first.
- Do not put tokens, logs with secrets, or internal-only URLs in the PR body.
