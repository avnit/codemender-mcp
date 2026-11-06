<!--
AI-generated pull requests must be reviewed and merged by a human.
The security agent may open this PR; it must not approve or merge it.
-->

## Summary

<!-- One or two sentences: what changes and why. -->

## Linked finding

- CodeMender ID: <!-- e.g. CM-0001 -->
- Wiz issue: <!-- e.g. wiz-issue-0001 -->
- Fix branch: <!-- e.g. security/CM-0001-parameterize-sql -->

## Security justification

- Vulnerability: <!-- e.g. SQL injection in get_transactions -->
- CWE: <!-- e.g. CWE-89 -->
- Root cause: <!-- what in the code allowed it -->
- Fix: <!-- what the patch changes -->
- Why it is safe: <!-- why the fix closes the issue and keeps behavior -->
- Residual risk: <!-- what is not covered; follow-ups -->

## Sandbox verification

- run_id: <!-- from sandbox-validate -->
- Verdict: <!-- PATCH_VERIFIED | PATCH_FAILED | POC_NOT_REPRODUCED | ERROR -->
- PoC before: <!-- EXPLOITABLE -->
- PoC after: <!-- NOT_EXPLOITABLE -->
- Unit tests: <!-- passed / total -->

## Human review checklist

- [ ] The linked finding and Wiz issue match this change.
- [ ] I read the full diff; it changes only what the fix needs.
- [ ] The sandbox verdict is PATCH_VERIFIED for the commit this PR is based on.
- [ ] Unit tests pass in CI.
- [ ] No secrets, credentials, or new external network calls were added.
- [ ] No new dependencies, or each new dependency is justified.
- [ ] A human (not the agent) will approve and merge this PR.
