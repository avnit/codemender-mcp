## Summary

<!-- What does this change fix and how? One or two sentences. -->

## CodeMender issue

- Issue ID: <!-- e.g. CM-0001 -->
- CWE: <!-- e.g. CWE-89 -->
- Wiz issue ID (if any): <!-- e.g. wiz-issue-0001 -->
- Opened by: <!-- human / AI agent (name the agent) -->

## Sandbox validation

- `sandbox-validate` run: <!-- link to the workflow run -->
- run_id: <!-- from the job summary -->
- Verdict: <!-- PATCH_VERIFIED | PATCH_FAILED | POC_NOT_REPRODUCED | ERROR -->
- PoC before / after: <!-- EXPLOITABLE / NOT_EXPLOITABLE -->
- Unit tests: <!-- passed / failed (tests_total, tests_failed) -->

## Reviewer checklist

- [ ] The change fixes the root cause, not only the PoC input.
- [ ] `sandbox-validate` verdict is `PATCH_VERIFIED` for this branch.
- [ ] Unit tests in `tests/unit/` pass.
- [ ] No secrets, credentials, or real customer data in the diff.
- [ ] If an AI agent opened this PR, a human has read the full diff.

AI agents may open pull requests but must never merge them. Merging requires
one approving review from a code owner (see `.github/CODEOWNERS` and
`docs/branch-protection.md`).
