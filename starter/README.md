# Starter files

Each file here is a copy of a solution file with a few parts replaced by `TODO(lab-NN)` comments. Each TODO says what to write and which test checks it. Imports, signatures, docstrings, and helpers are kept, so every Python file still imports. The rest of each file is identical to the solution.

If you fall behind on an in-class starter, copy the solution file and move on. Do the take-home starters after the lab.

## At a glance

The lab is 4 hours. Three starters are done in class, all in Module 07 (about 21 of its 45 minutes). The other two are **Optional / take-home**.

| When | Starter | Module step | Time |
|---|---|---|---|
| In class, 1st | `starter/mcp-server/services/security_data_service.py` | 07, Part A, A1 | 8 min |
| In class, 2nd | `starter/agent/skills/code-to-cloud-attribution/SKILL.md` | 07, Part B, B2 | 6 min |
| In class, 3rd | `starter/agent/security_agent/toolsets.py` | 07, Part C, C1 | 7 min |
| Take-home | `starter/log-ingestion/parser.py` | 05 | 15 min |
| Take-home | `starter/mcp-server/server_new_tools.py` | 07, A1 extra | 10 min |

Why two are take-home: Module 05 is deploy-and-verify in class (the facilitator deploys the solution parser), and in Module 07 you use the solution `mcp-server/server.py`, which already registers the new tools.

## File mapping

| Starter file | Solution file | Module | Status |
|---|---|---|---|
| `starter/log-ingestion/parser.py` | `log-ingestion/parser.py` | 05 | Optional / take-home |
| `starter/mcp-server/services/security_data_service.py` | `mcp-server/services/security_data_service.py` | 07 (A1) | In class |
| `starter/mcp-server/server_new_tools.py` | `mcp-server/server.py` (functions `query_security_events`, `trace_code_to_cloud`) | 07 (A1 extra) | Optional / take-home |
| `starter/agent/skills/code-to-cloud-attribution/SKILL.md` | `agent/skills/code-to-cloud-attribution/SKILL.md` | 07 (B2) | In class |
| `starter/agent/security_agent/toolsets.py` | `agent/security_agent/toolsets.py` | 07 (C1) | In class |

## What you write and how to test it

| Starter file | What you write | Tests to run |
|---|---|---|
| `security_data_service.py` | `query_security_events()`, `get_code_to_cloud()` (the BigQuery fallback for `trace_code_to_cloud`) | from `mcp-server/`: `TestSecurityDataService` in `tests/test_new_tools.py` |
| `SKILL.md` | the Steps and Output format sections | no unit test; use the Module 07 step B4 prompt about `wiz-issue-0004` |
| `toolsets.py` | `logging_toolset()`, `github_toolset()` (the Wiz and CodeMender factories are worked examples) | from `agent/`: `SkipTest` and `HeaderTest` in `tests/test_toolsets.py` |
| `parser.py` (take-home) | `classify()`, `build_security_event()` | from `log-ingestion/`: `ClassifyTests`, `SecurityEventTests`, `ParseLogEntryTests` in `tests/test_parser.py` |
| `server_new_tools.py` (take-home) | the two `@mcp.tool()` bodies; then paste them into `server.py` | from `mcp-server/`: `TestServerTools` in `tests/test_new_tools.py` |

Run a component's whole suite from its directory:

```
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Run one class, for example from `log-ingestion/`:

```
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_parser.ClassifyTests -v
```

## Expected failures before you start

These counts come from copying each starter over its solution file in a scratch copy and running that component's test suite.

| Starter | Tests that fail until the TODOs are done |
|---|---|
| `mcp-server/services/security_data_service.py` | 4 of 9 in `TestSecurityDataService`: `test_security_events`, `test_limits_and_days_clamped`, `test_query_errors_become_error_dicts`, `test_code_to_cloud_and_finding_lookup`. The other 5 pass. `TestServerTools` mocks the service, so this file does not affect it. |
| `agent/security_agent/toolsets.py` | 5 of 51: `HeaderTest.test_logging_access_token_and_quota_header`, `HeaderTest.test_github_static_bearer_and_filter`, `SkipTest.test_all_configured_builds_four_toolsets_without_network`, `SkipTest.test_missing_config_skips_cleanly`, `SkipTest.test_toggles_disable_each_toolset`. The two factories return `None` until done. |
| `log-ingestion/parser.py` | 30 of 42: all of `ClassifyTests`, `SecurityEventTests`, `SandboxRunTests`, `FindingTests`, `ParseLogEntryTests`, plus `TruncationTests.test_raw_payload_capped`. `build_sandbox_run()` and `build_finding()` call `classify()`, so their tests fail too. Do `classify()` first. |
| `mcp-server/server_new_tools.py` | Not run directly. Once pasted into `server.py` with TODO bodies: the four `test_trace_code_to_cloud_*` tests and `test_pass_through_tools`. |

## Swap a starter in, and restore the solution

Work in your own clone, not a shared one. From the repo root:

```
# swap in (example: security_data_service.py)
cp starter/mcp-server/services/security_data_service.py \
   mcp-server/services/security_data_service.py
cd mcp-server && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v; cd ..

# restore the solution
git checkout mcp-server/services/security_data_service.py
```

The same pattern works for `toolsets.py`, `SKILL.md`, and `parser.py`: copy the starter over the solution path, test, then `git checkout <path>`.

For `server_new_tools.py`, do not copy it over `server.py`. Fill in the two function bodies, delete the matching functions from `mcp-server/server.py`, paste yours in their place, and run the tests. `git checkout mcp-server/server.py` restores the solution.

Before you redeploy, run `git status` and check that you are deploying the files you intend to.
