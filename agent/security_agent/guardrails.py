"""Human-in-the-loop guardrails.

`before_tool_callback` runs before every tool call:
  1. Tools in TOOL_POLICY["blocked"] are refused.
  2. Tools in TOOL_POLICY["blocked_on_default_branch"] are refused when they
     target a default branch (or no branch), and need confirmation otherwise.
  3. Tools in TOOL_POLICY["confirm"] need explicit user confirmation.

Confirmation order of preference:
  a. ADK native confirmation (HITL_MODE=native, default):
     tool_context.request_confirmation(hint=..., payload=...) pauses the call;
     the client answers with a ToolConfirmation; on resume
     tool_context.tool_confirmation.confirmed tells us the decision.
  b. Chat confirmation (HITL_MODE=chat, or native unavailable): the user's
     latest message, saved in session state by `before_agent_callback`, must
     start with "confirm". One confirmation allows one action call.
  c. Otherwise the call returns
     {"error": "confirmation_required", "proposed_action": {...}}.

For `start_sandbox_validation` the callback sets `confirmed=True` in the tool
arguments only after confirmation was given. ADK passes the same args dict to
the tool after the callback returns None.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

# Single source of truth for tool names. README.md and the system instruction
# quote this constant.
TOOL_POLICY: dict[str, frozenset[str]] = {
    # Never allowed. Merge stays with humans; destructive and admin tools are
    # out of scope for the agent.
    "blocked": frozenset({
        "merge_pull_request",
        "enable_auto_merge",
        "enable_pull_request_auto_merge",
        "delete_branch",
        "delete_file",
        "delete_repository",
        "update_branch_protection",
        "update_branch_protection_rule",
        "create_or_update_branch_protection",
        "delete_branch_protection",
    }),
    # Refused when the target branch is a default branch or is not given.
    # On any other branch they require confirmation.
    "blocked_on_default_branch": frozenset({
        "create_or_update_file",
        "push_files",
    }),
    # ACTION tools: allowed only after explicit user confirmation.
    "confirm": frozenset({
        "create_pull_request",
        "run_workflow",
        "rerun_workflow_run",
        "rerun_failed_jobs",
        "start_sandbox_validation",
        "create_branch",
    }),
}

SANDBOX_TOOL = "start_sandbox_validation"
STATE_LATEST_USER_MESSAGE = "hitl_latest_user_message"
STATE_LATEST_USER_INVOCATION = "hitl_latest_user_invocation"
STATE_CONFIRMATION_USED = "hitl_confirmation_used_invocation"

_CONFIRM_RE = re.compile(r"^\s*(yes[\s,.!]*)?confirm(ed)?\b", re.IGNORECASE)


def default_branches() -> tuple[str, ...]:
  raw = os.environ.get("GITHUB_DEFAULT_BRANCHES", "main,master")
  return tuple(b.strip() for b in raw.split(",") if b.strip())


def hitl_mode() -> str:
  mode = (os.environ.get("HITL_MODE") or "native").strip().lower()
  return mode if mode in ("native", "chat") else "native"


def _base_name(name: str) -> str:
  # Strip a tool_name_prefix separated by "__" or ".". This agent sets no
  # prefixes; this only guards against someone adding one later.
  for sep in ("__", "."):
    if sep in name:
      name = name.rsplit(sep, 1)[-1]
  return name


def github_tool_filter(tool: Any, readonly_context: Any = None) -> bool:
  """McpToolset tool_filter: hide blocked tools from the model entirely."""
  return _base_name(getattr(tool, "name", "")) not in TOOL_POLICY["blocked"]


def _branch_from_args(args: dict[str, Any]) -> str | None:
  for key in ("branch", "ref", "head"):
    value = args.get(key)
    if isinstance(value, str) and value.strip():
      v = value.strip()
      return v[len("refs/heads/"):] if v.startswith("refs/heads/") else v
  return None


def classify(tool_name: str, args: dict[str, Any]) -> tuple[str, str]:
  """Returns (decision, reason). decision is "allow", "block" or "confirm"."""
  name = _base_name(tool_name)
  if name in TOOL_POLICY["blocked"]:
    return "block", f"{name} is blocked: merging, deleting and admin changes are done by humans."
  if name in TOOL_POLICY["blocked_on_default_branch"]:
    branch = _branch_from_args(args)
    if branch is None:
      return "block", f"{name} without an explicit branch could write to the default branch."
    if branch in default_branches():
      return "block", f"{name} targets default branch '{branch}'. Push to a security/<finding-id>-<slug> branch and open a PR."
    return "confirm", f"{name} writes to branch '{branch}'."
  if name in TOOL_POLICY["confirm"]:
    return "confirm", f"{name} is an action tool."
  return "allow", ""


def refusal(tool_name: str, reason: str) -> dict[str, Any]:
  return {
      "error": "tool_blocked",
      "tool": tool_name,
      "reason": reason,
      "message": (
          "This action is not allowed for the agent. A human must do it in"
          " GitHub after review."
      ),
  }


def proposed_action(tool_name: str, args: dict[str, Any], reason: str) -> dict[str, Any]:
  shown = {k: v for k, v in args.items() if k != "confirmed"}
  return {"tool": tool_name, "args": shown, "reason": reason}


def confirmation_required(tool_name: str, args: dict[str, Any], reason: str) -> dict[str, Any]:
  return {
      "error": "confirmation_required",
      "proposed_action": proposed_action(tool_name, args, reason),
      "message": (
          "Show the user the proposed action (diff, justification, target)"
          " and ask them to reply 'confirm'. Do not retry until they do."
      ),
  }


def _state_get(ctx: Any, key: str, default: Any = None) -> Any:
  state = getattr(ctx, "state", None)
  if state is None:
    return default
  try:
    return state.get(key, default)
  except Exception:
    return default


def _state_set(ctx: Any, key: str, value: Any) -> None:
  state = getattr(ctx, "state", None)
  if state is not None:
    state[key] = value


def chat_confirmed(ctx: Any) -> bool:
  """True if the latest user message starts with 'confirm' and is unused."""
  message = _state_get(ctx, STATE_LATEST_USER_MESSAGE) or ""
  invocation = _state_get(ctx, STATE_LATEST_USER_INVOCATION)
  if not _CONFIRM_RE.match(message):
    return False
  if invocation is not None and _state_get(ctx, STATE_CONFIRMATION_USED) == invocation:
    return False  # one confirmation, one action
  _state_set(ctx, STATE_CONFIRMATION_USED, invocation if invocation is not None else "used")
  return True


def _native_confirmation(tool_name: str, args: dict[str, Any], reason: str, ctx: Any):
  """Returns (handled, response). handled=False means native is unavailable."""
  confirmation = getattr(ctx, "tool_confirmation", None)
  if confirmation is not None:
    if getattr(confirmation, "confirmed", False):
      return True, None
    return True, {"error": "rejected_by_user", "tool": tool_name,
                  "message": "The user rejected this action. Do not retry it."}
  request = getattr(ctx, "request_confirmation", None)
  if request is None or not getattr(ctx, "function_call_id", None):
    return False, None
  try:
    request(
        hint=(
            f"Approve {tool_name}? {reason} Review the arguments before"
            " approving."
        ),
        payload=proposed_action(tool_name, args, reason),
    )
  except (ValueError, AttributeError) as exc:
    logger.info("Native confirmation unavailable: %s", exc)
    return False, None
  actions = getattr(ctx, "actions", None)
  if actions is not None:
    try:
      actions.skip_summarization = True  # pause; do not let the model loop
    except Exception:
      pass
  return True, confirmation_required(tool_name, args, reason)


def before_tool_callback(tool: Any, args: dict[str, Any], tool_context: Any):
  """ADK before_tool_callback(tool, args, tool_context) -> dict | None."""
  tool_name = getattr(tool, "name", str(tool))
  decision, reason = classify(tool_name, args)
  if decision == "allow":
    if _base_name(tool_name) == SANDBOX_TOOL:  # unreachable; kept explicit
      return confirmation_required(tool_name, args, reason)
    return None
  if decision == "block":
    logger.warning("Blocked tool call %s: %s", tool_name, reason)
    return refusal(tool_name, reason)

  # decision == "confirm"
  confirmed = False
  if hitl_mode() == "native":
    handled, response = _native_confirmation(tool_name, args, reason, tool_context)
    if handled and response is not None:
      return response
    confirmed = handled  # handled with no response => user approved
  if not confirmed:
    if chat_confirmed(tool_context):
      confirmed = True
    else:
      return confirmation_required(tool_name, args, reason)

  if _base_name(tool_name) == SANDBOX_TOOL:
    args["confirmed"] = True
  elif "confirmed" in args:
    pass
  return None


def before_agent_callback(callback_context: Any):
  """Saves the latest user message in state for chat-mode confirmation."""
  content = getattr(callback_context, "user_content", None)
  text = ""
  if content is not None and getattr(content, "parts", None):
    text = " ".join(
        p.text for p in content.parts if getattr(p, "text", None)
    ).strip()
  _state_set(callback_context, STATE_LATEST_USER_MESSAGE, text)
  _state_set(
      callback_context,
      STATE_LATEST_USER_INVOCATION,
      getattr(callback_context, "invocation_id", None),
  )
  return None
