import os
import types
import unittest
from unittest import mock

import tests  # noqa: F401  (sets sys.path and env)
from security_agent import guardrails as g


class FakeActions:
  skip_summarization = False


class FakeToolContext:
  """Mimics the parts of ADK ToolContext the guardrail uses."""

  def __init__(self, *, function_call_id="fc-1", confirmation=None, native=True):
    self.state = {}
    self.function_call_id = function_call_id
    self.tool_confirmation = confirmation
    self.actions = FakeActions()
    self.requested = []
    if not native:
      self.request_confirmation = None

  def request_confirmation(self, *, hint=None, payload=None):  # noqa: F811
    self.requested.append({"hint": hint, "payload": payload})


def tool(name):
  return types.SimpleNamespace(name=name)


def confirmation(confirmed):
  return types.SimpleNamespace(confirmed=confirmed, hint="", payload=None)


class PolicyTest(unittest.TestCase):

  def test_policy_lists_required_names(self):
    for name in ("merge_pull_request", "enable_auto_merge", "delete_branch",
                 "delete_file", "delete_repository"):
      self.assertIn(name, g.TOOL_POLICY["blocked"])
    for name in ("create_pull_request", "run_workflow", "start_sandbox_validation"):
      self.assertIn(name, g.TOOL_POLICY["confirm"])
    self.assertEqual(g.TOOL_POLICY["blocked_on_default_branch"],
                     frozenset({"create_or_update_file", "push_files"}))

  def test_lists_do_not_overlap(self):
    keys = list(g.TOOL_POLICY)
    for i, a in enumerate(keys):
      for b in keys[i + 1:]:
        self.assertFalse(g.TOOL_POLICY[a] & g.TOOL_POLICY[b], (a, b))

  def test_github_tool_filter(self):
    self.assertFalse(g.github_tool_filter(tool("merge_pull_request")))
    self.assertFalse(g.github_tool_filter(tool("gh__delete_branch")))
    self.assertTrue(g.github_tool_filter(tool("get_file_contents")))
    self.assertTrue(g.github_tool_filter(tool("create_pull_request")))


class BlockTest(unittest.TestCase):

  def test_merge_is_refused(self):
    ctx = FakeToolContext()
    out = g.before_tool_callback(tool("merge_pull_request"), {"pullNumber": 1}, ctx)
    self.assertEqual(out["error"], "tool_blocked")
    self.assertEqual(ctx.requested, [])

  def test_push_to_default_branch_is_refused(self):
    for branch in ("main", "master", "refs/heads/main"):
      out = g.before_tool_callback(tool("push_files"), {"branch": branch}, FakeToolContext())
      self.assertEqual(out["error"], "tool_blocked", branch)

  def test_push_without_branch_is_refused(self):
    out = g.before_tool_callback(tool("create_or_update_file"), {"path": "a"}, FakeToolContext())
    self.assertEqual(out["error"], "tool_blocked")

  def test_read_tools_are_allowed(self):
    for name in ("get_file_contents", "list_codemender_issues", "list_log_entries"):
      self.assertIsNone(g.before_tool_callback(tool(name), {}, FakeToolContext()))


@mock.patch.dict(os.environ, {"HITL_MODE": "native"})
class NativeConfirmationTest(unittest.TestCase):

  def test_first_call_requests_confirmation(self):
    ctx = FakeToolContext()
    args = {"title": "fix", "head": "security/cm-0001-x", "base": "main"}
    out = g.before_tool_callback(tool("create_pull_request"), args, ctx)
    self.assertEqual(out["error"], "confirmation_required")
    self.assertEqual(out["proposed_action"]["tool"], "create_pull_request")
    self.assertEqual(len(ctx.requested), 1)
    self.assertTrue(ctx.actions.skip_summarization)

  def test_approved_call_runs(self):
    ctx = FakeToolContext(confirmation=confirmation(True))
    self.assertIsNone(g.before_tool_callback(tool("run_workflow"), {}, ctx))

  def test_rejected_call_is_stopped(self):
    ctx = FakeToolContext(confirmation=confirmation(False))
    out = g.before_tool_callback(tool("run_workflow"), {}, ctx)
    self.assertEqual(out["error"], "rejected_by_user")

  def test_sandbox_confirmed_only_after_approval(self):
    args = {"repository": "o/payment-service", "commit_sha": "abc",
            "patch_uri": "gs://b/patches/CM-0001/r.diff", "issue_id": "CM-0001",
            "confirmed": True}  # model tried to self-confirm
    out = g.before_tool_callback(tool("start_sandbox_validation"), args, FakeToolContext())
    self.assertEqual(out["error"], "confirmation_required")
    self.assertNotIn("confirmed", out["proposed_action"]["args"])

    args2 = dict(args, confirmed=False)
    ctx = FakeToolContext(confirmation=confirmation(True))
    self.assertIsNone(g.before_tool_callback(tool("start_sandbox_validation"), args2, ctx))
    self.assertTrue(args2["confirmed"])

  def test_push_to_feature_branch_needs_confirmation(self):
    out = g.before_tool_callback(
        tool("push_files"), {"branch": "security/cm-0001-fix"}, FakeToolContext())
    self.assertEqual(out["error"], "confirmation_required")

  def test_falls_back_to_chat_when_native_unavailable(self):
    ctx = FakeToolContext(function_call_id=None)
    out = g.before_tool_callback(tool("create_pull_request"), {}, ctx)
    self.assertEqual(out["error"], "confirmation_required")
    ctx.state[g.STATE_LATEST_USER_MESSAGE] = "confirm"
    ctx.state[g.STATE_LATEST_USER_INVOCATION] = "inv-1"
    self.assertIsNone(g.before_tool_callback(tool("create_pull_request"), {}, ctx))


@mock.patch.dict(os.environ, {"HITL_MODE": "chat"})
class ChatConfirmationTest(unittest.TestCase):

  def _ctx(self, message, invocation="inv-1"):
    ctx = FakeToolContext()
    ctx.state[g.STATE_LATEST_USER_MESSAGE] = message
    ctx.state[g.STATE_LATEST_USER_INVOCATION] = invocation
    return ctx

  def test_requires_confirm_message(self):
    out = g.before_tool_callback(tool("create_pull_request"), {}, self._ctx("open a PR"))
    self.assertEqual(out["error"], "confirmation_required")

  def test_confirm_allows_one_action(self):
    ctx = self._ctx("Yes, confirm")
    self.assertIsNone(g.before_tool_callback(tool("create_pull_request"), {}, ctx))
    out = g.before_tool_callback(tool("run_workflow"), {}, ctx)
    self.assertEqual(out["error"], "confirmation_required")
    self.assertEqual(ctx.requested, [])  # native not used in chat mode

  def test_negated_message_is_not_confirmation(self):
    out = g.before_tool_callback(tool("run_workflow"), {}, self._ctx("do not confirm yet"))
    self.assertEqual(out["error"], "confirmation_required")

  def test_sandbox_sets_confirmed_in_chat_mode(self):
    args = {"issue_id": "CM-0002"}
    self.assertIsNone(g.before_tool_callback(
        tool("start_sandbox_validation"), args, self._ctx("confirm")))
    self.assertTrue(args["confirmed"])

  def test_before_agent_callback_saves_user_message(self):
    part = types.SimpleNamespace(text="confirm")
    cb = types.SimpleNamespace(
        user_content=types.SimpleNamespace(parts=[part]),
        invocation_id="inv-9", state={})
    self.assertIsNone(g.before_agent_callback(cb))
    self.assertEqual(cb.state[g.STATE_LATEST_USER_MESSAGE], "confirm")
    self.assertEqual(cb.state[g.STATE_LATEST_USER_INVOCATION], "inv-9")


if __name__ == "__main__":
  unittest.main()
