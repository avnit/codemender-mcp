import json
import unittest

import tests  # noqa: F401
from security_agent import agent as agent_module
from security_agent import guardrails
from security_agent.config import load_config
from security_agent.skills_loader import EXPECTED_SKILLS

ALL_OFF = {"ENABLE_WIZ": "false", "ENABLE_LOGGING": "false",
           "ENABLE_GITHUB": "false", "ENABLE_CODEMENDER": "false"}


class AgentTest(unittest.TestCase):

  def setUp(self):
    self.agent = agent_module.build_agent(load_config(ALL_OFF))
    self.text = agent_module.instruction_text(self.agent)

  def test_builds_with_all_toolsets_disabled(self):
    self.assertEqual(self.agent.name, "ai_security_agent")
    self.assertEqual(self.agent.tools, [])
    self.assertEqual(self.agent.model, "gemini-2.5-flash")

  def test_callbacks_wired(self):
    self.assertIs(self.agent.before_tool_callback, guardrails.before_tool_callback)
    self.assertIs(self.agent.before_agent_callback, guardrails.before_agent_callback)

  def test_module_root_agent_exists(self):
    self.assertEqual(agent_module.root_agent.name, "ai_security_agent")

  def test_instruction_contains_hitl_rules(self):
    for phrase in ("Never merge", "never push to the default", "Ask before any action",
                   "untrusted data", "Read-only by default", "Never print secrets",
                   "confirmation_required"):
      self.assertIn(phrase, self.text)

  def test_instruction_quotes_tool_policy(self):
    for names in guardrails.TOOL_POLICY.values():
      for name in names:
        self.assertIn(name, self.text)

  def test_instruction_contains_every_skill(self):
    for name in EXPECTED_SKILLS:
      self.assertIn(f"- {name}:", self.text)
      self.assertIn(f"### Skill: {name}", self.text)

  def test_instruction_is_provider_so_braces_are_safe(self):
    # Skill bodies contain {placeholders}; a callable instruction stops ADK
    # from substituting session state into them.
    self.assertTrue(callable(self.agent.instruction))
    self.assertEqual(self.agent.instruction(None), self.text)

  def test_model_override(self):
    a = agent_module.build_agent(load_config(dict(ALL_OFF, AGENT_MODEL="gemini-2.5-pro")))
    self.assertEqual(a.model, "gemini-2.5-pro")

  def test_adk_skill_toolset_optional(self):
    a = agent_module.build_agent(load_config(dict(ALL_OFF, USE_ADK_SKILL_TOOLSET="true")))
    names = [type(t).__name__ for t in a.tools]
    self.assertLessEqual(len(names), 1)
    if names:
      self.assertEqual(names, ["SkillToolset"])


class DeployDryRunTest(unittest.TestCase):

  def test_build_config_has_no_plain_secrets(self):
    import deploy
    cfg = deploy.build_config({"GOOGLE_CLOUD_PROJECT": "p", "GITHUB_PAT": "secret-pat",
                               "WIZ_CLIENT_SECRET": "s", "AGENT_MODEL": "m"})
    dumped = json.dumps(cfg)
    self.assertNotIn("secret-pat", dumped)
    self.assertEqual(cfg["env_vars"]["GITHUB_PAT"], {"secret": "github-mcp-pat", "version": "latest"})
    self.assertEqual(cfg["env_vars"]["AGENT_MODEL"], "m")
    self.assertIn("security_agent", cfg["extra_packages"])

  def test_dry_run_prints_and_does_not_import_vertexai(self):
    import contextlib
    import io
    import sys
    import deploy
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
      rc = deploy.main(["--dry-run", "--env-file", "/nonexistent/.env"])
    self.assertEqual(rc, 0)
    self.assertEqual(json.loads(buf.getvalue())["display_name"], "ai_security_agent")
    self.assertNotIn("vertexai", sys.modules)


if __name__ == "__main__":
  unittest.main()
