"""Defines `root_agent` for ADK (`adk web`, `adk run security_agent`, Agent Engine)."""

from __future__ import annotations

import logging
from typing import Any

from google.adk.agents import LlmAgent

from . import guardrails
from . import prompts
from . import skills_loader
from . import toolsets
from .config import AGENT_NAME, AgentConfig, load_config

logger = logging.getLogger(__name__)

DESCRIPTION = (
    "Investigates cloud and code security findings across Wiz, Cloud Logging,"
    " GitHub, CodeMender and BigQuery, proposes minimal patches, validates"
    " them in an isolated sandbox and opens pull requests for human review."
)


def _adk_skill_toolset(cfg: AgentConfig):
  """Optional: ADK's experimental SkillToolset (google.adk.tools.skill_toolset)."""
  try:
    from google.adk.skills import load_skill_from_dir
    from google.adk.tools.skill_toolset import SkillToolset
  except ImportError:
    logger.warning("ADK skills support not available; skills stay in the instruction")
    return None
  skills = []
  for path in sorted(cfg.skills_dir.glob("*/SKILL.md")):
    try:
      skills.append(load_skill_from_dir(path.parent))
    except Exception as exc:  # experimental API: never block startup
      logger.warning("ADK could not load skill %s: %s", path.parent.name, exc)
  return SkillToolset(skills=skills) if skills else None


def build_agent(cfg: AgentConfig | None = None) -> LlmAgent:
  cfg = cfg or load_config()
  skills = skills_loader.load_skills(cfg.skills_dir)
  instruction_text = prompts.build_instruction(skills)

  tools: list[Any] = toolsets.build_toolsets(cfg)
  if cfg.use_adk_skill_toolset:
    skill_ts = _adk_skill_toolset(cfg)
    if skill_ts is not None:
      tools.append(skill_ts)

  # A callable instruction (InstructionProvider) is used so ADK does not try
  # to substitute session state into {placeholders} found in skill bodies
  # (SQL, JSON and PR templates contain braces).
  def instruction(_readonly_context: Any = None) -> str:
    return instruction_text

  return LlmAgent(
      name=AGENT_NAME,
      model=cfg.model,
      description=DESCRIPTION,
      instruction=instruction,
      tools=tools,
      before_agent_callback=guardrails.before_agent_callback,
      before_tool_callback=guardrails.before_tool_callback,
  )


def instruction_text(agent: LlmAgent) -> str:
  inst = agent.instruction
  return inst(None) if callable(inst) else str(inst)


root_agent = build_agent()
