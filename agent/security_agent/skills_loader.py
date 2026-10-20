"""Loads agent/skills/<name>/SKILL.md files.

Each SKILL.md starts with YAML front matter between '---' lines containing at
least `name` and `description`, followed by a Markdown body.
"""

from __future__ import annotations

import dataclasses
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

EXPECTED_SKILLS = (
    "alert-triage",
    "investigation-routing",
    "code-to-cloud-attribution",
    "root-cause-and-patch",
    "sandbox-verification",
    "pr-creation",
    "bigquery-data-insights",
)


class SkillParseError(ValueError):
  pass


@dataclasses.dataclass(frozen=True)
class SkillDoc:
  name: str
  description: str
  body: str
  path: Path


def parse_skill_text(text: str, path: Path | None = None) -> SkillDoc:
  where = str(path) if path else "<text>"
  lines = text.lstrip("\ufeff").splitlines()
  if not lines or lines[0].strip() != "---":
    raise SkillParseError(f"{where}: missing front matter start '---'")
  try:
    end = next(i for i in range(1, len(lines)) if lines[i].strip() == "---")
  except StopIteration as exc:
    raise SkillParseError(f"{where}: missing front matter end '---'") from exc
  meta = yaml.safe_load("\n".join(lines[1:end])) or {}
  if not isinstance(meta, dict):
    raise SkillParseError(f"{where}: front matter is not a mapping")
  name = str(meta.get("name") or "").strip()
  description = " ".join(str(meta.get("description") or "").split())
  if not name or not description:
    raise SkillParseError(f"{where}: front matter needs name and description")
  body = "\n".join(lines[end + 1:]).strip()
  return SkillDoc(name=name, description=description, body=body,
                  path=path or Path(where))


def load_skill_file(path: Path) -> SkillDoc:
  doc = parse_skill_text(path.read_text(encoding="utf-8"), path)
  if doc.name != path.parent.name:
    raise SkillParseError(
        f"{path}: name '{doc.name}' does not match folder '{path.parent.name}'"
    )
  return doc


def load_skills(skills_dir: Path) -> list[SkillDoc]:
  """Loads every skills_dir/*/SKILL.md, sorted by folder name.

  A malformed skill is logged and skipped; the agent still starts.
  """
  skills_dir = Path(skills_dir)
  if not skills_dir.is_dir():
    logger.warning("Skills directory not found: %s", skills_dir)
    return []
  docs = []
  for path in sorted(skills_dir.glob("*/SKILL.md")):
    try:
      docs.append(load_skill_file(path))
    except (SkillParseError, OSError, yaml.YAMLError) as exc:
      logger.warning("Skipping skill %s: %s", path, exc)
  return docs
