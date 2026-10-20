import unittest
from pathlib import Path
from unittest import mock

import tests  # noqa: F401
from security_agent import skills_loader as sl

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"
REQUIRED_SECTIONS = ("## When to use", "## Steps", "## Tools", "## Output format", "## Do not")


class ParseTest(unittest.TestCase):

  def test_parses_front_matter_and_body(self):
    doc = sl.parse_skill_text("---\nname: demo\ndescription: >\n  Two\n  lines.\n---\n\n## Steps\nDo it.\n")
    self.assertEqual(doc.name, "demo")
    self.assertEqual(doc.description, "Two lines.")
    self.assertEqual(doc.body, "## Steps\nDo it.")

  def test_missing_front_matter(self):
    with self.assertRaises(sl.SkillParseError):
      sl.parse_skill_text("# no front matter\n")

  def test_unterminated_front_matter(self):
    with self.assertRaises(sl.SkillParseError):
      sl.parse_skill_text("---\nname: x\ndescription: y\n")

  def test_missing_description(self):
    with self.assertRaises(sl.SkillParseError):
      sl.parse_skill_text("---\nname: x\n---\nbody")

  def test_bad_skill_is_skipped_not_fatal(self):
    # In-memory file tree (no temp dirs: some sandboxes forbid deleting them).
    files = {
        Path("/skills/bad/SKILL.md"): "no front matter",
        Path("/skills/folder/SKILL.md"): "---\nname: other\ndescription: ok\n---\nb\n",
        Path("/skills/good/SKILL.md"): "---\nname: good\ndescription: ok\n---\nbody\n",
    }

    def fake_read_text(path_self, encoding=None):
      return files[path_self]

    with mock.patch.object(Path, "is_dir", return_value=True), \
         mock.patch.object(Path, "glob", return_value=list(files)), \
         mock.patch.object(Path, "read_text", fake_read_text):
      with self.assertLogs(sl.logger, level="WARNING") as logs:
        docs = sl.load_skills(Path("/skills"))
    self.assertEqual([d.name for d in docs], ["good"])
    self.assertEqual(len(logs.records), 2)

  def test_missing_dir_returns_empty(self):
    with self.assertLogs(sl.logger, level="WARNING"):
      self.assertEqual(sl.load_skills(Path("/nonexistent/skills")), [])


class RepoSkillsTest(unittest.TestCase):

  def test_all_expected_skills_load(self):
    docs = sl.load_skills(SKILLS_DIR)
    self.assertEqual(sorted(d.name for d in docs), sorted(sl.EXPECTED_SKILLS))

  def test_skills_have_required_sections(self):
    for doc in sl.load_skills(SKILLS_DIR):
      for section in REQUIRED_SECTIONS:
        self.assertIn(section, doc.body, f"{doc.name} missing {section}")

  def test_skills_load_with_adk_loader(self):
    try:
      from google.adk.skills import load_skill_from_dir
    except ImportError:
      self.skipTest("google.adk.skills not available")
    for name in sl.EXPECTED_SKILLS:
      skill = load_skill_from_dir(SKILLS_DIR / name)
      self.assertEqual(skill.frontmatter.name, name)

  def test_no_secrets_in_skills(self):
    for path in SKILLS_DIR.glob("*/SKILL.md"):
      text = path.read_text()
      self.assertNotRegex(text, r"ghp_[A-Za-z0-9]{20,}")
      self.assertNotIn("BEGIN PRIVATE KEY", text)


if __name__ == "__main__":
  unittest.main()
