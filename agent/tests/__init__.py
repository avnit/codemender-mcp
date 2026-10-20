"""Tests for ai_security_agent. Run from agent/:

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
"""

import os
import sys

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
  sys.path.insert(0, AGENT_DIR)

# Importing security_agent builds root_agent from the environment. Disable all
# remote toolsets so test imports never depend on local credentials.
for _key in ("ENABLE_WIZ", "ENABLE_LOGGING", "ENABLE_GITHUB", "ENABLE_CODEMENDER"):
  os.environ.setdefault(_key, "false")
