"""PoC tests: PASS while the exploit works (vulnerable code), FAIL after the fix.

All PoCs are local and benign: a SQLite file built from seed rows and a dummy
text file (data/not_a_secret.txt). No network access, no real secrets.
"""

import tests  # noqa: F401  (puts the app root on sys.path)
