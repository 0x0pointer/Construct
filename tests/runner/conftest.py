import sys
from pathlib import Path

SANDBOX_TESTS = Path(__file__).parent.parent / "sandbox"
sys.path.insert(0, str(SANDBOX_TESTS))

import fakeharness  # noqa: E402,F401  (registers the fake adapters)
