import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import fakeharness  # noqa: E402,F401  (registers the fake adapters)
