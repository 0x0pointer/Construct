import logging

import pytest


@pytest.fixture(autouse=True)
def _keep_root_logger():
    """prsec-trace / prsec-debug main() call setup_logging: undo it after each test."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for h in list(root.handlers):
        if h not in handlers:
            root.removeHandler(h)
    root.setLevel(level)
