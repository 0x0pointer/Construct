import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_devcontainer_uses_fabro_image_and_starts_test_db():
    config = json.loads((ROOT / ".devcontainer" / "devcontainer.json").read_text())

    assert config["build"]["dockerfile"] == "../.fabro/docker/Dockerfile"
    assert config["build"]["context"] == ".."
    assert "pip install -e '.[dev]'" in config["postCreateCommand"]
    assert config["postStartCommand"] == "start-test-db"
