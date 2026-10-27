from prsec.config import current_skills_version, settings


def test_version_file_wins(tmp_path, monkeypatch):
    (tmp_path / "2026.10.2").mkdir()
    (tmp_path / "2026.10.2" / "VERSION").write_text("2026.10.2-rc1\n")
    (tmp_path / "current").symlink_to("2026.10.2")
    monkeypatch.setattr(settings(), "skills_dir", tmp_path / "current")
    monkeypatch.setattr(settings(), "skills_version", "dev")
    assert current_skills_version() == "2026.10.2-rc1"


def test_symlink_target_and_repoint_without_restart(tmp_path, monkeypatch):
    for v in ("v1", "v2"):
        (tmp_path / v).mkdir()
    cur = tmp_path / "current"
    cur.symlink_to("v1")
    monkeypatch.setattr(settings(), "skills_dir", cur)
    monkeypatch.setattr(settings(), "skills_version", "dev")
    assert current_skills_version() == "v1"
    cur.unlink()
    cur.symlink_to("v2")  # `make skills SKILLS_VERSION=v2`
    assert current_skills_version() == "v2"


def test_falls_back_to_setting(tmp_path, monkeypatch):
    monkeypatch.setattr(settings(), "skills_dir", tmp_path / "plain-dir")
    monkeypatch.setattr(settings(), "skills_version", "env-ver")
    assert current_skills_version() == "env-ver"
