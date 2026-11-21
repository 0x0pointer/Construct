"""prsec.config.Settings: environment parsing."""
from prsec.config import Settings


def test_empty_values_count_as_unset(monkeypatch, tmp_path):
    """A .env copied from .env.example leaves keys empty; that must mean the default, not a parse error."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("PRSEC_GITHUB_APP_ID=\nPRSEC_WORKER_CONCURRENCY=\nPRSEC_ADMIN_TOKEN=\n")
    monkeypatch.setenv("PRSEC_RECONCILE_INTERVAL_S", "")
    s = Settings()
    assert s.github_app_id is None
    assert s.worker_concurrency == 4
    assert s.reconcile_interval_s == 900


def test_set_values_still_apply(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PRSEC_GITHUB_APP_ID", "123")
    monkeypatch.setenv("PRSEC_WORKER_CONCURRENCY", "2")
    s = Settings()
    assert (s.github_app_id, s.worker_concurrency) == (123, 2)
