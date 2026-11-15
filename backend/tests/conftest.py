import os

os.environ["DATABASE_URL"] = "sqlite:///./test_projectscore.db"
os.environ["COOKIE_SECURE"] = "false"
os.environ["SCHEDULER_ENABLED"] = "false"

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_network_discovery(monkeypatch):
    from app.collectors import discovery

    monkeypatch.setattr(discovery, "discover_hosts", lambda domain: [])
