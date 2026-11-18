import os

os.environ["DATABASE_URL"] = "sqlite:///./test_projectscore.db"
os.environ["COOKIE_SECURE"] = "false"
os.environ["SCHEDULER_ENABLED"] = "false"
os.environ["EXPOSURE_SOURCE"] = "off"
os.environ["COMPROMISE_FEEDS"] = "off"
os.environ["BREACH_FEED"] = "off"
os.environ["CVE_ENRICHMENT"] = "off"
os.environ["VENDOR_DETECTION"] = "off"
os.environ["ASSET_PROFILES"] = "off"
os.environ["INFOSTEALER_FEED"] = "off"
os.environ["RANSOMWARE_LIVE"] = "off"
os.environ["IMPERSONATION_CHECK"] = "off"
os.environ["BRAND_WATCH"] = "off"
os.environ["CERTIN_FEED"] = "off"
os.environ["INTEGRATIONS"] = "off"
os.environ["ADVISORY_FEEDS"] = "off"

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_network_discovery(monkeypatch):
    from app.collectors import discovery

    monkeypatch.setattr(discovery, "discover_hosts", lambda domain: [])
