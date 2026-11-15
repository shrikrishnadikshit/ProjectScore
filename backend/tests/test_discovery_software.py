from app import db
from app.collectors import discovery, software
from app.models import Entity
from app.scan import discover_assets, hosts_for


def codes(findings):
    return {f.code for f in findings}


def test_parse_ct_names_keeps_only_own_subdomains():
    records = [
        {"name_value": "*.shop.acme.example\nacme.example"},
        {"name_value": "api.acme.example"},
        {"name_value": "acme.example.attacker.example"},
        {"name_value": "notacme.example"},
        {"name_value": "bad_name.acme.example"},
        {"name_value": "API.ACME.EXAMPLE."},
    ]
    assert discovery.parse_ct_names("acme.example", records) == {"shop.acme.example", "acme.example", "api.acme.example"}


def test_prioritise_orders_and_limits():
    names = {"a.b.acme.example", "www.acme.example", "mail.acme.example", "acme.example", "api.acme.example"}
    assert discovery.prioritise("acme.example", names, limit=4) == [
        "acme.example", "www.acme.example", "api.acme.example", "mail.acme.example"]


def test_discovered_assets_are_stored_and_scanned():
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    session = db.SessionLocal()
    entity = Entity(name="Acme", primary_domain="acme.example")
    session.add(entity)
    session.commit()
    discover_assets(session, entity, lambda d: ["api.acme.example", "vpn.acme.example"])
    discover_assets(session, entity, lambda d: ["api.acme.example"])
    session.commit()
    assert sorted(a.value for a in entity.assets) == ["api.acme.example", "vpn.acme.example"]
    assert hosts_for(entity)[:2] == ["acme.example", "www.acme.example"]
    assert "vpn.acme.example" in hosts_for(entity)
    session.close()


def test_software_versions():
    f, has = software.evaluate("h", {"Server": "Apache/2.4.49 (Unix)"})
    assert codes(f) == {"apache_path_traversal_kev"} and has and f[0].evidence["kev"] is True
    f, _ = software.evaluate("h", {"Server": "Apache/2.2.15 (CentOS)", "X-Powered-By": "PHP/5.4.16"})
    assert codes(f) == {"apache_eol", "php_eol_old"}
    f, _ = software.evaluate("h", {"Server": "Microsoft-IIS/8.5", "X-Powered-By": "ASP.NET"})
    assert codes(f) == {"iis_eol"}
    f, _ = software.evaluate("h", {"Server": "nginx/1.26.2"})
    assert f == []
    f, has = software.evaluate("h", {"Server": "nginx"})
    assert f == [] and has is False
    f, _ = software.evaluate("h", {"Server": "Apache/2.4"})
    assert f == []
