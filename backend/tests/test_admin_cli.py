from app import admin, auth, db
from app.auth import create_user
from app.models import User, UserMfa


def setup_function():
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    u = create_user(s, "P", "owner@p.example", "old-password-123", role="owner")
    s.add(UserMfa(user_id=u.id, secret="ABC", enabled=True, recovery=[]))
    s.commit()
    s.close()


def test_list_and_reset(monkeypatch, capsys):
    assert admin.main(["list-users"]) == 0
    assert "owner@p.example" in capsys.readouterr().out
    monkeypatch.setenv("PASSWORD", "short")
    assert admin.main(["reset-password", "--email", "owner@p.example"]) == 1
    monkeypatch.setenv("PASSWORD", "brand-new-password-1")
    assert admin.main(["reset-password", "--email", "nobody@p.example"]) == 1
    assert admin.main(["reset-password", "--email", " Owner@P.example ", "--clear-mfa"]) == 0
    s = db.SessionLocal()
    assert auth.authenticate(s, "owner@p.example", "brand-new-password-1") is not None
    assert s.query(UserMfa).count() == 0
    s.close()
