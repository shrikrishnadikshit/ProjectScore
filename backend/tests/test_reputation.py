from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db, main
from app.auth import create_user
from app.models import Alert
from app.reputation import replies, sentiment, service, sources
from app.reputation.models import Brand, Mention

PASSWORD = "correct-horse-battery"
REAL_FETCH_APPLE = sources.fetch_apple


@pytest.fixture(autouse=True)
def _setup(monkeypatch):
    monkeypatch.setenv("REPUTATION_MODULE", "on")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    main.auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Org A", "a@a.example", PASSWORD, role="admin")
    create_user(s, "Org B", "b@b.example", PASSWORD, role="admin")
    s.close()
    # No network in tests: every source returns nothing unless a test says otherwise.
    for key in list(sources.FETCHERS):
        monkeypatch.setitem(sources.FETCHERS, key, lambda terms, since: [])
    monkeypatch.setattr(sources, "fetch_apple", lambda app_id, country="us", pages=2: [])


def client_for(email):
    c = TestClient(main.app)
    assert c.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    return c


def item(i, text, source="hackernews", rating=None, hours_ago=1, kind="mention"):
    return {"source": source, "kind": kind, "external_id": str(i), "url": None, "author": "alice", "title": None,
            "text": text, "rating": rating, "published_at": datetime.now(timezone.utc) - timedelta(hours=hours_ago)}


def make_brand(session, org_id=1, **kw):
    b = Brand(org_id=org_id, name=kw.pop("name", "Acme"), keywords=kw.pop("keywords", []), exclude=kw.pop("exclude", []),
              sources=kw.pop("sources", ["hackernews"]), **kw)
    session.add(b)
    session.commit()
    return b


# ------------------------------------------------------------------ sentiment
def test_sentiment_labels():
    assert sentiment.score("Acme support was fantastic and really helpful")[1] == "positive"
    assert sentiment.score("Acme is a scam, they overcharged me and never gave a refund")[1] == "negative"
    assert sentiment.score("Acme released version 4.2 today")[1] == "neutral"


def test_stars_outweigh_polite_words():
    value, lab = sentiment.score("Thanks, nice people but the app never works", rating=1)
    assert lab == "negative" and value < -0.5


def test_non_english_text_is_neutral_without_rating():
    assert sentiment.score("这个产品非常糟糕")[1] == "neutral"
    assert sentiment.score("这个产品非常糟糕", rating=1)[1] == "negative"


# ------------------------------------------------------------------ parsers (shapes from the providers' docs)
def test_parse_gdelt():
    data = {"articles": [{"url": "https://news.example/a", "title": "Acme hit by outage", "seendate": "20261114T093000Z",
                          "domain": "news.example", "language": "English"}]}
    [a] = sources.parse_gdelt(data)
    assert a["kind"] == "news" and a["published_at"] == datetime(2026, 11, 14, 9, 30, tzinfo=timezone.utc)


def test_parse_hn_strips_html():
    data = {"hits": [{"objectID": "42", "comment_text": "I <i>love</i> Acme &amp; its API", "story_title": "Show HN",
                      "author": "pg", "created_at_i": 1763000000}]}
    [h] = sources.parse_hn(data)
    assert h["text"] == "I love Acme & its API" and h["url"].endswith("id=42")


def test_parse_bluesky_builds_link():
    data = {"posts": [{"uri": "at://did:plc:abc/app.bsky.feed.post/3kxyz", "author": {"handle": "bob.bsky.social"},
                       "record": {"text": "Acme rocks", "createdAt": "2026-11-14T10:00:00.000Z", "langs": ["en"]}}]}
    [p] = sources.parse_bluesky(data)
    assert p["url"] == "https://bsky.app/profile/bob.bsky.social/post/3kxyz"


def test_parse_apple_skips_app_entry_and_handles_single():
    app_entry = {"im:name": {"label": "Acme"}}
    review = {"id": {"label": "1001"}, "im:rating": {"label": "2"}, "title": {"label": "Crashes"},
              "content": {"label": "Crashes on start"}, "author": {"name": {"label": "Sam"}},
              "updated": {"label": "2026-11-14T01:02:03-07:00"}}
    assert [r["rating"] for r in sources.parse_apple({"feed": {"entry": [app_entry, review]}}, "123456")] == [2]
    assert len(sources.parse_apple({"feed": {"entry": review}}, "123456")) == 1
    assert sources.parse_apple({"feed": {}}, "123456") == []


def test_parse_reddit_and_brave_and_google():
    rd = {"data": {"children": [{"data": {"id": "x1", "name": "t3_x1", "permalink": "/r/a/comments/x1/", "title": "Acme?",
                                          "selftext": "", "author": "u", "created_utc": 1763000000}}]}}
    assert sources.parse_reddit(rd)[0]["url"] == "https://www.reddit.com/r/a/comments/x1/"
    br = {"web": {"results": [{"title": "Acme review", "url": "https://www.trustsite.example/acme", "description": "Scam?"}]}}
    assert sources.parse_brave(br)[0] == {"rank": 1, "title": "Acme review", "url": "https://www.trustsite.example/acme",
                                          "domain": "trustsite.example", "snippet": "Scam?"}
    g = {"displayName": {"text": "Acme"}, "rating": 4.1, "userRatingCount": 10,
         "reviews": [{"rating": 1, "text": {"text": "bad"}, "authorAttribution": {"displayName": "Z"}}]}
    assert sources.parse_google(g)["reviews"][0]["author"] == "Z"


def test_apple_id_validated():
    with pytest.raises(ValueError):
        REAL_FETCH_APPLE("../../etc", "us")


# ------------------------------------------------------------------ ingest, scoring, alerts
def test_ingest_dedupes_and_filters():
    s = db.SessionLocal()
    b = make_brand(s, exclude=["acme corp jobs"])
    items = [item(1, "Acme is great"), item(1, "Acme is great"), item(2, "unrelated post about cats"),
             item(3, "acme corp jobs hiring now")]
    assert len(service.ingest(s, b, items)) == 1
    s.commit()
    assert service.ingest(s, b, [item(1, "Acme is great")]) == []
    s.close()


def test_score_needs_enough_data_and_mixes_stars():
    s = db.SessionLocal()
    b = make_brand(s)
    service.ingest(s, b, [item(i, "Acme is wonderful and helpful") for i in range(4)])
    s.commit()
    assert service.summary(s, b)["score"] is None
    service.ingest(s, b, [item(10 + i, "Acme app crashes", kind="review", rating=1, source="apple") for i in range(4)])
    s.commit()
    out = service.summary(s, b)
    assert out["score"] is not None and 0 <= out["score"] <= 100
    assert out["negative"] == 4 and out["average_rating"] == 1 and len(out["daily"]) == 31
    s.close()


def test_crisis_alert_on_spike_only_once_a_day():
    s = db.SessionLocal()
    b = make_brand(s)
    new = service.ingest(s, b, [item(i, "Acme is a scam and a fraud", hours_ago=2) for i in range(6)])
    s.commit()
    alerts = service.check_alerts(s, b, new)
    assert [a.kind for a in alerts] == ["reputation_crisis"] and alerts[0].severity == "critical"
    more = service.ingest(s, b, [item(100 + i, "Acme fraud again", hours_ago=1) for i in range(6)])
    s.commit()
    assert service.check_alerts(s, b, more) == []
    s.close()


def test_no_crisis_when_negatives_are_normal():
    s = db.SessionLocal()
    b = make_brand(s)
    # About 6 negative mentions every day for the past week: 6 today is not a spike.
    service.ingest(s, b, [item(f"o{i}", "Acme is terrible", hours_ago=30 + i * 4) for i in range(42)])
    new = service.ingest(s, b, [item(i, "Acme is terrible", hours_ago=2) for i in range(6)])
    s.commit()
    assert service.check_alerts(s, b, new) == []
    s.close()


def test_bad_review_alert():
    s = db.SessionLocal()
    b = make_brand(s)
    new = service.ingest(s, b, [item(1, "Crashes", source="apple", kind="review", rating=1)])
    s.commit()
    assert [a.kind for a in service.check_alerts(s, b, new)] == ["reputation_review"]
    s.close()


def test_poll_records_source_errors(monkeypatch):
    def boom(terms, since):
        raise RuntimeError("403 Forbidden")
    monkeypatch.setitem(sources.FETCHERS, "bluesky", boom)
    monkeypatch.setitem(sources.FETCHERS, "hackernews", lambda terms, since: [item(1, "Acme rocks")])
    s = db.SessionLocal()
    b = make_brand(s, sources=["hackernews", "bluesky"])
    assert service.poll_brand(s, b)["new"] == 1
    assert b.source_status["bluesky"]["ok"] is False and b.source_status["hackernews"]["count"] == 1
    s.close()


def test_import_csv():
    s = db.SessionLocal()
    b = make_brand(s)
    csv_text = "Date,Source,Author,Rating,Text\n2026-11-10,Trustpilot,Ann,1,Awful service\n,Google,Bo,5,Love it\n,,,,\n"
    assert service.import_csv(s, b, csv_text) == {"imported": 2, "skipped": 1, "duplicates": 0}
    assert service.import_csv(s, b, csv_text)["duplicates"] == 2
    with pytest.raises(ValueError):
        service.import_csv(s, b, "a,b\n1,2\n")
    s.close()


def test_search_summary_tracks_rank_changes():
    from app.reputation.models import SearchSnapshot

    old = SearchSnapshot(brand_id=1, query="Acme", results=[{"rank": 1, "url": "u1", "label": "neutral"}],
                         taken_at=datetime(2026, 11, 1, tzinfo=timezone.utc))
    new = SearchSnapshot(brand_id=1, query="Acme", results=[{"rank": 1, "url": "u2", "label": "negative"},
                                                            {"rank": 2, "url": "u1", "label": "neutral"}],
                         taken_at=datetime(2026, 11, 8, tzinfo=timezone.utc))
    new.id = 2
    out = service.search_summary([new, old])
    assert out["latest"]["negative_top10"] == 1
    assert out["latest"]["results"][0]["new"] is True and out["latest"]["results"][1]["previous_rank"] == 1


# ------------------------------------------------------------------ replies
def test_template_replies_pick_topic():
    r = replies.template_reply("Acme", "negative", "They charged me twice, want a refund", "Ann Lee", "help@acme.example")
    assert "payment" in r and "Ann" in r and "help@acme.example" in r
    assert "thank you" in replies.template_reply("Acme", "positive", "great", None, None).lower()


def test_ai_reply_falls_back_to_template(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setattr(replies, "ai_reply", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("down")))
    out = replies.suggest("Acme", "Apple", "negative", 1, "app crashes", "Sam", None)
    assert out["by"] == "template"
    monkeypatch.setattr(replies, "ai_reply", lambda *a, **k: "Sorry Sam, we're on it.")
    assert replies.suggest("Acme", "Apple", "negative", 1, "app crashes", "Sam", None) == {"text": "Sorry Sam, we're on it.", "by": "ai"}


# ------------------------------------------------------------------ API
def test_module_off_hides_everything(monkeypatch):
    monkeypatch.setenv("REPUTATION_MODULE", "off")
    c = client_for("a@a.example")
    assert c.get("/api/reputation/config").json() == {"enabled": False}
    assert c.get("/api/reputation/brands").status_code == 404


def test_api_flow_and_org_isolation():
    a, b = client_for("a@a.example"), client_for("b@b.example")
    assert a.get("/api/reputation/config").json()["enabled"] is True
    r = a.post("/api/reputation/brands", json={"name": "Acme", "keywords": ["Acme App", "acme app"],
                                               "apple_app_id": "https://apps.apple.com/in/app/acme/id310633997"})
    assert r.status_code == 201, r.text
    brand = r.json()
    assert brand["keywords"] == ["Acme App"] and brand["apple_app_id"] == "310633997"
    bid = brand["id"]
    m = a.post(f"/api/reputation/brands/{bid}/mentions", json={"text": "Terrible support, nobody answers", "rating": 1})
    assert m.status_code == 201 and m.json()["label"] == "negative"
    mid = m.json()["id"]
    assert a.get(f"/api/reputation/brands/{bid}/mentions?label=negative").json()["total"] == 1
    sug = a.post(f"/api/reputation/mentions/{mid}/suggest-reply", json={}).json()
    assert sug["by"] == "template" and "help" in sug["text"]
    assert a.patch(f"/api/reputation/mentions/{mid}", json={"status": "replied", "reply_text": sug["text"]}).json()["status"] == "replied"
    assert a.post(f"/api/reputation/brands/{bid}/import", json={"csv": "text,rating\nGreat,5\n"}).json()["imported"] == 1
    exp = a.get(f"/api/reputation/brands/{bid}/export.csv")
    assert exp.status_code == 200 and "Terrible support" in exp.text
    # Another organisation cannot see or touch it.
    assert b.get(f"/api/reputation/brands/{bid}").status_code == 404
    assert b.patch(f"/api/reputation/mentions/{mid}", json={"status": "ignored"}).status_code == 404
    assert b.get("/api/reputation/brands").json() == []
    # Alerts land in the normal alerts list without a company link.
    s = db.SessionLocal()
    kinds = s.scalars(select(Alert.kind).where(Alert.org_id == 1)).all()
    s.close()
    assert "reputation_review" in kinds
    assert a.delete(f"/api/reputation/brands/{bid}").status_code == 204


def test_members_cannot_create_brands():
    s = db.SessionLocal()
    create_user(s, "Org A", "m@a.example", PASSWORD)
    s.close()
    assert client_for("m@a.example").post("/api/reputation/brands", json={"name": "Acme"}).status_code == 403


def test_brand_limit_and_validation(monkeypatch):
    monkeypatch.setenv("REPUTATION_MAX_BRANDS", "1")
    a = client_for("a@a.example")
    assert a.post("/api/reputation/brands", json={"name": "Acme", "sources": ["myspace"]}).status_code == 400
    assert a.post("/api/reputation/brands", json={"name": "Acme", "entity_id": 999}).status_code == 400
    assert a.post("/api/reputation/brands", json={"name": "Acme"}).status_code == 201
    assert a.post("/api/reputation/brands", json={"name": "Other"}).status_code == 409


def test_google_and_search_need_keys():
    a = client_for("a@a.example")
    bid = a.post("/api/reputation/brands", json={"name": "Acme"}).json()["id"]
    assert a.get(f"/api/reputation/brands/{bid}/google").status_code == 404
    assert a.post(f"/api/reputation/brands/{bid}/search").status_code == 404
    assert a.get(f"/api/reputation/brands/{bid}/search").json()["available"] is False
