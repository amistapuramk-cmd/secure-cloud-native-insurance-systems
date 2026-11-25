import os

os.environ["DATABASE_URL"] = "sqlite:///./test.db"

import pytest
from fastapi.testclient import TestClient

from app.main import app

PW = "StrongPass123"


@pytest.fixture(scope="module")
def client():
    if os.path.exists("test.db"):
        os.remove("test.db")
    with TestClient(app) as c:
        yield c
    os.remove("test.db")


def login(c, email, pw=PW):
    r = c.post("/auth/login", data={"username": email, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_full_flow(client):
    c = client
    assert c.get("/health").json() == {"status": "ok"}
    assert c.post("/auth/register", json={"email": "a@x.com", "full_name": "A", "password": "weak"}).status_code == 422
    for e in ("a@x.com", "b@x.com"):
        assert c.post("/auth/register", json={"email": e, "full_name": e, "password": PW}).status_code == 201
    a, b = login(c, "a@x.com"), login(c, "b@x.com")
    admin = login(c, "admin@example.com", "ChangeMe!12345")

    for email, role in (("agent@x.com", "agent"), ("adj@x.com", "adjuster")):
        assert c.post("/users", headers=admin, json={"email": email, "full_name": role, "password": PW, "role": role}).status_code == 201
    agent, adj = login(c, "agent@x.com"), login(c, "adj@x.com")
    assert c.post("/users", headers=a, json={"email": "z@x.com", "full_name": "z", "password": PW, "role": "admin"}).status_code == 403

    p = c.post("/policies", headers=a, json={"type": "auto", "coverage_amount": 10000}).json()
    assert p["status"] == "pending" and p["premium"] == 300
    assert c.post("/claims", headers=a, json={"policy_id": p["id"], "amount": 500, "description": "dent"}).status_code == 409
    assert c.post(f"/policies/{p['id']}/approve", headers=a).status_code == 403
    assert c.post(f"/policies/{p['id']}/approve", headers=agent).json()["status"] == "active"
    assert c.get(f"/policies/{p['id']}", headers=b).status_code == 404  # IDOR blocked

    cl = c.post("/claims", headers=a, json={"policy_id": p["id"], "amount": 500, "description": "Rear bumper dent"}).json()
    assert cl["description"] == "Rear bumper dent"
    assert c.get("/claims", headers=b).json() == []
    assert c.post(f"/claims/{cl['id']}/review", headers=a, json={"decision": "approved"}).status_code == 403
    assert c.post(f"/claims/{cl['id']}/review", headers=adj, json={"decision": "approved"}).json()["status"] == "approved"
    assert len(c.get("/audit", headers=admin).json()) > 5
    assert c.get("/audit", headers=a).status_code == 403


def test_encrypted_at_rest(client):
    from app.database import SessionLocal
    from app.models import Claim
    with SessionLocal() as db:
        assert "Rear bumper" not in db.query(Claim).first().description_enc


def test_bad_token(client):
    assert client.get("/users/me", headers={"Authorization": "Bearer junk"}).status_code == 401
