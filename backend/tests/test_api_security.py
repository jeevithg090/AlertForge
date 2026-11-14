"""API-level security tests: RBAC on routers, the two-person approval flow,
production config validation and CORS. No database or Redis is needed — the
app lifespan is not started and data-layer calls are monkeypatched."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from app.api import approvals as approvals_api
from app.api import incidents as incidents_api
from app.config import Settings, settings
from app.main import app
from app.services.auth import create_token, stream_operator

STRONG_SECRET = "s" * 48


@pytest.fixture
def client() -> TestClient:
    # Not used as a context manager, so the lifespan (DB/Redis init) never runs.
    return TestClient(app)


@pytest.fixture
def enforce_auth(monkeypatch):
    """Turn the dev bypass off and use a strong signing key."""
    monkeypatch.setattr(settings, "auth_dev_bypass", False)
    monkeypatch.setattr(settings, "secret_key", STRONG_SECRET)


def _bearer(role: str, email: str | None = None) -> dict[str, str]:
    token = create_token({"email": email or f"{role}@example.test", "role": role})
    return {"Authorization": f"Bearer {token}"}


async def _fake_list_incidents(**_kwargs):
    return [{"id": "00000000-0000-0000-0000-000000000001", "status": "TRIAGING"}]


# --------------------------------------------------------------------------- RBAC


def test_read_endpoints_require_token_when_bypass_off(client, enforce_auth, monkeypatch):
    monkeypatch.setattr(incidents_api.incidents_db, "list_incidents", _fake_list_incidents)
    for path in (
        "/api/v1/incidents",
        "/api/v1/analytics/summary",
        "/api/v1/security/events",
        "/api/v1/approvals/pending",
    ):
        res = client.get(path)
        assert res.status_code == 401, path
        assert res.headers.get("www-authenticate") == "Bearer"


def test_viewer_can_read_incidents(client, enforce_auth, monkeypatch):
    monkeypatch.setattr(incidents_api.incidents_db, "list_incidents", _fake_list_incidents)
    res = client.get("/api/v1/incidents", headers=_bearer("viewer"))
    assert res.status_code == 200
    assert res.json()["count"] == 1


def test_tampered_token_rejected(client, enforce_auth):
    headers = _bearer("viewer")
    headers["Authorization"] += "x"
    assert client.get("/api/v1/incidents", headers=headers).status_code == 401


def test_viewer_cannot_write(client, enforce_auth):
    viewer = _bearer("viewer")
    incident = "00000000-0000-0000-0000-000000000001"
    writes = [
        (f"/api/v1/incidents/{incident}/feedback", {"human_verdict": "FALSE_POSITIVE"}),
        (f"/api/v1/incidents/{incident}/detection-rule", None),
        (f"/api/v1/incidents/{incident}/hunt", None),
        ("/api/v1/hunt", {"seed": "T1110"}),
        ("/api/v1/ingest/text", {"text": "failed password from 1.2.3.4"}),
        ("/api/v1/approvals/step-1/approve", {"rationale": None}),
    ]
    for path, body in writes:
        res = client.post(path, json=body, headers=viewer)
        assert res.status_code == 403, path


def test_analyst_cannot_approve(client, enforce_auth):
    res = client.post(
        "/api/v1/approvals/step-1/approve", json={"rationale": "x"}, headers=_bearer("analyst")
    )
    assert res.status_code == 403


def test_dev_bypass_only_in_development(client, monkeypatch):
    monkeypatch.setattr(incidents_api.incidents_db, "list_incidents", _fake_list_incidents)
    monkeypatch.setattr(settings, "auth_dev_bypass", True)
    monkeypatch.setattr(settings, "environment", "development")
    assert client.get("/api/v1/incidents").status_code == 200
    monkeypatch.setattr(settings, "environment", "production")
    assert client.get("/api/v1/incidents").status_code == 401


def test_stream_operator_accepts_query_token(enforce_auth):
    token = create_token({"email": "v@example.test", "role": "viewer"})
    claims = stream_operator(credentials=None, access_token=token)
    assert claims["sub"] == "v@example.test"


def test_public_endpoints_stay_open(client, enforce_auth):
    assert client.get("/").status_code == 200
    assert client.get("/metrics").status_code == 200


# ------------------------------------------------------------ two-person approval


class _ApprovalFakes:
    """Records the side effects of the approval endpoints."""

    def __init__(self, step: dict):
        self.step = step
        self.cas_calls: list[dict] = []
        self.sql: list[tuple] = []
        self.audit: list[str] = []

    async def get_step(self, step_id):
        return dict(self.step, id=step_id)

    async def cas_update_step(self, **kwargs):
        self.cas_calls.append(kwargs)
        return True

    async def execute(self, sql, *args):
        self.sql.append((sql, args))
        return "UPDATE 1"

    async def write_audit(self, **kwargs):
        self.audit.append(kwargs["action"])

    async def noop(self, *args, **kwargs):
        return None


@pytest.fixture
def approval_fakes(monkeypatch):
    def install(step: dict) -> _ApprovalFakes:
        fakes = _ApprovalFakes(step)
        monkeypatch.setattr(approvals_api.incidents_db, "get_step", fakes.get_step)
        monkeypatch.setattr(approvals_api.incidents_db, "cas_update_step", fakes.cas_update_step)
        monkeypatch.setattr(approvals_api, "write_audit", fakes.write_audit)
        monkeypatch.setattr(approvals_api, "publish_event", fakes.noop)
        monkeypatch.setattr("app.db.connection.execute", fakes.execute)
        monkeypatch.setattr("app.services.redis_client.publish_to_stream", fakes.noop)
        return fakes

    return install


_STEP = {
    "incident_id": "00000000-0000-0000-0000-000000000001",
    "step_number": 1,
    "risk_level": "HIGH",
    "description": "block_ip 203.0.113.9",
    "status": "AWAITING_APPROVAL",
    "second_approver": None,
}


def test_first_approval_claims_step(client, enforce_auth, approval_fakes):
    fakes = approval_fakes(dict(_STEP, approved_by=None))
    res = client.post(
        "/api/v1/approvals/s1/approve", json={"rationale": "ok"}, headers=_bearer("approver", "a@x")
    )
    assert res.status_code == 200
    assert res.json()["status"] == "APPROVED"
    assert fakes.cas_calls[0]["approved_by"] == "a@x"
    assert "remediation_step.approved" in fakes.audit


def test_second_distinct_approver_becomes_second_approver(client, enforce_auth, approval_fakes):
    """A step sent back for the two-person rule keeps its first approver; the
    next distinct approver is recorded as second_approver (not overwritten)."""
    fakes = approval_fakes(dict(_STEP, approved_by="a@x"))
    res = client.post(
        "/api/v1/approvals/s1/approve", json={"rationale": "ok"}, headers=_bearer("approver", "b@x")
    )
    assert res.status_code == 200
    assert res.json()["second_approver"] == "b@x"
    assert fakes.cas_calls == []  # first approval untouched
    assert "second_approver" in fakes.sql[0][0]
    assert "remediation_step.second_approved" in fakes.audit


def test_same_approver_cannot_satisfy_two_person_rule(client, enforce_auth, approval_fakes):
    fakes = approval_fakes(dict(_STEP, approved_by="a@x"))
    res = client.post(
        "/api/v1/approvals/s1/approve", json={"rationale": "ok"}, headers=_bearer("approver", "a@x")
    )
    assert res.status_code == 409
    assert fakes.cas_calls == [] and fakes.sql == []


# ------------------------------------------------------------ detection rule path


def test_detection_rule_path_is_sanitised():
    rel, full = incidents_api.detection_rule_path("12345678-aaaa", "../../etc/passwd")
    assert os.path.basename(rel) == "12345678_etc_passwd.yaml"
    assert ".." not in rel
    assert os.path.dirname(rel) == settings.detections_dir
    assert full == os.path.abspath(rel)


def test_detection_rule_path_keeps_technique_ids():
    rel, _ = incidents_api.detection_rule_path("abcdef0123", "T1059.001")
    assert rel.endswith("abcdef01_T1059.001.yaml")
    # Regression: the directory used to be doubled (detections/detections/generated).
    assert rel.count("detections") == 1


# ----------------------------------------------------------- settings validation


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


def test_production_rejects_placeholder_secret():
    with pytest.raises(ValueError, match="SECRET_KEY"):
        _settings(environment="production", default_admin_password="a-real-password")


def test_production_rejects_short_secret():
    with pytest.raises(ValueError, match="SECRET_KEY"):
        _settings(environment="production", secret_key="short", default_admin_password="real-pass")


def test_production_rejects_default_admin_password():
    with pytest.raises(ValueError, match="DEFAULT_ADMIN_PASSWORD"):
        _settings(environment="production", secret_key=STRONG_SECRET)


def test_production_accepts_strong_config():
    s = _settings(
        environment="production",
        secret_key=STRONG_SECRET,
        default_admin_password="a-real-password",
        auth_dev_bypass=True,
    )
    assert s.webhook_secret_configured
    assert not s.dev_auth_bypass_active  # bypass is ignored outside development


def test_development_tolerates_placeholders():
    s = _settings(environment="development")
    assert not s.webhook_secret_configured
    assert s.dev_auth_bypass_active


def test_cors_never_allows_wildcard():
    s = _settings(
        environment="production",
        secret_key=STRONG_SECRET,
        default_admin_password="a-real-password",
        frontend_url="https://soc.example.com/",
        cors_origins="*, https://admin.example.com",
    )
    assert s.allowed_cors_origins == ["https://soc.example.com", "https://admin.example.com"]


def test_cors_preflight_rejects_unknown_origin(client):
    res = client.options(
        "/api/v1/incidents",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert res.headers.get("access-control-allow-origin") != "https://evil.example"


# ------------------------------------------------------------------- SSE stream


def test_incident_stream_replays_unnamed_events(client, monkeypatch):
    """Regression: integer SSE ids crashed sse-starlette, and named events were
    invisible to EventSource.onmessage. Events must be unnamed with string ids."""
    from app.api import stream as stream_api

    async def fake_replay(_incident_id, after_index=0):
        return [{"type": "incident.created"}, {"type": "triage.started"}]

    async def fake_subscribe(_incident_id):
        yield {"type": "triage.complete"}

    monkeypatch.setattr(stream_api, "replay_events_from", fake_replay)
    monkeypatch.setattr(stream_api, "subscribe", fake_subscribe)
    monkeypatch.setattr(settings, "auth_dev_bypass", True)
    monkeypatch.setattr(settings, "environment", "development")

    with client.stream("GET", "/api/v1/incidents/abc/stream") as res:
        assert res.status_code == 200
        body = "".join(res.iter_text())

    assert "event:" not in body
    assert [line for line in body.splitlines() if line.startswith("id:")] == [
        "id: 1",
        "id: 2",
        "id: 3",
    ]
    assert body.count('"type": "triage.complete"') == 1
