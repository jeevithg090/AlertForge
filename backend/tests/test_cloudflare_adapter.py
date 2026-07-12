from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("DASHSCOPE_API_KEY", "")
os.environ.setdefault("USE_MOCK_TOOLS", "true")

from app.actions.adapters.cloudflare import CloudflareBlockIPAdapter
from app.actions.models import ActionRequest


@pytest.fixture
def adapter():
    return CloudflareBlockIPAdapter(api_token="test-token", zone_id="test-zone")


@pytest.fixture
def req():
    return ActionRequest(
        action_type="block_ip",
        target="198.51.100.42",
        incident_id="inc-123",
        severity="P1_CRITICAL",
        reason="test block",
    )


def _monkeypatch_httpx(monkeypatch, get_resp=None, post_resp=None, delete_resp=None):
    """Monkeypatch httpx.AsyncClient get/post/delete with canned responses."""

    class FakeResponse:
        def __init__(self, status_code, json_data):
            self.status_code = status_code
            self._json = json_data
            self.text = json.dumps(json_data) if json_data else ""
            self.ok = status_code < 400

        def json(self):
            return self._json

        def raise_for_status(self):
            if self.status_code >= 400:
                from httpx import HTTPStatusError
                raise HTTPStatusError("error", request=None, response=self)

    async def fake_get(self, url, **kwargs):
        return get_resp or FakeResponse(200, {"success": True, "result": []})

    async def fake_post(self, url, **kwargs):
        return post_resp or FakeResponse(200, {"success": True, "result": {"id": "cf-rule-001"}})

    async def fake_delete(self, url, **kwargs):
        return delete_resp or FakeResponse(200, {"success": True, "result": {"id": "cf-rule-001"}})

    import httpx
    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)
    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    monkeypatch.setattr(httpx.AsyncClient, "delete", fake_delete)


# ---------- preflight / dry_run (no HTTP) ----------


@pytest.mark.asyncio
async def test_preflight_no_http(adapter, req):
    br = await adapter.preflight(req)
    assert "block" in br.summary.lower()
    assert req.target in br.entities
    assert br.reversible


@pytest.mark.asyncio
async def test_dry_run_no_http(adapter, req):
    pe = await adapter.dry_run(req)
    assert "DRY-RUN" in pe.summary
    assert pe.details["target"] == req.target


# ---------- execute ----------


@pytest.mark.asyncio
async def test_execute_creates_rule(monkeypatch, adapter, req):
    _monkeypatch_httpx(
        monkeypatch,
        get_resp=None,  # no existing rules
        post_resp=type('R', (), {'status_code': 200, 'ok': True, 'text': '', 'json': lambda self: {"success": True, "result": {"id": "cf-rule-001"}}})(),
    )
    result = await adapter.execute(req)
    assert result["rule_id"] == "cf-rule-001"
    assert result["already_existed"] is False
    assert "applied_at" in result


@pytest.mark.asyncio
async def test_execute_idempotent_when_rule_exists(monkeypatch, adapter, req):
    _monkeypatch_httpx(
        monkeypatch,
        get_resp=type('R', (), {'status_code': 200, 'ok': True, 'text': '', 'json': lambda self: {"success": True, "result": [{"id": "cf-rule-001"}]}})(),
    )
    result = await adapter.execute(req)
    assert result["rule_id"] == "cf-rule-001"
    assert result["already_existed"] is True


# ---------- verify ----------


@pytest.mark.asyncio
async def test_verify_true(monkeypatch, adapter, req):
    _monkeypatch_httpx(
        monkeypatch,
        get_resp=type('R', (), {'status_code': 200, 'ok': True, 'text': '', 'json': lambda self: {"success": True, "result": [{"id": "cf-rule-001"}]}})(),
    )
    assert await adapter.verify(req, {"rule_id": "cf-rule-001"}) is True


@pytest.mark.asyncio
async def test_verify_false(monkeypatch, adapter, req):
    _monkeypatch_httpx(
        monkeypatch,
        get_resp=type('R', (), {'status_code': 200, 'ok': True, 'text': '', 'json': lambda self: {"success": True, "result": []}})(),
    )
    assert await adapter.verify(req, {"rule_id": "cf-rule-001"}) is False


# ---------- rollback ----------


@pytest.mark.asyncio
async def test_rollback_deletes_by_rule_id(monkeypatch, adapter, req):
    _monkeypatch_httpx(
        monkeypatch,
        delete_resp=type('R', (), {'status_code': 200, 'ok': True, 'text': '', 'json': lambda self: {"success": True, "result": {"id": "cf-rule-001"}}})(),
    )
    assert await adapter.rollback(req, {"rule_id": "cf-rule-001"}) is True


@pytest.mark.asyncio
async def test_rollback_looks_up_by_ip_when_no_rule_id(monkeypatch, adapter, req):
    _monkeypatch_httpx(
        monkeypatch,
        get_resp=type('R', (), {'status_code': 200, 'ok': True, 'text': '', 'json': lambda self: {"success": True, "result": [{"id": "cf-rule-002"}]}})(),
        delete_resp=type('R', (), {'status_code': 200, 'ok': True, 'text': '', 'json': lambda self: {"success": True, "result": {"id": "cf-rule-002"}}})(),
    )
    assert await adapter.rollback(req, {}) is True


# ---------- Cloudflare error ----------


@pytest.mark.asyncio
async def test_cloudflare_unsuccessful_response(monkeypatch, adapter, req):
    """When Cloudflare returns success: false, the adapter should surface failure."""
    err = type('R', (), {'status_code': 400, 'ok': False, 'text': '{"success":false,"errors":[{"message":"rate limit exceeded"}]}', 'json': lambda self: {"success": False, "errors": [{"message": "rate limit exceeded"}]}})()
    _monkeypatch_httpx(
        monkeypatch,
        get_resp=None,
        post_resp=err,
    )
    result = await adapter.execute(req)
    assert result["success"] is False
    assert "error" in result


# ---------- default_adapters selection ----------


def test_default_adapters_selects_cloudflare_when_configured(monkeypatch):
    monkeypatch.setattr("app.config.settings.cloudflare_api_token", "tok")
    monkeypatch.setattr("app.config.settings.cloudflare_zone_id", "zone")
    from app.actions.adapters import default_adapters

    adapters = default_adapters()
    block = [a for a in adapters if a.action_type == "block_ip"]
    assert len(block) == 1
    assert not block[0].simulated


def test_default_adapters_uses_mock_when_not_configured(monkeypatch):
    monkeypatch.setattr("app.config.settings.cloudflare_api_token", "")
    monkeypatch.setattr("app.config.settings.cloudflare_zone_id", "")
    from app.actions.adapters import default_adapters

    adapters = default_adapters()
    block = [a for a in adapters if a.action_type == "block_ip"]
    assert len(block) == 1
    assert block[0].simulated
