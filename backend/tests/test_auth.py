from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("DASHSCOPE_API_KEY", "")
os.environ.setdefault("USE_MOCK_TOOLS", "true")

from app.services.auth import (  # noqa: E402
    create_token,
    decode_token,
    hash_password,
    role_allowed,
    verify_password,
)

# ---------- password hashing ----------

def test_hash_verify_roundtrip():
    pw = "my-secret-password"
    stored = hash_password(pw)
    assert stored.startswith("pbkdf2$")
    assert len(stored.split("$")) == 3
    assert verify_password(pw, stored)


def test_wrong_password_fails():
    stored = hash_password("correct-password")
    assert not verify_password("wrong-password", stored)


def test_tampered_stored_hash_fails():
    stored = hash_password("correct-password")
    tampered = stored[:-4] + "beef"
    assert not verify_password("correct-password", tampered)


def test_invalid_format_returns_false():
    assert not verify_password("x", "")
    assert not verify_password("x", "notpbkdf2$salt$hash")
    assert not verify_password("x", "pbkdf2$too$few")


# ---------- JWT ----------

def test_token_roundtrip():
    operator = {"email": "alice@test.local", "role": "approver", "display_name": "Alice"}
    token = create_token(operator)
    claims = decode_token(token)
    assert claims["sub"] == "alice@test.local"
    assert claims["role"] == "approver"
    assert claims["name"] == "Alice"


def test_expired_token_raises():
    old = time.time() - 3600
    import jwt
    token = jwt.encode(
        {"sub": "x@x", "role": "viewer", "exp": old, "iat": old},
        "dev-secret-change-me",
        algorithm="HS256",
    )
    with pytest.raises(Exception) as exc:
        decode_token(token)
    assert "401" in str(exc.value) or "expired" in str(exc.value) or "token" in str(exc.value)


def test_modified_token_raises():
    operator = {"email": "alice@test.local", "role": "viewer", "display_name": ""}
    token = create_token(operator)
    modified = token[:-5] + "XXXXX"
    with pytest.raises(Exception) as exc:
        decode_token(modified)
    assert "401" in str(exc.value) or "invalid" in str(exc.value) or "token" in str(exc.value)


# ---------- role_allowed pure function ----------

def test_role_allowed_admin_always():
    assert role_allowed("admin", ("viewer",))
    assert role_allowed("admin", ())
    assert role_allowed("admin", ("approver",))


def test_role_allowed_viewer_denied():
    assert not role_allowed("viewer", ("approver", "admin"))
    assert role_allowed("viewer", ("viewer", "analyst"))


def test_role_allowed_approver_allowed():
    assert role_allowed("approver", ("approver", "admin"))
    assert not role_allowed("approver", ("viewer", "analyst"))
