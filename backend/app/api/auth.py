from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.db.audit import write_audit
from app.services.auth import (
    create_operator as _create_operator,
)
from app.services.auth import (
    create_token,
    current_operator,
    get_operator_by_email,
    require_role,
    verify_password,
)

router = APIRouter()


class LoginRequest(BaseModel):
    email: str
    password: str


class CreateOperatorRequest(BaseModel):
    email: str
    password: str
    role: str = "viewer"
    display_name: str = ""


@router.post("/login")
async def login(body: LoginRequest) -> dict:
    operator = await get_operator_by_email(body.email)
    if not operator or not verify_password(body.password, operator.get("password_hash", "")):
        await write_audit(
            incident_id=None,
            actor=body.email,
            action="auth.login_failed",
            details={"reason": "invalid credentials"},
        )
        raise HTTPException(status_code=401, detail="invalid email or password")
    if not operator.get("is_active", True):
        raise HTTPException(status_code=403, detail="account disabled")
    token = create_token(operator)
    await write_audit(
        incident_id=None,
        actor=operator["email"],
        action="auth.login",
        details={"role": operator["role"]},
    )
    return {
        "token": token,
        "role": operator["role"],
        "name": operator.get("display_name", "") or operator["email"],
    }


@router.get("/me")
async def me(op: dict = Depends(current_operator)) -> dict:
    return op


@router.post("/operators")
async def create_operator(
    body: CreateOperatorRequest,
    _: dict = Depends(require_role("admin")),
) -> dict:
    if body.role not in ("viewer", "analyst", "approver", "admin"):
        raise HTTPException(status_code=422, detail="invalid role")
    existing = await get_operator_by_email(body.email)
    if existing:
        raise HTTPException(status_code=409, detail="operator already exists")
    op_id = await _create_operator(
        email=body.email,
        password=body.password,
        role=body.role,
        display_name=body.display_name,
    )
    return {"id": op_id, "email": body.email, "role": body.role}
