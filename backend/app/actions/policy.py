"""Guardrail policy — the deterministic authorization layer for containment.

`evaluate()` is a pure function of `(policy, request, context)`. It is the single
place that decides whether a proposed action may run, and its DENY verdicts are
absolute: **no number of approvals, and no LLM output, can override a DENY.**
That property is what lets a security lead trust the system with prod — a fully
prompt-injected model still cannot block an internal range, suspend a break-glass
account, isolate a domain controller, run a shell command, or exceed the action
budget.

Everything here is stdlib-only (``ipaddress`` + ``fnmatch``) and side-effect free.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from app.actions.models import (
    ActionRequest,
    Decision,
    GuardrailContext,
    GuardrailDecision,
    TargetKind,
    is_mutating,
)

# ---- Safe built-in defaults (always applied, on top of any config) ---------- #

# Internal/reserved ranges an edge-block must never touch (would be a self-DoS).
_DEFAULT_PROTECTED_CIDRS = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8",
    "::1/128", "fc00::/7", "fe80::/10",
)
# Accounts that must never be auto-suspended/rotated (case-insensitive globs).
_DEFAULT_PROTECTED_USERS = (
    "breakglass", "break-glass", "root", "administrator", "admin",
    "svc-*", "*-svc", "svc_*", "*service*", "*-service", "backup*", "da-*",
    "domain admin*",
)
# Hosts that must never be auto-isolated (globs).
_DEFAULT_PROTECTED_HOSTS = (
    "dc-*", "*-dc", "*-dc[0-9]*", "*domaincontroller*", "*.dc.*",
)
# Action types considered too dangerous to ever auto-run in this build.
_HARD_DENY_ACTIONS = frozenset({"shell_command"})


def _split(csv: str) -> list[str]:
    return [x.strip() for x in (csv or "").split(",") if x.strip()]


@dataclass(frozen=True)
class GuardrailPolicy:
    kill_switch: bool = False
    dry_run_only: bool = True
    enabled_action_types: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {"notification", "block_ip", "suspend_account", "isolate_host", "rotate_credentials"}
        )
    )
    protected_ip_cidrs: tuple[str, ...] = _DEFAULT_PROTECTED_CIDRS
    protected_users: tuple[str, ...] = _DEFAULT_PROTECTED_USERS
    protected_hosts: tuple[str, ...] = _DEFAULT_PROTECTED_HOSTS
    hard_deny_actions: frozenset[str] = _HARD_DENY_ACTIONS
    max_actions_per_incident: int = 10
    max_actions_per_window: int = 25
    two_person_severities: frozenset[str] = field(default_factory=lambda: frozenset({"P1_CRITICAL"}))
    # (start, end) datetime pairs during which mutating actions are frozen.
    maintenance_windows: tuple[tuple[datetime, datetime], ...] = ()

    @classmethod
    def from_settings(cls, settings) -> GuardrailPolicy:
        return cls(
            kill_switch=settings.action_kill_switch,
            dry_run_only=settings.action_dry_run_only,
            enabled_action_types=frozenset(_split(settings.action_enabled_types)),
            protected_ip_cidrs=_DEFAULT_PROTECTED_CIDRS + tuple(_split(settings.action_protected_ip_cidrs)),
            protected_users=_DEFAULT_PROTECTED_USERS + tuple(_split(settings.action_protected_users)),
            protected_hosts=_DEFAULT_PROTECTED_HOSTS + tuple(_split(settings.action_protected_hosts)),
            max_actions_per_incident=settings.action_max_per_incident,
            max_actions_per_window=settings.action_max_per_window,
            two_person_severities=frozenset(_split(settings.action_two_person_severities)),
        )

    # ---- protected-target matchers ---- #

    def _ip_protected(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value.strip())
        except ValueError:
            # Not a parseable IP → refuse to act (can't prove it's safe).
            return True
        for cidr in self.protected_ip_cidrs:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _glob_match(value: str, patterns: tuple[str, ...]) -> bool:
        v = value.strip().lower()
        return any(fnmatch.fnmatch(v, p.lower()) for p in patterns)

    def _in_maintenance_window(self, now: datetime) -> bool:
        return any(start <= now <= end for start, end in self.maintenance_windows)


def evaluate(
    policy: GuardrailPolicy, request: ActionRequest, context: GuardrailContext
) -> GuardrailDecision:
    """Return the authorization decision for a proposed action. Pure."""
    at = request.action_type

    # 0. Non-mutating actions (notify a human, out-of-band task) are always safe.
    if not is_mutating(at):
        return GuardrailDecision(Decision.ALLOW, ("non-mutating action",), "non_mutating")

    # 1. Global emergency stop.
    if policy.kill_switch:
        return GuardrailDecision(Decision.DENY, ("kill switch engaged",), "kill_switch")

    # 2. Hard-deny classes (e.g. arbitrary shell) never auto-run — this takes
    #    precedence over enablement so a mis-configuration can't unlock them.
    if at in policy.hard_deny_actions:
        return GuardrailDecision(
            Decision.DENY, (f"action type '{at}' is hard-denied by policy",), "hard_deny"
        )

    # 3. Action type must be explicitly enabled in this environment.
    if at not in policy.enabled_action_types:
        return GuardrailDecision(
            Decision.DENY, (f"action type '{at}' is not enabled",), "action_disabled"
        )

    # 4. Change-freeze / maintenance window.
    if policy._in_maintenance_window(context.now):
        return GuardrailDecision(
            Decision.DENY, ("mutating actions are frozen during a maintenance window",),
            "maintenance_window",
        )

    # 5. Protected target — the absolute rule. No approval can override this.
    kind = request.target_kind
    tgt = request.target
    if kind == TargetKind.IP and policy._ip_protected(tgt):
        return GuardrailDecision(
            Decision.DENY, (f"{tgt} is an internal/reserved/unparseable address",), "protected_ip"
        )
    if kind == TargetKind.USER and policy._glob_match(tgt, policy.protected_users):
        return GuardrailDecision(
            Decision.DENY, (f"'{tgt}' is a protected account (break-glass/service/privileged)",),
            "protected_user",
        )
    if kind == TargetKind.HOST and policy._glob_match(tgt, policy.protected_hosts):
        return GuardrailDecision(
            Decision.DENY, (f"'{tgt}' is a protected host (critical infrastructure)",), "protected_host"
        )
    if kind in (TargetKind.CONFIG, TargetKind.SHELL) and not tgt:
        return GuardrailDecision(Decision.DENY, ("missing action target",), "no_target")

    # 6. Blast-radius / rate limits.
    if context.incident_action_count >= policy.max_actions_per_incident:
        return GuardrailDecision(
            Decision.DENY,
            (f"incident action budget exhausted ({policy.max_actions_per_incident})",),
            "incident_budget",
        )
    if context.window_action_count >= policy.max_actions_per_window:
        return GuardrailDecision(
            Decision.DENY,
            (f"system action rate limit hit ({policy.max_actions_per_window}/window)",),
            "rate_limit",
        )

    # 7. Two-person rule for the highest-stakes severities.
    if request.severity in policy.two_person_severities:
        return GuardrailDecision(
            Decision.REQUIRE_TWO_PERSON,
            (f"{request.severity} mutating action requires two distinct approvers",),
            "two_person",
        )

    # 8. Default for any mutating action: a human must approve.
    return GuardrailDecision(
        Decision.REQUIRE_APPROVAL, ("mutating action requires human approval",), "default_mutating"
    )
