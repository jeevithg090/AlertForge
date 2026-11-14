"""Prometheus metrics for SentinelForge.

All metric creation uses try/except to handle duplicate registration
on module re-import in tests.
"""

from __future__ import annotations

import logging
import re

from prometheus_client import REGISTRY, Counter, Gauge, Histogram

logger = logging.getLogger("sentinelforge.metrics")


def _metric(name: str, klass, **kwargs):
    try:
        return klass(name, **kwargs, registry=REGISTRY)
    except ValueError:
        return REGISTRY._names_to_collectors[name]


# --- Counters ---

sf_alerts_ingested_total = _metric(
    "sf_alerts_ingested_total",
    Counter,
    documentation="Total alerts ingested",
    labelnames=("source",),
)
sf_alerts_correlated_total = _metric(
    "sf_alerts_correlated_total",
    Counter,
    documentation="Alerts folded into existing incidents",
    labelnames=("reason_kind",),
)
sf_incidents_by_verdict_total = _metric(
    "sf_incidents_by_verdict_total",
    Counter,
    documentation="Incidents by triage verdict",
    labelnames=("verdict",),
)
sf_actions_total = _metric(
    "sf_actions_total",
    Counter,
    documentation="Actions by type and status",
    labelnames=("action_type", "status"),
)
sf_llm_tokens_total = _metric(
    "sf_llm_tokens_total",
    Counter,
    documentation="LLM tokens by model and kind",
    labelnames=("model", "kind"),
)

# --- Histograms ---

sf_stage_seconds = _metric(
    "sf_stage_seconds",
    Histogram,
    documentation="Pipeline stage latency in seconds",
    labelnames=("stage",),
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300),
)
sf_llm_latency_seconds = _metric(
    "sf_llm_latency_seconds",
    Histogram,
    documentation="LLM request latency by model",
    labelnames=("model",),
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300),
)

# --- Gauges ---

sf_approval_queue_size = _metric(
    "sf_approval_queue_size", Gauge, documentation="Number of steps awaiting approval"
)


# --- Helper functions ---

_reason_kind_patterns = {
    "signature": re.compile(r"duplicate\s*signature", re.I),
    "shared_ip": re.compile(r"shared\s*source\s*IP", re.I),
    "shared_host": re.compile(r"shared\s*host", re.I),
    "shared_user": re.compile(r"shared\s*user", re.I),
}


def _reason_kind(reason: str) -> str:
    for kind, pattern in _reason_kind_patterns.items():
        if pattern.search(reason):
            return kind
    return "other"


def record_ingested(source: str) -> None:
    try:
        sf_alerts_ingested_total.labels(source=source).inc()
    except Exception as exc:
        logger.warning("metrics error (ingested): %s", exc)


def record_correlated(reason: str) -> None:
    try:
        sf_alerts_correlated_total.labels(reason_kind=_reason_kind(reason)).inc()
    except Exception as exc:
        logger.warning("metrics error (correlated): %s", exc)


def record_verdict(verdict: str) -> None:
    try:
        sf_incidents_by_verdict_total.labels(verdict=verdict).inc()
    except Exception as exc:
        logger.warning("metrics error (verdict): %s", exc)


def record_action(action_type: str, status: str) -> None:
    try:
        sf_actions_total.labels(action_type=action_type, status=status).inc()
    except Exception as exc:
        logger.warning("metrics error (action): %s", exc)


def record_llm_tokens(model: str, kind: str, count: int) -> None:
    try:
        sf_llm_tokens_total.labels(model=model, kind=kind).inc(count)
    except Exception as exc:
        logger.warning("metrics error (llm tokens): %s", exc)


def record_stage(stage: str, seconds: float) -> None:
    try:
        sf_stage_seconds.labels(stage=stage).observe(seconds)
    except Exception as exc:
        logger.warning("metrics error (stage): %s", exc)


def record_llm_latency(model: str, seconds: float) -> None:
    try:
        sf_llm_latency_seconds.labels(model=model).observe(seconds)
    except Exception as exc:
        logger.warning("metrics error (llm latency): %s", exc)


def set_approval_queue_size(n: int) -> None:
    try:
        sf_approval_queue_size.set(n)
    except Exception as exc:
        logger.warning("metrics error (approval queue): %s", exc)
