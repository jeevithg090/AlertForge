from __future__ import annotations

import os

os.environ.setdefault("DASHSCOPE_API_KEY", "")
os.environ.setdefault("USE_MOCK_TOOLS", "true")

from app.purple.chains import ALL_CHAINS
from app.purple.scorecard import aggregate, score_chain


def test_perfect_observation_passes():
    chain = ALL_CHAINS[0]  # credential_assault
    observed = {
        "incidents_created": 1,
        "alerts_folded": 2,
        "technique_ids": ["T1110", "T1078", "T1041"],
        "verdict": "TRUE_POSITIVE",
    }
    score = score_chain(chain, observed)
    assert score["passed"] is True
    assert score["correlation_ok"] is True
    assert score["verdict_ok"] is True
    assert score["technique_recall"] == 1.0


def test_missed_correlation_fails():
    chain = ALL_CHAINS[0]  # expects correlation
    observed = {
        "incidents_created": 3,
        "alerts_folded": 0,
        "technique_ids": ["T1110", "T1078", "T1041"],
        "verdict": "TRUE_POSITIVE",
    }
    score = score_chain(chain, observed)
    assert score["passed"] is False
    assert score["correlation_ok"] is False


def test_technique_recall_with_subtechnique():
    chain = ALL_CHAINS[0]
    observed = {
        "incidents_created": 1,
        "alerts_folded": 2,
        "technique_ids": ["T1110.003", "T1078", "T1041"],
        "verdict": "TRUE_POSITIVE",
    }
    score = score_chain(chain, observed)
    assert score["technique_recall"] == 1.0


def test_partial_technique_recall():
    chain = ALL_CHAINS[0]
    observed = {
        "incidents_created": 1,
        "alerts_folded": 2,
        "technique_ids": ["T1110"],
        "verdict": "TRUE_POSITIVE",
    }
    score = score_chain(chain, observed)
    assert abs(score["technique_recall"] - 1.0/3.0) < 0.001
    assert score["passed"] is False  # recall < 0.5


def test_wrong_verdict_fails():
    chain = ALL_CHAINS[0]
    observed = {
        "incidents_created": 1,
        "alerts_folded": 2,
        "technique_ids": ["T1110", "T1078", "T1041"],
        "verdict": "FALSE_POSITIVE",
    }
    score = score_chain(chain, observed)
    assert score["passed"] is False
    assert score["verdict_ok"] is False


def test_single_step_chain_no_correlation():
    """recon_probe has expect_correlated=False, so single incident is fine."""
    chain = ALL_CHAINS[2]  # recon_probe
    observed = {
        "incidents_created": 1,
        "alerts_folded": 0,
        "technique_ids": ["T1595"],
        "verdict": "TRUE_POSITIVE",
    }
    score = score_chain(chain, observed)
    assert score["passed"] is True


def test_aggregate_math():
    scores = [
        {"passed": True, "technique_recall": 1.0, "chain": "a", "correlation_ok": True,
         "incidents_created": 1, "alerts_folded": 0, "technique_hits": [], "technique_expected": [],
         "verdict": "TRUE_POSITIVE", "verdict_ok": True},
        {"passed": False, "technique_recall": 0.5, "chain": "b", "correlation_ok": False,
         "incidents_created": 2, "alerts_folded": 0, "technique_hits": [], "technique_expected": [],
         "verdict": "TRUE_POSITIVE", "verdict_ok": True},
    ]
    agg = aggregate(scores)
    assert agg["chains"] == 2
    assert agg["passed"] == 1
    assert agg["detection_rate"] == 0.5
    assert agg["avg_technique_recall"] == 0.75


def test_chain_steps_have_non_empty_text():
    for chain in ALL_CHAINS:
        for step in chain.steps:
            assert step.raw_text, f"{chain.name}/{step.name} has empty raw_text"
            # Check that the expected technique's signature keyword appears
            if step.expected_technique == "T1110":
                assert "SSH" in step.raw_text or "failed" in step.raw_text
            elif step.expected_technique == "T1595":
                assert "scan" in step.raw_text.lower()
