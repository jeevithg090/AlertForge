# fmt: off
"""Tests for the triage evaluation harness (pure scoring + regression floor)."""
from __future__ import annotations

import os

os.environ.setdefault("DASHSCOPE_API_KEY", "")
os.environ.setdefault("USE_MOCK_TOOLS", "true")

from app.eval.corpus import CORPUS, EvalCase  # noqa: E402
from app.eval.harness import (  # noqa: E402
    Prediction,
    classify_heuristic,
    run,
    score,
)


def _case(verdict, severity, techs=()):
    return EvalCase("c", "x", verdict, severity, list(techs))


def test_perfect_predictions_score_one():
    cases = [_case("TRUE_POSITIVE", "P2_HIGH", ["T1110"]), _case("FALSE_POSITIVE", "P4_LOW")]
    preds = [Prediction("TRUE_POSITIVE", "P2_HIGH", ["T1110"]), Prediction("FALSE_POSITIVE", "P4_LOW")]
    m = score(cases, preds)
    assert m.verdict_accuracy == 1.0
    assert m.suppression_recall == 1.0
    assert m.technique_f1 == 1.0
    assert m.severity_exact == 1.0


def test_verdict_accuracy_drops_on_miss():
    cases = [_case("TRUE_POSITIVE", "P2_HIGH"), _case("TRUE_POSITIVE", "P2_HIGH")]
    preds = [Prediction("TRUE_POSITIVE", "P2_HIGH"), Prediction("FALSE_POSITIVE", "P4_LOW")]
    assert score(cases, preds).verdict_accuracy == 0.5


def test_suppression_recall_measures_missed_dismissals():
    # A false positive escalated as a true positive is a suppression miss.
    cases = [_case("FALSE_POSITIVE", "P4_LOW"), _case("BENIGN_ANOMALY", "P4_LOW")]
    preds = [Prediction("TRUE_POSITIVE", "P2_HIGH"), Prediction("BENIGN_ANOMALY", "P4_LOW")]
    assert score(cases, preds).suppression_recall == 0.5


def test_severity_within_one_is_lenient_by_one_rank():
    cases = [_case("TRUE_POSITIVE", "P2_HIGH")]
    preds = [Prediction("TRUE_POSITIVE", "P3_MEDIUM")]  # off by one rank
    m = score(cases, preds)
    assert m.severity_exact == 0.0
    assert m.severity_within_one == 1.0


def test_technique_precision_recall():
    cases = [_case("TRUE_POSITIVE", "P2_HIGH", ["T1110", "T1078"])]
    preds = [Prediction("TRUE_POSITIVE", "P2_HIGH", ["T1110", "T1190"])]  # 1 hit, 1 wrong, 1 missed
    m = score(cases, preds)
    assert m.technique_precision == 0.5
    assert m.technique_recall == 0.5


def test_heuristic_baseline_meets_the_gate():
    """Regression floor: the shipped heuristic must clear the CI gate so a
    change that degrades triage below baseline fails the build."""
    m = run(classify_heuristic, CORPUS)
    passed, failures = m.gate()
    assert passed, f"heuristic regressed below gate: {failures}"
    assert m.verdict_accuracy >= 0.85
    assert m.suppression_recall == 1.0
