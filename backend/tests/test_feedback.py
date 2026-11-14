from __future__ import annotations

import os

os.environ.setdefault("DASHSCOPE_API_KEY", "")
os.environ.setdefault("USE_MOCK_TOOLS", "true")

VALID_VERDICTS = ("TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_ANOMALY", "NEEDS_HUMAN")


def test_bad_verdict_rejected():
    for bad in ("INVALID", "true_positive", ""):
        assert bad not in VALID_VERDICTS


def test_good_verdict_accepted():
    for v in VALID_VERDICTS:
        assert v in VALID_VERDICTS


def test_agreement_stats_perfect():
    from app.eval.feedback_export import agreement_stats

    rows = [
        {"ai_verdict": "TRUE_POSITIVE", "human_verdict": "TRUE_POSITIVE", "count": 10},
    ]
    stats = agreement_stats(rows)
    assert stats["agreement_rate"] == 1.0
    assert stats["false_negatives"] == 0


def test_agreement_stats_false_negatives():
    from app.eval.feedback_export import agreement_stats

    rows = [
        {"ai_verdict": "FALSE_POSITIVE", "human_verdict": "TRUE_POSITIVE", "count": 3},
        {"ai_verdict": "TRUE_POSITIVE", "human_verdict": "TRUE_POSITIVE", "count": 7},
    ]
    stats = agreement_stats(rows)
    assert stats["false_negatives"] == 3
    assert stats["agreement_rate"] == 0.7


def test_agreement_stats_by_pair():
    from app.eval.feedback_export import agreement_stats

    rows = [
        {"ai_verdict": "TRUE_POSITIVE", "human_verdict": "TRUE_POSITIVE", "count": 5},
        {"ai_verdict": "TRUE_POSITIVE", "human_verdict": "FALSE_POSITIVE", "count": 2},
    ]
    stats = agreement_stats(rows)
    assert len(stats["by_pair"]) == 2


def test_feedback_export_constructs_eval_case():
    from app.eval.feedback_export import feedback_row_to_eval_case

    case = feedback_row_to_eval_case(
        {
            "incident_id": "abc12345-0000-0000-0000-000000000000",
            "alert_message": "Test alert",
            "human_verdict": "TRUE_POSITIVE",
            "human_severity": "P2_HIGH",
            "ai_verdict": "FALSE_POSITIVE",
            "ai_severity": "P3_MEDIUM",
        }
    )
    assert "fb_abc12345" in case["name"]
    assert case["expected_verdict"] == "TRUE_POSITIVE"
    assert case["expected_severity"] == "P2_HIGH"
    assert case["raw_text"] == "Test alert"
