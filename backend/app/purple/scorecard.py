from __future__ import annotations


def _normalize_technique(tid: str) -> str:
    return tid.split(".")[0].lower()


def score_chain(chain, observed: dict) -> dict:
    expected_techniques = {_normalize_technique(s.expected_technique) for s in chain.steps}
    observed_techniques = {_normalize_technique(t) for t in observed.get("technique_ids", [])}

    technique_hits = expected_techniques & observed_techniques
    technique_recall = len(technique_hits) / len(expected_techniques) if expected_techniques else 1.0

    correlation_ok = observed.get("incidents_created", 1) == 1 if chain.expect_correlated else True
    verdict_ok = observed.get("verdict", "") == "TRUE_POSITIVE"

    passed = correlation_ok and technique_recall >= 0.5 and verdict_ok

    return {
        "chain": chain.name,
        "correlation_ok": correlation_ok,
        "incidents_created": observed.get("incidents_created", 0),
        "alerts_folded": observed.get("alerts_folded", 0),
        "technique_hits": sorted(technique_hits),
        "technique_expected": sorted(expected_techniques),
        "technique_recall": round(technique_recall, 3),
        "verdict": observed.get("verdict", ""),
        "verdict_ok": verdict_ok,
        "time_to_triage_seconds": observed.get("time_to_triage_seconds"),
        "passed": passed,
    }


def aggregate(scores: list[dict]) -> dict:
    n = len(scores)
    k = sum(1 for s in scores if s["passed"])
    detection_rate = round(k / n, 3) if n else 0.0
    avg_recall = round(
        sum(s["technique_recall"] for s in scores) / n, 3
    ) if n else 0.0

    return {
        "chains": n,
        "passed": k,
        "detection_rate": detection_rate,
        "avg_technique_recall": avg_recall,
        "results": scores,
    }
