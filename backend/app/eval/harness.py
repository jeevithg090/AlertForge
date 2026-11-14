"""Triage evaluation harness — scoring + a CI-gateable runner.

`score()` is a pure function of `(cases, predictions)`. The default classifier is
the deterministic heuristic (so the gate runs in CI with zero API key); pass
``--llm`` to evaluate the real model instead.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import defaultdict
from dataclasses import dataclass, field

from app.eval.corpus import CORPUS, EvalCase

_SEV_RANK = {"P1_CRITICAL": 1, "P2_HIGH": 2, "P3_MEDIUM": 3, "P4_LOW": 4}
# Verdicts that mean "don't spin up an incident" — the noise-suppression classes.
_SUPPRESS = {"FALSE_POSITIVE", "BENIGN_ANOMALY"}

# CI regression floor. The heuristic baseline must clear these; the LLM should
# beat them comfortably. Tightening these over time ratchets quality upward.
DEFAULT_GATE = {
    "verdict_accuracy": 0.70,
    "suppression_recall": 0.80,  # of things that should be dismissed, how many we didn't escalate
    "severity_within_one": 0.75,
    "technique_recall": 0.70,
}


@dataclass
class Prediction:
    verdict: str
    severity: str
    techniques: list[str] = field(default_factory=list)


@dataclass
class Metrics:
    n: int
    verdict_accuracy: float
    suppression_recall: float
    tp_recall: float
    severity_exact: float
    severity_within_one: float
    technique_precision: float
    technique_recall: float
    technique_f1: float
    confusion: dict

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        return d

    def gate(self, thresholds: dict | None = None) -> tuple[bool, list[str]]:
        thresholds = thresholds or DEFAULT_GATE
        failures = []
        for k, minimum in thresholds.items():
            got = getattr(self, k, None)
            if got is None:
                continue
            if got + 1e-9 < minimum:
                failures.append(f"{k}={got:.2f} < {minimum:.2f}")
        return (not failures, failures)


def _f1(p: float, r: float) -> float:
    return 0.0 if (p + r) == 0 else 2 * p * r / (p + r)


def score(cases: list[EvalCase], preds: list[Prediction]) -> Metrics:
    """Pure scoring of predictions against the labeled corpus."""
    n = len(cases)
    verdict_hits = sev_exact = sev_within = 0
    suppress_total = suppress_hit = tp_total = tp_hit = 0
    tech_tp = tech_fp = tech_fn = 0
    confusion: dict = defaultdict(lambda: defaultdict(int))

    for c, p in zip(cases, preds):
        confusion[c.expected_verdict][p.verdict] += 1
        if p.verdict == c.expected_verdict:
            verdict_hits += 1

        if c.expected_verdict in _SUPPRESS:
            suppress_total += 1
            if p.verdict in _SUPPRESS:
                suppress_hit += 1
        if c.expected_verdict == "TRUE_POSITIVE":
            tp_total += 1
            if p.verdict == "TRUE_POSITIVE":
                tp_hit += 1

        er, pr = _SEV_RANK.get(c.expected_severity, 3), _SEV_RANK.get(p.severity, 3)
        sev_exact += int(er == pr)
        sev_within += int(abs(er - pr) <= 1)

        exp, got = set(c.expected_techniques), set(p.techniques)
        tech_tp += len(exp & got)
        tech_fp += len(got - exp)
        tech_fn += len(exp - got)

    tech_p = tech_tp / (tech_tp + tech_fp) if (tech_tp + tech_fp) else 1.0
    tech_r = tech_tp / (tech_tp + tech_fn) if (tech_tp + tech_fn) else 1.0
    return Metrics(
        n=n,
        verdict_accuracy=verdict_hits / n if n else 0.0,
        suppression_recall=suppress_hit / suppress_total if suppress_total else 1.0,
        tp_recall=tp_hit / tp_total if tp_total else 1.0,
        severity_exact=sev_exact / n if n else 0.0,
        severity_within_one=sev_within / n if n else 0.0,
        technique_precision=tech_p,
        technique_recall=tech_r,
        technique_f1=_f1(tech_p, tech_r),
        confusion={k: dict(v) for k, v in confusion.items()},
    )


# ---- classifiers ---- #


def classify_heuristic(case: EvalCase) -> Prediction:
    from app.agents.triage_agent import _heuristic_triage

    signal = {
        "alert_message": case.raw_text,
        "raw_input": case.raw_text,
        "source": case.source_hint,
    }
    r = _heuristic_triage(signal, "eval")
    return Prediction(
        r.verdict.value, r.severity.value, [t.technique_id for t in r.attack_techniques]
    )


async def classify_llm(case: EvalCase) -> Prediction:
    """Evaluate the real model (best-effort; falls back to heuristic on error)."""
    from app.agents.triage_agent import TRIAGE_SYSTEM
    from app.services.llm import extract_json, llm

    if not llm.enabled:
        return classify_heuristic(case)
    try:
        resp = await llm.complete(
            model=__import__("app.config", fromlist=["settings"]).settings.llm_model_smart,
            messages=[
                {"role": "system", "content": TRIAGE_SYSTEM},
                {
                    "role": "user",
                    "content": case.raw_text + "\n\nRespond with the TriageResult JSON only.",
                },
            ],
            temperature=0.0,
        )
        data = extract_json(resp["content"])
        return Prediction(
            data.get("verdict", "NEEDS_HUMAN"),
            data.get("severity", "P3_MEDIUM"),
            [
                t.get("technique_id", "")
                for t in (data.get("attack_techniques") or [])
                if t.get("technique_id")
            ],
        )
    except Exception:
        return classify_heuristic(case)


def run(classifier=classify_heuristic, cases: list[EvalCase] | None = None) -> Metrics:
    cases = cases or CORPUS
    if asyncio.iscoroutinefunction(classifier):
        preds = asyncio.run(_run_async(classifier, cases))
    else:
        preds = [classifier(c) for c in cases]
    return score(cases, preds)


async def _run_async(classifier, cases) -> list[Prediction]:
    return [await classifier(c) for c in cases]


def _report(m: Metrics, label: str) -> str:
    lines = [
        f"SentinelForge triage eval — {label}  (n={m.n})",
        f"  verdict accuracy      {m.verdict_accuracy:.2f}",
        f"  suppression recall    {m.suppression_recall:.2f}   (FP/benign correctly not escalated)",
        f"  true-positive recall  {m.tp_recall:.2f}",
        f"  severity exact        {m.severity_exact:.2f}",
        f"  severity within-one   {m.severity_within_one:.2f}",
        f"  technique P/R/F1      {m.technique_precision:.2f} / {m.technique_recall:.2f} / {m.technique_f1:.2f}",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SentinelForge triage evaluation gate")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Evaluate the real model instead of the heuristic baseline",
    )
    args = parser.parse_args()

    classifier = classify_llm if args.llm else classify_heuristic
    label = "LLM" if args.llm else "heuristic baseline"
    metrics = run(classifier)
    print(_report(metrics, label))
    passed, failures = metrics.gate()
    if passed:
        print("\nGATE: PASS")
        sys.exit(0)
    print("\nGATE: FAIL —", "; ".join(failures))
    sys.exit(1)


if __name__ == "__main__":
    main()
