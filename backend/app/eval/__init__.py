"""Offline evaluation harness — proving the triage is good enough to trust.

You can't responsibly grant autonomy without measuring quality. This package
scores a classifier (the heuristic baseline, or the real LLM) against a labeled
corpus and reports verdict accuracy, false-positive suppression, severity
calibration, and MITRE-mapping precision/recall — as a CI-gateable regression
floor so a prompt/model change can't silently degrade the SOC's judgment.
"""

from app.eval.corpus import CORPUS, EvalCase
from app.eval.harness import Metrics, Prediction, classify_heuristic, run, score

__all__ = ["CORPUS", "EvalCase", "Metrics", "Prediction", "classify_heuristic", "run", "score"]
