#!/usr/bin/env python3
"""Purple-team self-assessment: replay attack chains through the live pipeline.

Usage:
    python -m app.purple [--base-url http://localhost:8000] [--chain NAME]

Runs one or all attack chains against a running SentinelForge stack and prints
a Detection Scorecard.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys


async def main():
    parser = argparse.ArgumentParser(description="Purple-team self-assessment")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Backend URL")
    parser.add_argument("--chain", default="", help="Run a single chain by name")
    parser.add_argument("--output-dir", default="purple_results", help="Output directory for results JSON")
    args = parser.parse_args()

    from app.purple.chains import ALL_CHAINS
    from app.purple.runner import run_chain
    from app.purple.scorecard import aggregate, score_chain

    chains = [c for c in ALL_CHAINS if not args.chain or c.name == args.chain]
    if not chains:
        print(f"Unknown chain: {args.chain}")
        print(f"Available: {[c.name for c in ALL_CHAINS]}")
        sys.exit(1)

    results = []
    for chain in chains:
        observed = await run_chain(chain, base_url=args.base_url)
        if "error" in observed:
            print(f"\n  ⚠ Error: {observed['error']}")
        else:
            score = score_chain(chain, observed)
            results.append(score)

    if not results:
        print("\nNo valid results to score.")
        sys.exit(1)

    agg = aggregate(results)

    # Print scorecard table.
    print(f"\n{'='*60}")
    print("  DETECTION SCORECARD")
    print(f"{'='*60}")
    print(f"  {'Chain':<22} {'Pass':>5} {'Corr':>5} {'Recall':>8} {'Verdict':<18}")
    print(f"  {'-'*22} {'-'*5} {'-'*5} {'-'*8} {'-'*18}")
    for r in agg["results"]:
        passed = "✓" if r["passed"] else "✗"
        corr = "✓" if r["correlation_ok"] else "✗"
        print(f"  {r['chain']:<22} {passed:>5} {corr:>5} {r['technique_recall']:>8.1%} {r['verdict']:<18}")
    print()
    print(f"  DETECTION SCORE: {agg['passed']}/{agg['chains']} chains")
    print(f"  Detection rate:  {agg['detection_rate']:.0%}")
    print(f"  Avg technique recall: {agg['avg_technique_recall']:.1%}")

    # Write results.
    os.makedirs(args.output_dir, exist_ok=True)
    out_path = os.path.join(args.output_dir, "latest.json")
    with open(out_path, "w") as f:
        json.dump(agg, f, indent=2, default=str)
    print(f"\n  Results written to {out_path}")

    sys.exit(0 if agg["passed"] == agg["chains"] else 1)


if __name__ == "__main__":
    asyncio.run(main())
