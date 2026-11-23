"""Run a bounded, fully local synthetic Red/Blue security evaluation.

This CLI uses the same packaged engine as the operator's synthetic evaluation.
No hosted inference, network request or customer record is involved.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from shadow_hunter.synthetic_eval import evaluate, canonical_hash


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, choices=range(1, 9), default=8)
    parser.add_argument("--output", type=Path, help="Write stable redacted JSON evidence")
    args = parser.parse_args(argv)
    report = evaluate(rounds=args.rounds)
    encoded = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if report["all_expected_outcomes_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
