#!/usr/bin/env python3
"""Clean-build-test orchestration for all customer growth authorization examples."""

from __future__ import annotations

import argparse
import importlib
import sys
import time
import traceback

from common import (
    DEFAULT_SCENARIOS,
    SCENARIOS,
    RunContext,
    VerificationResult,
    archive_reports,
    write_round_report,
    write_summary,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Rebuild and verify the portable multi-language Authguard E2E use case."
    )
    parser.add_argument(
        "-r", "--rounds", type=int, default=1, help="Number of complete clean rounds."
    )
    parser.add_argument(
        "-s",
        "--scenario",
        action="append",
        default=[],
        help="Verifier id or comma-separated ids to run, for example -s 11,12.",
    )
    parser.add_argument(
        "-l", "--list", action="store_true", help="List verifier groups and exit."
    )
    parser.add_argument(
        "--skip-clean",
        action="store_true",
        help="Reuse project build output while still disabling test caches.",
    )
    parser.add_argument(
        "--skip-image-build",
        action="store_true",
        help="Reuse locally tagged images during k3s deployment phase 21.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=900,
        help="Per-command timeout in seconds.",
    )
    return parser.parse_args()


def selected_scenarios(raw_values: list[str]) -> list[str]:
    if not raw_values:
        return list(DEFAULT_SCENARIOS)
    selected: list[str] = []
    for raw_value in raw_values:
        for scenario_id in raw_value.split(","):
            scenario_id = scenario_id.strip().zfill(2)
            if scenario_id not in SCENARIOS:
                raise ValueError(f"Unknown verifier id: {scenario_id}")
            if scenario_id not in selected:
                selected.append(scenario_id)
    return selected


def run_verifier(scenario_id: str, context: RunContext) -> VerificationResult:
    title, module_name = SCENARIOS[scenario_id]
    started = time.monotonic()
    try:
        module = importlib.import_module(module_name)
        result = module.verify(context)
        if not isinstance(result, VerificationResult):
            raise TypeError(f"{module_name}.verify() returned an invalid result")
        return result
    except Exception:
        return VerificationResult(
            scenario_id=scenario_id,
            title=title,
            passed=False,
            duration_seconds=time.monotonic() - started,
            details=[traceback.format_exc()],
        )


def main() -> int:
    args = parse_args()
    if args.list:
        for scenario_id, (title, _) in SCENARIOS.items():
            print(f"{scenario_id}  {title}")
        return 0
    if args.rounds < 1:
        print("--rounds must be at least 1", file=sys.stderr)
        return 2
    if args.timeout < 1:
        print("--timeout must be at least 1", file=sys.stderr)
        return 2
    try:
        scenario_ids = selected_scenarios(args.scenario)
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    archive = archive_reports()
    if archive:
        print(f"Archived previous reports: {archive}")

    all_rounds: list[list[VerificationResult]] = []
    for round_number in range(1, args.rounds + 1):
        print(f"\nRound {round_number}/{args.rounds}")
        context = RunContext(
            round_number=round_number,
            clean=not args.skip_clean,
            timeout_seconds=args.timeout,
            build_images=not args.skip_image_build,
        )
        results: list[VerificationResult] = []
        for scenario_id in scenario_ids:
            title = SCENARIOS[scenario_id][0]
            print(f"  [{scenario_id}] {title} ... ", end="", flush=True)
            result = run_verifier(scenario_id, context)
            results.append(result)
            write_round_report(round_number, result)
            status = "PASS" if result.passed else "FAIL"
            print(f"{status} ({result.duration_seconds:.2f}s)")
        all_rounds.append(results)

    summary = write_summary(all_rounds)
    passed = all(result.passed for results in all_rounds for result in results)
    print(f"\nSummary: {summary}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
