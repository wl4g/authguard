#!/usr/bin/env python3
"""Clean-build-test orchestration for all customer growth authorization examples."""
from __future__ import annotations
from verifier.context import VerificationContext, VerificationResult
from util.constant import E2EOtherDefinitions
from util.report import E2EReportHelper
import argparse
import importlib
import sys
import time
import traceback


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deploy and verify the complete AuthGuard E2E use case."
    )
    parser.add_argument(
        "--deployer",
        choices=("kubernetes", "docker"),
        default="kubernetes",
        help="Disposable deployment backend used by scenarios 00 and 10-42.",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=("cleanup",),
        help="Run `cleanup` to remove resources owned by the selected deployer.",
    )
    parser.add_argument(
        "-r", "--rounds", type=int, default=1, help="Number of complete clean rounds."
    )
    parser.add_argument(
        "-s",
        "--scenario",
        action="append",
        default=[],
        help="Verifier id or comma-separated ids to run, for example -s 01,02.",
    )
    parser.add_argument(
        "-l", "--list", action="store_true", help="List verifier groups and exit."
    )
    parser.add_argument(
        "--skip-clean",
        action="store_true",
        help="Skip removal of owned deployment resources before redeploying.",
    )
    parser.add_argument(
        "--skip-image-build",
        action="store_true",
        help="Reuse locally tagged images during infrastructure phase 00.",
    )
    parser.add_argument(
        "--timeout", type=int, default=900, help="Per-command timeout in seconds."
    )
    parser.add_argument(
        "--cleanup-after-run",
        action="store_true",
        help="Remove resources owned by the selected deployer after the run, including after failure or interruption.",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Alias for the `cleanup` command; remove E2E resources and exit.",
    )
    return parser.parse_args()


def selected_scenarios(raw_values: list[str]) -> list[str]:
    if not raw_values:
        return list(E2EOtherDefinitions.DEFAULT_SCENARIOS)
    selected: list[str] = []
    for raw_value in raw_values:
        for scenario_id in raw_value.split(","):
            scenario_id = scenario_id.strip().zfill(2)
            if scenario_id not in E2EOtherDefinitions.SCENARIOS:
                raise ValueError(f"Unknown verifier id: {scenario_id}")
            if scenario_id not in selected:
                selected.append(scenario_id)
    return selected


def run_verifier(scenario_id: str, context: VerificationContext) -> VerificationResult:
    title, module_name = E2EOtherDefinitions.SCENARIOS[scenario_id]
    started = time.monotonic()
    try:
        module = importlib.import_module(module_name)
        class_name = (
            "E2ES"
            + scenario_id
            + "".join(
                (word.title() for word in module_name.rsplit(".", 1)[-1][4:].split("_"))
            )
            + "Verifier"
        )
        verifier = getattr(module, class_name)(context)
        verifier.deploy(context)
        verifier.init(context)
        result = verifier.verifier(context)
        if not isinstance(result, VerificationResult):
            raise TypeError(
                f"{module_name}.{class_name}.verifier() returned an invalid result"
            )
        result.duration_seconds = time.monotonic() - started
        return result
    except Exception:
        return VerificationResult(
            scenario_id=scenario_id,
            title=title,
            passed=False,
            duration_seconds=time.monotonic() - started,
            details=[traceback.format_exc()],
        )


def cleanup_deployment(context: VerificationContext) -> bool:
    started = time.monotonic()
    print(f"\n  [cleanup] Remove {context.deployer} E2E resources", flush=True)
    try:
        VerificationContext.create_deployer(context).cleanup()
    except Exception:
        print(f"  [cleanup] FAIL ({time.monotonic() - started:.2f}s)", flush=True)
        traceback.print_exc()
        return False
    print(f"  [cleanup] PASS ({time.monotonic() - started:.2f}s)", flush=True)
    return True


def main() -> int:
    args = parse_args()
    cleanup_requested = args.command == "cleanup" or args.cleanup
    if cleanup_requested:
        if args.cleanup_after_run:
            print(
                "--cleanup and --cleanup-after-run cannot be combined", file=sys.stderr
            )
            return 2
        context = VerificationContext(
            round_number=0,
            clean=False,
            timeout_seconds=args.timeout,
            build_images=False,
            deployer=args.deployer,
        )
        return 0 if cleanup_deployment(context) else 1
    if args.list:
        for scenario_id, (title, _) in E2EOtherDefinitions.SCENARIOS.items():
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
    archive = E2EReportHelper.archive_reports()
    if archive:
        print(f"Archived previous reports: {archive}")
    context = VerificationContext(
        round_number=args.rounds,
        clean=not args.skip_clean,
        timeout_seconds=args.timeout,
        build_images=not args.skip_image_build,
        deployer=args.deployer,
    )
    exit_code = 1
    try:
        all_rounds: list[list[VerificationResult]] = []
        for round_number in range(1, args.rounds + 1):
            print(f"\nRound {round_number}/{args.rounds}")
            context = VerificationContext(
                round_number=round_number,
                clean=not args.skip_clean,
                timeout_seconds=args.timeout,
                build_images=not args.skip_image_build,
                deployer=args.deployer,
            )
            results: list[VerificationResult] = []
            for scenario_id in scenario_ids:
                title = E2EOtherDefinitions.SCENARIOS[scenario_id][0]
                print(f"  [{scenario_id}] {title}", flush=True)
                result = run_verifier(scenario_id, context)
                results.append(result)
                E2EReportHelper.write_round_report(round_number, result)
                status = "PASS" if result.passed else "FAIL"
                print(
                    f"  [{scenario_id}] {status} ({result.duration_seconds:.2f}s)",
                    flush=True,
                )
            all_rounds.append(results)
        summary = E2EReportHelper.write_summary(all_rounds)
        passed = all((result.passed for results in all_rounds for result in results))
        print(f"\nSummary: {summary}")
        exit_code = 0 if passed else 1
    except KeyboardInterrupt:
        print("\nE2E interrupted by user.", file=sys.stderr, flush=True)
        exit_code = 130
    finally:
        if (
            args.cleanup_after_run
            and (not cleanup_deployment(context))
            and (exit_code == 0)
        ):
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
