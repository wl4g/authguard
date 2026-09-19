#!/usr/bin/env python3
"""Validate an AuthGuard business service Helm Chart integration without changing it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


ALLOWED_SUFFIXES = {".css", ".svg", ".png", ".webp", ".woff", ".woff2"}
MAX_CONFIG_MAP_BYTES = 900 * 1024
AUTHGUARD_OCI_REFERENCE = "oci://ghcr.io/wl4g/charts/authguard"
INTEGRATION_ROOT = "authguard-middleware"


class ValidationError(RuntimeError):
    """A business service Helm Chart violates the AuthGuard integration contract."""


def command(arguments: list[str]) -> str:
    completed = subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    if completed.returncode != 0:
        raise ValidationError(
            f"command failed ({completed.returncode}): {' '.join(arguments)}\n"
            f"{completed.stdout}"
        )
    return completed.stdout


def require_tokens(path: Path, tokens: tuple[str, ...]) -> str:
    if not path.is_file():
        raise ValidationError(f"missing required file: {path}")
    source = path.read_text(encoding="utf-8")
    missing = [token for token in tokens if token not in source]
    if missing:
        raise ValidationError(f"{path} lacks required contract markers: {missing}")
    return source


def latest_stable_version() -> str:
    metadata = command(["helm", "show", "chart", AUTHGUARD_OCI_REFERENCE])
    match = re.search(r"(?m)^version:\s*['\"]?([^'\"\s]+)['\"]?\s*$", metadata)
    if match is None:
        raise ValidationError("GHCR AuthGuard Chart metadata does not declare a version")
    return match.group(1)


def validate_application_hosts(application_id: str | None, hosts: list[str]) -> None:
    if bool(application_id) != bool(hosts):
        raise ValidationError(
            "--application-id and at least one --application-host must be provided together"
        )
    domain = re.compile(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    )
    for host in hosts:
        if host != host.lower() or domain.fullmatch(host) is None:
            raise ValidationError(
                f"Application host must be an exact lower-case DNS name: {host!r}"
            )


def validate_assets(theme_dir: Path, application_id: str | None) -> list[Path]:
    if theme_dir.is_symlink() or not theme_dir.is_dir():
        raise ValidationError(f"theme directory does not exist: {theme_dir}")
    assets = sorted(path for path in theme_dir.rglob("*") if path.is_file())
    if not assets:
        raise ValidationError(f"theme directory is empty: {theme_dir}")
    if any(path.is_symlink() for path in theme_dir.rglob("*")):
        raise ValidationError("theme directory must not contain symbolic links")
    invalid = [path for path in assets if path.suffix.lower() not in ALLOWED_SUFFIXES]
    if invalid:
        raise ValidationError(f"unsupported theme assets: {invalid}")
    if sum(path.stat().st_size for path in assets) > MAX_CONFIG_MAP_BYTES:
        raise ValidationError("theme assets exceed the 900 KiB ConfigMap safety budget")
    basenames = [path.name for path in assets]
    if len(basenames) != len(set(basenames)):
        raise ValidationError("theme asset basenames must be unique because ConfigMap keys are flat")

    css_files = [path for path in assets if path.suffix.lower() == ".css"]
    if not css_files:
        raise ValidationError("theme requires at least one CSS file")
    for path in css_files:
        source = path.read_text(encoding="utf-8")
        lowered = source.lower()
        if (
            "@import" in lowered
            or "javascript:" in lowered
            or "expression(" in lowered
            or re.search(r"url\(\s*['\"]?\s*(?:https?:)?//", lowered)
        ):
            raise ValidationError(f"theme CSS must be self-contained and non-executable: {path}")
        if application_id and not re.search(
            rf"data-application-theme\s*=\s*(['\"]){re.escape(application_id)}\1",
            source,
        ):
            raise ValidationError(f"theme CSS is not scoped to application {application_id!r}: {path}")
    for path in (path for path in assets if path.suffix.lower() == ".svg"):
        lowered = path.read_text(encoding="utf-8").lower()
        if (
            any(token in lowered for token in ("<script", "javascript:", "<foreignobject"))
            or re.search(r"\bon[a-z]+\s*=", lowered)
            or re.search(r"(?:href|xlink:href)\s*=\s*(['\"])\s*(?:https?:|//)", lowered)
        ):
            raise ValidationError(f"SVG contains executable or remote content: {path}")
    return assets


def render(
    chart: Path,
    release: str,
    values_files: list[Path],
    set_values: list[str],
    enabled: bool | None,
) -> str:
    arguments = ["helm", "template", release, str(chart)]
    for values_file in values_files:
        arguments.extend(("--values", str(values_file)))
    for value in set_values:
        arguments.extend(("--set", value))
    if enabled is not None:
        arguments.extend(("--set", f"{INTEGRATION_ROOT}.enabled={'true' if enabled else 'false'}"))
    return command(arguments)


def deploy(
    chart: Path,
    release: str,
    namespace: str,
    timeout: str,
    values_files: list[Path],
    set_values: list[str],
    cleanup: bool,
) -> None:
    arguments = [
        "helm",
        "upgrade",
        "--install",
        release,
        str(chart),
        "--namespace",
        namespace,
        "--create-namespace",
        "--atomic",
        "--wait",
        "--timeout",
        timeout,
    ]
    for values_file in values_files:
        arguments.extend(("--values", str(values_file)))
    for value in set_values:
        arguments.extend(("--set", value))
    arguments.extend(("--set", f"{INTEGRATION_ROOT}.enabled=true"))

    installed = False
    try:
        command(arguments)
        installed = True
        try:
            status = json.loads(
                command(
                    [
                        "helm",
                        "status",
                        release,
                        "--namespace",
                        namespace,
                        "--output",
                        "json",
                    ]
                )
            )
        except json.JSONDecodeError as error:
            raise ValidationError("Helm status did not return valid JSON") from error
        if status.get("info", {}).get("status") != "deployed":
            raise ValidationError("deployment smoke test did not reach Helm deployed status")
    finally:
        if cleanup and installed:
            command(["helm", "uninstall", release, "--namespace", namespace, "--wait"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a vendored AuthGuard dependency, values, renders, and optional deployment."
    )
    parser.add_argument(
        "--chart", type=Path, required=True, help="Business service Helm Chart root"
    )
    parser.add_argument("--theme-dir", default="files/authguard-theme")
    parser.add_argument("--release", default="authguard-integration-check")
    parser.add_argument("--application-id")
    parser.add_argument(
        "--application-host",
        action="append",
        default=[],
        help="Developer-provided business service DNS host; repeat for additional hosts",
    )
    parser.add_argument(
        "--allow-local-repository",
        action="store_true",
        help="Allow a file:// AuthGuard dependency only for repository-local Chart development",
    )
    parser.add_argument(
        "--deploy-release",
        help="Explicit Helm release for an authorized deployment smoke test",
    )
    parser.add_argument(
        "--deploy-namespace",
        help="Explicit Kubernetes namespace for an authorized deployment smoke test",
    )
    parser.add_argument("--deploy-timeout", default="10m")
    parser.add_argument(
        "--cleanup-deployment",
        action="store_true",
        help="Uninstall the smoke-test release after a successful deployment",
    )
    parser.add_argument("--values", action="append", default=[], type=Path)
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        dest="set_values",
        help="Additional Helm key=value used for both render modes; repeat as needed",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    validate_application_hosts(args.application_id, args.application_host)
    if bool(args.deploy_release) != bool(args.deploy_namespace):
        raise ValidationError("--deploy-release and --deploy-namespace must be provided together")
    if args.cleanup_deployment and not args.deploy_release:
        raise ValidationError("--cleanup-deployment requires deployment arguments")

    chart = args.chart.resolve()
    values_path = chart / "values.yaml"
    chart_source = require_tokens(
        chart / "Chart.yaml",
        (
            "name: authguard",
            "alias: authguard-middleware",
            "condition: authguard-middleware.enabled",
        ),
    )
    authguard_dependency = re.search(
        r"(?ms)^\s*-\s*name:\s*authguard\s*$.*?(?=^\s*-\s*name:|\Z)",
        chart_source,
    )
    if authguard_dependency is None:
        raise ValidationError("Chart.yaml lacks the AuthGuard dependency")
    ghcr_repository = "repository: oci://ghcr.io/wl4g/charts"
    if ghcr_repository not in chart_source and not args.allow_local_repository:
        raise ValidationError(
            "AuthGuard dependency must use oci://ghcr.io/wl4g/charts; "
            "use --allow-local-repository only for repository-local Chart development"
        )
    values_source = require_tokens(
        values_path,
        (
            "enabled: false",
        ),
    )
    integration_roots = re.findall(
        rf"(?m)^{re.escape(INTEGRATION_ROOT)}:\s*(?:#.*)?$", values_source
    )
    if len(integration_roots) != 1:
        raise ValidationError(
            f"values.yaml must contain exactly one top-level {INTEGRATION_ROOT} map"
        )
    if re.search(r"(?m)^authguard:\s*(?:#.*)?$", values_source):
        raise ValidationError("values.yaml must not contain a parallel AuthGuard values root")

    theme_dir = chart / args.theme_dir
    theme_template = chart / "templates/authguard-theme.yaml"
    theme_configured = (
        theme_dir.exists()
        or theme_template.exists()
        or "files/authguard-theme/*" in values_source
    )
    assets: list[Path] = []
    if theme_configured:
        require_tokens(
            values_path,
            ("themeRevision:", "themeConfigMap:", "files: files/authguard-theme/*"),
        )
        require_tokens(
            theme_template,
            ('index .Values "authguard-middleware"', ".Files.Glob", "authguard-login-theme"),
        )
        assets = validate_assets(theme_dir, args.application_id)

    dependency_output = command(["helm", "dependency", "list", str(chart)])
    dependency = re.search(
        r"(?mi)^authguard\s+(\S+)\s+(\S+)\s+ok\s*$", dependency_output
    )
    if dependency is None:
        raise ValidationError("the vendored AuthGuard dependency is missing or out of date")
    version, repository = dependency.groups()
    if not re.fullmatch(
        r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?",
        version,
    ):
        raise ValidationError("AuthGuard dependency must use one exact release version")
    if not repository.startswith("oci://ghcr.io/wl4g/charts") and not args.allow_local_repository:
        raise ValidationError("resolved AuthGuard dependency did not come from GHCR")
    if not args.allow_local_repository:
        latest_version = latest_stable_version()
        if version != latest_version:
            raise ValidationError(
                f"AuthGuard {version} is pinned, but GHCR latest stable is {latest_version}"
            )
    lock_source = require_tokens(chart / "Chart.lock", ("name: authguard", "digest:"))
    del lock_source
    archives = list((chart / "charts").glob("authguard-*.tgz"))
    expected_archive = chart / "charts" / f"authguard-{version}.tgz"
    if len(archives) != 1 or not expected_archive.is_file():
        raise ValidationError(
            f"charts/ must contain only the locked archive {expected_archive.name}"
        )

    lint_arguments = ["helm", "lint", str(chart)]
    for values_file in args.values:
        lint_arguments.extend(("--values", str(values_file)))
    for value in args.set_values:
        lint_arguments.extend(("--set", value))
    command(lint_arguments)
    normal = render(chart, f"{args.release}-app", args.values, args.set_values, None)
    dependency_source = re.compile(
        r"(?m)^# Source: .*/charts/authguard-middleware/"
    )
    if dependency_source.search(normal):
        raise ValidationError("normal business service render must keep AuthGuard disabled")
    if theme_configured and "app.kubernetes.io/component: authguard-login-theme" in normal:
        raise ValidationError("normal business service render must keep the theme disabled")

    enabled = render(chart, f"{args.release}-authguard", args.values, args.set_values, True)
    if not dependency_source.search(enabled):
        raise ValidationError("opt-in render did not include the AuthGuard dependency")
    if theme_configured:
        if "app.kubernetes.io/component: authguard-login-theme" not in enabled:
            raise ValidationError("opt-in render did not create the business theme ConfigMap")
        missing_assets = [
            path.name
            for path in assets
            if not re.search(rf"(?m)^  {re.escape(path.name)}:", enabled)
        ]
        if missing_assets:
            raise ValidationError(f"rendered theme ConfigMap lacks assets: {missing_assets}")
        mount = "/usr/share/nginx/html/assets/themes/custom"
        if enabled.count(mount) != 1:
            raise ValidationError("custom theme must be mounted exactly once, in AuthGuard Web")
    if "theme-pack-installer" in enabled:
        raise ValidationError("obsolete theme image/init-container delivery is present")
    if args.application_id and not re.search(
        rf"(?m)^      applications:\s*$[\s\S]*?^        {re.escape(args.application_id)}:\s*$",
        enabled,
    ):
        raise ValidationError("rendered AuthGuard configuration lacks the requested application ID")
    missing_hosts = [host for host in args.application_host if host not in enabled]
    if missing_hosts:
        raise ValidationError(
            f"rendered AuthGuard configuration lacks Application hosts: {missing_hosts}"
        )

    if args.deploy_release:
        deploy(
            chart,
            args.deploy_release,
            args.deploy_namespace,
            args.deploy_timeout,
            args.values,
            args.set_values,
            args.cleanup_deployment,
        )

    theme_summary = (
        f", packages {len(assets)} local theme assets, and mounts them only in AuthGuard Web"
        if theme_configured
        else ", with no custom theme requested"
    )
    deployment_summary = (
        f", and validated deployment {args.deploy_release} in {args.deploy_namespace}"
        if args.deploy_release
        else ""
    )
    print(
        f"PASS: {chart} vendors AuthGuard {version} from {repository}, keeps it opt-in"
        f"{theme_summary}{deployment_summary}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValidationError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
