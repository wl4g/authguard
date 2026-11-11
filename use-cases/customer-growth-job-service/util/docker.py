"""Docker Compose deployment lifecycle equivalent to the Kubernetes E2E."""
from __future__ import annotations
from util.process import E2EProcessHelper
from contextlib import contextmanager
from dataclasses import replace
import os
import re
import shutil
import socket
import time
from pathlib import Path
from typing import Iterator
from urllib import error, request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from verifier.context import VerificationContext


class E2EDockerDeployer(E2EProcessHelper.Deployment):
    """Own one isolated Docker Compose project and all of its volumes."""

    backend = "docker"

    def internal_hostname(self, service: str) -> str:
        return service

    def detect_runtime(self) -> str:
        """Keep the caller's Docker endpoint for native, Colima and OrbStack."""
        active = self.environment.get("DOCKER_CONTEXT") or os.getenv("DOCKER_CONTEXT")
        if (
            not active
            and (not self.environment.get("DOCKER_HOST"))
            and (not os.getenv("DOCKER_HOST"))
        ):
            active = self._run(("docker", "context", "show")).output.strip()
            if active:
                self.environment["DOCKER_CONTEXT"] = active
        runtime = (
            "colima"
            if active and active.startswith("colima")
            else "orbstack"
            if active == "orbstack"
            else "native"
        )
        self.details.append(
            f"Docker runtime: {runtime}; endpoint: {active or 'DOCKER_HOST/default'}"
        )
        return runtime

    @contextmanager
    def _forward_service(self, service: str, remote_port: int) -> Iterator[int]:
        key = (service, remote_port)
        port = self._published_ports.get(key)
        if port is None:
            result = self._compose("port", service, str(remote_port))
            endpoint = result.output.strip().splitlines()[-1]
            try:
                port = int(endpoint.rsplit(":", 1)[1])
            except (IndexError, ValueError) as failure:
                raise RuntimeError(
                    f"Docker Compose returned an invalid port for {service}:{remote_port}: {endpoint!r}"
                ) from failure
            self._published_ports[key] = port
        yield port

    def service_logs(self, service: str, tail: int = 5000) -> str:
        output = self._compose("logs", "--no-color", f"--tail={tail}", service).output
        records: list[str] = []
        for line in output.splitlines():
            if line.startswith("Attaching to "):
                continue
            records.append(line.split(" | ", 1)[1] if " | " in line else line)
        return "\n".join(records)

    def _wait_for_tcp(self, service: str, remote_port: int) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        last_error = "not published"
        while time.monotonic() < deadline:
            try:
                with self._forward_service(service, remote_port) as port:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        return
            except (OSError, RuntimeError) as failure:
                last_error = str(failure)
                time.sleep(1)
        raise RuntimeError(
            f"timed out waiting for Docker service {service}: {last_error}"
        )

    def _wait_for_http(self, service: str, remote_port: int, path: str) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        last_error = "not available"
        while time.monotonic() < deadline:
            try:
                with self._forward_service(service, remote_port) as port:
                    with request.urlopen(
                        f"http://127.0.0.1:{port}{path}", timeout=3
                    ) as response:
                        if response.status < 500:
                            return
            except (error.URLError, OSError, RuntimeError) as failure:
                last_error = str(failure)
                time.sleep(1)
        raise RuntimeError(
            f"timed out waiting for Docker HTTP service {service}{path}: {last_error}"
        )

    def _wait_for_json_rpc(self, service: str, remote_port: int, method: str) -> None:
        deadline = time.monotonic() + self.context.timeout_seconds
        last_error = "not available"
        while time.monotonic() < deadline:
            try:
                self.json_rpc(service, remote_port, method)
                return
            except (error.URLError, OSError, RuntimeError) as failure:
                last_error = str(failure)
                time.sleep(1)
        raise RuntimeError(
            f"timed out waiting for Docker JSON-RPC {service}.{method}: {last_error}"
        )

    def _compose_container_id(self, service: str) -> str:
        container_id = self._compose("ps", "-q", service).output.strip()
        if not container_id:
            raise RuntimeError(f"Docker Compose service has no container: {service}")
        return container_id

    def _compose(self, *arguments: str, allowed_codes: set[int] | None = None):
        result = self._run(
            (
                "docker",
                "compose",
                "-p",
                self.project_name,
                "-f",
                str(self.compose_file),
                *arguments,
            ),
            cwd=self.compose_file.parent,
            allowed_codes=allowed_codes,
        )
        output = re.sub("\\x1b\\[[0-9;]*m", "", result.output)
        output = "\n".join(
            (
                line
                for line in output.splitlines()
                if not line.startswith(">>>> Executing external compose provider ")
            )
        ).strip()
        return replace(result, output=output)

    def cleanup(self) -> None:
        E2EDockerCleaner(self).cleanup()

    def __init__(
        self,
        context: VerificationContext,
        *,
        project_name: str,
        compose_file: Path,
        runtime_dir: Path,
        cleanup_image: str | None = None,
    ) -> None:
        super().__init__(context)
        self.project_name = project_name
        self.compose_file = compose_file
        self.runtime_dir = runtime_dir
        self.owned_runtime_dir = runtime_dir.resolve()
        self._published_ports = {}
        self.cleanup_image = cleanup_image

    def verify_prerequisites(self) -> None:
        self.require_executables("docker")
        self._run(("docker", "version"))
        self.detect_runtime()
        self._run(("docker", "compose", "version"))

    def redeploy(self) -> None:
        raise NotImplementedError(
            "the infrastructure scenario supplies the deployment plan"
        )

    def exec(self, service: str, *command: str):
        return self._compose("exec", "-T", service, *command)


class E2EDockerCleaner:
    """Remove only resources owned by the supplied E2E deployment."""

    def __init__(self, deployer: E2EDockerDeployer) -> None:
        self.deployer = deployer

    def __getattr__(self, name):
        return getattr(self.deployer, name)

    def cleanup(self) -> None:
        if not self.compose_file.is_file():
            return
        if not self.runtime_dir.exists():
            self._prepare_runtime_files()
        self._compose(
            "down",
            "--volumes",
            "--remove-orphans",
            "--timeout",
            "15",
            allowed_codes={0, 1},
        )
        if self.runtime_dir.exists():
            try:
                shutil.rmtree(self.runtime_dir)
            except PermissionError:
                if not self.cleanup_image:
                    raise
                expected = self.owned_runtime_dir
                if self.runtime_dir.resolve() != expected:
                    raise RuntimeError(
                        f"refusing privileged cleanup outside {expected}"
                    )
                self._run(
                    (
                        "docker",
                        "run",
                        "--rm",
                        "--user",
                        "0",
                        "-v",
                        f"{self.runtime_dir}:/runtime",
                        "--entrypoint",
                        "/bin/bash",
                        self.cleanup_image,
                        "-ec",
                        "find /runtime -mindepth 1 -delete",
                    )
                )
                shutil.rmtree(self.runtime_dir)
        self._published_ports.clear()
