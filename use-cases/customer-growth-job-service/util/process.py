"""Subprocess execution with deterministic environment and captured evidence."""
from __future__ import annotations
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
import json
import shutil
import socket
import os
import selectors
import shlex
import signal
import subprocess
import time
from typing import Iterator
from urllib import request
from util.images import E2EImagesDefinitions
from pathlib import Path


class E2EProcessHelper:
    @dataclass(frozen=True)
    class CommandResult:
        command: tuple[str, ...]
        cwd: Path
        return_code: int
        duration_seconds: float
        output: str

        @property
        def passed(self) -> bool:
            return self.return_code == 0

    class Deployment(ABC):
        """Backend-neutral contract used by every ordered E2E verifier."""

        backend = ""

        def __init__(self, context: VerificationContext) -> None:
            self.context = context
            self.environment = E2EImagesDefinitions.environment()
            self.container_proxy_host = (
                "127.0.0.1" if os.uname().sysname == "Linux" else "host.docker.internal"
            )
            self.commands = []
            self.details = []
            self.project_root = getattr(self, "project_root", Path.cwd())
            self.image_references = E2EImagesDefinitions.references(self.environment)
            self.images = E2EImagesDefinitions.E2EImageCatalog.from_environment(
                self.environment
            )
            self.workload_images = {
                name: self.image_references[name]
                for name in E2EImagesDefinitions.WORKLOADS
            }
            self.local_images = (
                tuple(
                    (
                        image
                        for image in self.image_references.values()
                        if image in E2EImagesDefinitions.LOCAL_IMAGES.values()
                    )
                )
                + self.images.local_chain_images
            )

        @abstractmethod
        def verify_prerequisites(self) -> None:
            """Fail unless all tools and runtime dependencies are available."""

        @abstractmethod
        def redeploy(self) -> None:
            """Create a clean, complete E2E topology."""

        @abstractmethod
        def cleanup(self) -> None:
            """Remove only resources owned by this E2E backend."""

        @abstractmethod
        @contextmanager
        def _forward_service(self, service: str, remote_port: int) -> Iterator[int]:
            """Expose one internal service port on loopback for the verifier."""
            yield 0

        @abstractmethod
        def service_logs(self, service: str, tail: int = 5000) -> str:
            """Return recent logs for one logical service."""

        @abstractmethod
        def internal_hostname(self, service: str) -> str:
            """Return the DNS name used by containers for another service."""

        def service_url(self, service: str, port: int, scheme: str) -> str:
            return f"{scheme}://{self.internal_hostname(service)}:{port}"

        def json_rpc(
            self,
            service: str,
            remote_port: int,
            method: str,
            params: list[object] | None = None,
        ) -> object:
            payload = json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
            ).encode()
            with self._forward_service(service, remote_port) as port:
                outgoing = request.Request(
                    f"http://127.0.0.1:{port}",
                    data=payload,
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with request.urlopen(outgoing, timeout=15) as response:
                    result = json.loads(response.read())
            if "error" in result or "result" not in result:
                raise RuntimeError(f"{service} JSON-RPC {method} failed: {result}")
            return result["result"]

        def _ensure_local_image(self, image: str) -> None:
            """Populate the local image store without trusting one registry request."""
            inspected = self._run(
                ("docker", "image", "inspect", image), allowed_codes={0, 1, 125}
            )
            if inspected.return_code != 0:
                self._pull_image(image)

        def _pull_image(self, image: str) -> None:
            """Retry image pulls that fail on transient registry transport errors."""
            failures: list[str] = []
            attempts = 3
            for attempt in range(1, attempts + 1):
                result = self._run(("docker", "pull", image), allowed_codes={0, 1, 125})
                if result.return_code == 0:
                    if attempt > 1:
                        self.details.append(
                            f"pulled {image} after {attempt} registry attempts"
                        )
                    return
                failure = "\n".join(result.output.splitlines()[-8:]).strip()
                failures.append(f"attempt {attempt}: {failure or 'no output'}")
                if attempt < attempts:
                    delay_seconds = 2**attempt
                    print(
                        f"        registry pull failed; retrying {image} in {delay_seconds}s ({attempt}/{attempts})",
                        flush=True,
                    )
                    time.sleep(delay_seconds)
            raise RuntimeError(
                f"docker pull failed after {attempts} attempts: {image}\n"
                + "\n".join(failures)
            )

        def _run(
            self,
            command: tuple[str, ...],
            *,
            cwd: Path = None,
            allowed_codes: set[int] | None = None,
        ) -> E2EProcessHelper.CommandResult:
            result = E2EProcessHelper.run_command(
                command,
                cwd=cwd or self.project_root,
                environment=self.environment,
                timeout_seconds=self.context.timeout_seconds,
                stream=False,
            )
            self.commands.append(result)
            if result.return_code not in (allowed_codes or {0}):
                tail = "\n".join(result.output.splitlines()[-40:])
                raise RuntimeError(
                    f"command failed ({result.return_code}): {' '.join(command)}\n{tail}"
                )
            return result

        @staticmethod
        def require_executables(*executables: str) -> None:
            for executable in executables:
                if shutil.which(executable) is None:
                    raise RuntimeError(
                        f"required executable is unavailable: {executable}"
                    )

        def free_port(self) -> int:
            for port in getattr(self, "port_range", (0,)):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                    try:
                        listener.bind(("127.0.0.1", port))
                    except OSError:
                        continue
                    return listener.getsockname()[1]
            raise RuntimeError("no free port remains in the configured E2E host range")

    @staticmethod
    def run_command(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str] | None = None,
        timeout_seconds: int = 900,
        stream: bool = True,
    ) -> E2EProcessHelper.CommandResult:
        env = os.environ.copy()
        if environment:
            env.update(environment)
        started = time.monotonic()
        display = shlex.join(command)
        if len(display) > 240:
            display = f"{display[:237]}..."
        print(f"      $ {display}", flush=True)
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            assert process.stdout is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            output_lines: list[str] = []
            heartbeat_at = started + 15
            deadline = started + timeout_seconds
            timed_out = False
            while process.poll() is None:
                now = time.monotonic()
                if now >= deadline:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                events = selector.select(timeout=min(1, deadline - now))
                for key, _ in events:
                    line = key.fileobj.readline()
                    if line:
                        output_lines.append(line)
                        if stream:
                            print(f"        {line}", end="", flush=True)
                if time.monotonic() >= heartbeat_at:
                    elapsed = int(time.monotonic() - started)
                    print(f"        ... still running ({elapsed}s)", flush=True)
                    heartbeat_at = time.monotonic() + 15
            remainder = process.stdout.read()
            if remainder:
                output_lines.append(remainder)
                if stream:
                    for line in remainder.splitlines(keepends=True):
                        print(f"        {line}", end="", flush=True)
            return_code = process.wait()
            if timed_out:
                return_code = 124
                message = f"Timed out after {timeout_seconds} seconds.\n"
                output_lines.append(message)
                print(f"        {message}", end="", flush=True)
            output = "".join(output_lines)
        except OSError as error:
            return_code = 127
            output = str(error)
            print(f"        {output}", flush=True)
        return E2EProcessHelper.CommandResult(
            command=command,
            cwd=cwd,
            return_code=return_code,
            duration_seconds=time.monotonic() - started,
            output=output,
        )
