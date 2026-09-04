"""Subprocess execution with deterministic environment and captured evidence."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import time

from .model import CommandResult


def run_command(
    command: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
    timeout_seconds: int = 900,
) -> CommandResult:
    env = os.environ.copy()
    if environment:
        env.update(environment)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout_seconds,
        )
        return_code = completed.returncode
        output = completed.stdout
    except subprocess.TimeoutExpired as error:
        return_code = 124
        captured = error.stdout or ""
        if isinstance(captured, bytes):
            captured = captured.decode("utf-8", errors="replace")
        output = f"{captured}\nTimed out after {timeout_seconds} seconds."
    except OSError as error:
        return_code = 127
        output = str(error)
    return CommandResult(
        command=command,
        cwd=cwd,
        return_code=return_code,
        duration_seconds=time.monotonic() - started,
        output=output,
    )
