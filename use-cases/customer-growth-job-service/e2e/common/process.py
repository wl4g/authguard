"""Subprocess execution with deterministic environment and captured evidence."""

from __future__ import annotations

import os
from pathlib import Path
import selectors
import shlex
import signal
import subprocess
import time

from .model import CommandResult


def run_command(
    command: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str] | None = None,
    timeout_seconds: int = 900,
    stream: bool = True,
) -> CommandResult:
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
    return CommandResult(
        command=command,
        cwd=cwd,
        return_code=return_code,
        duration_seconds=time.monotonic() - started,
        output=output,
    )
