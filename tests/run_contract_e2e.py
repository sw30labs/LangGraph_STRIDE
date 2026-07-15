#!/usr/bin/env python3
"""Exercise the real CLI against each bundled mock-server persona."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_ready(url: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/v1/models", timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("mock inference server did not become ready")


def run_cli(env: dict[str, str], *args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "src.cli", *args],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--persona", choices=("vllm", "omlx"), required=True)
    args = parser.parse_args()
    port = free_port()
    root_url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "tests" / "mock_inference_server.py"),
            "--persona",
            args.persona,
            "--port",
            str(port),
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        wait_ready(root_url)
        env = os.environ.copy()
        env["STRIDE_BACKEND"] = args.persona
        env[f"{'VLLM' if args.persona == 'vllm' else 'MLX'}_BASE_URL"] = f"{root_url}/v1"
        info = run_cli(env, "info", "--json")
        assert f'"backend": "{args.persona}"' in info
        models = run_cli(
            env,
            "models",
            "--backend",
            args.persona,
            "--inference-url",
            f"{root_url}/admin/dashboard",
            "--inference-api-key",
            "local",
        )
        assert models.strip()
        smoke = run_cli(
            env,
            "smoke-inference",
            "--backend",
            args.persona,
            "--inference-url",
            root_url,
            "--inference-api-key",
            "local",
        )
        assert f"MOCK-INFERENCE persona={args.persona}" in smoke
        assert "<think>" not in smoke
        print(f"contract-e2e {args.persona}: PASS")
    finally:
        process.terminate()
        process.wait(timeout=5)


if __name__ == "__main__":
    main()
