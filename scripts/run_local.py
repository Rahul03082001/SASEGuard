#!/usr/bin/env python3
"""Start all four services natively, without Docker.

Every service binds to 127.0.0.1 only. That is not decoration: the private
identity, policy, and application services must not be reachable from the
network, because the gateway is the component that enforces policy and the
others assume they are only ever called by it.

Usage::

    python scripts/run_local.py             # start everything, Ctrl-C to stop
    python scripts/run_local.py --reload    # auto-reload on source changes
"""

from __future__ import annotations

import argparse
import pathlib
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apps.common import ENV_FILE, PUBLIC_KEY_FILE, load_dotenv  # noqa: E402

HOST = "127.0.0.1"

#: (name, import path, port, public?) -- order matters: dependencies first, so
#: the gateway is not accepting requests before policy can answer them.
SERVICES: tuple[tuple[str, str, int, bool], ...] = (
    ("identity", "apps.identity:app", 8081, False),
    ("policy", "apps.policy:app", 8082, False),
    ("apps", "apps.mock_apps:app", 8083, False),
    ("gateway", "apps.gateway:app", 8080, True),
)


def wait_for_health(port: int, timeout: float = 20.0) -> bool:
    """Poll ``/healthz`` until it answers or the timeout expires."""
    deadline = time.monotonic() + timeout
    url = f"http://{HOST}:{port}/healthz"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.25)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SASEGuard lab natively.")
    parser.add_argument("--reload", action="store_true", help="Reload services on source changes.")
    parser.add_argument("--log-level", default="info", choices=["critical", "error", "warning", "info", "debug"])
    args = parser.parse_args()

    if not ENV_FILE.exists() or not PUBLIC_KEY_FILE.exists():
        print("Setup has not run yet. Run this first:\n")
        print("    python scripts/setup.py\n")
        return 1
    load_dotenv()

    processes: list[tuple[str, subprocess.Popen]] = []

    def shutdown(*_: object) -> None:
        print("\nStopping services...")
        # Reverse order: stop the public gateway first so no new request can
        # arrive while its dependencies are going away.
        for name, process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for name, process in reversed(processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print(f"  {name} did not stop; killing it")
                process.kill()
        print("All services stopped.")

    signal.signal(signal.SIGINT, lambda *a: (shutdown(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *a: (shutdown(), sys.exit(0)))

    print("SASEGuard — starting local services")
    print("=" * 56)

    try:
        for name, target, port, public in SERVICES:
            command = [
                sys.executable, "-m", "uvicorn", target,
                "--host", HOST, "--port", str(port),
                "--log-level", args.log_level,
            ]
            if args.reload:
                command += ["--reload", "--reload-dir", str(ROOT / "apps")]

            process = subprocess.Popen(command, cwd=str(ROOT))
            processes.append((name, process))

            if not wait_for_health(port):
                print(f"  {name:9s} FAILED to become healthy on port {port}")
                shutdown()
                return 1

            visibility = "public (dashboard)" if public else "private"
            print(f"  {name:9s} http://{HOST}:{port}  [{visibility}]")

    except Exception as exc:  # noqa: BLE001
        print(f"Startup failed: {exc}")
        shutdown()
        return 1

    print("=" * 56)
    print(f"  Dashboard : http://{HOST}:8080")
    print(f"  OpenAPI   : http://{HOST}:8080/openapi.json")
    print("  Logins    : cat secrets/demo_credentials.txt")
    print()
    print("  Smoke test: python scripts/smoke.py")
    print("  Benchmark : python scripts/benchmark.py")
    print()
    print("Press Ctrl-C to stop.")

    try:
        while True:
            for name, process in processes:
                if process.poll() is not None:
                    print(f"\nService '{name}' exited with code {process.returncode}.")
                    shutdown()
                    return 1
            time.sleep(0.5)
    except KeyboardInterrupt:
        shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
