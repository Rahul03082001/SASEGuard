#!/usr/bin/env python3
"""Repeatable latency benchmark against a running gateway.

What this measures, precisely: wall-clock time from the moment the client
issues an HTTP request to the moment the full response body is received.
For an allowed application read, that single number contains all of:

    client -> gateway
        gateway: JWT signature verification (RS256)
        gateway -> policy service (HTTP)
            policy: SQLite read of the device registry
            policy: SQLite read of the revocation list
            policy: evaluate grants
        gateway: SQLite audit INSERT + commit
        gateway -> private application (HTTP)
    gateway -> client

It therefore is **not** "the cost of a policy decision". It is the cost of
the whole enforced request path on one machine, including two SQLite
round-trips that open their own connections (see apps/audit.py for why).

What this is not: a capacity measurement. Everything runs on one host, over
loopback, against SQLite, with concurrency 1 by default. These numbers say
how this lab behaves on the machine that produced them and nothing about
how any real deployment would scale. No improvement percentage is claimed
anywhere, because there is no baseline to improve on.

Usage::

    python scripts/run_local.py           # in one terminal
    python scripts/benchmark.py           # in another
    python scripts/benchmark.py --requests 500 --workload denied-app
"""

from __future__ import annotations

import argparse
import json
import pathlib
import platform
import re
import statistics
import sys
import time
from datetime import datetime, timezone

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apps.common import CREDENTIALS_FILE, read_text_file  # noqa: E402

BENCH_DIR = ROOT / "bench"

WORKLOADS = {
    "health": "GET /healthz — no auth, no policy call, no audit write.",
    "allowed-app": "GET /apps/payroll as finance — full path: verify, policy, audit, forward.",
    "denied-app": "GET /apps/engineering as finance — verify, policy, audit. No forward.",
    "allowed-web": "GET /web/docs — verify, policy, audit, forward.",
    "clean-upload": "POST /saas/upload with benign text — adds a DLP scan before forwarding.",
    "blocked-upload": "POST /saas/upload with a synthetic secret — DLP blocks before forwarding.",
}


def load_password(username: str) -> str:
    text = read_text_file(CREDENTIALS_FILE, "generated demo credentials")
    block = re.search(
        rf"username\s*:\s*{re.escape(username)}\s*\n\s*password\s*:\s*(\S+)", text
    )
    if not block:
        raise SystemExit(
            f"Could not find a generated password for {username!r}. "
            "Run: python scripts/setup.py --force"
        )
    return block.group(1)


def percentile(values: list[float], fraction: float) -> float:
    """Nearest-rank percentile. Stated explicitly because methods differ."""
    if not values:
        return float("nan")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(fraction * len(ordered) + 0.5)) - 1))
    return ordered[index]


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark the SASEGuard gateway.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--workload", default="allowed-app", choices=sorted(WORKLOADS))
    parser.add_argument("--requests", type=int, default=200, help="Measured requests.")
    parser.add_argument("--warmup", type=int, default=20, help="Unmeasured warm-up requests.")
    parser.add_argument(
        "--concurrency", type=int, default=1,
        help="Sequential only in this MVP; values other than 1 are rejected.",
    )
    parser.add_argument("--save", action="store_true", help="Write the result to bench/.")
    args = parser.parse_args()

    if args.concurrency != 1:
        print("This MVP benchmark is sequential. Re-run with --concurrency 1.")
        return 2

    started_at = datetime.now(timezone.utc)

    with httpx.Client(base_url=args.base_url, timeout=15.0, trust_env=False) as client:
        try:
            if client.get("/healthz").status_code != 200:
                raise httpx.HTTPError("gateway is not healthy")
        except httpx.HTTPError as exc:
            print(f"Cannot reach the gateway at {args.base_url}: {exc}")
            print("Start it with: python scripts/run_local.py")
            return 1

        headers: dict[str, str] = {}
        if args.workload != "health":
            login = client.post("/auth/login", json={
                "username": "alice",
                "password": load_password("alice"),
                "device_id": "dev-alice-laptop",
            })
            if login.status_code != 200:
                print(f"Login failed: {login.text}")
                return 1
            headers = {"Authorization": "Bearer " + login.json()["access_token"]}

        def fire() -> int:
            if args.workload == "health":
                return client.get("/healthz").status_code
            if args.workload == "allowed-app":
                return client.get("/apps/payroll", headers=headers).status_code
            if args.workload == "denied-app":
                return client.get("/apps/engineering", headers=headers).status_code
            if args.workload == "allowed-web":
                return client.get("/web/docs", headers=headers).status_code
            if args.workload == "clean-upload":
                return client.post("/saas/upload", headers=headers, json={
                    "filename": "bench.txt",
                    "content": "Benchmark payload with nothing sensitive in it.",
                }).status_code
            return client.post("/saas/upload", headers=headers, json={
                "filename": "bench.txt",
                "content": "Benchmark payload with SG-DEMO-SECRET-A1B2C3D4 inside.",
            }).status_code

        #: Status codes this workload is supposed to produce. A denial is a
        #: successful measurement of a denial, not an error.
        expected = {
            "health": {200}, "allowed-app": {200}, "denied-app": {403},
            "allowed-web": {200}, "clean-upload": {200}, "blocked-upload": {403},
        }[args.workload]

        print(f"SASEGuard benchmark — {args.workload}")
        print("=" * 64)
        print(f"  {WORKLOADS[args.workload]}")
        print(f"  warm-up {args.warmup}, measured {args.requests}, concurrency 1\n")

        for _ in range(args.warmup):
            fire()

        latencies: list[float] = []
        errors = 0
        unexpected: dict[int, int] = {}

        wall_start = time.perf_counter()
        for index in range(args.requests):
            request_start = time.perf_counter()
            try:
                status = fire()
            except httpx.HTTPError:
                errors += 1
                continue
            latencies.append((time.perf_counter() - request_start) * 1000.0)
            if status not in expected:
                unexpected[status] = unexpected.get(status, 0) + 1
            if (index + 1) % 50 == 0:
                print(f"  {index + 1}/{args.requests} requests")
        wall_seconds = time.perf_counter() - wall_start

    result = {
        "workload": args.workload,
        "workload_description": WORKLOADS[args.workload],
        "started_at_utc": started_at.isoformat(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "base_url": args.base_url,
        "warmup_requests": args.warmup,
        "measured_requests": args.requests,
        "concurrency": 1,
        "completed_requests": len(latencies),
        "transport_errors": errors,
        "unexpected_status_codes": unexpected,
        "expected_status_codes": sorted(expected),
        "wall_clock_seconds": round(wall_seconds, 4),
        "observed_requests_per_second": (
            round(len(latencies) / wall_seconds, 2) if wall_seconds > 0 else None
        ),
        "latency_ms": {
            "min": round(min(latencies), 3) if latencies else None,
            "p50": round(percentile(latencies, 0.50), 3) if latencies else None,
            "p95": round(percentile(latencies, 0.95), 3) if latencies else None,
            "max": round(max(latencies), 3) if latencies else None,
            "mean": round(statistics.fmean(latencies), 3) if latencies else None,
        },
        "latency_includes": (
            "Full client-observed round trip: HTTP to the gateway, RS256 signature "
            "verification, an HTTP call to the policy service, two SQLite reads there, "
            "a committed SQLite audit insert, and (when allowed) an HTTP call to the "
            "private application."
        ),
        "caveats": [
            "Single host, loopback networking, SQLite, concurrency 1.",
            "Measures this lab on this machine. Not a capacity or scalability claim.",
            "Percentiles use the nearest-rank method.",
            "No baseline comparison is made and no improvement is claimed.",
        ],
    }

    print("\n" + "=" * 64)
    print(f"  completed        : {result['completed_requests']}/{args.requests}")
    print(f"  transport errors : {errors}")
    if unexpected:
        print(f"  unexpected status: {unexpected}")
    print(f"  wall clock       : {result['wall_clock_seconds']} s")
    print(f"  throughput       : {result['observed_requests_per_second']} req/s (sequential)")
    print(f"  latency p50      : {result['latency_ms']['p50']} ms")
    print(f"  latency p95      : {result['latency_ms']['p95']} ms")
    print(f"  latency min/max  : {result['latency_ms']['min']} / {result['latency_ms']['max']} ms")
    print(f"  python / platform: {result['python_version']} on {result['platform']}")
    print("=" * 64)

    if args.save:
        BENCH_DIR.mkdir(parents=True, exist_ok=True)
        stamp = started_at.strftime("%Y%m%dT%H%M%SZ")
        path = BENCH_DIR / f"{args.workload}-{stamp}.json"
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nSaved: {path.relative_to(ROOT)}")

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
