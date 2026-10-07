#!/usr/bin/env python3
"""Live HTTP smoke test against running services.

The pytest suite drives the apps in-process over ASGI, which is fast and
isolated but proves nothing about uvicorn, port binding, or the real network
path. This script talks to the actual gateway over actual TCP, so it catches
the class of bug that only appears once there is a socket involved.

It is read-mostly but not read-only: it logs in, revokes a token, and flips
one device's posture back and forth. It restores the posture it changed.

Usage::

    python scripts/run_local.py        # in one terminal
    python scripts/smoke.py            # in another
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

import httpx

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from apps.common import CREDENTIALS_FILE, read_text_file  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"

_results: list[tuple[str, str, str]] = []


def check(name: str, condition: bool, detail: str = "") -> bool:
    _results.append((PASS if condition else FAIL, name, detail))
    marker = "  ok  " if condition else " FAIL "
    print(f"[{marker}] {name}" + (f"  — {detail}" if detail else ""))
    return condition


def load_demo_passwords() -> dict[str, str]:
    """Scrape the generated credentials file written by scripts/setup.py."""
    text = read_text_file(CREDENTIALS_FILE, "generated demo credentials")
    passwords: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        username = re.match(r"\s*username\s*:\s*(\S+)", line)
        if username:
            current = username.group(1)
            continue
        password = re.match(r"\s*password\s*:\s*(\S+)", line)
        if password and current:
            passwords[current] = password.group(1)
            current = None
    return passwords


def main() -> int:
    parser = argparse.ArgumentParser(description="Live smoke test for SASEGuard.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()

    print("SASEGuard live smoke test")
    print("=" * 62)
    print(f"target: {args.base_url}\n")

    passwords = load_demo_passwords()
    if not passwords:
        print("Could not read generated passwords. Run: python scripts/setup.py --force")
        return 1

    # trust_env=False so an ambient proxy variable cannot silently reroute us.
    with httpx.Client(base_url=args.base_url, timeout=10.0, trust_env=False) as client:

        # -- reachability --------------------------------------------------
        print("-- service reachability")
        try:
            health = client.get("/healthz")
        except httpx.HTTPError as exc:
            print(f"\nCannot reach the gateway: {exc}")
            print("Start it with: python scripts/run_local.py")
            return 1
        check("gateway /healthz is 200", health.status_code == 200)
        check("policy version reported", bool(health.json().get("policy_version")))

        page = client.get("/")
        check("dashboard served", page.status_code == 200 and "SASEGuard" in page.text)
        check("styles.css served", client.get("/static/styles.css").status_code == 200)
        check("app.js served", client.get("/static/app.js").status_code == 200)
        check("openapi.json served locally", client.get("/openapi.json").status_code == 200)
        check(
            "security headers present",
            page.headers.get("X-Content-Type-Options") == "nosniff"
            and "no-store" in page.headers.get("Cache-Control", "")
            and "unsafe-inline" not in page.headers.get("Content-Security-Policy", ""),
        )

        # -- authentication ------------------------------------------------
        print("\n-- authentication")
        unauthenticated = client.get("/apps/wiki")
        check("no token is 401", unauthenticated.status_code == 401,
              unauthenticated.json().get("reason_code", ""))

        bad = client.post("/auth/login", json={
            "username": "alice", "password": "wrong-password", "device_id": "dev-alice-laptop"})
        check("wrong password is 401", bad.status_code == 401)

        wrong_device = client.post("/auth/login", json={
            "username": "alice", "password": passwords["alice"], "device_id": "dev-bob-laptop"})
        check("unenrolled device is 401", wrong_device.status_code == 401,
              wrong_device.json().get("reason_code", ""))

        def login(username: str) -> str:
            device = {
                "alice": "dev-alice-laptop", "bob": "dev-bob-laptop",
                "carol": "dev-carol-byod", "admin": "dev-admin-workstation",
            }[username]
            response = client.post("/auth/login", json={
                "username": username, "password": passwords[username], "device_id": device})
            if response.status_code != 200:
                raise SystemExit(f"login failed for {username}: {response.text}")
            return response.json()["access_token"]

        alice = login("alice")
        carol = login("carol")
        admin = login("admin")
        check("alice, carol and admin logged in", all([alice, carol, admin]))

        def auth(token: str) -> dict[str, str]:
            return {"Authorization": f"Bearer {token}"}

        # -- least privilege ------------------------------------------------
        print("\n-- least-privilege application access")
        check("alice -> payroll allowed",
              client.get("/apps/payroll", headers=auth(alice)).status_code == 200)
        check("alice -> wiki allowed",
              client.get("/apps/wiki", headers=auth(alice)).status_code == 200)

        denied = client.get("/apps/engineering", headers=auth(alice))
        check("alice -> engineering denied", denied.status_code == 403,
              denied.json().get("reason_code", ""))

        carol_payroll = client.get("/apps/payroll", headers=auth(carol))
        check("carol -> payroll denied", carol_payroll.status_code == 403,
              carol_payroll.json().get("reason_code", ""))

        check("admin -> all three allowed", all(
            client.get(f"/apps/{app}", headers=auth(admin)).status_code == 200
            for app in ("payroll", "engineering", "wiki")))

        unknown = client.get("/apps/hr-secrets", headers=auth(admin))
        check("unknown app denied", unknown.status_code == 403,
              unknown.json().get("reason_code", ""))

        # -- spoofed headers ------------------------------------------------
        print("\n-- spoofed identity headers")
        spoofed = client.get("/apps/payroll", headers={
            **auth(carol), "X-Role": "administrator", "X-Device-Compliant": "true"})
        check("spoofed headers ignored", spoofed.status_code == 403,
              spoofed.json().get("reason_code", ""))

        # -- web categories -------------------------------------------------
        print("\n-- lab web categories")
        docs = client.get("/web/docs", headers=auth(alice))
        check("docs allowed", docs.status_code == 200, docs.json().get("category", ""))

        for destination in ("phishing-sim", "gambling-sim"):
            blocked = client.get(f"/web/{destination}", headers=auth(alice))
            check(f"{destination} blocked", blocked.status_code == 403,
                  blocked.json().get("reason_code", ""))

        arbitrary = client.get("/web/evil.example.com", headers=auth(alice))
        check("arbitrary destination rejected", arbitrary.status_code in (400, 403, 404),
              arbitrary.json().get("reason_code", ""))

        # -- DLP -------------------------------------------------------------
        print("\n-- text-only DLP")
        clean = client.post("/saas/upload", headers=auth(alice), json={
            "filename": "notes.txt", "content": "Quarterly summary, nothing sensitive."})
        check("clean upload accepted", clean.status_code == 200)
        baseline = clean.json().get("upstream", {}).get("accepted_uploads", -1)
        check("upstream accepted counter reported", baseline >= 1, f"count={baseline}")

        for rule, content in (
            ("SG-DLP-001", "key SG-DEMO-SECRET-A1B2C3D4 rotate soon"),
            ("SG-DLP-002", "account SG-CUSTOMER-204517 escalation"),
            ("SG-DLP-003", "contact dana.reyes@example.com please"),
        ):
            blocked = client.post("/saas/upload", headers=auth(alice), json={
                "filename": "leak.txt", "content": content})
            rules = [f["rule_id"] for f in blocked.json().get("dlp", {}).get("findings", [])]
            check(f"{rule} blocks the upload", blocked.status_code == 403 and rule in rules)
            # The sensitive substring must not come back in the error.
            sensitive = [w.strip(".,") for w in content.split()
                         if w.startswith("SG-") or "@" in w]
            check(f"{rule} does not echo the match",
                  all(value not in blocked.text for value in sensitive))

        after = client.post("/saas/upload", headers=auth(alice), json={
            "filename": "notes2.txt", "content": "still nothing sensitive"})
        now = after.json().get("upstream", {}).get("accepted_uploads", -1)
        check("blocked uploads never reached storage", now == baseline + 1,
              f"{baseline} -> {now} after 3 blocked attempts")

        contractor = client.post("/saas/upload", headers=auth(carol), json={
            "filename": "x.txt", "content": "harmless"})
        check("contractor cannot upload", contractor.status_code == 403,
              contractor.json().get("reason_code", ""))

        extra = client.post("/saas/upload", headers=auth(alice), json={
            "filename": "x.txt", "content": "hi", "skip_dlp": True})
        check("extra JSON field rejected", extra.status_code == 400)

        oversized = client.post(
            "/saas/upload", headers={**auth(alice), "content-type": "application/json"},
            content=b'{"filename":"b.txt","content":"' + b"a" * 70_000 + b'"}')
        check("oversized body rejected", oversized.status_code == 413)

        # -- admin and posture ----------------------------------------------
        print("\n-- posture, revocation and audit")
        forbidden = client.get("/admin/devices", headers=auth(alice))
        check("non-admin cannot read devices", forbidden.status_code == 403,
              forbidden.json().get("reason_code", ""))

        devices = client.get("/admin/devices", headers=auth(admin))
        check("admin reads device registry",
              devices.status_code == 200 and len(devices.json()["devices"]) == 4)

        # Live re-evaluation: same token, posture flipped underneath it.
        check("alice allowed before posture change",
              client.get("/apps/payroll", headers=auth(alice)).status_code == 200)

        broken = client.put("/admin/devices/dev-alice-laptop",
                            headers=auth(admin), json={"compliant": False})
        check("admin breaks alice's device posture", broken.status_code == 200)

        after_break = client.get("/apps/payroll", headers=auth(alice))
        check("SAME token now denied", after_break.status_code == 403,
              after_break.json().get("reason_code", ""))

        restored = client.put("/admin/devices/dev-alice-laptop",
                              headers=auth(admin), json={"compliant": True})
        check("admin restores posture", restored.status_code == 200)
        check("SAME token allowed again",
              client.get("/apps/payroll", headers=auth(alice)).status_code == 200)

        # Revocation.
        logout = client.post("/auth/logout", headers=auth(alice))
        check("logout revokes the token", logout.status_code == 200)
        reused = client.get("/apps/payroll", headers=auth(alice))
        check("revoked token is denied", reused.status_code == 403,
              reused.json().get("reason_code", ""))

        # Audit.
        events = client.get("/admin/events?limit=100", headers=auth(admin))
        check("admin reads audit events", events.status_code == 200)
        body = events.json()
        check("audit has recorded this run", body["total"] > 20, f"total={body['total']}")

        serialized = json.dumps(body)
        check("audit contains no passwords", passwords["alice"] not in serialized)
        check("audit contains no bearer tokens", alice.split(".")[2] not in serialized)
        check("audit contains no DLP-matched values",
              "SG-DEMO-SECRET-A1B2C3D4" not in serialized
              and "SG-CUSTOMER-204517" not in serialized)
        check("audit records DLP rule IDs", any(
            "SG-DLP-001" in (e.get("dlp_rule_ids") or []) for e in body["events"]))

        denies = client.get("/admin/events?result=deny&limit=50", headers=auth(admin))
        check("audit result filter works",
              denies.status_code == 200
              and all(e["result"] == "deny" for e in denies.json()["events"]))

    # -- summary -----------------------------------------------------------
    failures = [row for row in _results if row[0] == FAIL]
    print("\n" + "=" * 62)
    print(f"{len(_results) - len(failures)}/{len(_results)} checks passed")
    if failures:
        print("\nFailed checks:")
        for _, name, detail in failures:
            print(f"  - {name}" + (f" ({detail})" if detail else ""))
        return 1
    print("All live checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
