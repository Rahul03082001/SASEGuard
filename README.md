# SASEGuard — Zero Trust Access and Data Protection Lab

[![CI](https://github.com/Rahul03082001/SASEGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Rahul03082001/SASEGuard/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A runnable, **SASE-inspired** local security lab. Four services enforce
application-level Zero Trust access, live device posture, lab web-category
controls, and text-only DLP — and record a redacted audit decision before
anything is forwarded.

**185 passing tests · 50/50 live HTTP checks · verified under Docker Compose.**

> ### Honest scope
>
> This is **SASE-inspired**, not SASE. Complete SASE also includes network
> functions — SD-WAN, global PoPs, TLS inspection, FWaaS — none of which are
> implemented here. There is **no vendor affiliation and no Prisma Access
> integration**. There is no real MFA, no hardware attestation, no production
> CASB, no commercial threat detection, and nothing in this repository is
> production-ready. All identities, services, and data are synthetic.
>
> [`docs/threat-model.md`](docs/threat-model.md) lists every limitation.
> [`docs/validation.md`](docs/validation.md) separates *implemented*,
> *tested*, and *not performed*.

---

## The problem

A distributed company has employees and contractors who need different
application permissions. Three things follow:

1. **A password proves who is asking, not what they may do.** Alice in
   finance and Carol the contractor both authenticate successfully and need
   completely different answers.
2. **A password says nothing about the device.** A valid login from an
   unpatched, unmanaged laptop is still a valid login.
3. **Outbound uploads can carry data that should never leave.**

SASEGuard addresses all three, server-side, and writes down every decision.

## What it does

| | |
|---|---|
| **Identity** | Password + enrolled device → ten-minute RS256 token. The private key lives in one process; the gateway has only the public key. |
| **Least privilege** | Per-role grants across three synthetic apps, from a hashed `policy.yaml`. Absence is denial — there is no wildcard. |
| **Live posture** | Ownership, managed, compliant, risk ≤ 30, seen within 24 h — re-read on **every** request, so a posture change blocks an already-issued token. |
| **Revocation** | `POST /auth/logout` persistently revokes that token's `jti`. Survives a restart. Per-token, not per-account. |
| **Web categories** | Three fixed local fixtures: one allowed, two blocked. No URL parameter exists, so there is no SSRF primitive. |
| **DLP** | Three explainable regex rules over text, applied **before** storage is contacted. Rule IDs are reported; matched values never are. |
| **Audit** | Subject, resource, action, result, reason code, policy version, latency, DLP rule IDs. Committed before forwarding. |
| **Fail closed** | Policy unreachable, slow, or incoherent → 503, nothing forwarded. Audit write fails on an allow → 503, nothing forwarded. |

## Architecture

```
                      ┌───────────────────────┐
     browser ────────▶│  gateway       :8080  │  ENFORCEMENT point
                      │  dashboard + API      │  the only public service
                      └───┬───────────┬───────┘
          control plane   │           │   data plane
            ┌─────────────┴──┐     ┌──┴────────────────┐
            ▼                ▼     ▼                   │
   ┌──────────────┐  ┌──────────────┐        ┌─────────▼────────┐
   │ identity     │  │ policy       │        │ mock_apps  :8083 │
   │        :8081 │  │        :8082 │        │ payroll          │
   │ RSA PRIVATE  │  │ DECISION pt. │        │ engineering      │
   │ key — only   │  │ device reg.  │        │ wiki             │
   │ here         │  │ revocations  │        │ web fixtures     │
   └──────────────┘  └──────┬───────┘        │ storage sink     │
                            │                └──────────────────┘
                     policy.sqlite3            audit.sqlite3
```

**The request path.** verify token locally → ask the policy service →
scan (uploads) → **commit the audit row** → forward to a fixed private URL.
A failure at any step denies, and nothing reaches the private application.

Full diagram and the five design choices with their trade-offs:
[`docs/architecture.md`](docs/architecture.md).

## Stack

Python 3.12 · FastAPI · Uvicorn · HTTPX · PyJWT + cryptography · Pydantic v2
· PyYAML · pytest. SQLite for persistence. Dashboard in HTML/CSS/vanilla JS
with no CDN and no build step. Versions are pinned in `requirements.txt` to
exactly what CI installs and tests.

---

## Quickstart — native

```bash
git clone https://github.com/Rahul03082001/SASEGuard.git
cd SASEGuard

python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python scripts/setup.py          # generates keys, passwords, databases
python scripts/run_local.py      # starts all four services
```

Open **http://127.0.0.1:8080**.

```bash
cat secrets/demo_credentials.txt   # your generated logins
```

In another terminal:

```bash
python -m pytest            # 185 passed, 1 skipped
python scripts/smoke.py     # 50/50 live HTTP checks
python scripts/benchmark.py # real latency numbers
```

### Quickstart — Docker Compose

```bash
python scripts/setup.py      # on the host: secrets are mounted, never baked in
docker compose up --build -d
python scripts/smoke.py
docker compose down
```

Only the gateway publishes a port, bound to `127.0.0.1:8080`. The three
private services sit on `internal: true` networks with no outbound route and
are unreachable from the host.

## Generated credentials

`scripts/setup.py` generates, locally and per installation:

- a 2048-bit RSA keypair — private half for the identity issuer only;
- a random 20-character password per demo user, stored only as a salted
  PBKDF2-HMAC-SHA256 hash (200,000 iterations);
- a random service credential for the private policy API;
- `.env` and both SQLite databases.

Everything lands in `secrets/` (mode `0700`, files `0600`) and `data/`, both
git-ignored and excluded from the Docker build context. **There are no
hard-coded passwords anywhere in this repository**, and two people who clone
it get different credentials. CI fails the build if a generated secret ever
becomes visible to git.

Rotate with `python scripts/setup.py --force`.

| User | Role | Device | May access |
|---|---|---|---|
| `alice` | finance | `dev-alice-laptop` | payroll, wiki · upload |
| `bob` | engineer | `dev-bob-laptop` | engineering, wiki · upload |
| `carol` | contractor | `dev-carol-byod` | wiki only · **no upload** |
| `admin` | administrator | `dev-admin-workstation` | all three · posture · audit |

---

## Demo in 60 seconds

The full script is [`docs/demo.md`](docs/demo.md). The one moment to show:

1. Sign in as **alice**, click **GET /apps/payroll** → `200`.
2. In a second tab, sign in as **admin** and click **break** on
   `dev-alice-laptop`.
3. Back in Alice's tab — **without signing in again** — click payroll:

```
403  DENY_DEVICE_NONCOMPLIANT
```

Same token, byte for byte. Nothing expired and nothing was re-issued; the
device record changed and posture is re-read on every request. Click **fix**
and the same token works again.

Then upload `SG-DEMO-SECRET-A1B2C3D4`:

```
403  DENY_DLP_MATCH   rules: SG-DLP-001 x1
```

Watch the upstream *accepted-upload counter* stay where it was. That counter
is the proof the payload never reached storage — a 403 returned *after*
forwarding would look identical to the user.

## Tests

```bash
python -m pytest -v
```

**185 passed, 1 skipped** (the skip is an automated-browser case; browser
behaviour was verified manually — see [`docs/validation.md`](docs/validation.md)).

These are integration tests. A real gateway calls a real policy service,
which really reads SQLite. The decision is never mocked.

**Every denial test asserts the HTTP status *and* that the upstream call
counter did not move.** A gateway that returned 403 after forwarding would
pass a status-only test and fail these.

Among what is covered: `alg=none` and HS256 key-confusion tokens
hand-assembled with `hmac` rather than PyJWT; forged signatures; payload
tampering; wrong issuer and audience; expiry and not-before; missing claims;
spoofed identity headers; SSRF attempts including `169.254.169.254`; the
risk-score boundary at exactly 30; revocation surviving a database reopen;
five distinct policy failure modes; and audit rows searched for the password,
every bearer-token segment, and the DLP-matched value.

## Benchmark

Real measurements, sequential, concurrency 1, 200 requests after 20 warm-ups,
on macOS 26.5.2 arm64 / Python 3.12.15:

| Workload | p50 | p95 | req/s |
|---|---|---|---|
| `health` (no auth, no policy, no audit) | 0.37 ms | 0.44 ms | 2638 |
| `denied-app` (verify + policy + audit, no forward) | 2.62 ms | 3.35 ms | 330 |
| `allowed-app` (full path + forward) | 3.96 ms | 6.86 ms | 224 |
| `clean-upload` (+ DLP + forward) | 4.07 ms | 5.72 ms | 233 |

Same workload under Compose: p50 **9.48 ms**, p95 **12.89 ms**, 98.6 req/s.
Zero errors throughout.

Latency covers the whole enforced path — HTTP to the gateway, RS256
verification, the policy call, two SQLite reads there, a committed audit
insert, and the upstream call.

**These are not capacity claims.** One host, loopback, SQLite, concurrency 1.
No baseline comparison is made and no improvement percentage is claimed
anywhere in this repository.

## Limitations

The short version — the full list is in
[`docs/threat-model.md`](docs/threat-model.md):

- No MFA. An enrolled device ID is a string in a token, **not** hardware
  attestation.
- Device posture is **asserted by an administrator, not measured**. No agent.
- DLP is three regexes over UTF-8 text. Base64-encode a secret and it passes.
  The email rule has false positives by design. It stops accidents, not
  adversaries.
- Web control is three hard-coded fixtures. No TLS inspection, no real
  categorization, no proxy.
- The audit log is a plain SQLite file: **not tamper-evident**, not
  replicated. An `allow` row records authorization, not application success,
  and is not atomic with any upstream change.
- Re-evaluation blocks the **next** request. It does not interrupt a response
  in flight or a long-lived connection.
- Single instance. SQLite, one host, no HA. Plain HTTP on loopback.

## File map

```
apps/
  common.py      paths, settings, reason codes, policy loading, password hashing
  identity.py    demo issuer — sole holder of the RSA private key
  policy.py      decision point — device registry, revocations, grant evaluation
  gateway.py     enforcement point — verify, decide, scan, audit, forward
  audit.py       redacted SQLite audit log
  dlp.py         three explainable text rules
  mock_apps.py   synthetic apps, inert web fixtures, amnesiac storage sink
config/
  policy.yaml    policy-as-code: grants, posture thresholds, categories
  devices.json   device registry seed
web/
  index.html  styles.css  app.js      dashboard — no CDN, no build step
scripts/
  setup.py       generate keys, passwords, credentials, databases
  run_local.py   start all four services natively
  smoke.py       50 live HTTP checks against a running stack
  benchmark.py   repeatable latency measurement
tests/
  conftest.py        wires all four services in-process over ASGI
  test_security.py   186 integration tests
docs/
  architecture.md  api.md  demo.md  threat-model.md  interview-notes.md  validation.md
Dockerfile  docker-compose.yml  .github/workflows/ci.yml
```

Generated at setup and never committed: `secrets/`, `data/`, `.env`, `bench/`.

## Résumé bullets

Two, written to survive a follow-up question:

> **Built a SASE-inspired Zero Trust access lab (Python, FastAPI, SQLite):**
> four services enforcing RS256 token verification, per-role application
> grants, and server-side device posture re-evaluated on every request, so a
> device marked non-compliant is denied on its next call using an
> already-issued token. Covered by 185 integration tests, including
> `alg=none` and HS256 key-confusion forgeries, and five policy-outage modes
> that all fail closed.

> **Implemented text-only DLP and a redacted audit trail at the enforcement
> point:** uploads are scanned before the storage service is contacted, and
> each denial test asserts the upstream call counter never moved — proving
> prevention rather than detection. Audit rows carry reason codes and DLP
> rule IDs with no tokens, passwords, or matched values, verified by tests
> that search stored rows for each.

## Further reading

- [What is SASE? — Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-is-sase)
- [SASE access — Palo Alto Networks](https://www.paloaltonetworks.com/sase/access)
- [Zero Trust Architecture (NIST SP 800-207)](https://www.nist.gov/publications/zero-trust-architecture)
- [PyJWT API reference](https://pyjwt.readthedocs.io/en/latest/api.html)
- [FastAPI OAuth2 with JWT](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)

## License

[MIT](LICENSE). All data, identities, and services in this repository are
synthetic.
