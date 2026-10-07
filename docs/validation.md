# Validation record

What was actually run, what the results were, and what was not verified.
Checks marked **not performed** were not performed — they are not implied to
have passed.

**Environment**

| | |
|---|---|
| Date (UTC) | 2026-10-07 |
| Python | 3.12.15 |
| Platform | macOS 26.5.2, arm64 (Apple Silicon) |
| Docker | 29.3.0, daemon running |
| Dependencies | the exact pins in `requirements.txt` |

---

## 1. Implemented

Behaviour that exists and runs.

- Four separately runnable FastAPI services: gateway (8080, the only public
  one), identity issuer (8081), policy decision service (8082), synthetic
  applications (8083).
- RS256 login with password + enrolled device; ten-minute tokens carrying
  `iss`, `aud`, `iat`, `nbf`, `exp`, `sub`, `role`, `device_id`, `jti`.
- The RSA private key exists only in the identity service. Under Compose the
  gateway container mounts `jwt_public.pem` as a single file.
- Per-role least-privilege grants across three applications, from a hashed
  `policy.yaml`.
- Server-side device posture: ownership, managed, compliant, risk ≤ 30,
  posture fresher than 24 h — re-read from SQLite on every request.
- Persistent per-token revocation via `POST /auth/logout`.
- Lab web-category control over three fixed local fixtures.
- Text-only DLP with three explainable rules, applied before any upstream
  contact.
- Redacted audit log committed before forwarding.
- Fail-closed handling of policy outage, invalid policy responses, and audit
  write failure.
- Responsive dashboard (HTML/CSS/vanilla JS), no CDN, strict CSP, token held
  in memory only.
- Dockerfile + Compose on three networks, non-root container user.
- GitHub Actions CI running the same commands documented in the README.
- `scripts/setup.py`, `run_local.py`, `smoke.py`, `benchmark.py`.

## 2. Tested

### 2.1 Automated suite — **185 passed, 1 skipped**

```
$ python -m pytest -q
185 passed, 1 skipped
```

186 collected. The skip is the browser case (§3.1).

Coverage by required area:

| Area | Test class(es) | Tests | Result |
|---|---|---|---|
| 1. Login, passwords, device enrollment | `TestLogin` | 13 | pass |
| 2. Role grants, missing auth, forbidden admin | `TestApplicationAccess` | 31 | pass |
| 3. Token forgery and verification | `TestTokenVerification` | 26 | pass |
| 4. Device posture | `TestDevicePosture` | 13 | pass |
| 5. Posture re-evaluation and revocation | `TestRevocationAndReevaluation` | 7 | pass |
| 6. Web categories and spoofed headers | `TestWebCategories` | 16 | pass |
| 7. DLP | `TestDataLossPrevention` | 30 | pass |
| 8. Audit, fail-closed, private service auth | `TestAudit`, `TestFailClosed`, `TestPrivateServiceAuthentication` | 35 | pass |
| 9. Dashboard assets and API surface | `TestDashboardAndSurface`, `TestRealBrowser` | 15 | 14 pass, 1 skip |
| | **Total** | **186** | **185 pass, 1 skip** |

The tests are integration tests: a real gateway calls a real policy service
over ASGI transports, and the policy service really reads SQLite. The
decision is never mocked.

**Every denial test asserts two things** — the HTTP status *and* the
upstream call counter. A gateway that returned 403 after forwarding would
pass a status-only test and fail these.

Specifically verified:

- `alg=none` and HS256-confusion tokens, both **hand-assembled with `hmac`**
  rather than via PyJWT, because PyJWT's own refusal to sign them is a
  guardrail for honest callers, not a defence.
- Five distinct policy failure modes all produce 503 with no forwarding:
  connection refused, read timeout, non-JSON body, HTTP 500, and a 200 with
  `{"allow": "yes"}` — the string, which a truthiness check would misread.
- Audit write failure on an *allowed* request produces 503 with no
  forwarding.
- The risk-score threshold is inclusive at exactly 30; 31 denies.
- Revocation survives reopening the SQLite file.
- Audit rows are searched for the password, every segment of the bearer
  token, and the DLP-matched value. None appear.

### 2.2 Live HTTP, native services — **50/50 checks passed**

```
$ python scripts/run_local.py
$ python scripts/smoke.py
50/50 checks passed
```

Real TCP, real uvicorn, real port binding. Notable line:

```
[  ok  ] blocked uploads never reached storage — 1 -> 2 after 3 blocked attempts
```

The upstream counter advanced by exactly one across three blocked attempts
and one clean upload.

### 2.3 Docker Compose — **performed, 50/50 checks passed**

Docker was available, so this was actually run rather than skipped.

```
$ docker compose build && docker compose up -d
$ docker compose ps
apps      Up (healthy)   8080/tcp
gateway   Up (healthy)   127.0.0.1:8080->8080/tcp
identity  Up (healthy)   8080/tcp
policy    Up (healthy)   8080/tcp

$ python scripts/smoke.py
50/50 checks passed
```

Additional checks run inside the stack:

| Check | Result |
|---|---|
| Gateway reachable from the host | HTTP 200 |
| Ports 8081 / 8082 / 8083 reachable from the host | connection refused (correct) |
| `apps` container → `policy` service | `URLError` (correct: different network) |
| `apps` container → `identity` service | `URLError` (correct) |
| `gateway` container → all three | HTTP 200 each |
| `policy` container secret mounts | none |
| `gateway` container secret mounts | `jwt_public.pem` only |

**A real defect was found and fixed during this step.** The first Compose
draft mounted the whole `./secrets` directory into the gateway read-only,
which gave the gateway container the RSA *private* key — quietly
invalidating the project's central claim that a compromised gateway cannot
mint tokens. Both the gateway and identity services now mount individual
files. CI asserts `test -f /app/secrets/jwt_private.pem` fails inside the
gateway container, so this cannot silently regress.

A second issue was found and fixed in the same step: with every attached
network marked `internal: true`, Docker cannot publish a host port, so the
dashboard was unreachable. The gateway is now additionally on a
non-internal `edge` network — which is the more correct topology anyway,
since the enforcement point is the one component meant to be reachable.

**A third defect was found only by CI, on Linux.** The generated secrets are
mode `0600`, owned by whoever ran `scripts/setup.py`. On Linux a bind mount
preserves real uid/gid, so containers running as the image's baked-in uid
10001 could not read them at all and the identity service's login path
failed. This did not reproduce locally: Docker Desktop on macOS masks
ownership across its file-sharing layer, so every container could read the
files regardless of uid. `setup.py` now records the host uid/gid in `.env`
and Compose runs all four services as that user. The files stay at `0600` —
the alternative fix, widening permissions until the container could read
them, would have traded a real protection for a convenience.

### 2.3.1 CI — Ubuntu x86-64, green

Both jobs pass on GitHub Actions (run `37673752876`):

| Job | Result |
|---|---|
| Tests on Python 3.12 | pass — 185 passed, 1 skipped |
| Docker Compose | pass — build, health, isolation checks, **50/50 smoke** |

The Compose job additionally asserts from inside the runner that ports
8081–8083 are unreachable from the host and that `jwt_private.pem` does not
exist inside the gateway container, so neither of the first two defects can
silently regress.

### 2.4 Browser — **performed manually**

Driven in a real Chromium browser against the live native stack at
`http://127.0.0.1:8080`:

| Interaction | Result |
|---|---|
| Page, `styles.css`, `app.js` load | all 200 |
| Login as alice | chip shows `alice · finance · dev-alice-laptop`; password field cleared |
| `GET /apps/payroll` | allowed |
| `GET /apps/engineering` | denied, `DENY_ROLE_NOT_PERMITTED` |
| `GET /web/phishing-sim` | denied, `DENY_WEB_CATEGORY` |
| Upload with a synthetic secret | denied, `DENY_DLP_MATCH`, `SG-DLP-001 x1` |
| Clean upload | allowed, upstream counter advanced |
| `/admin/devices` as finance | denied, `DENY_NOT_ADMIN`, table shows the reason |
| Login as admin, device registry | 4 rows rendered |
| Audit table | 25 rows; deny filter returned 22, all `deny` |
| `localStorage.length` after login | `0` — the token is never persisted |
| Console errors | only the expected 401/403 from deliberate denials; **no CSP violations, no JS errors** |

### 2.5 Benchmark — real measurements

Native, sequential, concurrency 1, 20 warm-up + 200 measured, Python 3.12.15
on macOS 26.5.2 arm64:

| Workload | p50 (ms) | p95 (ms) | req/s | errors |
|---|---|---|---|---|
| `health` (no auth, no policy, no audit) | 0.374 | 0.440 | 2637.8 | 0 |
| `denied-app` (verify + policy + audit, no forward) | 2.622 | 3.352 | 330.3 | 0 |
| `blocked-upload` (+ DLP, no forward) | 2.688 | 3.135 | 362.3 | 0 |
| `allowed-web` (full path + forward) | 3.433 | 3.724 | 289.9 | 0 |
| `allowed-app` (full path + forward) | 3.959 | 6.862 | 223.8 | 0 |
| `clean-upload` (+ DLP + forward) | 4.067 | 5.721 | 233.3 | 0 |

Same `allowed-app` workload under Docker Compose: **p50 9.477 ms, p95 12.89
ms, 98.6 req/s, 0 errors** — container networking roughly doubles the cost.

Latency includes the whole enforced path: HTTP to the gateway, RS256
verification, an HTTP call to the policy service, two SQLite reads there, a
committed SQLite audit insert, and the upstream HTTP call. Percentiles use
the nearest-rank method.

**These are not capacity claims.** One host, loopback, SQLite, concurrency 1.
No baseline comparison is made and no improvement percentage is claimed
anywhere in this repository.

### 2.6 Secret hygiene

```
$ ls -l secrets/
-rw-------  demo_credentials.txt
-rw-------  jwt_private.pem
-rw-------  jwt_public.pem
-rw-------  users.json
$ ls -ld secrets/      # drwx------
$ ls -l .env           # -rw-------
$ git status --porcelain | grep -E 'secrets|data|\.env|\.pem'
(no output)
```

CI fails the build if any generated secret becomes visible to git.

---

## 3. Not performed

- **3.1 Automated browser tests.** Playwright is not installed and is not in
  `requirements.txt` — adding it would pull a browser download into every
  clone and CI run. The pytest case skips with an explanatory message rather
  than passing vacuously. Browser behaviour was verified manually instead
  (§2.4).
- **3.2 Multi-platform.** Verified on macOS 26.5.2 arm64 and, through CI,
  Ubuntu x86-64 (both the native suite and the full Compose stack). Not
  tested on Windows; `setup.py` falls back to uid/gid 10001 there, which is
  untested.
- **3.3 Concurrency and load.** Only sequential, concurrency 1. No parallel
  benchmark, no soak test, no SQLite write-contention testing.
- **3.4 Any TLS path.** Everything runs over plain HTTP on loopback.
- **3.5 Penetration testing.** No external security review, no fuzzing, no
  static analysis beyond the tests in this repository.
- **3.6 Dependency vulnerability scanning.** No Dependabot, `pip-audit`, or
  SCA tooling is configured.
- **3.7 Long-running stability.** Longest continuous run is a few minutes.

---

## 4. Future work — explicitly not implemented

Listed so there is no ambiguity about what exists today.

- Real OIDC/OAuth 2.0 identity provider and MFA.
- OPA or Cedar in place of hand-written grant evaluation.
- PostgreSQL in place of SQLite; horizontal scale; high availability.
- Tamper-evident audit (hash chaining, append-only storage, off-host shipping).
- A posture agent that measures device state instead of an administrator
  asserting it, with hardware attestation.
- Real URL categorization, TLS inspection, CASB API integration.
- Content classification and exact-data-match DLP instead of regex.
- A React dashboard.
- Rate limiting and account lockout on login.
- Key rotation with `kid`-based rollover and an overlap period.
