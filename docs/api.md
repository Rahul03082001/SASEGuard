# API reference

The machine-readable schema is served locally at
`http://127.0.0.1:8080/openapi.json`. Swagger UI is deliberately disabled
because it loads JavaScript from a CDN, which the dashboard's
Content-Security-Policy forbids.

All responses carry `Cache-Control: no-store` plus the security headers
listed at the end of this page.

## Status codes

| Code | Meaning |
|---|---|
| 200 | allowed, and forwarded |
| 400 | malformed request — bad JSON, unknown field, unsafe identifier |
| 401 | authentication failed — missing, invalid, expired, or forged token |
| 403 | authenticated, but denied by policy, posture, or DLP |
| 413 | body exceeded 65,536 bytes |
| 502 | authorized, but the private application was unreachable |
| 503 | fail-closed — policy unavailable or the audit write failed |

A 403 and a 503 both guarantee the private application was **not** contacted.

Every response that represents a decision includes a `reason_code` from the
closed set in `apps/common.py`.

---

## Public gateway API — `http://127.0.0.1:8080`

### `GET /`
The dashboard. HTML, no authentication.

### `GET /healthz`
```json
{"status": "ok", "service": "gateway", "policy_version": "1.0.0+a3d129eea7ab"}
```

### `GET /openapi.json`
The OpenAPI 3.1 schema, served from this host.

### `GET /meta/dlp-rules`
The active DLP rules, including their regex source, so a blocked user can see
why. No authentication — the rules are not a secret, and hiding them would
only make the product harder to use.

### `POST /auth/login`
Proxied to the private identity issuer.

```json
{"username": "alice", "password": "<from secrets/demo_credentials.txt>", "device_id": "dev-alice-laptop"}
```

`200`:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 600,
  "subject": "alice",
  "role": "finance",
  "device_id": "dev-alice-laptop",
  "token_id": "jti_8f2c..."
}
```

`401` — `DENY_BAD_LOGIN` (wrong password *or* unknown user, identical
response so the endpoint is not a user-enumeration oracle) or
`DENY_DEVICE_NOT_ENROLLED`.
`400` — `DENY_MALFORMED_REQUEST`, including any unexpected field.

### `POST /auth/logout`
Requires a bearer token. Persistently revokes that token's `jti`.

Does **not** require healthy posture: logout only reduces privilege, so
requiring a healthy device to log out would be a trap.

```json
{"revoked": true, "audit_event_id": "evt_...", "detail": "This token is now revoked."}
```

### `GET /apps/{app_id}`
`app_id` ∈ `payroll` · `engineering` · `wiki`. Anything else is denied; it is
never used to build a URL beyond that fixed set.

| Role | Permitted |
|---|---|
| finance | payroll, wiki |
| engineer | engineering, wiki |
| contractor | wiki |
| administrator | all three |

`200`:
```json
{
  "allowed": true,
  "audit_event_id": "evt_...",
  "upstream_status": 200,
  "data": {"app_id": "payroll", "title": "Payroll (synthetic)", "...": "..."}
}
```

`403` — `DENY_ROLE_NOT_PERMITTED`, `DENY_UNKNOWN_RESOURCE`,
`DENY_TOKEN_REVOKED`, or a `DENY_DEVICE_*` / `DENY_POSTURE_STALE` posture code.

### `GET /web/{destination}`
`destination` ∈ `docs` (allow) · `phishing-sim` (block) · `gambling-sim`
(block).

There is no URL parameter in this endpoint. The destination is an ID checked
against a compiled-in tuple, which is why it cannot be used as an open proxy
or an SSRF primitive.

`403` — `DENY_WEB_CATEGORY` (with `category`) or `DENY_UNKNOWN_DESTINATION`.

### `POST /saas/upload`
Finance, engineers, and administrators may upload. Contractors may not.

```json
{"filename": "notes.txt", "content": "text to scan"}
```

Exactly those two fields. Limits: 65,536 bytes of HTTP body (checked before
JSON parsing) and 32,000 characters of `content`.

`200`:
```json
{
  "allowed": true,
  "reason_code": "ALLOW_UPLOAD_CLEAN",
  "audit_event_id": "evt_...",
  "dlp": {"blocked": false, "scanned_chars": 74, "findings": []},
  "upstream": {"stored": false, "accepted_uploads": 3}
}
```

`403` — `DENY_DLP_MATCH`:
```json
{
  "detail": "Upload blocked by data loss prevention rules.",
  "reason_code": "DENY_DLP_MATCH",
  "allowed": false,
  "audit_event_id": "evt_...",
  "dlp": {
    "blocked": true,
    "scanned_chars": 58,
    "findings": [{"rule_id": "SG-DLP-001", "rule_name": "synthetic-credential", "match_count": 1}]
  }
}
```

Rule IDs and counts only — the matched text is never echoed. `upstream` is
absent because synthetic storage was never contacted.

`403` — `DENY_UPLOAD_NOT_PERMITTED` for contractors.

### `GET /admin/devices`
Administrator only, and the administrator's own device must be healthy.

### `PUT /admin/devices/{device_id}`
Administrator only. Any subset of:

```json
{"managed": true, "compliant": true, "risk_score": 5, "last_seen": "2026-10-07T18:00:00+00:00", "label": "..."}
```

Unknown fields are rejected. `risk_score` must be 0–100, `last_seen` must
parse as ISO-8601.

### `GET /admin/events?limit=50&result=deny`
Administrator only. `result` ∈ `allow` · `deny` · `error`. `limit` is clamped
to 500 server-side rather than trusted.

Rows contain `event_id`, `occurred_at`, `subject`, `role`, `device_id`,
`resource`, `action`, `result`, `reason_code`, `policy_version`,
`dlp_rule_ids`, `http_status`, `decision_latency_ms` — and nothing else.

---

## Private policy API — `http://127.0.0.1:8082`

Not reachable from the host under Compose. Every endpoint except `/healthz`
requires `X-SASEGuard-Service-Credential`, compared with `hmac.compare_digest`.

### `POST /evaluate`
```json
{
  "subject": "alice", "role": "finance", "device_id": "dev-alice-laptop",
  "token_id": "jti_...", "resource": "payroll", "action": "app.read"
}
```
Note what is absent: the bearer token. The policy service has no use for it
and should not be able to replay it.

```json
{
  "allow": true,
  "reason_code": "ALLOW_ROLE_GRANT",
  "policy_version": "1.0.0+a3d129eea7ab",
  "category": null,
  "device": {"device_id": "dev-alice-laptop", "owner": "alice", "managed": true, "...": "..."},
  "detail": "Role finance may read payroll."
}
```

Actions: `app.read` · `web.visit` · `saas.upload` · `admin.read` ·
`admin.write`. Unknown actions and unknown roles are denied, not ignored.

### `GET /devices` · `PUT /devices/{device_id}` · `POST /revoke`
Registry read, posture update, and revocation. `POST /revoke` takes
`{"token_id": "...", "subject": "..."}` and is idempotent.

### `GET /healthz`
Unauthenticated, on purpose: Compose health checks need it and it reveals
nothing.

---

## Reason codes

**Allow** — `ALLOW_ROLE_GRANT`, `ALLOW_WEB_CATEGORY`, `ALLOW_UPLOAD_CLEAN`,
`ALLOW_ADMIN`, `ALLOW_LOGIN`, `ALLOW_LOGOUT`

**401** — `DENY_NO_CREDENTIALS`, `DENY_BAD_TOKEN_SIGNATURE`,
`DENY_TOKEN_ALGORITHM`, `DENY_TOKEN_EXPIRED`, `DENY_TOKEN_NOT_YET_VALID`,
`DENY_TOKEN_CLAIMS`, `DENY_TOKEN_ISSUER`, `DENY_TOKEN_AUDIENCE`,
`DENY_BAD_LOGIN`, `DENY_DEVICE_NOT_ENROLLED`

**403** — `DENY_UNKNOWN_RESOURCE`, `DENY_UNKNOWN_ACTION`, `DENY_UNKNOWN_ROLE`,
`DENY_ROLE_NOT_PERMITTED`, `DENY_NOT_ADMIN`, `DENY_UPLOAD_NOT_PERMITTED`,
`DENY_DEVICE_UNKNOWN`, `DENY_DEVICE_NOT_OWNED`, `DENY_DEVICE_UNMANAGED`,
`DENY_DEVICE_NONCOMPLIANT`, `DENY_DEVICE_RISK_SCORE`, `DENY_POSTURE_STALE`,
`DENY_TOKEN_REVOKED`, `DENY_WEB_CATEGORY`, `DENY_UNKNOWN_DESTINATION`,
`DENY_DLP_MATCH`

**400 / 413** — `DENY_MALFORMED_REQUEST`, `DENY_BODY_TOO_LARGE`,
`DENY_CONTENT_TOO_LARGE`

**503 / 502** — `ERROR_POLICY_UNAVAILABLE`, `ERROR_POLICY_INVALID_RESPONSE`,
`ERROR_AUDIT_UNAVAILABLE`, `ERROR_UPSTREAM_UNAVAILABLE`,
`ERROR_IDENTITY_UNAVAILABLE`

## Response headers

```
Cache-Control: no-store, no-cache, must-revalidate
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; connect-src 'self'; font-src 'self'; form-action 'none';
  frame-ancestors 'none'; base-uri 'none'; object-src 'none'
```

No `Strict-Transport-Security`: the lab runs over plain HTTP on 127.0.0.1,
where HSTS would be a header for show. Add it behind a TLS terminator.
