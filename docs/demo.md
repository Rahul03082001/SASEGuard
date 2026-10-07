# Five-minute demo walkthrough

Everything below is clickable in the dashboard at `http://127.0.0.1:8080`,
and every button calls the real API. The equivalent `curl` is given so you
can see there is no browser-side magic.

## Setup (once)

```bash
python scripts/setup.py
python scripts/run_local.py        # leave this running
cat secrets/demo_credentials.txt   # your generated passwords
```

Open `http://127.0.0.1:8080`. Keep **panel 7, "Last decision"**, in view — it
shows the reason code and audit event ID for every request.

---

## 0:00 — Frame the problem (20 seconds)

> "Three roles, three applications, and three things a password alone can't
> answer: *may* this person use this app, is their device safe right now, and
> is the data they're uploading allowed to leave. Every decision is made
> server-side and written down."

---

## 0:20 — Sign in as Alice (finance)

Click **alice · finance**, paste her password, **Sign in**.

> "A password *and* an enrolled device. The token is RS256, lives ten
> minutes, and is held in a JavaScript variable — not localStorage. The
> gateway only ever has the public key; the private key is in a separate
> process."

**Show the failure first.** Click **alice on Bob's device**, sign in again:

```
401 DENY_DEVICE_NOT_ENROLLED
```

> "Right password, wrong device. Enrollment is checked on its own."

Sign back in properly as alice.

---

## 1:00 — Least privilege

Click **GET /apps/payroll** → `200`.
Click **GET /apps/engineering** → `403 DENY_ROLE_NOT_PERMITTED`.

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/apps/engineering | jq
```

> "Finance reaches payroll and the wiki, not engineering. The server decides
> — the UI isn't hiding anything."

Now the part that matters. Click **GET /apps/hr-secrets**:

```
403 DENY_UNKNOWN_RESOURCE
```

> "Absence is denial. There's no wildcard in the policy file."

---

## 1:40 — Spoofed headers do nothing

Sign in as **carol · contractor**, then run:

```bash
curl -s -H "Authorization: Bearer $CAROL" \
     -H "X-Role: administrator" -H "X-Device-Compliant: true" \
     http://127.0.0.1:8080/apps/payroll | jq -r .reason_code
# DENY_ROLE_NOT_PERMITTED
```

> "Authorization reads verified token claims and the policy database. Nothing
> else in the request is consulted."

---

## 2:10 — DLP blocks *before* the data moves

Back as alice. Click **clean** → **POST /saas/upload** → `200`. Note
`upstream accepted: 1`.

Click **SG-DEMO-SECRET** → **POST /saas/upload**:

```
403 DENY_DLP_MATCH   rules: SG-DLP-001 x1
```

> "Two things to notice. The response names the *rule*, never the matched
> value — otherwise the error message would leak the secret we just saved.
> And the upstream counter is still 1."

Click **clean** → upload again → counter reads `2`.

> "The blocked payload never reached storage. That's the counter proving it.
> A 403 after forwarding would look identical to a user and be a total
> failure."

Then click **extra JSON field** → upload → `400`.

> "`{"skip_dlp": true}` is rejected, not ignored. Silently dropping an
> unknown field is how a client ends up believing it turned off scanning."

Try contractor: Carol gets `403 DENY_UPLOAD_NOT_PERMITTED` before her content
is even looked at.

---

## 3:00 — Web categories, and why there's no SSRF here

As alice: **docs** → `200`. **phishing-sim** → `403 DENY_WEB_CATEGORY`.

Then type `169.254.169.254` into the arbitrary-destination box and click
**Try arbitrary destination**:

```
403 DENY_UNKNOWN_DESTINATION
```

> "There's no URL parameter in that endpoint — just an ID matched against a
> fixed tuple. Which is why the cloud-metadata address goes nowhere. The
> phishing fixture is a local inert file; under Compose the app network has
> no route to the internet at all."

---

## 3:40 — The headline: posture, live, on an already-issued token

**Keep Alice's existing session.** Open a second browser tab, sign in as
**admin**, click **GET /admin/devices**.

In the admin tab, click **break** on `dev-alice-laptop`.

Back in Alice's tab — *without signing in again* — click **GET /apps/payroll**:

```
403 DENY_DEVICE_NONCOMPLIANT
```

> "Same token. Byte for byte the same token. Nothing was re-issued and
> nothing expired — the device record changed, and posture is re-read on
> every single request. No positive decision is cached."

In the admin tab click **fix**. In Alice's tab click payroll again → `200`.

> "And it comes back. Posture is a state, not a destroyed credential."

Say the limitation out loud:

> "This stops the *next* request. It doesn't interrupt a response already in
> flight or a long-lived connection authorized at open time."

---

## 4:20 — Revocation is different, and permanent

In Alice's tab, click **Log out (revoke token)**, then click payroll:

```
403 DENY_TOKEN_REVOKED
```

```bash
sqlite3 data/policy.sqlite3 "SELECT token_id, subject FROM revoked_tokens;"
```

> "That's in SQLite. Restart every service and it's still revoked. And it's
> per-token, not per-account — each login gets its own `jti`, so logging out
> on your laptop doesn't kill your phone."

---

## 4:40 — The audit trail

In the admin tab: **GET /admin/events**, set Result to **deny**.

> "Subject, resource, action, result, reason code, policy version, latency,
> DLP rule IDs. No tokens, no passwords, no request bodies, no matched text.
> The redaction is structural — there is no column that *could* hold a
> secret."

Point at the policy version column:

> "`1.0.0+a3d129eea7ab` — version plus a hash of the exact policy file. Six
> months from now you can still answer which ruleset produced this decision."

Two honest caveats:

> "An `allow` row means the gateway authorized the call before forwarding.
> It's not confirmation the app succeeded. And this is a plain SQLite file —
> not tamper-proof. Anyone with write access can edit it."

---

## 5:00 — Fail closed (optional, 30 seconds)

```bash
docker compose stop policy      # or Ctrl-C the policy process
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/apps/payroll | jq
# 503 ERROR_POLICY_UNAVAILABLE
```

> "Policy is down, so nothing is authorized and nothing is forwarded. Five
> failure modes are tested — down, hung, non-JSON, HTTP 500, and a 200 with
> `{"allow": "yes"}` as a string. That last one would pass a truthiness
> check, so the gateway type-checks the boolean."

---

## If someone asks "how do you know the denial really blocked it?"

That is the right question, and it has a concrete answer:

```bash
python -m pytest tests/test_security.py -k "blocks_before_upstream" -v
```

The synthetic services count every call they receive. Each denial test
asserts both the HTTP status *and* that the counter did not move. A gateway
that returned 403 after forwarding would pass a status-only test and fail
these.

```bash
python scripts/smoke.py | grep "never reached storage"
# [  ok  ] blocked uploads never reached storage — 1 -> 2 after 3 blocked attempts
```
