# Interview notes

Short answers you can actually say out loud, plus the reasoning behind them.
Everything here is backed by something in the repository — nothing is
aspirational.

---

## "What is it?"

> A local Zero Trust access lab. Four services: a gateway that enforces,
> an identity issuer that signs short-lived RS256 tokens, a policy service
> that decides, and some synthetic applications. Every request is
> authenticated, authorized against live device posture, scanned for
> sensitive text if it's an upload, and written to an audit log before
> anything is forwarded.

Say **SASE-inspired**, not SASE. If asked why: complete SASE includes
network functions — SD-WAN, global PoPs, TLS inspection, CASB — and none of
those are here. Claiming otherwise is the fastest way to lose credibility
with someone who builds the real thing.

---

## "What problem does it solve?"

> Three things a password can't answer. *May* this person use this
> application — Alice in finance and Carol the contractor both authenticate
> fine and need different answers. Is the device safe *right now* — a valid
> login from an unpatched laptop is still a valid login. And is the data
> they're uploading allowed to leave.

---

## "Walk me through a request."

Six steps, in order:

1. Client sends `Authorization: Bearer <JWT>`.
2. Gateway verifies the signature **locally** with the issuer's public key —
   fixed RS256 allowlist, issuer, audience, `exp`, `nbf`, required claims.
   No network call. Fail → 401.
3. Gateway POSTs the **verified claims** to the policy service. Policy reads
   SQLite: revocation list first, then device posture, then the grant.
4. Uploads only: DLP scans the text.
5. Gateway writes the audit row and **commits**.
6. Only then does it forward, to a fixed private URL.

> The ordering of 5 and 6 is the part I'd defend. A decision that wasn't
> durably recorded is treated as a decision that didn't happen — if the
> audit write fails on an allowed request, the gateway returns 503 and
> forwards nothing.

---

## "Why those design choices?"

**Application layer, not network layer.** Network reachability can't express
"Carol may read the wiki but not payroll". Per-request, per-resource, per-
identity is the only way to state that. Cost: ~4 ms per request, and it only
covers traffic that goes through the gateway.

**Separate policy service.** The gateway is the exposed component, so it's
the one most likely to be compromised. If it's also the decider, compromising
it compromises authorization. Keeping the decision and the posture database
elsewhere means a compromised gateway can be tricked into forwarding but not
into *authorizing*. Cost: an extra hop, and a hard availability dependency.

**Posture server-side, re-read every request.** A client-asserted "I'm
compliant" header is worth nothing. Reading the authoritative record every
time is what makes a posture change take effect against a token that was
already issued. Cost: two SQLite reads per request and no caching.

**Deterministic policy-as-code.** `policy.yaml` is diffable and hashed, and
every audit row carries the version plus a hash prefix, so months later you
can still answer "which rules allowed this?". Cost: no dynamic rules; adding
a resource means an edit and a redeploy.

**Fail closed.** Policy down, policy slow, policy returning garbage, audit
write failing, unparseable timestamp — all deny. A control that fails open
works right up until the first outage. Cost: a policy outage is a total
outage. That's the right default here and the wrong default for some
workloads; the point is that it's a decision, not an accident.

---

## "How do you know a denial actually prevented the call?"

This is the question that separates a demo from an implementation, and it
has a concrete answer.

> Every synthetic service counts the calls it receives. Every denial test
> asserts two things: the HTTP status the caller saw, **and** that the
> upstream counter didn't move. A gateway that returned 403 *after*
> forwarding would pass a status-only test and fail mine.

```bash
python scripts/smoke.py | grep "never reached storage"
# [  ok  ] blocked uploads never reached storage — 1 -> 2 after 3 blocked attempts
```

Three blocked uploads and one clean one; the counter advanced by exactly one.

---

## "What attacks did you actually test?"

185 passing tests. The ones worth naming:

- **`alg=none`** and **HS256 key confusion** — signing an HS256 token using
  the RSA *public* key as the HMAC secret. Both are **hand-assembled with
  `hmac` in the test**, not via PyJWT, because PyJWT refuses to *sign* them
  — that's a guardrail for honest callers, not a defence. The rejection has
  to happen at verification, and `algorithms=["RS256"]` is what does it.
- **Forged signature** from a second RSA keypair the gateway doesn't trust.
- **Payload tampering** — flip `role` to `administrator`, signature breaks.
- **Wrong issuer / wrong audience** — a validly signed token minted for
  another service still fails.
- **Spoofed `X-Role` / `X-Device-Compliant` headers** — ignored entirely.
- **SSRF** — `/web/169.254.169.254` is denied. There's no URL parameter in
  that endpoint at all; it's an ID matched against a fixed tuple.
- **Five policy failure modes** — down, hung, non-JSON, HTTP 500, and a 200
  with `{"allow": "yes"}`. That last one is the interesting one: a
  truthiness check would read the string as an allow, so the gateway
  type-checks the boolean.

---

## "What are the limitations?"

Lead with these. Volunteering them is worth more than being caught by them.

- **No MFA**, and an enrolled device ID is **not hardware attestation** —
  it's a string in a token. No TPM, no certificate binding.
- **Posture is asserted by an administrator, not measured.** No agent.
- **DLP is three regexes over UTF-8 text.** Base64-encode a secret and it
  sails through. The email rule has false positives by design — it'd match
  `jenkins@build-01.internal` all day. It stops accidents, not adversaries.
- **Web control is three hard-coded fixtures**, not a categorization
  database, and it inspects nothing real.
- **The audit log is a plain SQLite file** — not tamper-evident, not
  replicated. An `allow` row means the gateway authorized the call, not that
  the application succeeded.
- **Re-evaluation stops the next request.** It doesn't interrupt a response
  in flight or a long-lived connection.
- **Single instance.** SQLite, one host, no HA.

`docs/threat-model.md` has the full list. `docs/validation.md` separates
what was tested from what wasn't.

---

## "What would you do next?"

In the order I'd actually do it:

1. **Real OIDC + MFA.** The issuer is the single point of total compromise;
   it should be someone else's hardened product.
2. **OPA or Cedar** instead of hand-written grant evaluation, so the policy
   language is a real one with its own test tooling.
3. **Tamper-evident audit** — hash chaining and off-host shipping. Right now
   anyone with write access to the file can rewrite history.
4. **PostgreSQL** and a short-TTL posture cache, which is what unblocks more
   than one instance.
5. **A posture agent** that measures instead of an administrator asserting.
6. Rate limiting on login, and `kid`-based key rotation with an overlap
   period.

---

## Things to be careful about

- Don't say "SASE". Say "SASE-inspired".
- Don't claim any vendor integration, Prisma Access, or affiliation.
- Don't quote a throughput number as capacity. The benchmark is one host,
  loopback, SQLite, concurrency 1 — ~4 ms p50 native, ~9.5 ms in Compose.
  It says how this lab behaves on this machine and nothing more. There is no
  baseline and no improvement percentage anywhere in the repo, deliberately.
- Don't say "production-ready" or "enterprise-grade".
- If you don't know, say so. The repo is written so you don't have to bluff.

---

## A defect I found and fixed, worth telling

Good answer to "tell me about a bug you caught".

> My first Docker Compose draft mounted the whole `secrets/` directory into
> the gateway container read-only. That quietly handed the gateway the RSA
> *private* key — which invalidates the central claim of the design, that a
> compromised gateway can read tokens but can't mint them. The code was
> fine; the deployment contradicted it. I found it by actually running the
> stack and listing the directory inside the container rather than trusting
> the compose file. Fixed it to mount individual files, and added a CI step
> that fails if `jwt_private.pem` is readable inside the gateway, so it
> can't silently regress.

Second one, same session:

> With every attached network marked `internal: true`, Docker silently can't
> publish a host port — the stack came up "healthy" and the dashboard was
> unreachable. Four green health checks and a completely broken deployment.
> Adding an `edge` network for the gateway fixed it, and it's the more
> correct topology anyway: the enforcement point is the one component that's
> supposed to be reachable.

---

## References

- [What is SASE? — Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-is-sase)
- [SASE access — Palo Alto Networks](https://www.paloaltonetworks.com/sase/access)
- [Zero Trust Architecture (NIST SP 800-207)](https://www.nist.gov/publications/zero-trust-architecture)
- [PyJWT API reference](https://pyjwt.readthedocs.io/en/latest/api.html)
- [FastAPI OAuth2 with JWT](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
