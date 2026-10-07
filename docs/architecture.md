# Architecture

## The problem

A distributed company has employees and contractors who need different
application permissions. Three things follow from that:

1. A password proves *who* is asking, not *what they may do*. Alice in
   finance and Carol the contractor can both authenticate successfully and
   still need completely different answers.
2. A password says nothing about whether the device asking is safe. A valid
   login from a jailbroken, unpatched, or unmanaged laptop is still a valid
   login.
3. Once someone is inside, outbound uploads can carry data that should never
   leave.

SASEGuard is a local lab that addresses those three with application-level
Zero Trust access, server-side device posture, and text-only DLP, and records
every decision.

## Scope, stated honestly

This is **SASE-inspired**. Complete SASE also includes network functions —
SD-WAN, global PoPs, TLS inspection, CASB, FWaaS — none of which are here.
There is no vendor affiliation and no Prisma Access integration. Nothing in
this repository is production-ready.

What *is* implemented is listed in [validation.md](validation.md), separated
into implemented, tested, and future work.

## The four services

```
                         host loopback only
                      ┌───────────────────────┐
     browser ────────▶│  gateway       :8080  │  policy ENFORCEMENT point
                      │  (dashboard + API)    │  the only public service
                      └───┬───────────┬───────┘
          control plane   │           │   data plane
            ┌─────────────┴──┐     ┌──┴────────────────┐
            ▼                ▼     ▼                   │
   ┌──────────────┐  ┌──────────────┐        ┌─────────▼────────┐
   │ identity     │  │ policy       │        │ mock_apps  :8083 │
   │        :8081 │  │        :8082 │        │                  │
   │ RSA PRIVATE  │  │ DECISION pt. │        │ payroll          │
   │ key lives    │  │ device reg.  │        │ engineering      │
   │ here, only   │  │ revocations  │        │ wiki             │
   │ here         │  │ policy.yaml  │        │ web fixtures     │
   └──────────────┘  └──────┬───────┘        │ storage sink     │
                            │                └──────────────────┘
                     policy.sqlite3            audit.sqlite3
                                                (gateway writes)
```

| Service | Port | Public? | Owns |
|---|---|---|---|
| `apps/gateway.py` | 8080 | yes, 127.0.0.1 | enforcement, DLP, audit writes, dashboard |
| `apps/identity.py` | 8081 | no | the RSA **private** key, the user table |
| `apps/policy.py` | 8082 | no | device registry, revocation list, `policy.yaml` |
| `apps/mock_apps.py` | 8083 | no | synthetic apps, inert web fixtures, storage sink |

## The request path

```
client
  │  Authorization: Bearer <RS256 JWT>
  ▼
gateway
  │  1. verify signature locally with the PUBLIC key
  │     fixed RS256 allowlist · issuer · audience · exp · nbf · required claims
  │     ──▶ fail: 401, nothing forwarded
  │
  │  2. POST /evaluate to the policy service  (verified claims only)
  │       policy reads SQLite: revocation list, then device posture
  │       policy applies policy.yaml grants
  │     ──▶ unreachable / invalid answer: 503, nothing forwarded
  │     ──▶ deny: 403, nothing forwarded
  │
  │  3. uploads only: DLP scan of the text
  │     ──▶ match: 403, nothing forwarded
  │
  │  4. INSERT the authorization event and COMMIT
  │     ──▶ write fails on an allow: 503, nothing forwarded
  │
  │  5. forward to a FIXED private URL
  ▼
private application
```

Steps 4 and 5 are in that order deliberately. A decision that was not
durably recorded is treated as a decision that did not happen.

## Five design choices, and what they cost

### 1. Enforce at the application layer, not the network layer

**Why.** Network reachability is a blunt instrument. "Carol's laptop can
reach 10.0.3.0/24" cannot express "Carol may read the wiki but not payroll".
Deciding per request, per resource, per identity is the only way to state a
grant that matches how people actually think about permissions.

**What it costs.** Every protected request pays for a decision. Measured on
one machine: ~4 ms p50 native, ~9.5 ms p50 in Compose (see
[validation.md](validation.md)). It also only covers traffic that goes
through the gateway — anything that bypasses it is unprotected, which is why
a real deployment needs network controls *as well*, not instead.

### 2. A separate policy decision service

**Why.** The gateway is the component exposed to the internet, so it is the
component most likely to be compromised. Keeping the decision somewhere else
means a gateway that is tricked into forwarding a request still cannot
*authorize* one, and the policy service's database is the authority on
posture no matter what the gateway believes. It also means the rules can be
reviewed, versioned, and changed in one place.

**What it costs.** An extra network hop on every request, a second service to
run and monitor, and a hard dependency: if policy is down, everything is
down. That is a deliberate trade — see choice 5.

### 3. Posture evaluated server-side, re-read every request

**Why.** Device state is not a credential the client can be trusted to
carry. A client-asserted "I am compliant" header is worth nothing. Reading
the authoritative record on every request is what makes revocation and
posture changes take effect *now*, against tokens that were already issued.

**What it costs.** Two SQLite reads per request, and no caching to amortize
them. The MVP accepts that for correctness. A production system would cache
with a short TTL and accept a bounded window of staleness.

**What it does not do.** It stops the *next* request. A response already in
flight completes, and a long-lived connection authorized at open time is not
revisited.

### 4. Deterministic policy-as-code and fixed resource IDs

**Why.** `policy.yaml` is diffable, reviewable, and hashed — every audit row
carries the version and a hash prefix of the exact file that produced it, so
you can answer "which rules allowed this?" months later. Resources are fixed
IDs checked against a compiled-in tuple, never caller-supplied URLs, which is
why `/web/{destination}` cannot be turned into an open proxy or an SSRF
primitive.

**What it costs.** No dynamic rules, no per-user exceptions, no attribute
expressions. Adding a resource means editing a file and redeploying. For a
real system you would want OPA or Cedar; this is deliberately the simplest
thing that is honest.

### 5. Fail closed, everywhere

**Why.** Every ambiguous outcome denies: policy unreachable, policy slow,
policy returning something unparseable, audit write failing, malformed token
claim, unparseable `last_seen`. A security control that fails open is not a
security control, it is a control that works until the first outage.

**What it costs.** Availability is strictly coupled to the policy service and
the audit database. A policy outage is a total outage. That is the right
default for this workload and the wrong default for some others; the point is
that it is a choice, made explicitly, not an accident.

## Trust boundaries

| Boundary | Control |
|---|---|
| internet → gateway | RS256 verification, fixed allowlist, issuer + audience |
| gateway → policy | random service credential, `compare_digest`, internal network |
| gateway → identity | internal network; login is gated by password + enrollment |
| gateway → apps | internal network, fixed URLs, no redirects, bounded timeout |
| anything → secrets | file mode 0600, generated at setup, git-ignored, per-file mounts |

In Compose the three private services sit on `internal: true` networks with
no outbound route, and only the gateway is additionally on `edge` so its port
can be published to 127.0.0.1. The gateway container mounts
`jwt_public.pem` **only** — not the directory — so the claim "the gateway
cannot mint tokens" is enforced by the deployment, not just asserted in prose.

## Storage

Two SQLite files, both created by `scripts/setup.py`:

- `data/policy.sqlite3` — `devices`, `revoked_tokens`
- `data/audit.sqlite3` — `audit_events`

**Single-instance limitations.** SQLite with WAL handles one writer at a
time. These databases are local files on one host: not replicated, not
highly available, not shared between instances. Running two gateways against
one audit file over a network filesystem would be a correctness problem, not
just a performance one. A second instance needs PostgreSQL, which is listed
as future work. Connections are opened per operation rather than pooled —
slower, and in exchange there is no cross-thread connection state to reason
about and durability is provable by simply reopening the file.

## Data model

A token carries exactly: `iss`, `aud`, `iat`, `nbf`, `exp`, `sub`, `role`,
`device_id`, `jti`. Ten-minute lifetime. The `jti` is what makes revocation
surgical — logging out one session does not kill another.

An audit row carries exactly: `event_id`, `occurred_at`, `subject`, `role`,
`device_id`, `resource`, `action`, `result`, `reason_code`, `policy_version`,
`dlp_rule_ids`, `http_status`, `decision_latency_ms`. There is no column that
could hold a password, a token, a request body, or DLP-matched text — the
redaction is structural rather than a filter someone has to remember to apply.
