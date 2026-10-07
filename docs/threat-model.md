# Threat model and limitations

This document exists to be read *before* anyone believes a claim about this
project. Where a control is weak, it says so.

## Assets

| Asset | Where it lives | If it leaked |
|---|---|---|
| RSA private signing key | `secrets/jwt_private.pem`, identity service only | attacker mints any identity, any role |
| Demo passwords | `secrets/users.json` as PBKDF2 hashes; plaintext once in `secrets/demo_credentials.txt` | attacker logs in as that user |
| Service credential | `.env`, gateway + policy + apps | attacker queries the private policy API directly |
| Device registry | `data/policy.sqlite3` | attacker marks their own device compliant |
| Audit log | `data/audit.sqlite3` | history can be rewritten |

All of it is synthetic and generated locally. None of it is committed.

## Adversaries considered

1. **Unauthenticated network attacker** — can reach the gateway, nothing else.
2. **Authenticated low-privilege user** (Carol the contractor) — has a valid
   token and wants payroll.
3. **Malicious insider with a valid token** — wants to exfiltrate data.
4. **Attacker on a compromised endpoint** — holds a live token from a device
   that has since been flagged.

## Attacks and what stops them

| Attack | Control | Verified by |
|---|---|---|
| No credentials | 401 before any upstream call | `test_missing_authorization_header` |
| `alg=none` unsigned token | fixed RS256 allowlist | `test_alg_none_is_rejected` |
| HS256 confusion, HMAC'd with the public key | same allowlist; hand-forged in the test, not via PyJWT | `test_hs256_key_confusion_is_rejected` |
| Token signed with an attacker's RSA key | signature check against the issuer's public key | `test_forged_signature_from_an_untrusted_key` |
| Payload tampering (`role` → `administrator`) | signature covers the payload | `test_tampered_payload_is_rejected` |
| Expired / not-yet-valid token | `exp`, `nbf`, zero leeway | `test_expired_token_is_rejected`, `test_not_yet_valid_token_is_rejected` |
| Token minted for another audience | `aud` check | `test_wrong_audience_is_rejected` |
| Token from another issuer | `iss` check | `test_wrong_issuer_is_rejected` |
| Missing claims | `options={"require": [...]}` | `test_missing_required_claim_is_rejected` |
| Hostile claim values (newlines, `../`) | `SAFE_ID_PATTERN` before any lookup or log | `test_malformed_claim_values_are_rejected` |
| Spoofed `X-Role` / `X-Compliant` headers | only verified claims are read | `test_spoofed_identity_headers_are_ignored` |
| Role not defined in policy | explicit `DENY_UNKNOWN_ROLE` | `test_forged_role_in_a_validly_signed_token_is_denied` |
| Horizontal access (contractor → payroll) | per-role grants in `policy.yaml` | the 12-case `GRANT_MATRIX` |
| Unknown resource | denied by default, no wildcard | `test_unknown_application_is_denied` |
| Compromised endpoint with a live token | posture re-read every request | `test_posture_change_blocks_the_same_already_issued_token` |
| Replay after logout | persistent `revoked_tokens` table | `test_revocation_survives_reopening_the_database` |
| Arbitrary URL / SSRF via `/web/{destination}` | fixed ID tuple, no URL parameter, redirects disabled | `test_arbitrary_destinations_are_rejected` (incl. `169.254.169.254`) |
| Exfiltration via upload | DLP scan before upstream contact | `test_each_rule_blocks_before_upstream_contact` |
| `{"skip_dlp": true}` | `extra='forbid'` → 400 | `test_unexpected_or_missing_fields_are_rejected` |
| Oversized body | 65,536-byte cap before JSON parsing | `test_body_byte_limit_is_enforced_before_parsing` |
| SQL injection in audit filters | parameterized SQL, validated enum, clamped limit | `test_audit_rejects_an_invalid_result_filter` |
| XSS via a stored device label | `textContent` only, no `innerHTML`, strict CSP | `test_dashboard_javascript_avoids_unsafe_patterns` |
| Token theft from browser storage | token held in a JS variable; `localStorage` never written | `test_dashboard_javascript_avoids_unsafe_patterns` |
| Direct call to the private policy API | service credential, `compare_digest`, internal network | `test_every_private_endpoint_is_protected` |
| Policy outage used to force an allow | fail closed → 503 | `test_policy_problems_fail_closed` (five failure modes) |
| Disabling audit to hide an access | audit failure on an allow → 503, no forward | `test_audit_write_failure_blocks_an_allowed_request` |

## What this does NOT defend against

Read this section as the real scope statement.

### Identity

- **No MFA.** A password plus an enrolled device ID. Someone with both gets in.
- **An enrolled device ID is not hardware attestation.** It is a string in a
  token. There is no TPM, no secure enclave, no certificate binding, no
  proof the request came from that physical machine. Anyone who can read a
  device ID can claim it; what stops them is the password and the ownership
  check, not the device ID itself.
- **No OAuth/OIDC.** No discovery, no JWKS rotation, no refresh tokens, no
  consent, no account recovery.
- **No rate limiting on login.** Online password guessing is not slowed down
  beyond the PBKDF2 cost. A real deployment needs lockout and throttling.
- **The issuer is trusted absolutely.** It will mint whatever role it is told
  a user has. Compromise it and every other control downstream is moot — this
  is why it is the only process holding the private key, and why the gateway
  container mounts only the public key.

### Posture

- **Posture is administrator-asserted, not measured.** No agent reports in.
  An administrator sets `compliant` and `risk_score` by hand. Real posture
  needs an endpoint agent and a signed attestation path.
- **Only the next request is blocked.** A response already being streamed is
  not interrupted, and a long-lived connection authorized at open time is
  never re-checked.
- **The risk score is a made-up number.** There is no threat intelligence
  behind it. `30` is a threshold in a YAML file, not a calibrated value.

### DLP

- **Regex over UTF-8 text only.** No binary, no archives, no images, no OCR,
  no encrypted or encoded payloads. Base64-encode a secret and it sails
  through — the scanner sees a long alphanumeric string, not a credential.
- **Known false negatives**, each one covered by a test so the boundary is
  documented rather than discovered: `SG-DEMO-SECRET-ABC123` (too short),
  `...ABCDEFGHI` (too long), `...abc12345` (lowercase),
  `SG-CUSTOMER-12345` and `SG-CUSTOMER-1234567` (wrong digit count). Real
  secrets that do not match these three shapes are not detected at all.
- **Known false positives.** The email rule matches anything
  `local@domain.tld`-shaped, including `jenkins@build-01.internal` and
  `no-reply@example.com` in a signature block. In a real deployment this
  rule alone would generate enough noise to get DLP switched off.
- **Not a CASB.** No API integration with SaaS providers, no out-of-band
  discovery, no sanctioned/unsanctioned app inventory, no retroactive scan.
- **No content classification, fingerprinting, or exact data matching** —
  the techniques commercial DLP actually relies on.

### Web controls

- **Three hard-coded fixtures.** Not a URL categorization database, not a
  feed, not a crawler.
- **No TLS inspection, no proxy, no DNS filtering.** This demonstrates what
  category enforcement *is*; it does not inspect real browsing. Normal
  traffic from the browser does not pass through SASEGuard at all.
- **No outbound requests, ever.** The "phishing" and "gambling" fixtures are
  local inert files. In Compose the app network has no route out.

### Audit

- **Not tamper-evident.** A plain SQLite file. Anyone with write access can
  edit or delete rows. No hash chain, no append-only storage, no WORM, no
  signing, no off-host shipping.
- **An `allow` row records authorization, not success.** The gateway wrote
  down that it permitted the call. Whether the upstream application then
  succeeded is not captured.
- **Not atomic with upstream effects.** The audit commit and the upstream
  call are two operations. A crash between them leaves an `allow` row for a
  request that never arrived. There is no distributed transaction and no
  compensating log.
- **Single file, single host.** No replication, no high availability.

### Infrastructure

- **Plain HTTP on loopback.** No TLS, so no HSTS header is set — adding one
  over `http://` would be decoration. Behind a real TLS terminator, add it.
- **Not horizontally scalable.** SQLite, per-request connections, in-process
  counters.
- **No secret rotation story.** `scripts/setup.py --force` regenerates
  everything and invalidates every live token. There is no key overlap
  period and no `kid`-based rollover.
- **`.env` and `secrets/` are plain files**, protected by mode 0600 and
  `.gitignore`. No KMS, no vault, no envelope encryption.

## Residual risk worth naming

The honest weak point is **the issuer plus the device registry**. Compromise
the identity service and you can mint any role. Compromise the policy
database and you can declare any device healthy. Both are protected only by
file permissions and network isolation, which is appropriate for a laptop
lab and would not be appropriate for anything real.

The second weak point is that **DLP is regex matching**, and regex matching
loses to anyone who is actually trying. It stops accidents. It does not stop
an adversary.

## References

- [What is SASE? — Palo Alto Networks](https://www.paloaltonetworks.com/cyberpedia/what-is-sase)
- [SASE access — Palo Alto Networks](https://www.paloaltonetworks.com/sase/access)
- [Zero Trust Architecture (NIST SP 800-207)](https://www.nist.gov/publications/zero-trust-architecture)
- [PyJWT API reference](https://pyjwt.readthedocs.io/en/latest/api.html)
- [FastAPI OAuth2 with JWT](https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/)
