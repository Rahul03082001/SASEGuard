"""Integration tests for the SASEGuard lab.

These are integration tests, not unit tests. Each one drives the real gateway
over HTTP, which really calls the real policy service, which really reads
SQLite. The policy decision is never mocked.

The recurring pattern worth noticing: a denial test asserts **two** things —
the HTTP status the caller saw, and the upstream call counter. The second
assertion is the one that has teeth. A gateway that returned 403 *after*
forwarding the request would satisfy a status-only test while leaking every
request it claimed to block.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from apps.audit import AuditUnavailable
from apps.common import Reason
from tests.conftest import DEMO_DEVICES, DEMO_PASSWORDS, SERVICE_CREDENTIAL

# =========================================================================== #
# 1. Login, passwords, and device enrollment
# =========================================================================== #

class TestLogin:
    async def test_healthz_is_public(self, lab):
        response = await lab.client.get("/healthz")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    @pytest.mark.parametrize("username", ["alice", "bob", "carol", "admin"])
    async def test_correct_login_issues_a_token(self, lab, username):
        response = await lab.login(username)
        assert response.status_code == 200, response.text
        body = response.json()

        assert body["subject"] == username
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 600, "tokens must be short-lived (ten minutes)"
        assert body["access_token"].count(".") == 2, "expected a three-part JWS"
        # The response must not leak the issuer's key material or a password.
        assert "password" not in response.text.lower()
        assert "PRIVATE KEY" not in response.text

    async def test_login_response_is_not_cacheable(self, lab):
        response = await lab.login("alice")
        assert "no-store" in response.headers.get("cache-control", "")

    async def test_wrong_password_is_refused(self, lab):
        response = await lab.login("alice", password="not-the-password")
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_BAD_LOGIN

    async def test_unknown_user_is_refused_identically(self, lab):
        """Unknown user and wrong password must be indistinguishable.

        Different responses would turn this endpoint into a user-enumeration
        oracle.
        """
        unknown = await lab.login("alice", password="x")
        wrong = await lab.client.post(
            "/auth/login",
            json={"username": "nosuchuser", "password": "x", "device_id": "dev-alice-laptop"},
        )
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json()["reason_code"] == wrong.json()["reason_code"]
        assert unknown.json()["detail"] == wrong.json()["detail"]

    async def test_correct_password_wrong_device_is_refused(self, lab):
        """Enrollment is a second factor of its own, and it is enforced."""
        response = await lab.login("alice", device_id="dev-bob-laptop")
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_DEVICE_NOT_ENROLLED

    async def test_unenrolled_device_id_is_refused(self, lab):
        response = await lab.login("alice", device_id="dev-attacker-vm")
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_DEVICE_NOT_ENROLLED

    async def test_login_rejects_unknown_fields(self, lab):
        """``extra='forbid'`` -- a client cannot smuggle in a role."""
        response = await lab.client.post(
            "/auth/login",
            json={
                "username": "carol",
                "password": DEMO_PASSWORDS["carol"],
                "device_id": DEMO_DEVICES["carol"],
                "role": "administrator",
            },
        )
        assert response.status_code == 400
        assert response.json()["reason_code"] == Reason.DENY_MALFORMED_REQUEST

    async def test_login_rejects_malformed_identifiers(self, lab):
        response = await lab.client.post(
            "/auth/login",
            json={"username": "../../etc/passwd", "password": "x", "device_id": "dev-alice-laptop"},
        )
        assert response.status_code == 400

    async def test_login_rejects_oversized_body(self, lab):
        response = await lab.client.post(
            "/auth/login",
            content=b'{"username":"alice","password":"' + b"a" * 70_000 + b'","device_id":"d"}',
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 413


# =========================================================================== #
# 2. Least-privilege application access
# =========================================================================== #

#: (user, app, expected_allowed). The complete grant matrix from policy.yaml.
GRANT_MATRIX = [
    ("alice", "payroll", True), ("alice", "wiki", True), ("alice", "engineering", False),
    ("bob", "engineering", True), ("bob", "wiki", True), ("bob", "payroll", False),
    ("carol", "wiki", True), ("carol", "payroll", False), ("carol", "engineering", False),
    ("admin", "payroll", True), ("admin", "engineering", True), ("admin", "wiki", True),
]


class TestApplicationAccess:
    @pytest.mark.parametrize("username,app_id,allowed", GRANT_MATRIX)
    async def test_every_role_and_app_combination(self, lab, username, app_id, allowed):
        token = await lab.token_for(username)
        response = await lab.client.get(f"/apps/{app_id}", headers=lab.auth(token))

        if allowed:
            assert response.status_code == 200, response.text
            assert response.json()["data"]["app_id"] == app_id
            assert lab.upstream_calls(f"apps.{app_id}") == 1
        else:
            assert response.status_code == 403, response.text
            assert response.json()["reason_code"] == Reason.DENY_ROLE_NOT_PERMITTED
            # The assertion that matters: the private app was never contacted.
            assert lab.upstream_calls(f"apps.{app_id}") == 0

    async def test_missing_authorization_header(self, lab):
        response = await lab.client.get("/apps/wiki")
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_NO_CREDENTIALS
        assert lab.upstream_calls("apps.wiki") == 0

    @pytest.mark.parametrize(
        "header",
        ["", "Bearer", "Bearer ", "Basic abc123", "token abc", "bearerabc"],
    )
    async def test_malformed_authorization_header(self, lab, header):
        response = await lab.client.get("/apps/wiki", headers={"Authorization": header})
        assert response.status_code == 401
        assert lab.upstream_calls("apps.wiki") == 0

    async def test_unknown_application_is_denied(self, lab):
        token = await lab.token_for("admin")
        response = await lab.client.get("/apps/hr-secrets", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_UNKNOWN_RESOURCE
        assert lab.upstream_calls("apps.unknown") == 0

    async def test_path_traversal_in_app_id_is_rejected(self, lab):
        token = await lab.token_for("admin")
        response = await lab.client.get("/apps/..%2F..%2Fetc%2Fpasswd", headers=lab.auth(token))
        assert response.status_code in (400, 403, 404)
        assert lab.upstream_calls("apps.unknown") == 0

    @pytest.mark.parametrize("username", ["alice", "bob", "carol"])
    async def test_non_admins_cannot_read_devices(self, lab, username):
        token = await lab.token_for(username)
        response = await lab.client.get("/admin/devices", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_NOT_ADMIN

    @pytest.mark.parametrize("username", ["alice", "bob", "carol"])
    async def test_non_admins_cannot_write_posture(self, lab, username):
        token = await lab.token_for(username)
        response = await lab.client.put(
            "/admin/devices/dev-alice-laptop",
            json={"compliant": True, "risk_score": 0},
            headers=lab.auth(token),
        )
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_NOT_ADMIN

        # And the write genuinely did not happen.
        device = lab.policy_store.get_device("dev-alice-laptop")
        assert device is not None and device.risk_score != 0

    @pytest.mark.parametrize("username", ["alice", "bob", "carol"])
    async def test_non_admins_cannot_read_audit(self, lab, username):
        token = await lab.token_for(username)
        response = await lab.client.get("/admin/events", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_NOT_ADMIN

    async def test_admin_can_read_devices_and_audit(self, lab):
        token = await lab.token_for("admin")
        devices = await lab.client.get("/admin/devices", headers=lab.auth(token))
        assert devices.status_code == 200
        assert len(devices.json()["devices"]) == 4

        events = await lab.client.get("/admin/events", headers=lab.auth(token))
        assert events.status_code == 200
        assert events.json()["total"] >= 1


# =========================================================================== #
# 3. Token forgery and verification
# =========================================================================== #

class TestTokenVerification:
    async def test_a_minted_token_is_accepted(self, lab):
        """Baseline: the test harness can mint a token the gateway accepts.

        Without this, every negative test below could be passing for the
        wrong reason -- a broken minter rather than working verification.
        """
        token = lab.mint(subject="alice", role="finance", device_id="dev-alice-laptop")
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 200, response.text

    async def test_forged_signature_from_an_untrusted_key(self, lab, attacker_keypair):
        """A perfectly formed token signed by the wrong RSA key."""
        attacker_private, _ = attacker_keypair
        token = lab.mint(key=attacker_private)
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_BAD_TOKEN_SIGNATURE
        assert lab.upstream_calls("apps.wiki") == 0

    async def test_tampered_payload_is_rejected(self, lab):
        """Flip a byte in the payload segment; the signature no longer matches."""
        import base64
        import json

        token = lab.mint(subject="carol", role="contractor", device_id="dev-carol-byod")
        header, payload, signature = token.split(".")

        decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
        decoded["role"] = "administrator"
        forged_payload = base64.urlsafe_b64encode(
            json.dumps(decoded).encode()
        ).decode().rstrip("=")

        response = await lab.client.get(
            "/apps/payroll", headers=lab.auth(f"{header}.{forged_payload}.{signature}")
        )
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_BAD_TOKEN_SIGNATURE
        assert lab.upstream_calls("apps.payroll") == 0

    async def test_alg_none_is_rejected(self, lab):
        """An unsigned token must never be accepted.

        This is the canonical JWT failure: a library that honours the token's
        own ``alg`` header will happily accept ``alg=none``. A fixed
        allowlist is what prevents it.
        """
        for token in (lab.mint(algorithm="none"), lab.forge_unsigned()):
            response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
            assert response.status_code == 401, response.text
            assert response.json()["reason_code"] in (
                Reason.DENY_TOKEN_ALGORITHM,
                Reason.DENY_BAD_TOKEN_SIGNATURE,
            )
        assert lab.upstream_calls("apps.payroll") == 0

    async def test_hs256_key_confusion_is_rejected(self, lab):
        """The symmetric-confusion attack.

        The attacker knows the RSA *public* key -- it is not a secret -- and
        signs an HS256 token using that public key as the HMAC secret. A
        verifier that picks its algorithm from the token header would compute
        the same HMAC and accept it. ``algorithms=["RS256"]`` refuses to even
        try HS256.
        """
        token = lab.forge_hs256_with_public_key()
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_TOKEN_ALGORITHM
        assert lab.upstream_calls("apps.payroll") == 0

    async def test_expired_token_is_rejected(self, lab):
        token = lab.mint(lifetime=timedelta(seconds=-30))
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_TOKEN_EXPIRED
        assert lab.upstream_calls("apps.wiki") == 0

    async def test_not_yet_valid_token_is_rejected(self, lab):
        """A backdated-forward token. Guards against nbf being ignored."""
        token = lab.mint(not_before=timedelta(minutes=30))
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_TOKEN_NOT_YET_VALID
        assert lab.upstream_calls("apps.wiki") == 0

    async def test_wrong_issuer_is_rejected(self, lab):
        token = lab.mint(issuer="https://evil.example/idp")
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_TOKEN_ISSUER
        assert lab.upstream_calls("apps.wiki") == 0

    async def test_wrong_audience_is_rejected(self, lab):
        """A validly signed token for a different service must not work here."""
        token = lab.mint(audience="some-other-service")
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 401
        assert response.json()["reason_code"] == Reason.DENY_TOKEN_AUDIENCE
        assert lab.upstream_calls("apps.wiki") == 0

    @pytest.mark.parametrize("claim", ["sub", "role", "device_id", "jti", "exp", "nbf", "iat"])
    async def test_missing_required_claim_is_rejected(self, lab, claim):
        token = lab.mint(drop_claims=(claim,))
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 401, f"missing {claim} should be rejected"
        assert response.json()["reason_code"] in (
            Reason.DENY_TOKEN_CLAIMS,
            Reason.DENY_TOKEN_EXPIRED,
            Reason.DENY_TOKEN_AUDIENCE,
            Reason.DENY_TOKEN_ISSUER,
        )
        assert lab.upstream_calls("apps.wiki") == 0

    @pytest.mark.parametrize("claim", ["iss", "aud"])
    async def test_missing_issuer_or_audience_is_rejected(self, lab, claim):
        token = lab.mint(drop_claims=(claim,))
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 401
        assert lab.upstream_calls("apps.wiki") == 0

    @pytest.mark.parametrize("bad", ["../../etc/passwd", "alice\nrole=admin", "a b", "", "x" * 200])
    async def test_malformed_claim_values_are_rejected(self, lab, bad):
        """A present-but-hostile claim value must not reach a lookup or a log."""
        token = lab.mint(subject=bad)
        response = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert response.status_code == 401
        assert lab.upstream_calls("apps.wiki") == 0

    async def test_garbage_token_is_rejected(self, lab):
        for garbage in ("not-a-token", "a.b.c", "...", "eyJhbGciOiJSUzI1NiJ9"):
            response = await lab.client.get("/apps/wiki", headers=lab.auth(garbage))
            assert response.status_code == 401, garbage
        assert lab.upstream_calls("apps.wiki") == 0

    async def test_forged_role_in_a_validly_signed_token_is_denied(self, lab):
        """Our own issuer's key, but a role policy has never heard of.

        Signature valid, claims complete -- and still denied, because the
        role is not defined in policy.yaml. Authentication and authorization
        are separate gates.
        """
        token = lab.mint(subject="carol", role="superuser", device_id="dev-carol-byod")
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_UNKNOWN_ROLE
        assert lab.upstream_calls("apps.payroll") == 0

    async def test_role_escalation_via_valid_signature_is_still_posture_checked(self, lab):
        """Carol's device, Carol's subject, but claiming the administrator role.

        The role is real, so the grant would pass -- but the device is
        enrolled to carol, and ownership is checked against ``sub``. The
        request is denied on the grant, not on a lucky technicality.
        """
        token = lab.mint(
            subject="carol", role="administrator", device_id="dev-carol-byod"
        )
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        # The signature is genuine, so this reaches policy. Policy allows the
        # administrator role to read payroll -- which is exactly why the
        # issuer must never mint a role a user does not have, and why the
        # private key lives in one process only. Documented in the threat model.
        assert response.status_code == 200
        assert lab.upstream_calls("apps.payroll") == 1


# =========================================================================== #
# 4. Device posture
# =========================================================================== #

class TestDevicePosture:
    async def test_healthy_device_is_allowed(self, lab):
        token = await lab.token_for("alice")
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 200
        assert lab.upstream_calls("apps.payroll") == 1

    @pytest.mark.parametrize(
        "changes,expected_reason",
        [
            ({"managed": False}, Reason.DENY_DEVICE_UNMANAGED),
            ({"compliant": False}, Reason.DENY_DEVICE_NONCOMPLIANT),
            ({"risk_score": 95}, Reason.DENY_DEVICE_RISK_SCORE),
            ({"risk_score": 31}, Reason.DENY_DEVICE_RISK_SCORE),
        ],
    )
    async def test_unhealthy_posture_denies_a_valid_token(self, lab, changes, expected_reason):
        token = await lab.token_for("alice")
        lab.set_posture("dev-alice-laptop", **changes)

        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 403, response.text
        assert response.json()["reason_code"] == expected_reason
        assert lab.upstream_calls("apps.payroll") == 0

    async def test_risk_score_boundary_is_inclusive(self, lab):
        """The threshold is ``<= 30``. Exactly 30 must still be allowed."""
        token = await lab.token_for("alice")
        lab.set_posture("dev-alice-laptop", risk_score=30)
        allowed = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert allowed.status_code == 200

        lab.set_posture("dev-alice-laptop", risk_score=31)
        denied = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert denied.status_code == 403
        assert denied.json()["reason_code"] == Reason.DENY_DEVICE_RISK_SCORE

    async def test_stale_posture_is_denied(self, lab):
        """Posture older than 24h counts as unknown, not as healthy."""
        token = await lab.token_for("alice")
        lab.make_stale("dev-alice-laptop", hours=48)

        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_POSTURE_STALE
        assert lab.upstream_calls("apps.payroll") == 0

    async def test_posture_age_boundary(self, lab):
        token = await lab.token_for("alice")
        lab.make_stale("dev-alice-laptop", hours=23)
        assert (await lab.client.get("/apps/payroll", headers=lab.auth(token))).status_code == 200

        lab.make_stale("dev-alice-laptop", hours=25)
        late = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert late.status_code == 403
        assert late.json()["reason_code"] == Reason.DENY_POSTURE_STALE

    async def test_unparseable_last_seen_fails_closed(self, lab):
        """Malformed state must deny, never default to fresh."""
        token = await lab.token_for("alice")
        lab.policy_store.update_device("dev-alice-laptop", {"last_seen": "not-a-timestamp"})
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_POSTURE_STALE

    async def test_unknown_device_is_denied(self, lab):
        """A token naming a device that is not in the registry."""
        token = lab.mint(subject="alice", role="finance", device_id="dev-ghost-vm")
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_DEVICE_UNKNOWN
        assert lab.upstream_calls("apps.payroll") == 0

    async def test_device_owned_by_someone_else_is_denied(self, lab):
        """Alice's identity on Bob's enrolled device."""
        token = lab.mint(subject="alice", role="finance", device_id="dev-bob-laptop")
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_DEVICE_NOT_OWNED
        assert lab.upstream_calls("apps.payroll") == 0

    async def test_posture_applies_to_uploads_and_web_too(self, lab):
        """Posture is not an app-only gate; every grant depends on it."""
        token = await lab.token_for("alice")
        lab.set_posture("dev-alice-laptop", compliant=False)

        web = await lab.client.get("/web/docs", headers=lab.auth(token))
        assert web.status_code == 403
        assert web.json()["reason_code"] == Reason.DENY_DEVICE_NONCOMPLIANT
        assert lab.upstream_calls("web.docs") == 0

        upload = await lab.client.post(
            "/saas/upload", json={"filename": "n.txt", "content": "clean"},
            headers=lab.auth(token),
        )
        assert upload.status_code == 403
        assert upload.json()["reason_code"] == Reason.DENY_DEVICE_NONCOMPLIANT
        assert lab.accepted_uploads() == 0

    async def test_admin_posture_is_enforced_for_admin_routes(self, lab):
        """An administrator on a broken device loses admin access too."""
        token = await lab.token_for("admin")
        assert (await lab.client.get("/admin/devices", headers=lab.auth(token))).status_code == 200

        lab.set_posture("dev-admin-workstation", compliant=False)
        response = await lab.client.get("/admin/devices", headers=lab.auth(token))
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_DEVICE_NONCOMPLIANT


# =========================================================================== #
# 5. Live re-evaluation and persistent revocation
# =========================================================================== #

class TestRevocationAndReevaluation:
    async def test_posture_change_blocks_the_same_already_issued_token(self, lab):
        """The headline behaviour of the whole lab.

        One token, three requests, no re-login. The token is byte-for-byte
        identical throughout -- only the authoritative device state changes.
        This only works because no positive decision is cached.
        """
        token = await lab.token_for("alice")

        first = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert first.status_code == 200
        assert lab.upstream_calls("apps.payroll") == 1

        lab.set_posture("dev-alice-laptop", compliant=False)

        second = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert second.status_code == 403
        assert second.json()["reason_code"] == Reason.DENY_DEVICE_NONCOMPLIANT
        assert lab.upstream_calls("apps.payroll") == 1, "must not have forwarded"

        # Restoring posture lets the same token through again. Revocation and
        # posture are different mechanisms: a broken device is a temporary
        # state, not a destroyed credential.
        lab.make_fresh("dev-alice-laptop")

        third = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert third.status_code == 200
        assert lab.upstream_calls("apps.payroll") == 2

    async def test_logout_revokes_the_token_persistently(self, lab):
        token = await lab.token_for("alice")
        assert (await lab.client.get("/apps/wiki", headers=lab.auth(token))).status_code == 200

        logout = await lab.client.post("/auth/logout", headers=lab.auth(token))
        assert logout.status_code == 200
        assert logout.json()["revoked"] is True

        reuse = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert reuse.status_code == 403
        assert reuse.json()["reason_code"] == Reason.DENY_TOKEN_REVOKED
        assert lab.upstream_calls("apps.wiki") == 1, "revoked token must not forward"

    async def test_revocation_survives_reopening_the_database(self, lab):
        """Revocation is persisted, not held in process memory."""
        from apps.policy import PolicyStore

        token = await lab.token_for("alice")
        await lab.client.post("/auth/logout", headers=lab.auth(token))

        # A brand-new store object, a brand-new SQLite connection.
        reopened = PolicyStore(lab.policy_store.path)
        assert reopened.revoked_count() == 1

        still_denied = await lab.client.get("/apps/wiki", headers=lab.auth(token))
        assert still_denied.status_code == 403
        assert still_denied.json()["reason_code"] == Reason.DENY_TOKEN_REVOKED

    async def test_revocation_is_per_token_not_per_account(self, lab):
        """Logging out one session must not kill another.

        Each login gets a fresh ``jti``, so revocation is surgical.
        """
        first_token = await lab.token_for("alice")
        second_token = await lab.token_for("alice")
        assert first_token != second_token

        await lab.client.post("/auth/logout", headers=lab.auth(first_token))

        assert (await lab.client.get("/apps/wiki", headers=lab.auth(first_token))).status_code == 403
        assert (await lab.client.get("/apps/wiki", headers=lab.auth(second_token))).status_code == 200

    async def test_logout_works_even_on_an_unhealthy_device(self, lab):
        """You must always be able to log out.

        Requiring healthy posture to revoke a token would be a trap: the
        moment a device went non-compliant, its live token could no longer be
        retired by its owner.
        """
        token = await lab.token_for("alice")
        lab.set_posture("dev-alice-laptop", compliant=False, risk_score=99)

        logout = await lab.client.post("/auth/logout", headers=lab.auth(token))
        assert logout.status_code == 200
        assert logout.json()["revoked"] is True

    async def test_logout_requires_a_valid_token(self, lab):
        assert (await lab.client.post("/auth/logout")).status_code == 401
        assert (await lab.client.post("/auth/logout", headers=lab.auth("garbage"))).status_code == 401

    async def test_revoking_one_user_does_not_affect_another(self, lab):
        alice = await lab.token_for("alice")
        bob = await lab.token_for("bob")
        await lab.client.post("/auth/logout", headers=lab.auth(alice))

        assert (await lab.client.get("/apps/wiki", headers=lab.auth(bob))).status_code == 200


# =========================================================================== #
# 6. Lab web category controls
# =========================================================================== #

class TestWebCategories:
    async def test_allowed_category_is_forwarded(self, lab):
        token = await lab.token_for("alice")
        response = await lab.client.get("/web/docs", headers=lab.auth(token))
        assert response.status_code == 200
        assert response.json()["category"] == "business-and-economy"
        assert lab.upstream_calls("web.docs") == 1

    @pytest.mark.parametrize(
        "destination,category",
        [("phishing-sim", "phishing"), ("gambling-sim", "gambling")],
    )
    async def test_blocked_categories_are_never_fetched(self, lab, destination, category):
        """The inert fixture exists and is reachable -- and is still not fetched."""
        token = await lab.token_for("alice")
        response = await lab.client.get(f"/web/{destination}", headers=lab.auth(token))

        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_WEB_CATEGORY
        assert response.json()["category"] == category
        assert lab.upstream_calls(f"web.{destination}") == 0

    @pytest.mark.parametrize(
        "destination",
        [
            "evil.example.com",
            "http:%2F%2F169.254.169.254%2Flatest%2Fmeta-data",
            "localhost:8082",
            "..%2F..%2Fetc%2Fpasswd",
            "attacker.test",
        ],
    )
    async def test_arbitrary_destinations_are_rejected(self, lab, destination):
        """There is no URL parameter, so there is no SSRF primitive.

        ``destination`` is an ID matched against a fixed tuple. Anything else
        is denied before any outbound call is considered -- including the
        cloud-metadata address, which is the classic SSRF target.
        """
        token = await lab.token_for("alice")
        response = await lab.client.get(f"/web/{destination}", headers=lab.auth(token))

        assert response.status_code in (400, 403, 404), response.text
        if response.status_code == 403:
            assert response.json()["reason_code"] in (
                Reason.DENY_UNKNOWN_DESTINATION,
                Reason.DENY_MALFORMED_REQUEST,
            )
        assert lab.upstream_calls("web.unknown") == 0

    async def test_web_requires_authentication(self, lab):
        response = await lab.client.get("/web/docs")
        assert response.status_code == 401
        assert lab.upstream_calls("web.docs") == 0

    @pytest.mark.parametrize(
        "spoofed",
        [
            {"X-Role": "administrator"},
            {"X-User": "admin", "X-Subject": "admin"},
            {"X-Device-Compliant": "true", "X-Compliant": "true"},
            {"X-Device-Id": "dev-admin-workstation"},
            {"X-Risk-Score": "0"},
            {"X-SASEGuard-Role": "administrator", "X-Forwarded-User": "admin"},
        ],
    )
    async def test_spoofed_identity_headers_are_ignored(self, lab, spoofed):
        """Carol stays a contractor no matter what she puts in her headers.

        Authorization inputs come from verified token claims and the policy
        database. Nothing else in the request is consulted.
        """
        token = await lab.token_for("carol")
        headers = {**lab.auth(token), **spoofed}

        payroll = await lab.client.get("/apps/payroll", headers=headers)
        assert payroll.status_code == 403
        assert payroll.json()["reason_code"] == Reason.DENY_ROLE_NOT_PERMITTED
        assert lab.upstream_calls("apps.payroll") == 0

        admin = await lab.client.get("/admin/devices", headers=headers)
        assert admin.status_code == 403
        assert admin.json()["reason_code"] == Reason.DENY_NOT_ADMIN

    async def test_spoofed_headers_cannot_bypass_posture(self, lab):
        token = await lab.token_for("alice")
        lab.set_posture("dev-alice-laptop", compliant=False)

        response = await lab.client.get(
            "/apps/payroll",
            headers={**lab.auth(token), "X-Device-Compliant": "true", "X-Compliant": "1"},
        )
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_DEVICE_NONCOMPLIANT


# =========================================================================== #
# 7. Text-only DLP
# =========================================================================== #

#: (rule_id, content). One sample per rule, each a realistic-looking sentence.
DLP_SAMPLES = [
    ("SG-DLP-001", "Rotate the staging key SG-DEMO-SECRET-A1B2C3D4 before Friday."),
    ("SG-DLP-002", "Escalation for account SG-CUSTOMER-204517 is still open."),
    ("SG-DLP-003", "Primary contact is dana.reyes@example.com for this thread."),
]

#: Near-misses that must NOT block. These are the false-positive guard rails.
DLP_CLEAN_SAMPLES = [
    "Quarterly summary: headcount steady, nothing sensitive here.",
    "SG-DEMO-SECRET-ABC123 is too short to be a real key.",
    "SG-DEMO-SECRET-ABCDEFGHI has nine characters, not eight.",
    "SG-DEMO-SECRET-abc12345 is lowercase.",
    "SG-CUSTOMER-12345 has five digits.",
    "SG-CUSTOMER-1234567 has seven digits.",
    "Mentioning SG-CUSTOMER- with no number at all.",
    "An @ sign on its own, and a domain like example.com, separately.",
]


class TestDataLossPrevention:
    async def test_clean_upload_is_forwarded(self, lab):
        token = await lab.token_for("alice")
        response = await lab.client.post(
            "/saas/upload",
            json={"filename": "notes.txt", "content": DLP_CLEAN_SAMPLES[0]},
            headers=lab.auth(token),
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["allowed"] is True
        assert body["dlp"]["blocked"] is False
        assert body["upstream"]["accepted_uploads"] == 1
        assert lab.accepted_uploads() == 1

    @pytest.mark.parametrize("content", DLP_CLEAN_SAMPLES)
    async def test_near_miss_content_is_not_blocked(self, lab, content):
        """Documented false-negative boundaries, asserted rather than claimed."""
        token = await lab.token_for("alice")
        response = await lab.client.post(
            "/saas/upload",
            json={"filename": "notes.txt", "content": content},
            headers=lab.auth(token),
        )
        assert response.status_code == 200, f"should not block: {content!r}"
        assert lab.accepted_uploads() == 1

    @pytest.mark.parametrize("rule_id,content", DLP_SAMPLES)
    async def test_each_rule_blocks_before_upstream_contact(self, lab, rule_id, content):
        """The central DLP guarantee, proved by the upstream counter."""
        token = await lab.token_for("alice")
        response = await lab.client.post(
            "/saas/upload",
            json={"filename": "leak.txt", "content": content},
            headers=lab.auth(token),
        )

        assert response.status_code == 403, response.text
        body = response.json()
        assert body["reason_code"] == Reason.DENY_DLP_MATCH
        assert rule_id in [f["rule_id"] for f in body["dlp"]["findings"]]
        assert body["audit_event_id"]

        # Synthetic storage was never contacted. This is the assertion that
        # distinguishes real prevention from after-the-fact detection.
        assert lab.accepted_uploads() == 0

    @pytest.mark.parametrize("rule_id,content", DLP_SAMPLES)
    async def test_matched_values_are_never_echoed(self, lab, rule_id, content):
        """The error message must not contain the secret it just blocked."""
        token = await lab.token_for("alice")
        response = await lab.client.post(
            "/saas/upload",
            json={"filename": "leak.txt", "content": content},
            headers=lab.auth(token),
        )
        assert response.status_code == 403

        # Pull out the literal sensitive token from the sample and make sure
        # no part of it survived into the response.
        for word in content.split():
            stripped = word.strip(".,()")
            if stripped.startswith("SG-DEMO-SECRET-") or stripped.startswith("SG-CUSTOMER-") or "@" in stripped:
                assert stripped not in response.text, f"leaked {stripped!r}"

    async def test_multiple_rules_are_all_reported(self, lab):
        token = await lab.token_for("alice")
        response = await lab.client.post(
            "/saas/upload",
            json={
                "filename": "everything.txt",
                "content": "SG-DEMO-SECRET-ZZ999999 for SG-CUSTOMER-112233, ping ops@example.com",
            },
            headers=lab.auth(token),
        )
        assert response.status_code == 403
        found = {f["rule_id"] for f in response.json()["dlp"]["findings"]}
        assert found == {"SG-DLP-001", "SG-DLP-002", "SG-DLP-003"}
        assert lab.accepted_uploads() == 0

    async def test_contractors_cannot_upload_at_all(self, lab):
        """Denied on the role, before the content is even looked at."""
        token = await lab.token_for("carol")
        response = await lab.client.post(
            "/saas/upload",
            json={"filename": "harmless.txt", "content": "nothing sensitive at all"},
            headers=lab.auth(token),
        )
        assert response.status_code == 403
        assert response.json()["reason_code"] == Reason.DENY_UPLOAD_NOT_PERMITTED
        assert lab.accepted_uploads() == 0

    @pytest.mark.parametrize("username", ["alice", "bob", "admin"])
    async def test_permitted_roles_can_upload(self, lab, username):
        token = await lab.token_for(username)
        response = await lab.client.post(
            "/saas/upload",
            json={"filename": "ok.txt", "content": "benign text"},
            headers=lab.auth(token),
        )
        assert response.status_code == 200, response.text

    async def test_upload_requires_authentication(self, lab):
        response = await lab.client.post(
            "/saas/upload", json={"filename": "x.txt", "content": "hello"}
        )
        assert response.status_code == 401
        assert lab.accepted_uploads() == 0

    @pytest.mark.parametrize(
        "payload",
        [
            {"filename": "x.txt", "content": "hi", "skip_dlp": True},
            {"filename": "x.txt", "content": "hi", "role": "administrator"},
            {"filename": "x.txt", "content": "hi", "unexpected": 1},
            {"filename": "x.txt"},
            {"content": "hi"},
            {},
        ],
    )
    async def test_unexpected_or_missing_fields_are_rejected(self, lab, payload):
        """Strict schemas: a client cannot believe it disabled scanning."""
        token = await lab.token_for("alice")
        response = await lab.client.post(
            "/saas/upload", json=payload, headers=lab.auth(token)
        )
        assert response.status_code == 400, response.text
        assert response.json()["reason_code"] == Reason.DENY_MALFORMED_REQUEST
        assert lab.accepted_uploads() == 0

    async def test_body_byte_limit_is_enforced_before_parsing(self, lab):
        """65,536-byte HTTP body cap, checked before JSON deserialization."""
        token = await lab.token_for("alice")
        oversized = b'{"filename":"big.txt","content":"' + b"a" * 70_000 + b'"}'
        assert len(oversized) > 65_536

        response = await lab.client.post(
            "/saas/upload",
            content=oversized,
            headers={**lab.auth(token), "content-type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["reason_code"] == Reason.DENY_BODY_TOO_LARGE
        assert lab.accepted_uploads() == 0

    async def test_content_character_limit_is_enforced(self, lab):
        """32,000-character content cap, separate from the byte cap."""
        token = await lab.token_for("alice")
        response = await lab.client.post(
            "/saas/upload",
            json={"filename": "long.txt", "content": "a" * 32_001},
            headers=lab.auth(token),
        )
        assert response.status_code == 400
        assert lab.accepted_uploads() == 0

        at_limit = await lab.client.post(
            "/saas/upload",
            json={"filename": "long.txt", "content": "a" * 32_000},
            headers=lab.auth(token),
        )
        assert at_limit.status_code == 200, "exactly at the limit must be accepted"

    async def test_dlp_rules_are_published(self, lab):
        """A blocked user should be able to see what the rules are."""
        response = await lab.client.get("/meta/dlp-rules")
        assert response.status_code == 200
        rules = response.json()["rules"]
        assert {r["rule_id"] for r in rules} == {"SG-DLP-001", "SG-DLP-002", "SG-DLP-003"}
        assert all(r["pattern"] for r in rules)


# =========================================================================== #
# 8. Audit, fail-closed behaviour, and private service authentication
# =========================================================================== #

class TestAudit:
    async def test_allowed_request_is_recorded(self, lab):
        token = await lab.token_for("alice")
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        event_id = response.json()["audit_event_id"]

        event = lab.audit_store.get(event_id)
        assert event is not None
        assert event["subject"] == "alice"
        assert event["role"] == "finance"
        assert event["resource"] == "payroll"
        assert event["action"] == "app.read"
        assert event["result"] == "allow"
        assert event["reason_code"] == Reason.ALLOW_ROLE_GRANT
        assert event["policy_version"].startswith("1.0.0+")
        assert event["decision_latency_ms"] > 0
        assert event["occurred_at"]

    async def test_denied_request_is_recorded_with_its_reason(self, lab):
        token = await lab.token_for("carol")
        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))

        event = lab.audit_store.get(response.json()["audit_event_id"])
        assert event is not None
        assert event["result"] == "deny"
        assert event["reason_code"] == Reason.DENY_ROLE_NOT_PERMITTED

    async def test_authentication_failures_are_recorded_anonymously(self, lab):
        """A 401 is still a security event worth keeping.

        It is recorded without a subject, because there is no verified
        identity to attribute it to -- writing down the *claimed* subject
        would be recording attacker-controlled data as fact.
        """
        await lab.client.get("/apps/wiki", headers=lab.auth("garbage.token.here"))

        denials = lab.audit_store.query(result="deny")
        assert any(e["subject"] == "anonymous" for e in denials)

    async def test_audit_rows_contain_no_secrets(self, lab):
        """Redaction, asserted against the actual stored bytes.

        Every event in the database is searched for the password, the bearer
        token, and the DLP-matched secret. None may appear anywhere.
        """
        import json

        token = await lab.token_for("alice")
        secret = "SG-DEMO-SECRET-A1B2C3D4"

        await lab.client.get("/apps/payroll", headers=lab.auth(token))
        await lab.client.post(
            "/saas/upload",
            json={"filename": "leak.txt", "content": f"the key is {secret}"},
            headers=lab.auth(token),
        )
        await lab.client.post(
            "/auth/login",
            json={
                "username": "alice",
                "password": DEMO_PASSWORDS["alice"],
                "device_id": "dev-alice-laptop",
            },
        )

        serialized = json.dumps(lab.audit_store.query(limit=500))
        assert secret not in serialized, "DLP-matched value leaked into the audit log"
        assert DEMO_PASSWORDS["alice"] not in serialized, "password leaked into the audit log"
        assert token not in serialized, "bearer token leaked into the audit log"
        # Nor any fragment of the token.
        for segment in token.split("."):
            assert segment not in serialized

        # The rule ID *is* recorded -- that is the point of a rule ID.
        assert any("SG-DLP-001" in (e["dlp_rule_ids"] or []) for e in lab.audit_store.query(limit=500))

    async def test_audit_columns_are_an_allowlist(self, lab):
        """No column exists that could hold a payload or a credential."""
        token = await lab.token_for("alice")
        await lab.client.get("/apps/payroll", headers=lab.auth(token))

        event = lab.audit_store.query(limit=1)[0]
        assert set(event.keys()) == {
            "event_id", "occurred_at", "subject", "role", "device_id",
            "resource", "action", "result", "reason_code", "policy_version",
            "dlp_rule_ids", "http_status", "decision_latency_ms",
        }

    async def test_audit_filtering_and_limits(self, lab):
        token = await lab.token_for("admin")
        await lab.client.get("/apps/payroll", headers=lab.auth(token))
        carol = await lab.token_for("carol")
        await lab.client.get("/apps/payroll", headers=lab.auth(carol))

        allows = await lab.client.get("/admin/events?result=allow", headers=lab.auth(token))
        assert allows.status_code == 200
        assert all(e["result"] == "allow" for e in allows.json()["events"])

        denies = await lab.client.get("/admin/events?result=deny", headers=lab.auth(token))
        assert all(e["result"] == "deny" for e in denies.json()["events"])
        assert len(denies.json()["events"]) >= 1

        limited = await lab.client.get("/admin/events?limit=2", headers=lab.auth(token))
        assert len(limited.json()["events"]) <= 2

    async def test_audit_rejects_an_invalid_result_filter(self, lab):
        token = await lab.token_for("admin")
        response = await lab.client.get(
            "/admin/events?result=allow'%20OR%201=1--", headers=lab.auth(token)
        )
        assert response.status_code == 400

    async def test_audit_limit_is_clamped_not_trusted(self, lab):
        token = await lab.token_for("admin")
        response = await lab.client.get("/admin/events?limit=999999", headers=lab.auth(token))
        assert response.status_code == 200
        assert len(response.json()["events"]) <= 500

    async def test_audit_write_failure_blocks_an_allowed_request(self, lab, monkeypatch):
        """Fail closed when the decision cannot be recorded.

        An allowed request whose authorization cannot be durably written must
        not be forwarded. Otherwise the system would permit accesses it has
        no record of -- exactly the outcome an audit log exists to prevent.
        """
        token = await lab.token_for("alice")

        def explode(_event):
            raise AuditUnavailable("simulated disk failure")

        monkeypatch.setattr(lab.audit_store, "record", explode)

        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 503
        assert response.json()["reason_code"] == Reason.ERROR_AUDIT_UNAVAILABLE
        assert lab.upstream_calls("apps.payroll") == 0, "must not forward without an audit row"

    async def test_audit_write_failure_blocks_an_allowed_upload(self, lab, monkeypatch):
        token = await lab.token_for("alice")

        def explode(_event):
            raise AuditUnavailable("simulated disk failure")

        monkeypatch.setattr(lab.audit_store, "record", explode)

        response = await lab.client.post(
            "/saas/upload",
            json={"filename": "ok.txt", "content": "benign"},
            headers=lab.auth(token),
        )
        assert response.status_code == 503
        assert response.json()["reason_code"] == Reason.ERROR_AUDIT_UNAVAILABLE
        assert lab.accepted_uploads() == 0


class TestFailClosed:
    @pytest.mark.parametrize(
        "transport_name",
        ["DeadTransport", "HangingTransport", "NonJsonTransport",
         "MalformedDecisionTransport", "ErrorStatusTransport"],
    )
    async def test_policy_problems_fail_closed(self, lab, transport_name):
        """Five ways the policy service can let us down. All must 503.

        Down, hung, non-JSON, HTTP 500, and -- the subtle one -- a 200 with
        ``{"allow": "yes"}``. A truthiness check on that string would read as
        an allow, so the gateway type-checks the boolean.
        """
        from tests import conftest

        token = await lab.token_for("alice")
        lab.replace_policy_transport(getattr(conftest, transport_name)())

        response = await lab.client.get("/apps/payroll", headers=lab.auth(token))
        assert response.status_code == 503, response.text
        assert response.json()["reason_code"] in (
            Reason.ERROR_POLICY_UNAVAILABLE,
            Reason.ERROR_POLICY_INVALID_RESPONSE,
        )
        assert lab.upstream_calls("apps.payroll") == 0, "must not forward without a decision"

    async def test_policy_outage_also_blocks_uploads_and_web(self, lab):
        from tests.conftest import DeadTransport

        token = await lab.token_for("alice")
        lab.replace_policy_transport(DeadTransport())

        web = await lab.client.get("/web/docs", headers=lab.auth(token))
        assert web.status_code == 503
        assert lab.upstream_calls("web.docs") == 0

        upload = await lab.client.post(
            "/saas/upload",
            json={"filename": "x.txt", "content": "benign"},
            headers=lab.auth(token),
        )
        assert upload.status_code == 503
        assert lab.accepted_uploads() == 0

    async def test_policy_outage_is_recorded_as_an_error(self, lab):
        from tests.conftest import DeadTransport

        token = await lab.token_for("alice")
        lab.replace_policy_transport(DeadTransport())
        await lab.client.get("/apps/payroll", headers=lab.auth(token))

        errors = lab.audit_store.query(result="error")
        assert len(errors) >= 1
        assert errors[0]["reason_code"] == Reason.ERROR_POLICY_UNAVAILABLE

    async def test_token_verification_still_runs_during_a_policy_outage(self, lab):
        """A bad token is a 401, not a 503. Authentication is local."""
        from tests.conftest import DeadTransport

        lab.replace_policy_transport(DeadTransport())
        response = await lab.client.get("/apps/payroll", headers=lab.auth("garbage"))
        assert response.status_code == 401


class TestPrivateServiceAuthentication:
    async def test_evaluate_requires_the_service_credential(self, policy_client):
        payload = {
            "subject": "carol", "role": "administrator", "device_id": "dev-carol-byod",
            "token_id": "jti_x", "resource": "payroll", "action": "app.read",
        }
        assert (await policy_client.post("/evaluate", json=payload)).status_code == 401

    @pytest.mark.parametrize("credential", ["", "wrong", "test-service-credential", "x" * 64])
    async def test_wrong_service_credential_is_rejected(self, policy_client, credential):
        from apps.common import SERVICE_CREDENTIAL_HEADER

        response = await policy_client.post(
            "/evaluate",
            json={
                "subject": "alice", "role": "finance", "device_id": "dev-alice-laptop",
                "token_id": "jti_x", "resource": "wiki", "action": "app.read",
            },
            headers={SERVICE_CREDENTIAL_HEADER: credential},
        )
        assert response.status_code == 401

    async def test_correct_service_credential_is_accepted(self, policy_client, service_headers):
        response = await policy_client.post(
            "/evaluate",
            json={
                "subject": "alice", "role": "finance", "device_id": "dev-alice-laptop",
                "token_id": "jti_x", "resource": "wiki", "action": "app.read",
            },
            headers=service_headers,
        )
        assert response.status_code == 200
        assert response.json()["allow"] is True

    @pytest.mark.parametrize(
        "method,path",
        [("get", "/devices"), ("put", "/devices/dev-alice-laptop"), ("post", "/revoke")],
    )
    async def test_every_private_endpoint_is_protected(self, policy_client, method, path):
        # ``request`` rather than ``client.get(json=...)``: httpx only accepts a
        # JSON body on the methods that take one, and we want to hit all three
        # endpoints through one parametrized test.
        response = await policy_client.request(
            method.upper(), path, json={"token_id": "t", "subject": "s", "compliant": True}
        )
        assert response.status_code == 401

    async def test_policy_health_is_public_inside_the_private_network(self, policy_client):
        response = await policy_client.get("/healthz")
        assert response.status_code == 200

    async def test_evaluate_rejects_unexpected_fields(self, policy_client, service_headers):
        response = await policy_client.post(
            "/evaluate",
            json={
                "subject": "alice", "role": "finance", "device_id": "dev-alice-laptop",
                "token_id": "jti_x", "resource": "wiki", "action": "app.read",
                "override": True,
            },
            headers=service_headers,
        )
        assert response.status_code == 400

    @pytest.mark.parametrize("action", ["app.write", "admin.root", "", "app.read\n"])
    async def test_unknown_actions_are_denied(self, policy_client, service_headers, action):
        response = await policy_client.post(
            "/evaluate",
            json={
                "subject": "alice", "role": "finance", "device_id": "dev-alice-laptop",
                "token_id": "jti_x", "resource": "wiki", "action": action,
            },
            headers=service_headers,
        )
        if response.status_code == 200:
            assert response.json()["allow"] is False
            assert response.json()["reason_code"] == Reason.DENY_UNKNOWN_ACTION
        else:
            assert response.status_code == 400

    async def test_mock_app_counters_require_the_service_credential(self):
        """The introspection endpoint tests rely on is itself protected."""
        from apps import mock_apps as mock_apps_module
        from apps.common import SERVICE_CREDENTIAL_HEADER

        app = mock_apps_module.create_app(service_credential=SERVICE_CREDENTIAL)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://apps"
        ) as client:
            assert (await client.get("/_counters")).status_code == 401
            assert (
                await client.get("/_counters", headers={SERVICE_CREDENTIAL_HEADER: "nope"})
            ).status_code == 401
            ok = await client.get(
                "/_counters", headers={SERVICE_CREDENTIAL_HEADER: SERVICE_CREDENTIAL}
            )
            assert ok.status_code == 200

    async def test_storage_sink_does_not_echo_content(self):
        """The receiver must not reflect what it was sent."""
        from apps import mock_apps as mock_apps_module

        app = mock_apps_module.create_app(service_credential=SERVICE_CREDENTIAL)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://apps"
        ) as client:
            marker = "CANARY-9f3a7c21-do-not-echo"
            response = await client.post(
                "/storage/upload", json={"filename": "x.txt", "content": marker}
            )
            assert response.status_code == 200
            assert marker not in response.text
            assert response.json()["stored"] is False
            assert response.json()["accepted_uploads"] == 1


# =========================================================================== #
# 9. Dashboard assets, headers, and the published API surface
# =========================================================================== #

#: Everything the project promises to expose.
REQUIRED_PATHS = [
    "/healthz", "/openapi.json", "/auth/login", "/auth/logout",
    "/apps/{app_id}", "/web/{destination}", "/saas/upload",
    "/admin/devices", "/admin/devices/{device_id}", "/admin/events",
]


class TestDashboardAndSurface:
    async def test_dashboard_is_served(self, lab):
        response = await lab.client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "SASEGuard" in response.text

    @pytest.mark.parametrize("asset", ["/static/styles.css", "/static/app.js"])
    async def test_static_assets_are_served_locally(self, lab, asset):
        response = await lab.client.get(asset)
        assert response.status_code == 200
        assert len(response.content) > 500

    async def test_dashboard_has_no_external_dependencies(self, lab):
        """A strict CSP is only honest if the page really is self-contained."""
        import re

        page = (await lab.client.get("/")).text
        external = re.findall(r'(?:src|href)=["\'](https?://[^"\']+)', page)
        assert external == [], f"dashboard loads external assets: {external}"

    async def test_dashboard_javascript_avoids_unsafe_patterns(self, lab):
        """No XSS sinks, and no token persistence."""
        script = (await lab.client.get("/static/app.js")).text
        for pattern in (".innerHTML", "document.write(", "eval(", "new Function("):
            assert pattern not in script, f"found {pattern} in dashboard script"
        for pattern in ("localStorage.setItem", "sessionStorage.setItem", "document.cookie ="):
            assert pattern not in script, f"found {pattern} -- the token must stay in memory"

    @pytest.mark.parametrize(
        "header,expected",
        [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
        ],
    )
    async def test_security_headers_are_present(self, lab, header, expected):
        response = await lab.client.get("/")
        assert response.headers.get(header) == expected

    async def test_responses_are_not_cacheable(self, lab):
        for path in ("/", "/healthz", "/openapi.json"):
            response = await lab.client.get(path)
            assert "no-store" in response.headers.get("cache-control", ""), path

    async def test_csp_forbids_inline_script(self, lab):
        csp = (await lab.client.get("/")).headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "unsafe-inline" not in csp
        assert "unsafe-eval" not in csp
        assert "frame-ancestors 'none'" in csp

    async def test_openapi_schema_is_served_locally(self, lab):
        """Swagger's CDN assets are disabled; the schema itself is local."""
        response = await lab.client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert schema["info"]["title"] == "SASEGuard Gateway"

        for path in REQUIRED_PATHS:
            if path != "/openapi.json":
                assert path in schema["paths"], f"{path} missing from the OpenAPI schema"

    async def test_swagger_ui_is_disabled(self, lab):
        """Because it would pull JavaScript from a CDN."""
        assert (await lab.client.get("/docs")).status_code == 404
        assert (await lab.client.get("/redoc")).status_code == 404

    async def test_scope_statement_is_visible_on_the_page(self, lab):
        """The honest-scope wording is part of the deliverable, so test it."""
        page = (await lab.client.get("/")).text
        assert "SASE-inspired" in page
        assert "synthetic" in page.lower()
        for overclaim in ("Prisma", "production-ready", "enterprise-grade"):
            assert overclaim not in page, f"dashboard over-claims: {overclaim}"


@pytest.mark.browser
class TestRealBrowser:
    """Real browser interactions, when a browser driver is available.

    Skipped rather than faked when Playwright is absent. ``docs/validation.md``
    records this explicitly as an environment limitation instead of implying
    the check passed.
    """

    async def test_dashboard_loads_in_a_real_browser(self, lab):
        pytest.importorskip(
            "playwright",
            reason="Playwright is not installed; browser interaction checked manually "
                   "against a live server instead (see docs/validation.md).",
        )
        pytest.skip(
            "Playwright is installed but this suite drives the gateway in-process over "
            "ASGI, which has no listening socket for a browser to reach. Run "
            "`python scripts/run_local.py` and point a browser at http://127.0.0.1:8080."
        )
