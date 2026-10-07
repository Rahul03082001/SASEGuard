"""Test harness: all four services wired together in one process.

The whole suite runs against real FastAPI applications talking real HTTP over
in-process ASGI transports. Nothing is stubbed, and in particular the policy
decision is never faked — the gateway genuinely calls the policy service,
which genuinely reads SQLite. A suite that mocked the decision would pass
even if the gateway stopped asking.

How the wiring works: ``httpx`` lets a client *mount* a transport against a
URL pattern. The gateway is configured with ``policy_url='http://policy'``
and given a client that maps ``http://policy`` to the policy app's ASGI
transport. From the gateway's point of view it is making ordinary outbound
HTTP calls.

Every test gets fresh SQLite databases and a fresh device registry, so test
order cannot matter. The RSA keypair is generated once per session because
2048-bit key generation is slow enough to notice across ~70 tests.
"""

from __future__ import annotations

import json
import pathlib
import sys
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from apps import identity as identity_module  # noqa: E402
from apps import mock_apps as mock_apps_module  # noqa: E402
from apps import policy as policy_module  # noqa: E402
from apps.audit import AuditStore  # noqa: E402
from apps.common import (  # noqa: E402
    JWT_AUDIENCE,
    JWT_ISSUER,
    SERVICE_CREDENTIAL_HEADER,
    Settings,
    hash_password,
    iso,
    load_policy,
    new_salt_hex,
    utcnow,
)
from apps.gateway import GatewayState  # noqa: E402
from apps.gateway import create_app as create_gateway  # noqa: E402

#: Mount points. These are hostnames, not real DNS names -- the httpx client
#: resolves them to in-process ASGI apps.
IDENTITY_URL = "http://identity"
POLICY_URL = "http://policy"
APPS_URL = "http://apps"

SERVICE_CREDENTIAL = "test-service-credential-not-a-real-secret"

#: Known passwords, so tests can assert on correct *and* incorrect logins.
#: Generated credentials would make a negative test meaningless.
DEMO_PASSWORDS: dict[str, str] = {
    "alice": "alice-test-password-1",
    "bob": "bob-test-password-2",
    "carol": "carol-test-password-3",
    "admin": "admin-test-password-4",
}

DEMO_ROLES: dict[str, str] = {
    "alice": "finance",
    "bob": "engineer",
    "carol": "contractor",
    "admin": "administrator",
}

DEMO_DEVICES: dict[str, str] = {
    "alice": "dev-alice-laptop",
    "bob": "dev-bob-laptop",
    "carol": "dev-carol-byod",
    "admin": "dev-admin-workstation",
}


# --------------------------------------------------------------------------- #
# Session-scoped key material
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="session")
def keypair() -> tuple[str, str]:
    """An ephemeral RSA keypair, generated once for the whole session."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture(scope="session")
def attacker_keypair() -> tuple[str, str]:
    """A second keypair the gateway does *not* trust.

    Used to forge a structurally perfect, correctly signed token that must
    still be rejected, because it was signed by the wrong key.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


@pytest.fixture(scope="session")
def demo_users() -> dict[str, dict[str, Any]]:
    """The user table, with salted hashes of the known test passwords."""
    users: dict[str, dict[str, Any]] = {}
    for username, password in DEMO_PASSWORDS.items():
        salt = new_salt_hex()
        users[username] = {
            "role": DEMO_ROLES[username],
            "salt": salt,
            # Hashing with the real PBKDF2 cost is the point: we are testing
            # the real verification path, not a shortcut.
            "password_hash": hash_password(password, salt),
            "devices": [DEMO_DEVICES[username]],
        }
    return users


# --------------------------------------------------------------------------- #
# The lab
# --------------------------------------------------------------------------- #

@dataclass
class Lab:
    """Everything a test needs to drive and inspect the running lab."""

    client: httpx.AsyncClient
    gateway_state: GatewayState
    policy_store: "policy_module.PolicyStore"
    audit_store: AuditStore
    counters: "mock_apps_module.CallCounters"
    private_key: str
    public_key: str
    identity_transport: Any = None
    apps_transport: Any = None
    policy_transport: Any = None

    def replace_policy_transport(self, transport: Any) -> None:
        """Swap the policy service for a broken one, mid-test.

        Used to prove the gateway fails *closed*: when policy cannot be
        reached or answers nonsense, the request must 503 and no private
        application may be contacted.
        """
        self.gateway_state._client = httpx.AsyncClient(
            timeout=httpx.Timeout(2.0),
            trust_env=False,
            follow_redirects=False,
            mounts={
                "http://identity": self.identity_transport,
                "http://policy": transport,
                "http://apps": self.apps_transport,
            },
        )

    # -- convenience -------------------------------------------------------- #

    async def login(
        self, username: str, password: str | None = None, device_id: str | None = None
    ) -> httpx.Response:
        return await self.client.post(
            "/auth/login",
            json={
                "username": username,
                "password": DEMO_PASSWORDS[username] if password is None else password,
                "device_id": DEMO_DEVICES[username] if device_id is None else device_id,
            },
        )

    async def token_for(self, username: str) -> str:
        """Log in through the real endpoint and return the bearer token."""
        response = await self.login(username)
        assert response.status_code == 200, response.text
        return response.json()["access_token"]

    @staticmethod
    def auth(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def mint(
        self,
        *,
        subject: str = "alice",
        role: str = "finance",
        device_id: str = "dev-alice-laptop",
        token_id: str = "jti_test_token",
        issuer: str = JWT_ISSUER,
        audience: str = JWT_AUDIENCE,
        algorithm: str = "RS256",
        key: str | None = None,
        lifetime: timedelta = timedelta(minutes=10),
        not_before: timedelta = timedelta(0),
        drop_claims: tuple[str, ...] = (),
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Mint an arbitrary token for negative testing.

        This is the attacker's toolkit: wrong key, wrong algorithm, wrong
        audience, expired, not-yet-valid, missing claims, forged role. Signing
        directly rather than going through the issuer is the only way to
        produce tokens the issuer would never emit.
        """
        import jwt

        now = utcnow()
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "iat": int(now.timestamp()),
            "nbf": int((now + not_before).timestamp()),
            "exp": int((now + not_before + lifetime).timestamp()),
            "sub": subject,
            "role": role,
            "device_id": device_id,
            "jti": token_id,
        }
        for claim in drop_claims:
            claims.pop(claim, None)
        if extra_claims:
            claims.update(extra_claims)

        signing_key = key if key is not None else self.private_key
        if algorithm == "none":
            # PyJWT refuses to *sign* with alg=none unless the key is None.
            return jwt.encode(claims, None, algorithm="none")  # type: ignore[arg-type]
        return jwt.encode(claims, signing_key, algorithm=algorithm)

    def forge_hs256_with_public_key(
        self,
        *,
        subject: str = "carol",
        role: str = "administrator",
        device_id: str = "dev-carol-byod",
        token_id: str = "jti_forged",
    ) -> str:
        """Hand-build an HS256 token HMAC'd with the RSA public key.

        PyJWT refuses to *sign* with a PEM as an HMAC secret, which is a good
        guardrail for honest callers and useless as a defence -- an attacker
        is not using PyJWT. So this assembles the JWS directly with
        ``hmac``, exactly as an attacker's own script would, to prove the
        rejection happens on the *verification* side where it belongs.

        The attack: the RSA public key is not secret. If the verifier picked
        its algorithm from the token's own header, it would HMAC the signing
        input with that same public key and get a match.
        """
        import base64
        import hashlib
        import hmac
        import json

        def b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        now = utcnow()
        header = {"alg": "HS256", "typ": "JWT"}
        claims = {
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            "sub": subject,
            "role": role,
            "device_id": device_id,
            "jti": token_id,
        }
        signing_input = (
            b64(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64(json.dumps(claims, separators=(",", ":")).encode())
        )
        signature = hmac.new(
            self.public_key.encode(), signing_input.encode(), hashlib.sha256
        ).digest()
        return f"{signing_input}.{b64(signature)}"

    def forge_unsigned(
        self,
        *,
        subject: str = "carol",
        role: str = "administrator",
        device_id: str = "dev-carol-byod",
    ) -> str:
        """Hand-build an ``alg=none`` token with an empty signature."""
        import base64
        import json

        def b64(raw: bytes) -> str:
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        now = utcnow()
        header = {"alg": "none", "typ": "JWT"}
        claims = {
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            "sub": subject,
            "role": role,
            "device_id": device_id,
            "jti": "jti_unsigned",
        }
        return (
            b64(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64(json.dumps(claims, separators=(",", ":")).encode())
            + "."
        )

    # -- posture control ---------------------------------------------------- #

    def set_posture(self, device_id: str, **changes: Any) -> None:
        """Change authoritative posture directly in the policy database."""
        assert self.policy_store.update_device(device_id, changes) is not None

    def make_stale(self, device_id: str, hours: int = 48) -> None:
        self.set_posture(device_id, last_seen=iso(utcnow() - timedelta(hours=hours)))

    def make_fresh(self, device_id: str) -> None:
        self.set_posture(
            device_id, last_seen=iso(utcnow()), managed=True, compliant=True, risk_score=5
        )

    # -- upstream evidence -------------------------------------------------- #

    def upstream_calls(self, key: str) -> int:
        """How many times a private service was actually contacted.

        This is the assertion that makes a denial test meaningful: a 403 that
        still forwarded the request is a bug an HTTP-status check would miss.
        """
        return self.counters.get(key)

    def accepted_uploads(self) -> int:
        return self.counters.get("storage.accepted")


@pytest_asyncio.fixture
async def lab(tmp_path, keypair, demo_users):
    """A complete, isolated lab with fresh databases per test."""
    private_key, public_key = keypair

    # -- private services --------------------------------------------------
    policy_store = policy_module.PolicyStore(tmp_path / "policy.sqlite3")
    policy_store.initialize()
    policy_store.seed_devices(force=True)

    policy_app = policy_module.create_app(
        store=policy_store,
        policy=load_policy(),
        service_credential=SERVICE_CREDENTIAL,
    )

    counters = mock_apps_module.CallCounters()
    apps_app = mock_apps_module.create_app(
        counters=counters, service_credential=SERVICE_CREDENTIAL
    )

    identity_app = identity_module.create_app(
        state=identity_module.IdentityState(private_key=private_key, users=demo_users)
    )

    # -- the gateway's outbound client -------------------------------------
    # Same security settings as production (no env proxies, no redirects,
    # bounded timeout) with the three private hosts mapped in-process.
    identity_transport = httpx.ASGITransport(app=identity_app)
    policy_transport = httpx.ASGITransport(app=policy_app)
    apps_transport = httpx.ASGITransport(app=apps_app)

    gateway_client = httpx.AsyncClient(
        timeout=httpx.Timeout(5.0),
        trust_env=False,
        follow_redirects=False,
        mounts={
            "http://identity": identity_transport,
            "http://policy": policy_transport,
            "http://apps": apps_transport,
        },
    )

    audit_store = AuditStore(tmp_path / "audit.sqlite3")
    audit_store.initialize()

    gateway_state = GatewayState(
        settings=Settings(
            identity_url=IDENTITY_URL,
            policy_url=POLICY_URL,
            apps_url=APPS_URL,
            service_credential=SERVICE_CREDENTIAL,
        ),
        audit=audit_store,
        client=gateway_client,
        public_key=public_key,
        policy_label=load_policy().label,
    )
    gateway_app = create_gateway(state=gateway_state)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gateway_app),
        base_url="http://gateway",
        timeout=httpx.Timeout(10.0),
    ) as client:
        yield Lab(
            client=client,
            gateway_state=gateway_state,
            policy_store=policy_store,
            audit_store=audit_store,
            counters=counters,
            private_key=private_key,
            public_key=public_key,
            identity_transport=identity_transport,
            apps_transport=apps_transport,
            policy_transport=policy_transport,
        )

    await gateway_client.aclose()


@pytest.fixture
def service_headers() -> dict[str, str]:
    return {SERVICE_CREDENTIAL_HEADER: SERVICE_CREDENTIAL}


@pytest_asyncio.fixture
async def policy_client(tmp_path):
    """A direct client for the policy service, bypassing the gateway.

    Used to prove the private API rejects callers without the credential.
    """
    store = policy_module.PolicyStore(tmp_path / "direct-policy.sqlite3")
    store.initialize()
    store.seed_devices(force=True)
    app = policy_module.create_app(
        store=store, policy=load_policy(), service_credential=SERVICE_CREDENTIAL
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://policy"
    ) as client:
        yield client


# --------------------------------------------------------------------------- #
# Deliberately broken transports, for fail-closed tests
# --------------------------------------------------------------------------- #

class DeadTransport(httpx.AsyncBaseTransport):
    """Refuses every connection, like a service that is down."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused (simulated outage)", request=request)


class HangingTransport(httpx.AsyncBaseTransport):
    """Times out, like a service that accepted the socket and then stalled."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out (simulated hang)", request=request)


class NonJsonTransport(httpx.AsyncBaseTransport):
    """Returns HTTP 200 with a body that is not JSON at all."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>definitely not json</html>")


class MalformedDecisionTransport(httpx.AsyncBaseTransport):
    """Returns valid JSON that is not a valid decision.

    ``allow`` is the string "yes" rather than a boolean. A gateway that did a
    truthiness check instead of a type check would read this as an allow --
    which is precisely the bug this transport exists to catch.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"allow": "yes", "reason_code": "ALLOW_ROLE_GRANT"})


class ErrorStatusTransport(httpx.AsyncBaseTransport):
    """Returns HTTP 500."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "internal policy error"})
