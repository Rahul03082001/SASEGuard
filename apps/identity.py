"""Demo identity issuer — the only holder of the RSA private signing key.

Honest scope: this models the *login* step so the rest of the lab has a
verifiable token to reason about. It is not an OAuth 2.0 / OIDC provider, it
has no MFA, no consent screen, no refresh tokens, no device-code flow, and no
account recovery. Swapping it for a real IdP is listed as future work in the
README, and the gateway is written so that only this file's URL would change.

Why it is a separate service: the private key lives in exactly one process.
The gateway holds only the public key, so a gateway compromise lets an
attacker *read* tokens but never *mint* them. That split is the whole point.

Runs privately. ``POST /login`` is intentionally not behind the service
credential — a login endpoint is meant to be callable; the password and
device enrollment are the access control.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from typing import Any

import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from apps.common import (
    JWT_AUDIENCE,
    JWT_ISSUER,
    MAX_BODY_BYTES,
    PRIVATE_KEY_FILE,
    Reason,
    TOKEN_TTL_SECONDS,
    USERS_FILE,
    is_safe_id,
    load_json_file,
    read_text_file,
    utcnow,
    verify_password,
)

logger = logging.getLogger("saseguard.identity")

# A login endpoint must never log the submitted password, and must not log the
# issued token. We log the subject and the outcome, nothing else.


# --------------------------------------------------------------------------- #
# Request / response schemas
# --------------------------------------------------------------------------- #

class LoginRequest(BaseModel):
    """Strict login payload. ``extra='forbid'`` rejects unexpected fields.

    That strictness is not pedantry: silently ignoring an unknown field is how
    a client ends up believing it set ``role`` or ``admin`` and the server
    disagreeing.
    """

    model_config = {"extra": "forbid"}

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    device_id: str = Field(min_length=1, max_length=64)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    subject: str
    role: str
    device_id: str
    token_id: str


# --------------------------------------------------------------------------- #
# Key and user material
# --------------------------------------------------------------------------- #

class IdentityState:
    """Lazily loaded signing key and user table.

    Lazy so that importing this module (as the tests and tooling do) does not
    require setup to have run yet.
    """

    def __init__(
        self,
        *,
        private_key: str | None = None,
        users: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        # Both may be supplied directly, which is how the test suite runs an
        # issuer against an ephemeral keypair without touching secrets/.
        self._private_key = private_key
        self._users = users

    @property
    def private_key(self) -> str:
        if self._private_key is None:
            self._private_key = read_text_file(PRIVATE_KEY_FILE, "RSA private signing key")
        return self._private_key

    @property
    def users(self) -> dict[str, dict[str, Any]]:
        if self._users is None:
            document = load_json_file(USERS_FILE, "demo user table")
            self._users = document["users"]
        return self._users

    def reload(self) -> None:
        """Drop caches. Used by tests and by scripts/setup.py --force."""
        self._private_key = None
        self._users = None


state = IdentityState()


# --------------------------------------------------------------------------- #
# Token minting
# --------------------------------------------------------------------------- #

def mint_token(
    *,
    subject: str,
    role: str,
    device_id: str,
    private_key: str,
    ttl_seconds: int = TOKEN_TTL_SECONDS,
) -> tuple[str, str, int]:
    """Sign an RS256 bearer token.

    Every claim the gateway later demands is set here. ``jti`` is a fresh
    UUID per login, which is what makes targeted revocation possible: logout
    revokes one token, not an entire account.

    Returns:
        ``(encoded_token, token_id, expires_in_seconds)``
    """
    now = utcnow()
    token_id = f"jti_{uuid.uuid4().hex}"
    claims = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        # No backdating. A token is valid from the moment it is issued.
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "sub": subject,
        "role": role,
        "device_id": device_id,
        "jti": token_id,
    }
    encoded = jwt.encode(claims, private_key, algorithm="RS256")
    return encoded, token_id, ttl_seconds


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

def create_app(*, state: IdentityState | None = None) -> FastAPI:
    issuer = state or globals()["state"]
    app = FastAPI(
        title="SASEGuard Demo Identity Issuer",
        version="1.0.0",
        description=(
            "Private demo identity issuer. Models password + enrolled-device login and "
            "signs short-lived RS256 bearer tokens. Not an OAuth/OIDC provider; no MFA."
        ),
        docs_url=None,
        redoc_url=None,
    )

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, Any]:
        """Public inside the private network so Compose can health-check it."""
        return {"status": "ok", "service": "identity"}

    @app.post("/login", tags=["auth"])
    async def login(request: Request) -> JSONResponse:
        """Verify password and device enrollment, then issue a token.

        The body is read and size-checked before JSON parsing so an oversized
        payload is rejected without being deserialized.
        """
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return _error(413, Reason.DENY_BODY_TOO_LARGE, "Request body too large.")

        try:
            payload = LoginRequest.model_validate_json(raw)
        except ValidationError:
            return _error(400, Reason.DENY_MALFORMED_REQUEST, "Malformed login request.")

        username = payload.username
        device_id = payload.device_id

        # Reject hostile-looking identifiers before they touch any lookup or
        # log line.
        if not is_safe_id(username) or not is_safe_id(device_id):
            return _error(400, Reason.DENY_MALFORMED_REQUEST, "Malformed identifier.")

        record = issuer.users.get(username)

        # Unknown user and wrong password return the identical response, so the
        # endpoint is not a user-enumeration oracle. We still run a hash
        # computation for unknown users to keep timing roughly similar.
        if record is None:
            verify_password(payload.password, "00" * 16, "0" * 64)
            logger.info("login denied: unknown subject")
            return _error(401, Reason.DENY_BAD_LOGIN, "Invalid username, password, or device.")

        if not verify_password(payload.password, record["salt"], record["password_hash"]):
            logger.info("login denied: bad password for subject=%s", username)
            return _error(401, Reason.DENY_BAD_LOGIN, "Invalid username, password, or device.")

        # Enrollment is checked only after the password is correct. Leaking
        # "that device is not yours" to an already-authenticated caller is
        # acceptable and much more useful in a lab.
        if device_id not in record.get("devices", []):
            logger.info("login denied: device not enrolled for subject=%s", username)
            return _error(
                401,
                Reason.DENY_DEVICE_NOT_ENROLLED,
                "That device is not enrolled to this account.",
            )

        token, token_id, expires_in = mint_token(
            subject=username,
            role=record["role"],
            device_id=device_id,
            private_key=issuer.private_key,
        )
        logger.info("login allowed: subject=%s role=%s", username, record["role"])

        body = LoginResponse(
            access_token=token,
            expires_in=expires_in,
            subject=username,
            role=record["role"],
            device_id=device_id,
            token_id=token_id,
        )
        # no-store so the token is never written to a shared HTTP cache.
        return JSONResponse(body.model_dump(), headers={"Cache-Control": "no-store"})

    return app


def _error(status: int, reason_code: str, message: str) -> JSONResponse:
    return JSONResponse(
        {"detail": message, "reason_code": reason_code},
        status_code=status,
        headers={"Cache-Control": "no-store"},
    )


app = create_app()
