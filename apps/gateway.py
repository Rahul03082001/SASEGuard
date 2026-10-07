"""The gateway — policy enforcement point and the only publicly bound service.

Every protected request walks the same path, in this order:

1. **Verify the bearer token** locally, with the issuer's public key, against
   a fixed RS256 allowlist. No network call, no shared secret.
2. **Ask the policy service** for a decision, passing only verified claims.
3. **Scan content** with the DLP rules, for uploads only.
4. **Commit an audit row**, synchronously.
5. **Forward** to a fixed private URL — never a caller-supplied one.

Step 4 happens before step 5 and that ordering is the point of the design: a
decision that was not durably recorded is treated as a decision that did not
happen, so an audit failure on an allowed request becomes a 503 and nothing
is forwarded.

Fail-closed rules, stated once:

* policy unreachable, slow, or returning something unexpected -> 503, no forward
* audit write fails on an allow -> 503, no forward
* anything the policy service denies -> 403, no forward
* a DLP match -> 403, no forward

What the gateway refuses to trust: anything in the request except the token
signature. ``X-Role``, ``X-Compliant``, a ``role`` field in a JSON body — all
ignored. Authorization inputs come from verified claims and from the policy
service's own database, never from the caller.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from apps import dlp
from apps.audit import AuditEvent, AuditStore, AuditUnavailable
from apps.common import (
    APP_IDS,
    Action,
    JWT_ALLOWED_ALGORITHMS,
    JWT_AUDIENCE,
    JWT_ISSUER,
    JWT_REQUIRED_CLAIMS,
    MAX_BODY_BYTES,
    MAX_CONTENT_CHARS,
    PUBLIC_KEY_FILE,
    Reason,
    SERVICE_CREDENTIAL_HEADER,
    Settings,
    WEB_DESTINATIONS,
    WEB_DIR,
    is_safe_id,
    load_policy,
    make_async_client,
    read_text_file,
)

logger = logging.getLogger("saseguard.gateway")

#: Resource labels used in audit rows for non-application requests.
RESOURCE_STORAGE = "storage"
RESOURCE_DEVICES = "devices"
RESOURCE_AUDIT = "audit"
RESOURCE_AUTH = "auth"

#: Placeholders for audit rows where no verified identity exists yet.
UNKNOWN_SUBJECT = "anonymous"
UNKNOWN_FIELD = "-"


# --------------------------------------------------------------------------- #
# Token verification
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class VerifiedIdentity:
    """Claims the gateway has actually verified. The only trusted input."""

    subject: str
    role: str
    device_id: str
    token_id: str
    expires_at: int


class TokenError(Exception):
    """Token verification failed. Carries the reason code for the audit row."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


def extract_bearer(authorization: str | None) -> str:
    """Pull the token out of an ``Authorization: Bearer <token>`` header."""
    if not authorization:
        raise TokenError(Reason.DENY_NO_CREDENTIALS, "Missing Authorization header.")
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise TokenError(Reason.DENY_NO_CREDENTIALS, "Expected 'Authorization: Bearer <token>'.")
    return parts[1].strip()


def verify_token(token: str, public_key: str) -> VerifiedIdentity:
    """Verify signature, algorithm, issuer, audience, window, and claims.

    The three arguments that do the security work:

    * ``algorithms=["RS256"]`` — a fixed allowlist. This is what defeats both
      ``alg=none`` and the classic HS256 confusion attack, where an attacker
      re-signs a token symmetrically using the *public* key as the HMAC
      secret. PyJWT will not even attempt an algorithm outside this list.
    * ``issuer`` / ``audience`` — a validly signed token minted for some other
      audience is still rejected, so a token cannot be replayed across
      services that happen to share a key.
    * ``options={"require": [...]}`` — every claim we later rely on must be
      present. A token missing ``device_id`` must fail loudly rather than fall
      through to a lookup with ``None``.

    ``leeway=0``: no clock grace. An expired token is expired.
    """
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=JWT_ALLOWED_ALGORITHMS,
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            leeway=0,
            options={
                "require": JWT_REQUIRED_CLAIMS,
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError(Reason.DENY_TOKEN_EXPIRED, "Token has expired.") from exc
    except jwt.ImmatureSignatureError as exc:
        raise TokenError(Reason.DENY_TOKEN_NOT_YET_VALID, "Token is not valid yet.") from exc
    except jwt.InvalidAudienceError as exc:
        raise TokenError(Reason.DENY_TOKEN_AUDIENCE, "Token audience is not this gateway.") from exc
    except jwt.InvalidIssuerError as exc:
        raise TokenError(Reason.DENY_TOKEN_ISSUER, "Token issuer is not trusted.") from exc
    except jwt.MissingRequiredClaimError as exc:
        raise TokenError(Reason.DENY_TOKEN_CLAIMS, f"Token is missing a required claim: {exc.claim}") from exc
    except jwt.InvalidAlgorithmError as exc:
        # alg=none and HS256-confusion both land here.
        raise TokenError(Reason.DENY_TOKEN_ALGORITHM, "Token algorithm is not permitted.") from exc
    except jwt.InvalidSignatureError as exc:
        raise TokenError(Reason.DENY_BAD_TOKEN_SIGNATURE, "Token signature is invalid.") from exc
    except jwt.InvalidTokenError as exc:
        # Catch-all for malformed tokens. Reported as a signature failure
        # rather than echoing parser internals back to the caller.
        raise TokenError(Reason.DENY_BAD_TOKEN_SIGNATURE, "Token could not be verified.") from exc

    # Claims are present; now check they are *usable*. A present-but-hostile
    # value (newlines, path separators) must not reach a lookup or a log line.
    for field in ("sub", "role", "device_id"):
        if not is_safe_id(str(claims.get(field, ""))):
            raise TokenError(Reason.DENY_TOKEN_CLAIMS, f"Token claim '{field}' is malformed.")
    token_id = str(claims.get("jti", ""))
    if not token_id or len(token_id) > 128 or any(c.isspace() for c in token_id):
        raise TokenError(Reason.DENY_TOKEN_CLAIMS, "Token claim 'jti' is malformed.")

    return VerifiedIdentity(
        subject=str(claims["sub"]),
        role=str(claims["role"]),
        device_id=str(claims["device_id"]),
        token_id=token_id,
        expires_at=int(claims["exp"]),
    )


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #

class UploadRequest(BaseModel):
    """A bounded text upload. Extra fields are rejected, not ignored.

    ``extra='forbid'`` matters here beyond tidiness: a client that sends
    ``{"content": "...", "skip_dlp": true}`` gets a 400, instead of quietly
    believing it disabled scanning.
    """

    model_config = {"extra": "forbid"}

    filename: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=0, max_length=MAX_CONTENT_CHARS)


# --------------------------------------------------------------------------- #
# Gateway state
# --------------------------------------------------------------------------- #

class GatewayState:
    """Public key, policy label, audit store, and the one HTTP client."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        audit: AuditStore | None = None,
        client: httpx.AsyncClient | None = None,
        public_key: str | None = None,
        policy_label: str | None = None,
    ) -> None:
        self.settings = settings or Settings.from_env()
        self.audit = audit or AuditStore()
        self._client = client
        # ``public_key`` may be supplied directly so the test suite can run a
        # gateway against an ephemeral keypair. In normal operation it is read
        # from secrets/jwt_public.pem on first use.
        self._public_key = public_key
        # The gateway loads policy.yaml only to label audit rows with the
        # version it believes is current. It never evaluates it -- that would
        # defeat the point of a separate decision service.
        self._policy_label = policy_label

    @property
    def public_key(self) -> str:
        if self._public_key is None:
            self._public_key = read_text_file(PUBLIC_KEY_FILE, "RSA public verification key")
        return self._public_key

    @property
    def policy_label(self) -> str:
        if self._policy_label is None:
            try:
                self._policy_label = load_policy().label
            except Exception:
                self._policy_label = "unknown"
        return self._policy_label

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = make_async_client()
        return self._client

    def service_headers(self) -> dict[str, str]:
        return {SERVICE_CREDENTIAL_HEADER: self.settings.service_credential}


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

SECURITY_HEADERS = {
    # Nothing this gateway serves should ever be cached: responses are
    # authorization decisions about one caller at one moment.
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # 'self' only, with no 'unsafe-inline'. This is enforceable because the
    # dashboard ships zero inline scripts and zero CDN dependencies.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
        "form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    ),
    # Deliberately no Strict-Transport-Security: the lab is plain HTTP on
    # 127.0.0.1, where HSTS would be a no-op header for show. Add it when you
    # put this behind TLS.
}


def create_app(*, state: GatewayState | None = None) -> FastAPI:
    app = FastAPI(
        title="SASEGuard Gateway",
        version="1.0.0",
        description=(
            "SASE-inspired Zero Trust policy enforcement point. Verifies RS256 bearer "
            "tokens, consults a separate policy decision service for every request, "
            "applies text-only DLP to uploads, records a redacted audit decision before "
            "forwarding, and forwards only to fixed private URLs.\n\n"
            "This is a local lab built from synthetic data. It is not affiliated with "
            "any vendor, implements no SD-WAN or other network-layer SASE function, and "
            "is not production-ready."
        ),
        # Swagger UI is disabled because it loads assets from a CDN. The raw
        # schema is served locally at /openapi.json instead.
        docs_url=None,
        redoc_url=None,
    )
    app.state.gw = state or GatewayState()

    # -- middleware -------------------------------------------------------- #

    @app.middleware("http")
    async def guard_and_harden(request: Request, call_next: Any) -> Response:
        """Reject oversized bodies up front, then harden every response.

        The Content-Length check runs before routing, so an oversized payload
        is refused without being buffered or parsed. It is belt-and-braces
        with the per-route check: Content-Length can be absent or a lie.
        """
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
            response: Response = JSONResponse(
                {
                    "detail": f"Request body exceeds {MAX_BODY_BYTES} bytes.",
                    "reason_code": Reason.DENY_BODY_TOO_LARGE,
                },
                status_code=413,
            )
        else:
            response = await call_next(request)

        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response

    # -- dashboard --------------------------------------------------------- #

    if (WEB_DIR / "styles.css").exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def dashboard() -> Response:
        index = WEB_DIR / "index.html"
        if not index.exists():
            return JSONResponse({"detail": "Dashboard assets are missing."}, status_code=404)
        return FileResponse(str(index), media_type="text/html")

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "gateway",
            "policy_version": app.state.gw.policy_label,
        }

    @app.get("/meta/dlp-rules", tags=["ops"])
    async def dlp_rules() -> dict[str, Any]:
        """Published so a blocked user can see exactly what matched them."""
        return {"rules": dlp.describe_rules(), "max_content_chars": MAX_CONTENT_CHARS}

    # -- helpers ----------------------------------------------------------- #

    def gw() -> GatewayState:
        return app.state.gw

    def _audit(
        *,
        subject: str,
        role: str,
        device_id: str,
        resource: str,
        action: str,
        result: str,
        reason_code: str,
        http_status: int,
        started: float,
        dlp_rule_ids: tuple[str, ...] = (),
    ) -> str:
        """Commit one audit row. Returns the event ID.

        Raises:
            AuditUnavailable: propagated to the caller, which decides whether
                that is fatal. It is fatal for an allow and tolerated for a
                deny -- an unrecorded denial still blocked the request, while
                an unrecorded allow would be an untraceable access.
        """
        event = gw().audit.record(
            AuditEvent(
                subject=subject,
                role=role,
                device_id=device_id,
                resource=resource,
                action=action,
                result=result,
                reason_code=reason_code,
                policy_version=gw().policy_label,
                http_status=http_status,
                decision_latency_ms=(time.perf_counter() - started) * 1000.0,
                dlp_rule_ids=dlp_rule_ids,
            )
        )
        return event.event_id

    def _audit_best_effort(**kwargs: Any) -> str:
        """Audit a denial, tolerating a storage failure."""
        try:
            return _audit(**kwargs)
        except AuditUnavailable as exc:
            logger.error("audit write failed while recording a denial: %s", exc)
            return ""

    def _deny_response(
        status: int, reason_code: str, message: str, event_id: str = "", **extra: Any
    ) -> JSONResponse:
        body = {"detail": message, "reason_code": reason_code, "allowed": False, **extra}
        if event_id:
            body["audit_event_id"] = event_id
        return JSONResponse(body, status_code=status)

    def _authenticate(request: Request, *, resource: str, action: str, started: float):
        """Verify the token, or return a ready-made 401 response.

        Returns ``(identity, None)`` on success and ``(None, response)`` on
        failure, so each route can stay flat.
        """
        try:
            token = extract_bearer(request.headers.get("authorization"))
            identity = verify_token(token, gw().public_key)
            return identity, None
        except TokenError as exc:
            event_id = _audit_best_effort(
                subject=UNKNOWN_SUBJECT,
                role=UNKNOWN_FIELD,
                device_id=UNKNOWN_FIELD,
                resource=resource,
                action=action,
                result="deny",
                reason_code=exc.reason_code,
                http_status=401,
                started=started,
            )
            logger.info("authentication failed reason=%s", exc.reason_code)
            return None, _deny_response(401, exc.reason_code, exc.message, event_id)

    async def _decide(identity: VerifiedIdentity, *, resource: str, action: str) -> dict[str, Any]:
        """Ask the policy service. Raises ``PolicyUnavailable`` to fail closed.

        Only verified claims are sent. The request carries no bearer token, no
        client headers, and nothing the caller could have influenced beyond
        which resource they asked for.
        """
        payload = {
            "subject": identity.subject,
            "role": identity.role,
            "device_id": identity.device_id,
            "token_id": identity.token_id,
            "resource": resource,
            "action": action,
        }
        try:
            response = await gw().client.post(
                f"{gw().settings.policy_url}/evaluate",
                json=payload,
                headers=gw().service_headers(),
            )
        except httpx.HTTPError as exc:
            raise PolicyUnavailable(Reason.ERROR_POLICY_UNAVAILABLE, str(exc)) from exc

        if response.status_code != 200:
            raise PolicyUnavailable(
                Reason.ERROR_POLICY_UNAVAILABLE,
                f"Policy service returned HTTP {response.status_code}.",
            )
        try:
            decision = response.json()
        except ValueError as exc:
            raise PolicyUnavailable(
                Reason.ERROR_POLICY_INVALID_RESPONSE, "Policy response was not JSON."
            ) from exc

        # A malformed decision is not treated as an allow. Anything we cannot
        # read with confidence is an outage.
        if not isinstance(decision, dict) or not isinstance(decision.get("allow"), bool):
            raise PolicyUnavailable(
                Reason.ERROR_POLICY_INVALID_RESPONSE,
                "Policy response did not contain a boolean 'allow'.",
            )
        if not isinstance(decision.get("reason_code"), str) or not decision["reason_code"]:
            raise PolicyUnavailable(
                Reason.ERROR_POLICY_INVALID_RESPONSE,
                "Policy response did not contain a reason code.",
            )
        return decision

    async def _guard(request: Request, *, resource: str, action: str, started: float):
        """Authenticate, then authorize. The common prologue for every route.

        Returns ``(identity, decision, None)`` when the request may proceed,
        or ``(None, None, response)`` with the response to send back.
        """
        identity, failure = _authenticate(request, resource=resource, action=action, started=started)
        if failure is not None:
            return None, None, failure

        assert identity is not None
        try:
            decision = await _decide(identity, resource=resource, action=action)
        except PolicyUnavailable as exc:
            _audit_best_effort(
                subject=identity.subject,
                role=identity.role,
                device_id=identity.device_id,
                resource=resource,
                action=action,
                result="error",
                reason_code=exc.reason_code,
                http_status=503,
                started=started,
            )
            logger.error("failing closed: %s (%s)", exc.reason_code, exc.detail)
            return None, None, _deny_response(
                503,
                exc.reason_code,
                "Policy decision service is unavailable. The request was not forwarded.",
            )

        if not decision["allow"]:
            event_id = _audit_best_effort(
                subject=identity.subject,
                role=identity.role,
                device_id=identity.device_id,
                resource=resource,
                action=action,
                result="deny",
                reason_code=decision["reason_code"],
                http_status=403,
                started=started,
            )
            return None, None, _deny_response(
                403,
                decision["reason_code"],
                decision.get("detail") or "Denied by policy.",
                event_id,
                category=decision.get("category"),
            )

        return identity, decision, None

    # -- auth -------------------------------------------------------------- #

    @app.post("/auth/login", tags=["auth"])
    async def login(request: Request) -> JSONResponse:
        """Proxy login to the private identity issuer.

        The gateway does not verify the password itself and never sees the
        private signing key. It records the outcome, never the credential.
        """
        started = time.perf_counter()
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return _deny_response(413, Reason.DENY_BODY_TOO_LARGE, "Request body too large.")

        try:
            upstream = await gw().client.post(
                f"{gw().settings.identity_url}/login",
                content=raw,
                headers={"content-type": "application/json"},
            )
        except httpx.HTTPError as exc:
            logger.error("identity issuer unreachable: %s", exc)
            _audit_best_effort(
                subject=UNKNOWN_SUBJECT, role=UNKNOWN_FIELD, device_id=UNKNOWN_FIELD,
                resource=RESOURCE_AUTH, action=Action.AUTH_LOGIN, result="error",
                reason_code=Reason.ERROR_IDENTITY_UNAVAILABLE, http_status=503, started=started,
            )
            return _deny_response(
                503, Reason.ERROR_IDENTITY_UNAVAILABLE, "Identity service is unavailable."
            )

        try:
            body = upstream.json()
        except ValueError:
            return _deny_response(
                503, Reason.ERROR_IDENTITY_UNAVAILABLE, "Identity service returned an invalid response."
            )

        if upstream.status_code == 200:
            _audit_best_effort(
                subject=str(body.get("subject", UNKNOWN_SUBJECT)),
                role=str(body.get("role", UNKNOWN_FIELD)),
                device_id=str(body.get("device_id", UNKNOWN_FIELD)),
                resource=RESOURCE_AUTH, action=Action.AUTH_LOGIN, result="allow",
                reason_code=Reason.ALLOW_LOGIN, http_status=200, started=started,
            )
        else:
            _audit_best_effort(
                subject=UNKNOWN_SUBJECT, role=UNKNOWN_FIELD, device_id=UNKNOWN_FIELD,
                resource=RESOURCE_AUTH, action=Action.AUTH_LOGIN, result="deny",
                reason_code=str(body.get("reason_code", Reason.DENY_BAD_LOGIN)),
                http_status=upstream.status_code, started=started,
            )

        return JSONResponse(body, status_code=upstream.status_code)

    @app.post("/auth/logout", tags=["auth"])
    async def logout(request: Request) -> JSONResponse:
        """Persistently revoke the caller's own verified token ID.

        No policy call: logout only ever reduces privilege, so it must succeed
        even for a user whose device has just gone non-compliant. Requiring a
        healthy posture to log out would be a trap, not a control.
        """
        started = time.perf_counter()
        identity, failure = _authenticate(
            request, resource=RESOURCE_AUTH, action=Action.AUTH_LOGOUT, started=started
        )
        if failure is not None:
            return failure
        assert identity is not None

        try:
            response = await gw().client.post(
                f"{gw().settings.policy_url}/revoke",
                json={"token_id": identity.token_id, "subject": identity.subject},
                headers=gw().service_headers(),
            )
        except httpx.HTTPError as exc:
            logger.error("revocation failed: %s", exc)
            return _deny_response(
                503, Reason.ERROR_POLICY_UNAVAILABLE, "Could not record revocation; token is still valid."
            )

        if response.status_code != 200:
            return _deny_response(
                503, Reason.ERROR_POLICY_UNAVAILABLE, "Could not record revocation; token is still valid."
            )

        event_id = _audit_best_effort(
            subject=identity.subject, role=identity.role, device_id=identity.device_id,
            resource=RESOURCE_AUTH, action=Action.AUTH_LOGOUT, result="allow",
            reason_code=Reason.ALLOW_LOGOUT, http_status=200, started=started,
        )
        return JSONResponse(
            {
                "revoked": True,
                "audit_event_id": event_id,
                "detail": "This token is now revoked. Reusing it will be denied.",
            }
        )

    # -- applications ------------------------------------------------------- #

    @app.get("/apps/{app_id}", tags=["apps"])
    async def read_app(app_id: str, request: Request) -> JSONResponse:
        """Authorize, audit, then fetch one fixed private application."""
        started = time.perf_counter()

        # Validated against a compiled-in tuple before anything else. The ID
        # is used to pick a fixed URL, so it can never become a path or host
        # the caller chose.
        if not is_safe_id(app_id):
            return _deny_response(400, Reason.DENY_MALFORMED_REQUEST, "Malformed application ID.")

        identity, _decision, failure = await _guard(
            request, resource=app_id, action=Action.APP_READ, started=started
        )
        if failure is not None:
            return failure
        assert identity is not None

        if app_id not in APP_IDS:
            # Unreachable while policy.yaml and APP_IDS agree; kept as a
            # second gate so a policy edit alone cannot open a new upstream.
            return _deny_response(403, Reason.DENY_UNKNOWN_RESOURCE, "Unknown application.")

        try:
            event_id = _audit(
                subject=identity.subject, role=identity.role, device_id=identity.device_id,
                resource=app_id, action=Action.APP_READ, result="allow",
                reason_code=Reason.ALLOW_ROLE_GRANT, http_status=200, started=started,
            )
        except AuditUnavailable as exc:
            logger.error("blocking allowed request: audit unavailable (%s)", exc)
            return _deny_response(
                503, Reason.ERROR_AUDIT_UNAVAILABLE,
                "Authorization could not be recorded, so the request was not forwarded.",
            )

        return await _forward_get(f"{gw().settings.apps_url}/apps/{app_id}", event_id)

    # -- lab web controls --------------------------------------------------- #

    @app.get("/web/{destination}", tags=["web"])
    async def visit_web(destination: str, request: Request) -> JSONResponse:
        """Category enforcement over a fixed set of local fixture IDs.

        There is no URL parameter anywhere in this route. ``destination`` is
        an ID checked against a compiled-in tuple, which is why this endpoint
        cannot be turned into an open proxy or an SSRF primitive.
        """
        started = time.perf_counter()
        if not is_safe_id(destination):
            return _deny_response(400, Reason.DENY_MALFORMED_REQUEST, "Malformed destination.")

        identity, decision, failure = await _guard(
            request, resource=destination, action=Action.WEB_VISIT, started=started
        )
        if failure is not None:
            return failure
        assert identity is not None and decision is not None

        if destination not in WEB_DESTINATIONS:
            return _deny_response(403, Reason.DENY_UNKNOWN_DESTINATION, "Unknown destination.")

        try:
            event_id = _audit(
                subject=identity.subject, role=identity.role, device_id=identity.device_id,
                resource=destination, action=Action.WEB_VISIT, result="allow",
                reason_code=Reason.ALLOW_WEB_CATEGORY, http_status=200, started=started,
            )
        except AuditUnavailable as exc:
            logger.error("blocking allowed request: audit unavailable (%s)", exc)
            return _deny_response(
                503, Reason.ERROR_AUDIT_UNAVAILABLE,
                "Authorization could not be recorded, so the request was not forwarded.",
            )

        return await _forward_get(
            f"{gw().settings.apps_url}/web/{destination}",
            event_id,
            extra={"category": decision.get("category")},
        )

    # -- DLP-scanned upload -------------------------------------------------- #

    @app.post("/saas/upload", tags=["dlp"])
    async def upload(request: Request) -> JSONResponse:
        """Authorize the role, scan the text, audit, then forward if clean.

        The scan happens before the synthetic storage service is contacted.
        That ordering is what the test suite verifies via the upstream
        accepted-upload counter: a blocked payload never arrives at all.
        """
        started = time.perf_counter()

        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return _deny_response(
                413, Reason.DENY_BODY_TOO_LARGE,
                f"Request body exceeds {MAX_BODY_BYTES} bytes.",
            )

        identity, _decision, failure = await _guard(
            request, resource=RESOURCE_STORAGE, action=Action.SAAS_UPLOAD, started=started
        )
        if failure is not None:
            return failure
        assert identity is not None

        try:
            payload = UploadRequest.model_validate_json(raw)
        except ValidationError:
            # Covers unknown fields and the character-count limit alike.
            return _deny_response(
                400, Reason.DENY_MALFORMED_REQUEST,
                "Upload must be JSON with exactly 'filename' and 'content', "
                f"and content must be at most {MAX_CONTENT_CHARS} characters.",
            )

        result = dlp.scan(payload.content)

        if result.blocked:
            rule_ids = tuple(result.rule_ids)
            event_id = _audit_best_effort(
                subject=identity.subject, role=identity.role, device_id=identity.device_id,
                resource=RESOURCE_STORAGE, action=Action.SAAS_UPLOAD, result="deny",
                reason_code=Reason.DENY_DLP_MATCH, http_status=403, started=started,
                dlp_rule_ids=rule_ids,
            )
            logger.info(
                "upload blocked subject=%s rules=%s", identity.subject, ",".join(rule_ids)
            )
            # Rule IDs and counts only. The matched text is never echoed --
            # otherwise the error message would leak the secret we just saved.
            return _deny_response(
                403, Reason.DENY_DLP_MATCH,
                "Upload blocked by data loss prevention rules.",
                event_id,
                dlp=result.as_dict(),
            )

        try:
            event_id = _audit(
                subject=identity.subject, role=identity.role, device_id=identity.device_id,
                resource=RESOURCE_STORAGE, action=Action.SAAS_UPLOAD, result="allow",
                reason_code=Reason.ALLOW_UPLOAD_CLEAN, http_status=200, started=started,
            )
        except AuditUnavailable as exc:
            logger.error("blocking allowed upload: audit unavailable (%s)", exc)
            return _deny_response(
                503, Reason.ERROR_AUDIT_UNAVAILABLE,
                "Authorization could not be recorded, so the upload was not forwarded.",
            )

        try:
            upstream = await gw().client.post(
                f"{gw().settings.apps_url}/storage/upload",
                json={"filename": payload.filename, "content": payload.content},
            )
        except httpx.HTTPError as exc:
            logger.error("storage upstream unreachable: %s", exc)
            return _deny_response(
                502, Reason.ERROR_UPSTREAM_UNAVAILABLE,
                "Upload was authorized but synthetic storage is unavailable.",
                event_id,
            )

        return JSONResponse(
            {
                "allowed": True,
                "reason_code": Reason.ALLOW_UPLOAD_CLEAN,
                "audit_event_id": event_id,
                "dlp": result.as_dict(),
                "upstream": _safe_json(upstream),
            },
            status_code=200 if upstream.status_code == 200 else 502,
        )

    # -- admin -------------------------------------------------------------- #

    @app.get("/admin/devices", tags=["admin"])
    async def admin_devices(request: Request) -> JSONResponse:
        """Device registry, for verified healthy administrators only.

        The UI hides these controls for non-admins, but the check that
        matters is this one, on the server.
        """
        started = time.perf_counter()
        identity, _decision, failure = await _guard(
            request, resource=RESOURCE_DEVICES, action=Action.ADMIN_READ, started=started
        )
        if failure is not None:
            return failure
        assert identity is not None

        event_id = _audit_best_effort(
            subject=identity.subject, role=identity.role, device_id=identity.device_id,
            resource=RESOURCE_DEVICES, action=Action.ADMIN_READ, result="allow",
            reason_code=Reason.ALLOW_ADMIN, http_status=200, started=started,
        )

        try:
            upstream = await gw().client.get(
                f"{gw().settings.policy_url}/devices", headers=gw().service_headers()
            )
        except httpx.HTTPError:
            return _deny_response(
                503, Reason.ERROR_POLICY_UNAVAILABLE, "Policy service is unavailable."
            )

        body = _safe_json(upstream)
        if isinstance(body, dict):
            body = {**body, "audit_event_id": event_id}
        return JSONResponse(body, status_code=upstream.status_code)

    @app.put("/admin/devices/{device_id}", tags=["admin"])
    async def admin_update_device(device_id: str, request: Request) -> JSONResponse:
        """Change a device's posture. Administrator only, enforced server-side."""
        started = time.perf_counter()
        if not is_safe_id(device_id):
            return _deny_response(400, Reason.DENY_MALFORMED_REQUEST, "Malformed device ID.")

        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            return _deny_response(413, Reason.DENY_BODY_TOO_LARGE, "Request body too large.")

        identity, _decision, failure = await _guard(
            request, resource=RESOURCE_DEVICES, action=Action.ADMIN_WRITE, started=started
        )
        if failure is not None:
            return failure
        assert identity is not None

        event_id = _audit_best_effort(
            subject=identity.subject, role=identity.role, device_id=identity.device_id,
            resource=RESOURCE_DEVICES, action=Action.ADMIN_WRITE, result="allow",
            reason_code=Reason.ALLOW_ADMIN, http_status=200, started=started,
        )

        try:
            upstream = await gw().client.put(
                f"{gw().settings.policy_url}/devices/{device_id}",
                content=raw,
                headers={**gw().service_headers(), "content-type": "application/json"},
            )
        except httpx.HTTPError:
            return _deny_response(
                503, Reason.ERROR_POLICY_UNAVAILABLE, "Policy service is unavailable."
            )

        body = _safe_json(upstream)
        if isinstance(body, dict):
            body = {**body, "audit_event_id": event_id}
        return JSONResponse(body, status_code=upstream.status_code)

    @app.get("/admin/events", tags=["admin"])
    async def admin_events(request: Request, limit: int = 50, result: str | None = None) -> JSONResponse:
        """Redacted audit decisions, newest first. Administrator only."""
        started = time.perf_counter()
        identity, _decision, failure = await _guard(
            request, resource=RESOURCE_AUDIT, action=Action.ADMIN_READ, started=started
        )
        if failure is not None:
            return failure
        assert identity is not None

        if result is not None and result not in ("allow", "deny", "error"):
            return _deny_response(
                400, Reason.DENY_MALFORMED_REQUEST,
                "result filter must be one of: allow, deny, error.",
            )

        _audit_best_effort(
            subject=identity.subject, role=identity.role, device_id=identity.device_id,
            resource=RESOURCE_AUDIT, action=Action.ADMIN_READ, result="allow",
            reason_code=Reason.ALLOW_ADMIN, http_status=200, started=started,
        )

        events = gw().audit.query(limit=limit, result=result)
        return JSONResponse(
            {
                "events": events,
                "returned": len(events),
                "total": gw().audit.count(),
                "filter": {"limit": limit, "result": result},
            }
        )

    # -- forwarding --------------------------------------------------------- #

    async def _forward_get(url: str, event_id: str, *, extra: dict[str, Any] | None = None) -> JSONResponse:
        """GET a fixed private URL and wrap the response.

        ``url`` is always built from a validated ID plus a configured base, so
        no caller-supplied string reaches httpx. Redirects are disabled on the
        client, so an upstream cannot bounce us somewhere unevaluated.
        """
        try:
            upstream = await gw().client.get(url)
        except httpx.HTTPError as exc:
            logger.error("upstream unreachable: %s", exc)
            return _deny_response(
                502, Reason.ERROR_UPSTREAM_UNAVAILABLE,
                "Request was authorized but the private application is unavailable.",
                event_id,
            )

        body: dict[str, Any] = {
            "allowed": True,
            "audit_event_id": event_id,
            "upstream_status": upstream.status_code,
            "data": _safe_json(upstream),
        }
        if extra:
            body.update({key: value for key, value in extra.items() if value is not None})
        return JSONResponse(body, status_code=200 if upstream.status_code == 200 else 502)

    return app


class PolicyUnavailable(Exception):
    """Policy could not be consulted, or answered incomprehensibly."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


def _safe_json(response: httpx.Response) -> Any:
    """Decode an upstream JSON body, or report that it was not JSON."""
    try:
        return response.json()
    except ValueError:
        return {"detail": "Upstream response was not JSON."}


app = create_app()
