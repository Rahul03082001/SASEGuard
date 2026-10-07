"""Policy decision point — owns device posture, revocation, and all grants.

This service answers one question: *given a verified identity and the
authoritative lab state, is this request allowed?* It never sees a bearer
token, only the claims the gateway already verified. It never forwards
traffic. Keeping the decision here, in its own process with its own database,
is what stops the enforcement point from quietly deciding for itself.

Two pieces of state live here and nowhere else:

* the **device registry** — owner, managed, compliant, risk score, last seen;
* the **revocation list** — token IDs that logout has retired.

Both are re-read from SQLite on *every* ``/evaluate`` call. Nothing positive
is cached. That is what makes a posture change take effect on the very next
request using an already-issued token, which is the behaviour the README
demo walks through.

Honest limitation: re-evaluating per request stops the *next* request. It
cannot claw back a response already in flight, and it does nothing for a
long-lived streaming connection that was authorized once at open time.
"""

from __future__ import annotations

import contextlib
import logging
import pathlib
import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Iterator

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError, field_validator

from apps.common import (
    Action,
    DEVICES_SEED_FILE,
    MAX_BODY_BYTES,
    POLICY_DB,
    PolicyDocument,
    Reason,
    SERVICE_CREDENTIAL_HEADER,
    Settings,
    is_safe_id,
    iso,
    load_json_file,
    load_policy,
    parse_iso,
    require_service_credential,
    utcnow,
)

logger = logging.getLogger("saseguard.policy")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    owner       TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',
    managed     INTEGER NOT NULL CHECK (managed IN (0, 1)),
    compliant   INTEGER NOT NULL CHECK (compliant IN (0, 1)),
    risk_score  INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    last_seen   TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id   TEXT PRIMARY KEY,
    subject    TEXT NOT NULL,
    revoked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_devices_owner ON devices (owner);
"""


# --------------------------------------------------------------------------- #
# Store
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DeviceRecord:
    """Authoritative posture for one enrolled lab device."""

    device_id: str
    owner: str
    label: str
    managed: bool
    compliant: bool
    risk_score: int
    last_seen: str
    updated_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "owner": self.owner,
            "label": self.label,
            "managed": self.managed,
            "compliant": self.compliant,
            "risk_score": self.risk_score,
            "last_seen": self.last_seen,
            "updated_at": self.updated_at,
        }

    def posture_age_hours(self, now: Any = None) -> float:
        reference = now or utcnow()
        try:
            seen = parse_iso(self.last_seen)
        except Exception:
            # An unparseable timestamp is treated as infinitely old, never
            # as fresh. Fail closed on malformed state.
            return float("inf")
        return (reference - seen).total_seconds() / 3600.0


class PolicyStore:
    """SQLite-backed device registry and revocation list.

    One connection per operation, same reasoning as the audit store: no
    cross-thread connection sharing, and durability is provable by reopening.
    """

    def __init__(self, path: Any = None) -> None:
        self.path = str(path or POLICY_DB)
        self._initialized = False

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # Create the data directory on demand so a fresh clone does not need
        # mkdir before the first request.
        pathlib.Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()
        self._initialized = True

    def _ensure(self) -> None:
        if not self._initialized:
            self.initialize()

    # -- devices ----------------------------------------------------------- #

    def seed_devices(self, seed_path: Any = None, *, force: bool = False) -> int:
        """Load config/devices.json into the registry.

        ``last_seen`` is stamped to *now* so a freshly set up lab starts with
        healthy posture rather than immediately-stale devices.
        """
        self._ensure()
        document = load_json_file(seed_path or DEVICES_SEED_FILE, "device registry seed")
        now = iso(utcnow())
        written = 0
        with self._connect() as conn:
            for entry in document["devices"]:
                if force:
                    sql = """
                        INSERT INTO devices (device_id, owner, label, managed, compliant,
                                             risk_score, last_seen, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(device_id) DO UPDATE SET
                            owner=excluded.owner, label=excluded.label,
                            managed=excluded.managed, compliant=excluded.compliant,
                            risk_score=excluded.risk_score,
                            last_seen=excluded.last_seen, updated_at=excluded.updated_at
                    """
                else:
                    sql = """
                        INSERT INTO devices (device_id, owner, label, managed, compliant,
                                             risk_score, last_seen, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(device_id) DO NOTHING
                    """
                conn.execute(
                    sql,
                    (
                        entry["device_id"],
                        entry["owner"],
                        entry.get("label", ""),
                        1 if entry.get("managed", True) else 0,
                        1 if entry.get("compliant", True) else 0,
                        int(entry.get("risk_score", 0)),
                        now,
                        now,
                    ),
                )
                written += 1
            conn.commit()
        return written

    def get_device(self, device_id: str) -> DeviceRecord | None:
        self._ensure()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        return self._row_to_device(row) if row else None

    def list_devices(self) -> list[DeviceRecord]:
        self._ensure()
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
        return [self._row_to_device(row) for row in rows]

    def update_device(self, device_id: str, changes: dict[str, Any]) -> DeviceRecord | None:
        """Apply a partial posture update.

        Column names come from a fixed allowlist, never from caller input, so
        the dynamic SET clause cannot be used to touch an unintended column.
        """
        self._ensure()
        allowed = {"managed", "compliant", "risk_score", "last_seen", "label"}
        applied = {key: value for key, value in changes.items() if key in allowed and value is not None}
        if not applied:
            return self.get_device(device_id)

        assignments: list[str] = []
        params: list[Any] = []
        for key, value in applied.items():
            assignments.append(f"{key} = ?")  # key is from `allowed`, not input
            if key in ("managed", "compliant"):
                params.append(1 if value else 0)
            elif key == "risk_score":
                params.append(int(value))
            else:
                params.append(str(value))

        assignments.append("updated_at = ?")
        params.append(iso(utcnow()))
        params.append(device_id)

        with self._connect() as conn:
            cursor = conn.execute(
                f"UPDATE devices SET {', '.join(assignments)} WHERE device_id = ?", params
            )
            conn.commit()
            if cursor.rowcount == 0:
                return None
        return self.get_device(device_id)

    # -- revocation -------------------------------------------------------- #

    def revoke_token(self, token_id: str, subject: str) -> bool:
        """Persist a token revocation. Idempotent."""
        self._ensure()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO revoked_tokens (token_id, subject, revoked_at) VALUES (?, ?, ?) "
                "ON CONFLICT(token_id) DO NOTHING",
                (token_id, subject, iso(utcnow())),
            )
            conn.commit()
        return True

    def is_revoked(self, token_id: str) -> bool:
        self._ensure()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM revoked_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
        return row is not None

    def revoked_count(self) -> int:
        self._ensure()
        with self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM revoked_tokens").fetchone()["n"])

    @staticmethod
    def _row_to_device(row: sqlite3.Row) -> DeviceRecord:
        return DeviceRecord(
            device_id=row["device_id"],
            owner=row["owner"],
            label=row["label"],
            managed=bool(row["managed"]),
            compliant=bool(row["compliant"]),
            risk_score=int(row["risk_score"]),
            last_seen=row["last_seen"],
            updated_at=row["updated_at"],
        )


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #

class EvaluateRequest(BaseModel):
    """Claims the gateway already verified, plus what is being attempted.

    Note what is *absent*: the bearer token itself. The policy service has no
    use for it and should not be able to replay it.
    """

    model_config = {"extra": "forbid"}

    subject: str = Field(min_length=1, max_length=64)
    role: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    token_id: str = Field(min_length=1, max_length=128)
    resource: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=32)

    @field_validator("subject", "role", "device_id", "resource")
    @classmethod
    def _safe(cls, value: str) -> str:
        if not is_safe_id(value):
            raise ValueError("unsafe identifier")
        return value


class DeviceUpdateRequest(BaseModel):
    """Partial posture update. Every field optional, extras forbidden."""

    model_config = {"extra": "forbid"}

    managed: bool | None = None
    compliant: bool | None = None
    risk_score: int | None = Field(default=None, ge=0, le=100)
    last_seen: str | None = Field(default=None, max_length=64)
    label: str | None = Field(default=None, max_length=128)

    @field_validator("last_seen")
    @classmethod
    def _iso(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parse_iso(value)  # raises on anything unparseable
        return value


class RevokeRequest(BaseModel):
    model_config = {"extra": "forbid"}

    token_id: str = Field(min_length=1, max_length=128)
    subject: str = Field(min_length=1, max_length=64)


@dataclass(frozen=True)
class Decision:
    """The policy answer. ``allow`` plus a reason code, always."""

    allow: bool
    reason_code: str
    policy_version: str
    category: str | None = None
    device: dict[str, Any] | None = None
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "allow": self.allow,
            "reason_code": self.reason_code,
            "policy_version": self.policy_version,
            "category": self.category,
            "device": self.device,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------- #
# The decision function
# --------------------------------------------------------------------------- #

def evaluate(
    request: EvaluateRequest,
    policy: PolicyDocument,
    store: PolicyStore,
    *,
    now: Any = None,
) -> Decision:
    """Decide one request. Pure apart from reading the store.

    The evaluation order is deliberate and worth being able to recite:

    1. **Structural validity** — is the action one we understand, is the role
       one the policy defines? Garbage in gets a specific answer, not a
       generic 403.
    2. **Revocation** — has this exact token been retired? Checked before
       anything expensive, and before any grant.
    3. **Device posture** — enrolled, owned by this subject, managed,
       compliant, low risk, recently seen. Every grant depends on this, so it
       is checked once, here, rather than per resource type.
    4. **The grant itself** — does this role reach this resource?

    Steps 2 and 3 read SQLite on every call. No positive result is cached.
    """
    reference = now or utcnow()
    version = policy.label

    def deny(reason: str, detail: str = "", **extra: Any) -> Decision:
        return Decision(False, reason, version, detail=detail, **extra)

    # 1. Structural validity ------------------------------------------------
    if request.action not in policy.known_actions:
        return deny(Reason.DENY_UNKNOWN_ACTION, f"Unknown action: {request.action}")

    role = policy.role(request.role)
    if role is None:
        # A token can carry any role string; only policy.yaml decides which
        # role strings mean anything.
        return deny(Reason.DENY_UNKNOWN_ROLE, f"Role not defined in policy: {request.role}")

    # 2. Revocation ---------------------------------------------------------
    if store.is_revoked(request.token_id):
        return deny(Reason.DENY_TOKEN_REVOKED, "This token was revoked by logout.")

    # 3. Device posture -----------------------------------------------------
    device = store.get_device(request.device_id)
    if device is None:
        return deny(Reason.DENY_DEVICE_UNKNOWN, "Device is not in the registry.")

    snapshot = device.as_dict()

    if policy.require_ownership and device.owner != request.subject:
        return deny(
            Reason.DENY_DEVICE_NOT_OWNED,
            "Device is enrolled to a different account.",
            device=snapshot,
        )
    if policy.require_managed and not device.managed:
        return deny(Reason.DENY_DEVICE_UNMANAGED, "Device is not managed.", device=snapshot)
    if policy.require_compliant and not device.compliant:
        return deny(
            Reason.DENY_DEVICE_NONCOMPLIANT, "Device is not compliant.", device=snapshot
        )
    if device.risk_score > policy.max_risk_score:
        return deny(
            Reason.DENY_DEVICE_RISK_SCORE,
            f"Device risk score {device.risk_score} exceeds maximum {policy.max_risk_score}.",
            device=snapshot,
        )

    age_hours = device.posture_age_hours(reference)
    if age_hours > policy.max_posture_age_hours:
        return deny(
            Reason.DENY_POSTURE_STALE,
            f"Device posture is {age_hours:.1f}h old; maximum is "
            f"{policy.max_posture_age_hours}h.",
            device=snapshot,
        )

    def allow(reason: str, detail: str = "", category: str | None = None) -> Decision:
        return Decision(True, reason, version, category=category, device=snapshot, detail=detail)

    # 4. The grant ----------------------------------------------------------
    if request.action == Action.APP_READ:
        if request.resource not in policy.known_apps:
            return deny(
                Reason.DENY_UNKNOWN_RESOURCE,
                f"Unknown application: {request.resource}",
                device=snapshot,
            )
        if request.resource not in role.get("apps", []):
            return deny(
                Reason.DENY_ROLE_NOT_PERMITTED,
                f"Role {request.role} may not read {request.resource}.",
                device=snapshot,
            )
        return allow(Reason.ALLOW_ROLE_GRANT, f"Role {request.role} may read {request.resource}.")

    if request.action == Action.WEB_VISIT:
        destination = policy.web_destination(request.resource)
        if destination is None:
            # Only fixed fixture IDs exist. There is no URL to supply, which
            # is why this lab cannot be turned into an open proxy.
            return deny(
                Reason.DENY_UNKNOWN_DESTINATION,
                f"Unknown lab destination: {request.resource}",
                device=snapshot,
            )
        category = str(destination["category"])
        if destination["action"] != "allow":
            return deny(
                Reason.DENY_WEB_CATEGORY,
                f"Destination category '{category}' is blocked.",
                category=category,
                device=snapshot,
            )
        return allow(
            Reason.ALLOW_WEB_CATEGORY, f"Category '{category}' is permitted.", category=category
        )

    if request.action == Action.SAAS_UPLOAD:
        if not role.get("upload", False):
            return deny(
                Reason.DENY_UPLOAD_NOT_PERMITTED,
                f"Role {request.role} may not upload.",
                device=snapshot,
            )
        # Policy says the role may upload. DLP still runs at the gateway
        # afterwards and can block the specific content.
        return allow(Reason.ALLOW_ROLE_GRANT, f"Role {request.role} may upload.")

    if request.action in (Action.ADMIN_READ, Action.ADMIN_WRITE):
        if not role.get("admin", False):
            return deny(
                Reason.DENY_NOT_ADMIN,
                "Administrator role required.",
                device=snapshot,
            )
        return allow(Reason.ALLOW_ADMIN, "Administrator access granted.")

    # Unreachable while policy.yaml and Action agree, but fail closed anyway.
    return deny(Reason.DENY_UNKNOWN_ACTION, f"Unhandled action: {request.action}")


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #

def create_app(
    *,
    store: PolicyStore | None = None,
    policy: PolicyDocument | None = None,
    service_credential: str | None = None,
) -> FastAPI:
    app = FastAPI(
        title="SASEGuard Policy Decision Service",
        version="1.0.0",
        description=(
            "Private policy decision point. Owns the lab device registry and the token "
            "revocation list. Requires the setup-generated service credential on every "
            "endpoint except /healthz."
        ),
        docs_url=None,
        redoc_url=None,
    )
    settings = Settings.from_env()
    app.state.store = store or PolicyStore()
    app.state.policy = policy or load_policy()
    app.state.service_credential = (
        service_credential if service_credential is not None else settings.service_credential
    )

    # No DB work at construction time: the store initializes itself lazily on
    # first use (``_ensure``). That keeps ``import apps.policy`` working before
    # setup has ever run, which tooling and the test suite both rely on.

    # -- auth dependency --------------------------------------------------- #

    async def require_credential(
        service_credential: str | None = Header(default=None, alias=SERVICE_CREDENTIAL_HEADER),
    ) -> None:
        """Gate every private endpoint on the shared service credential.

        This is a bearer secret, not an identity. It establishes "the caller
        is the gateway", which together with Compose network isolation is the
        reason a workload on the app network cannot ask for a decision.
        """
        expected = app.state.service_credential
        if not expected:
            # Refuse to run unauthenticated. A blank credential almost always
            # means setup did not run, and silently allowing everything would
            # be the worst possible default.
            raise HTTPException(
                status_code=503,
                detail="Policy service credential is not configured. Run scripts/setup.py.",
            )
        if not require_service_credential(service_credential, expected):
            raise HTTPException(status_code=401, detail="Invalid service credential.")

    # -- endpoints --------------------------------------------------------- #

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, Any]:
        """Unauthenticated on purpose: Compose needs it, and it reveals nothing."""
        return {
            "status": "ok",
            "service": "policy",
            "policy_version": app.state.policy.label,
        }

    @app.post("/evaluate", tags=["policy"], dependencies=[Depends(require_credential)])
    async def evaluate_endpoint(request: Request) -> JSONResponse:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Request body too large.")
        try:
            parsed = EvaluateRequest.model_validate_json(raw)
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid evaluate request: {exc.error_count()} problem(s).")

        decision = evaluate(parsed, app.state.policy, app.state.store)
        logger.info(
            "decision subject=%s action=%s resource=%s allow=%s reason=%s",
            parsed.subject, parsed.action, parsed.resource, decision.allow, decision.reason_code,
        )
        return JSONResponse(decision.as_dict(), headers={"Cache-Control": "no-store"})

    @app.get("/devices", tags=["posture"], dependencies=[Depends(require_credential)])
    async def list_devices() -> dict[str, Any]:
        return {
            "devices": [device.as_dict() for device in app.state.store.list_devices()],
            "policy_version": app.state.policy.label,
            "thresholds": {
                "max_risk_score": app.state.policy.max_risk_score,
                "max_posture_age_hours": app.state.policy.max_posture_age_hours,
            },
        }

    @app.put("/devices/{device_id}", tags=["posture"], dependencies=[Depends(require_credential)])
    async def update_device(device_id: str, request: Request) -> JSONResponse:
        if not is_safe_id(device_id):
            raise HTTPException(status_code=400, detail="Malformed device_id.")
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Request body too large.")
        try:
            changes = DeviceUpdateRequest.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(status_code=400, detail="Invalid device update.")

        updated = app.state.store.update_device(
            device_id, changes.model_dump(exclude_none=True)
        )
        if updated is None:
            raise HTTPException(status_code=404, detail="Unknown device.")
        logger.info("posture updated device=%s", device_id)
        return JSONResponse(
            {"device": updated.as_dict()}, headers={"Cache-Control": "no-store"}
        )

    @app.post("/revoke", tags=["posture"], dependencies=[Depends(require_credential)])
    async def revoke(request: Request) -> JSONResponse:
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Request body too large.")
        try:
            parsed = RevokeRequest.model_validate_json(raw)
        except ValidationError:
            raise HTTPException(status_code=400, detail="Invalid revoke request.")

        app.state.store.revoke_token(parsed.token_id, parsed.subject)
        logger.info("token revoked subject=%s", parsed.subject)
        return JSONResponse(
            {"revoked": True, "token_id": parsed.token_id},
            headers={"Cache-Control": "no-store"},
        )

    return app


app = create_app()
