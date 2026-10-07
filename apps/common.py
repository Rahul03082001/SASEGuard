"""Configuration, shared models, reason codes, and helpers.

This module deliberately has no FastAPI app of its own. It holds the things
all four services agree on: where files live, what a decision looks like, and
the fixed vocabulary of reason codes that end up in audit rows.

Design note for readers new to security code: the reason codes are a closed
set of constants rather than free-text strings. Free text drifts, and an
auditor cannot write a query against prose. A closed set means every denial
in the database can be counted and explained.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx
import yaml

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

#: Repository root, resolved from this file so services work from any cwd.
ROOT = pathlib.Path(__file__).resolve().parent.parent

CONFIG_DIR = ROOT / "config"
WEB_DIR = ROOT / "web"

#: Generated at setup time. Never committed — see .gitignore.
SECRETS_DIR = pathlib.Path(os.environ.get("SASEGUARD_SECRETS_DIR", ROOT / "secrets"))
DATA_DIR = pathlib.Path(os.environ.get("SASEGUARD_DATA_DIR", ROOT / "data"))

POLICY_FILE = pathlib.Path(os.environ.get("SASEGUARD_POLICY_FILE", CONFIG_DIR / "policy.yaml"))
DEVICES_SEED_FILE = CONFIG_DIR / "devices.json"

PRIVATE_KEY_FILE = SECRETS_DIR / "jwt_private.pem"
PUBLIC_KEY_FILE = SECRETS_DIR / "jwt_public.pem"
USERS_FILE = SECRETS_DIR / "users.json"
CREDENTIALS_FILE = SECRETS_DIR / "demo_credentials.txt"
ENV_FILE = ROOT / ".env"

AUDIT_DB = pathlib.Path(os.environ.get("SASEGUARD_AUDIT_DB", DATA_DIR / "audit.sqlite3"))
POLICY_DB = pathlib.Path(os.environ.get("SASEGUARD_POLICY_DB", DATA_DIR / "policy.sqlite3"))


# --------------------------------------------------------------------------- #
# .env loading
# --------------------------------------------------------------------------- #

def load_dotenv(path: pathlib.Path = ENV_FILE, *, override: bool = False) -> None:
    """Load ``KEY=value`` lines from ``path`` into ``os.environ``.

    Hand-rolled instead of pulling in python-dotenv: the format we generate is
    trivial, and every dependency in a security demo is a dependency a reader
    has to trust. Existing environment variables win unless ``override``.
    """
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if override or key not in os.environ:
            os.environ[key] = value


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #

JWT_ISSUER = "saseguard-demo-issuer"
JWT_AUDIENCE = "saseguard-gateway"

#: Fixed allowlist. Passed to ``jwt.decode(algorithms=...)`` so PyJWT refuses
#: anything else — this is what blocks ``alg=none`` and HS256 key confusion.
JWT_ALLOWED_ALGORITHMS = ["RS256"]

#: Claims that must be present and non-empty on every protected request.
JWT_REQUIRED_CLAIMS = ["iss", "aud", "iat", "nbf", "exp", "sub", "role", "device_id", "jti"]

TOKEN_TTL_SECONDS = 600  # ten minutes

#: Reject the HTTP body before it is parsed as JSON.
MAX_BODY_BYTES = 65_536
#: Reject the decoded upload text after parsing.
MAX_CONTENT_CHARS = 32_000

#: Bounded so a hung private service cannot pin a gateway worker forever.
HTTP_TIMEOUT_SECONDS = float(os.environ.get("SASEGUARD_HTTP_TIMEOUT", "3.0"))

SERVICE_CREDENTIAL_HEADER = "x-saseguard-service-credential"


@dataclass(frozen=True)
class Settings:
    """Resolved runtime settings for whichever service is starting."""

    identity_url: str = "http://127.0.0.1:8081"
    policy_url: str = "http://127.0.0.1:8082"
    apps_url: str = "http://127.0.0.1:8083"
    service_credential: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        return cls(
            identity_url=os.environ.get("SASEGUARD_IDENTITY_URL", cls.identity_url).rstrip("/"),
            policy_url=os.environ.get("SASEGUARD_POLICY_URL", cls.policy_url).rstrip("/"),
            apps_url=os.environ.get("SASEGUARD_APPS_URL", cls.apps_url).rstrip("/"),
            service_credential=os.environ.get("SASEGUARD_SERVICE_CREDENTIAL", ""),
        )


# --------------------------------------------------------------------------- #
# Reason codes
# --------------------------------------------------------------------------- #

class Reason:
    """The closed vocabulary of decision reasons.

    Anything that reaches the audit table uses one of these. Tests assert on
    them, so renaming one is a deliberate, visible change.
    """

    # Allow
    ALLOW_ROLE_GRANT = "ALLOW_ROLE_GRANT"
    ALLOW_WEB_CATEGORY = "ALLOW_WEB_CATEGORY"
    ALLOW_UPLOAD_CLEAN = "ALLOW_UPLOAD_CLEAN"
    ALLOW_ADMIN = "ALLOW_ADMIN"
    ALLOW_LOGIN = "ALLOW_LOGIN"
    ALLOW_LOGOUT = "ALLOW_LOGOUT"

    # Authentication (401)
    DENY_NO_CREDENTIALS = "DENY_NO_CREDENTIALS"
    DENY_BAD_TOKEN_SIGNATURE = "DENY_BAD_TOKEN_SIGNATURE"
    DENY_TOKEN_ALGORITHM = "DENY_TOKEN_ALGORITHM"
    DENY_TOKEN_EXPIRED = "DENY_TOKEN_EXPIRED"
    DENY_TOKEN_NOT_YET_VALID = "DENY_TOKEN_NOT_YET_VALID"
    DENY_TOKEN_CLAIMS = "DENY_TOKEN_CLAIMS"
    DENY_TOKEN_ISSUER = "DENY_TOKEN_ISSUER"
    DENY_TOKEN_AUDIENCE = "DENY_TOKEN_AUDIENCE"
    DENY_BAD_LOGIN = "DENY_BAD_LOGIN"
    DENY_DEVICE_NOT_ENROLLED = "DENY_DEVICE_NOT_ENROLLED"

    # Authorization (403)
    DENY_UNKNOWN_RESOURCE = "DENY_UNKNOWN_RESOURCE"
    DENY_UNKNOWN_ACTION = "DENY_UNKNOWN_ACTION"
    DENY_UNKNOWN_ROLE = "DENY_UNKNOWN_ROLE"
    DENY_ROLE_NOT_PERMITTED = "DENY_ROLE_NOT_PERMITTED"
    DENY_NOT_ADMIN = "DENY_NOT_ADMIN"
    DENY_UPLOAD_NOT_PERMITTED = "DENY_UPLOAD_NOT_PERMITTED"

    # Posture (403)
    DENY_DEVICE_UNKNOWN = "DENY_DEVICE_UNKNOWN"
    DENY_DEVICE_NOT_OWNED = "DENY_DEVICE_NOT_OWNED"
    DENY_DEVICE_UNMANAGED = "DENY_DEVICE_UNMANAGED"
    DENY_DEVICE_NONCOMPLIANT = "DENY_DEVICE_NONCOMPLIANT"
    DENY_DEVICE_RISK_SCORE = "DENY_DEVICE_RISK_SCORE"
    DENY_POSTURE_STALE = "DENY_POSTURE_STALE"
    DENY_TOKEN_REVOKED = "DENY_TOKEN_REVOKED"

    # Web categories (403)
    DENY_WEB_CATEGORY = "DENY_WEB_CATEGORY"
    DENY_UNKNOWN_DESTINATION = "DENY_UNKNOWN_DESTINATION"

    # DLP (403)
    DENY_DLP_MATCH = "DENY_DLP_MATCH"

    # Request shape (400/413)
    DENY_BODY_TOO_LARGE = "DENY_BODY_TOO_LARGE"
    DENY_CONTENT_TOO_LARGE = "DENY_CONTENT_TOO_LARGE"
    DENY_MALFORMED_REQUEST = "DENY_MALFORMED_REQUEST"

    # Infrastructure (503) — fail closed
    ERROR_POLICY_UNAVAILABLE = "ERROR_POLICY_UNAVAILABLE"
    ERROR_POLICY_INVALID_RESPONSE = "ERROR_POLICY_INVALID_RESPONSE"
    ERROR_AUDIT_UNAVAILABLE = "ERROR_AUDIT_UNAVAILABLE"
    ERROR_UPSTREAM_UNAVAILABLE = "ERROR_UPSTREAM_UNAVAILABLE"
    ERROR_IDENTITY_UNAVAILABLE = "ERROR_IDENTITY_UNAVAILABLE"


#: Reason codes that mean "the request never should have been authenticated".
AUTH_FAILURE_REASONS = frozenset(
    {
        Reason.DENY_NO_CREDENTIALS,
        Reason.DENY_BAD_TOKEN_SIGNATURE,
        Reason.DENY_TOKEN_ALGORITHM,
        Reason.DENY_TOKEN_EXPIRED,
        Reason.DENY_TOKEN_NOT_YET_VALID,
        Reason.DENY_TOKEN_CLAIMS,
        Reason.DENY_TOKEN_ISSUER,
        Reason.DENY_TOKEN_AUDIENCE,
    }
)


# --------------------------------------------------------------------------- #
# Actions and resources
# --------------------------------------------------------------------------- #

class Action:
    APP_READ = "app.read"
    WEB_VISIT = "web.visit"
    SAAS_UPLOAD = "saas.upload"
    ADMIN_READ = "admin.read"
    ADMIN_WRITE = "admin.write"

    # Gateway-local actions. These label audit rows for the authentication
    # endpoints; they are not sent to the policy service and are not listed
    # in policy.yaml, because login and logout are not authorization
    # decisions -- you may always log out, and logging in is gated by the
    # password and device enrollment instead.
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"


#: Fixed private application IDs. ``GET /apps/{app_id}`` maps an ID in this
#: set to a fixed upstream path; it never forwards a caller-supplied URL.
APP_IDS = ("payroll", "engineering", "wiki")

#: Fixed web-fixture IDs, same reasoning.
WEB_DESTINATIONS = ("docs", "phishing-sim", "gambling-sim")

#: Identifier shape shared by subjects, device IDs, app IDs and destinations.
SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def is_safe_id(value: str) -> bool:
    """True when ``value`` is a conservative identifier.

    Used before an ID is interpolated anywhere, including into a log line, so
    a caller cannot smuggle newlines or path separators into our records.
    """
    return bool(isinstance(value, str) and SAFE_ID_PATTERN.match(value))


# --------------------------------------------------------------------------- #
# Policy document
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class PolicyDocument:
    """A loaded policy.yaml plus the hash of the exact bytes it came from."""

    version: str
    content_hash: str
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def max_risk_score(self) -> int:
        return int(self.raw["posture"]["max_risk_score"])

    @property
    def max_posture_age_hours(self) -> int:
        return int(self.raw["posture"]["max_posture_age_hours"])

    @property
    def require_managed(self) -> bool:
        return bool(self.raw["posture"].get("require_managed", True))

    @property
    def require_compliant(self) -> bool:
        return bool(self.raw["posture"].get("require_compliant", True))

    @property
    def require_ownership(self) -> bool:
        return bool(self.raw["posture"].get("require_ownership", True))

    @property
    def known_apps(self) -> tuple[str, ...]:
        return tuple(self.raw["resources"]["apps"])

    @property
    def known_actions(self) -> tuple[str, ...]:
        return tuple(self.raw["actions"])

    def role(self, name: str) -> dict[str, Any] | None:
        return self.raw["roles"].get(name)

    def web_destination(self, name: str) -> dict[str, Any] | None:
        return self.raw["web_destinations"].get(name)

    @property
    def label(self) -> str:
        """What goes in the audit row: version plus a short hash prefix."""
        return f"{self.version}+{self.content_hash[:12]}"


def load_policy(path: pathlib.Path = POLICY_FILE) -> PolicyDocument:
    """Read and validate policy.yaml.

    The content hash is taken over the raw bytes, not the parsed structure, so
    a comment-only edit still produces a new label. That is intentional: the
    label answers "which file was on disk", not "was the meaning the same".
    """
    data_bytes = path.read_bytes()
    parsed = yaml.safe_load(data_bytes)
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a YAML mapping")

    for required in ("policy_version", "posture", "resources", "roles", "web_destinations", "actions"):
        if required not in parsed:
            raise ValueError(f"{path} is missing required key: {required}")

    return PolicyDocument(
        version=str(parsed["policy_version"]),
        content_hash=hashlib.sha256(data_bytes).hexdigest(),
        raw=parsed,
    )


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #

def utcnow() -> datetime:
    """Timezone-aware UTC now. Never use naive datetimes in this codebase."""
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    """Render a datetime as an ISO-8601 string with an explicit offset."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, assuming UTC when no offset is given."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# HTTP client
# --------------------------------------------------------------------------- #

def make_async_client(
    *,
    timeout: float | None = None,
    mounts: dict[str, Any] | None = None,
) -> httpx.AsyncClient:
    """Build the only kind of HTTP client the services are allowed to use.

    Three settings matter for security, not convenience:

    * ``trust_env=False`` — ignore ``HTTP_PROXY`` and friends. Otherwise an
      ambient proxy variable could silently route private traffic elsewhere.
    * ``follow_redirects=False`` — an upstream fixture must not be able to
      bounce the gateway to a host policy never evaluated.
    * a bounded ``timeout`` — so a hung dependency fails closed instead of
      holding the request open.

    ``mounts`` exists for the test suite, which maps the private service URLs
    onto in-process ASGI transports. Production callers leave it ``None``.
    """
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout if timeout is not None else HTTP_TIMEOUT_SECONDS),
        trust_env=False,
        follow_redirects=False,
        mounts=mounts or {},
    )


# --------------------------------------------------------------------------- #
# Misc
# --------------------------------------------------------------------------- #

def read_text_file(path: pathlib.Path, what: str) -> str:
    """Read a setup-generated file, with an error that says how to fix it."""
    if not path.exists():
        raise RuntimeError(
            f"{what} not found at {path}. Run `python scripts/setup.py` first."
        )
    return path.read_text(encoding="utf-8")


def load_json_file(path: pathlib.Path, what: str) -> Any:
    return json.loads(read_text_file(path, what))


def require_service_credential(presented: str | None, expected: str) -> bool:
    """Constant-time comparison of the private-API service credential.

    ``==`` on secrets leaks length and prefix information through timing.
    ``compare_digest`` does not.
    """
    import hmac

    if not presented or not expected:
        return False
    return hmac.compare_digest(presented, expected)


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #

#: PBKDF2-HMAC-SHA256 work factor. Chosen to be slow enough to be a real
#: speed bump and fast enough that the test suite stays quick. A production
#: system should prefer Argon2id or scrypt and re-tune this annually.
PBKDF2_ITERATIONS = 200_000
PBKDF2_SALT_BYTES = 16


def hash_password(password: str, salt_hex: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Derive a salted PBKDF2-HMAC-SHA256 hash, returned as hex.

    Per-user salting is what stops one precomputed table from cracking every
    account at once, and it is why two users with the same demo password get
    different stored hashes.
    """
    import binascii
    import hashlib as _hashlib

    derived = _hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        binascii.unhexlify(salt_hex),
        iterations,
    )
    return derived.hex()


def new_salt_hex() -> str:
    """A fresh cryptographically random salt, hex-encoded."""
    import secrets as _secrets

    return _secrets.token_hex(PBKDF2_SALT_BYTES)


def verify_password(
    password: str, salt_hex: str, expected_hash_hex: str, iterations: int = PBKDF2_ITERATIONS
) -> bool:
    """Constant-time password check.

    The comparison uses ``compare_digest`` so an attacker cannot learn the
    stored hash byte-by-byte from response timing.
    """
    import hmac as _hmac

    try:
        candidate = hash_password(password, salt_hex, iterations)
    except Exception:
        return False
    return _hmac.compare_digest(candidate, expected_hash_hex)
