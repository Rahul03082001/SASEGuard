"""Persistent, redacted authorization audit log (SQLite).

What this records: the *decision* the gateway reached — who asked, for what,
what the answer was, which reason code applied, and which policy version
produced it.

What this deliberately does not record: passwords, bearer tokens, token IDs
in any reversible form beyond the jti the policy service already holds,
request bodies, or DLP-matched text. A DLP finding is stored as a rule ID.
If the audit table held the secret, blocking the upload would have
accomplished nothing.

Honest limitations (also in docs/threat-model.md):

* An ``allow`` row means the gateway *authorized* the call before forwarding
  it. It is not a confirmation that the upstream application succeeded.
* One SQLite file on one host. Not replicated, not tamper-evident, not
  append-only at the storage layer. Anyone with write access to the file can
  edit history.
* The gateway audit write and any upstream state change are two separate
  operations, not one distributed transaction.
"""

from __future__ import annotations

import contextlib
import json
import pathlib
import sqlite3
import uuid
from dataclasses import dataclass
from typing import Any, Iterator

from apps.common import AUDIT_DB, iso, utcnow

#: Columns written by ``record``. Nothing outside this list reaches the table.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    event_id            TEXT PRIMARY KEY,
    occurred_at         TEXT NOT NULL,
    subject             TEXT NOT NULL,
    role                TEXT NOT NULL,
    device_id           TEXT NOT NULL,
    resource            TEXT NOT NULL,
    action              TEXT NOT NULL,
    result              TEXT NOT NULL CHECK (result IN ('allow', 'deny', 'error')),
    reason_code         TEXT NOT NULL,
    policy_version      TEXT NOT NULL,
    dlp_rule_ids        TEXT NOT NULL DEFAULT '[]',
    http_status         INTEGER NOT NULL,
    decision_latency_ms REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON audit_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_result ON audit_events (result);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_events (subject);
"""

RESULT_VALUES = ("allow", "deny", "error")


class AuditUnavailable(RuntimeError):
    """The audit log could not be written.

    The gateway turns this into a 503 and does **not** forward the request.
    An unrecorded decision is treated as a decision that did not happen.
    """


@dataclass(frozen=True)
class AuditEvent:
    """One decision, ready to persist. All fields are non-sensitive."""

    subject: str
    role: str
    device_id: str
    resource: str
    action: str
    result: str
    reason_code: str
    policy_version: str
    http_status: int
    decision_latency_ms: float
    dlp_rule_ids: tuple[str, ...] = ()
    event_id: str = ""
    occurred_at: str = ""

    def finalized(self) -> "AuditEvent":
        """Fill in the event ID and timestamp if the caller left them blank."""
        return AuditEvent(
            subject=self.subject,
            role=self.role,
            device_id=self.device_id,
            resource=self.resource,
            action=self.action,
            result=self.result,
            reason_code=self.reason_code,
            policy_version=self.policy_version,
            http_status=self.http_status,
            decision_latency_ms=round(float(self.decision_latency_ms), 3),
            dlp_rule_ids=tuple(self.dlp_rule_ids),
            event_id=self.event_id or f"evt_{uuid.uuid4().hex}",
            occurred_at=self.occurred_at or iso(utcnow()),
        )


class AuditStore:
    """SQLite-backed audit log.

    A fresh connection is opened per operation rather than held open. That
    costs a little latency (visible in scripts/benchmark.py) and buys two
    things worth more in a teaching repo: no cross-thread connection sharing
    to reason about, and tests can prove durability by simply reopening.
    """

    def __init__(self, path: Any = None) -> None:
        self.path = str(path or AUDIT_DB)
        self._initialized = False

    # -- plumbing ---------------------------------------------------------- #

    @contextlib.contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        pathlib.Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the schema. Idempotent; safe to call on every startup."""
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.commit()
        self._initialized = True

    def _ensure(self) -> None:
        if not self._initialized:
            self.initialize()

    # -- writes ------------------------------------------------------------ #

    def record(self, event: AuditEvent) -> AuditEvent:
        """Persist one decision and commit before returning.

        The commit is synchronous on purpose. The gateway calls this *before*
        contacting a private application, so a successful return is the
        gateway's evidence that the decision is durable.

        Raises:
            AuditUnavailable: on any storage failure.
        """
        final = event.finalized()
        if final.result not in RESULT_VALUES:
            raise AuditUnavailable(f"invalid audit result: {final.result!r}")

        try:
            self._ensure()
            with self._connect() as conn:
                # Parameterized throughout. No f-strings in SQL anywhere in
                # this file -- that is the whole defence against injection.
                conn.execute(
                    """
                    INSERT INTO audit_events (
                        event_id, occurred_at, subject, role, device_id,
                        resource, action, result, reason_code, policy_version,
                        dlp_rule_ids, http_status, decision_latency_ms
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        final.event_id,
                        final.occurred_at,
                        final.subject,
                        final.role,
                        final.device_id,
                        final.resource,
                        final.action,
                        final.result,
                        final.reason_code,
                        final.policy_version,
                        json.dumps(list(final.dlp_rule_ids)),
                        int(final.http_status),
                        float(final.decision_latency_ms),
                    ),
                )
                conn.commit()
        except AuditUnavailable:
            raise
        except Exception as exc:  # sqlite3.Error, OSError, disk full, ...
            raise AuditUnavailable(f"audit write failed: {exc}") from exc

        return final

    # -- reads ------------------------------------------------------------- #

    def query(
        self,
        *,
        limit: int = 50,
        result: str | None = None,
        subject: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return recent events, newest first.

        ``limit`` is clamped rather than trusted, and ``result``/``subject``
        are bound parameters, so a caller cannot widen the query or inject.
        """
        self._ensure()
        limit = max(1, min(int(limit), 500))

        sql = "SELECT * FROM audit_events"
        clauses: list[str] = []
        params: list[Any] = []

        if result:
            if result not in RESULT_VALUES:
                raise ValueError(f"result must be one of {RESULT_VALUES}")
            clauses.append("result = ?")
            params.append(result)
        if subject:
            clauses.append("subject = ?")
            params.append(subject)

        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY occurred_at DESC, rowid DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [self._row_to_dict(row) for row in rows]

    def count(self, *, result: str | None = None) -> int:
        self._ensure()
        with self._connect() as conn:
            if result:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM audit_events WHERE result = ?", (result,)
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS n FROM audit_events").fetchone()
        return int(row["n"])

    def get(self, event_id: str) -> dict[str, Any] | None:
        self._ensure()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM audit_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["dlp_rule_ids"] = json.loads(data.get("dlp_rule_ids") or "[]")
        return data
