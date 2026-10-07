"""Synthetic private applications, lab web fixtures, and a mock storage sink.

Nothing here is real and nothing here reaches the internet. The three
"applications" return fixed strings. The three "web destinations" are local
fixtures, so a blocked category can be demonstrated without anyone fetching
an actual phishing page.

The important part of this file is the **call counter**. Every handler
increments a counter before it returns. That turns "the gateway denied the
request" into something a test can *prove*: assert the counter did not move.
A test that only checks for HTTP 403 cannot tell the difference between a
real denial and a denial that still leaked the request upstream.

The storage sink is deliberately amnesiac: it never stores, echoes, or logs
the body it receives. It reports only how many uploads it has accepted. A
rejected payload is therefore provably absent from this service.

Runs on the private application network. The application routes themselves
are unauthenticated and rely on that isolation — a real private app would not
share the gateway's credential. The ``/_counters`` introspection routes do
require the credential, because they exist for tests and operators.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from apps.common import (
    MAX_BODY_BYTES,
    SERVICE_CREDENTIAL_HEADER,
    Settings,
    is_safe_id,
    iso,
    require_service_credential,
    utcnow,
)

logger = logging.getLogger("saseguard.mock_apps")


# --------------------------------------------------------------------------- #
# Fixed synthetic content
# --------------------------------------------------------------------------- #

APP_CONTENT: dict[str, dict[str, Any]] = {
    "payroll": {
        "app_id": "payroll",
        "title": "Payroll (synthetic)",
        "sensitivity": "restricted",
        "records": [
            {"employee": "E-1001", "department": "finance", "gross_monthly": "redacted-in-demo"},
            {"employee": "E-1002", "department": "engineering", "gross_monthly": "redacted-in-demo"},
        ],
        "note": "Synthetic finance application. No real payroll data exists in this lab.",
    },
    "engineering": {
        "app_id": "engineering",
        "title": "Engineering Services (synthetic)",
        "sensitivity": "internal",
        "records": [
            {"service": "build-runner", "owner": "platform", "status": "green"},
            {"service": "artifact-store", "owner": "platform", "status": "green"},
        ],
        "note": "Synthetic engineering application.",
    },
    "wiki": {
        "app_id": "wiki",
        "title": "Company Wiki (synthetic)",
        "sensitivity": "general",
        "records": [
            {"page": "onboarding", "updated": "2026-01-04"},
            {"page": "expense-policy", "updated": "2026-02-18"},
        ],
        "note": "Synthetic general-access application. Every role may read this.",
    },
}

WEB_CONTENT: dict[str, dict[str, Any]] = {
    "docs": {
        "destination": "docs",
        "title": "Internal Documentation Portal (local fixture)",
        "body": "Local fixture standing in for an allowed business category.",
    },
    "phishing-sim": {
        "destination": "phishing-sim",
        "title": "Phishing Simulation Fixture (local, inert)",
        "body": (
            "Local inert fixture. If you can read this, the gateway failed to block a "
            "phishing-category destination -- that is a bug, not a feature."
        ),
    },
    "gambling-sim": {
        "destination": "gambling-sim",
        "title": "Gambling Simulation Fixture (local, inert)",
        "body": (
            "Local inert fixture. If you can read this, the gateway failed to block a "
            "gambling-category destination."
        ),
    },
}


# --------------------------------------------------------------------------- #
# Counters
# --------------------------------------------------------------------------- #

class CallCounters:
    """Thread-safe tally of what actually reached this service."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    def bump(self, key: str) -> int:
        with self._lock:
            self._counts[key] = self._counts.get(key, 0) + 1
            return self._counts[key]

    def get(self, key: str) -> int:
        with self._lock:
            return self._counts.get(key, 0)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counts)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()


def create_app(
    *, counters: CallCounters | None = None, service_credential: str | None = None
) -> FastAPI:
    app = FastAPI(
        title="SASEGuard Synthetic Private Applications",
        version="1.0.0",
        description=(
            "Private synthetic applications, inert local web fixtures, and an amnesiac "
            "storage sink. Reachable only from the gateway on the private app network."
        ),
        docs_url=None,
        redoc_url=None,
    )
    app.state.counters = counters or CallCounters()
    app.state.service_credential = (
        service_credential
        if service_credential is not None
        else Settings.from_env().service_credential
    )

    async def require_credential(
        service_credential: str | None = Header(default=None, alias=SERVICE_CREDENTIAL_HEADER),
    ) -> None:
        expected = app.state.service_credential
        if not expected:
            raise HTTPException(status_code=503, detail="Service credential not configured.")
        if not require_service_credential(service_credential, expected):
            raise HTTPException(status_code=401, detail="Invalid service credential.")

    # -- ops --------------------------------------------------------------- #

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, Any]:
        return {"status": "ok", "service": "mock_apps"}

    @app.get("/_counters", tags=["ops"], dependencies=[Depends(require_credential)])
    async def read_counters() -> dict[str, Any]:
        """What reached this service. The evidence tests assert against."""
        return {"counters": app.state.counters.snapshot()}

    @app.post("/_counters/reset", tags=["ops"], dependencies=[Depends(require_credential)])
    async def reset_counters() -> dict[str, Any]:
        app.state.counters.reset()
        return {"reset": True}

    # -- synthetic applications -------------------------------------------- #

    @app.get("/apps/{app_id}", tags=["apps"])
    async def read_app(app_id: str) -> JSONResponse:
        """Return fixed content for one of three known application IDs."""
        if not is_safe_id(app_id) or app_id not in APP_CONTENT:
            # Counted separately so a test can distinguish "never arrived"
            # from "arrived and was rejected here".
            app.state.counters.bump("apps.unknown")
            raise HTTPException(status_code=404, detail="Unknown application.")

        count = app.state.counters.bump(f"apps.{app_id}")
        logger.info("private app served app_id=%s total=%d", app_id, count)
        payload = dict(APP_CONTENT[app_id])
        payload["served_at"] = iso(utcnow())
        payload["upstream_call_count"] = count
        return JSONResponse(payload)

    # -- inert web fixtures ------------------------------------------------- #

    @app.get("/web/{destination}", tags=["web"])
    async def read_web(destination: str) -> JSONResponse:
        """Serve a local fixture. Never performs an outbound request."""
        if not is_safe_id(destination) or destination not in WEB_CONTENT:
            app.state.counters.bump("web.unknown")
            raise HTTPException(status_code=404, detail="Unknown destination.")

        count = app.state.counters.bump(f"web.{destination}")
        payload = dict(WEB_CONTENT[destination])
        payload["served_at"] = iso(utcnow())
        payload["upstream_call_count"] = count
        return JSONResponse(payload)

    # -- amnesiac storage sink --------------------------------------------- #

    @app.post("/storage/upload", tags=["storage"])
    async def storage_upload(request: Request) -> JSONResponse:
        """Accept an upload without retaining or echoing any of it.

        The body is read (so the HTTP exchange completes) and then discarded.
        Only its length is noted, and only in the counter total. Nothing from
        the payload appears in the response, in a log line, or on disk.
        """
        raw = await request.body()
        if len(raw) > MAX_BODY_BYTES:
            raise HTTPException(status_code=413, detail="Body too large.")

        accepted = app.state.counters.bump("storage.accepted")
        logger.info("storage accepted upload #%d (%d bytes, content discarded)", accepted, len(raw))

        return JSONResponse(
            {
                "stored": False,
                "accepted_uploads": accepted,
                "note": (
                    "Synthetic receiver. Body content is discarded, never persisted "
                    "or echoed. This counter is how tests prove a DLP-blocked payload "
                    "never arrived."
                ),
                "received_at": iso(utcnow()),
            }
        )

    return app


app = create_app()
