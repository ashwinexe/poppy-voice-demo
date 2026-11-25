"""Skyline Air: a mock airline that speaks Personal Agent Protocol 1.0.

What it implements, and nothing more:
- Discovery: poppy.json, protected resource metadata, OAuth server metadata (spec 3)
- Session header verification with delegated keys (spec 5.2, 5.3)
- Device Sign-In with a consent page, refresh and revocation (spec 4.3 to 4.7)
- One OpenAPI API: flight search signed out, bookings signed in (spec 7)
- Operations v3 on booking changes (Operations extension)
- A tasks endpoint with one excluded task (spec 9)

Run with: uv run uvicorn skyline.app:app --port 8443 --ssl-keyfile ... --ssl-certfile ...
"""

from __future__ import annotations

import copy
import hashlib
import html
import json
import pathlib
import secrets
import time

import fastapi
from fastapi import Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from poppy.common import OPERATIONS_VERSION, SKYLINE_URL, host_of
from poppy.verify import PoppyError, SessionClaims, verify_client_assertion, verify_session_header

from . import data

ISSUER = SKYLINE_URL
DOMAIN = host_of(SKYLINE_URL)
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SCOPES = {
    "bookings:read": "See your trips and bookings. Needed to find a booking to change.",
    "bookings:write": "Change your bookings, which can charge the card on file. Needed for any change to a booking.",
}
SCOPE_HINTS = {
    "bookings:read": {"changes": "none", "personal_data": True},
    "bookings:write": {"changes": "irreversible", "personal_data": True},
}
ACCESS_TTL = 900
OPERATION_TTL = 600

app = fastapi.FastAPI(title="Skyline Air", docs_url=None, redoc_url=None, openapi_url=None)

# In-memory state. Restart the server to reset the demo.
device_grants: dict[str, dict] = {}  # device_code -> grant
user_codes: dict[str, str] = {}  # user_code -> device_code
consents: dict[str, dict] = {}  # consent id -> pending approval on the page
access_tokens: dict[str, dict] = {}
refresh_tokens: dict[str, dict] = {}
sessions: dict[tuple, dict] = {}  # (client_id, sid, user_id) -> session
operations: dict[str, dict] = {}  # operation_id -> operation record
activity: list[dict] = []  # what the company sees, for the /console page


def record(kind: str, **fields) -> None:
    activity.append({"t": time.strftime("%H:%M:%S"), "kind": kind, **fields})
    del activity[:-200]


@app.exception_handler(PoppyError)
async def poppy_error(_: Request, exc: PoppyError):
    record("error", error=exc.error, detail=exc.description)
    return JSONResponse(exc.body(), status_code=exc.status)


# ---------------------------------------------------------------------------
# Discovery (spec 3)
# ---------------------------------------------------------------------------
@app.get("/.well-known/poppy.json")
async def poppy_json():
    return {
        "protocol_version": "1.0",
        "organization": {"name": "Skyline Air", "domain": DOMAIN, "logo_uri": f"{SKYLINE_URL}/logo.svg"},
        "auth": {"scopes": SCOPES, "scope_hints": SCOPE_HINTS},
        "apis": [
            {
                "type": "openapi",
                "url": f"{SKYLINE_URL}/openapi.json",
                "description": "Search flights, see your bookings, and change a booking",
            }
        ],
        "tasks": {"endpoint": f"{SKYLINE_URL}/poppy/tasks"},
        "extensions": {"operations": [{"version": OPERATIONS_VERSION}]},
    }


@app.get("/.well-known/oauth-protected-resource")
async def protected_resource():
    return {
        "resource": f"https://{DOMAIN}",
        "authorization_servers": [ISSUER],
        "scopes_supported": list(SCOPES),
    }


@app.get("/.well-known/oauth-authorization-server")
async def as_metadata():
    return {
        "issuer": ISSUER,
        "token_endpoint": f"{ISSUER}/oauth/token",
        "revocation_endpoint": f"{ISSUER}/oauth/revoke",
        "device_authorization_endpoint": f"{ISSUER}/oauth/device_authorization",
        "grant_types_supported": ["refresh_token", DEVICE_GRANT],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "revocation_endpoint_auth_methods_supported": ["private_key_jwt"],
        "scopes_supported": list(SCOPES),
        "protected_resources": [f"https://{DOMAIN}"],
    }


@app.get("/openapi.json")
async def openapi_doc():
    # Scopes are described in poppy.json's auth.scopes (spec 4.7), since OpenAPI
    # has no flow type for Device Sign-In.
    return {
        "openapi": "3.1.0",
        "info": {"title": "Skyline Air API", "version": "1.0"},
        "servers": [{"url": f"{SKYLINE_URL}/api"}],
        "paths": {
            "/flights": {"get": {
                "operationId": "searchFlights",
                "summary": "Search flights. Works signed out.",
                "parameters": [
                    {"name": n, "in": "query", "required": n != "date", "schema": {"type": "string"}}
                    for n in ("origin", "destination", "date")
                ],
            }},
            "/bookings": {"get": {
                "operationId": "listBookings",
                "summary": "Your bookings. Needs bookings:read.",
            }},
            "/bookings/{booking_id}/change": {"post": {
                "operationId": "changeBooking",
                "summary": "Move a booking to another flight on the same route. Needs bookings:write "
                "and returns an operation for approval first.",
                "parameters": [{"name": "booking_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "requestBody": {"content": {"application/json": {"schema": {
                    "type": "object", "properties": {"new_flight": {"type": "string"}}, "required": ["new_flight"]}}}},
            }},
        },
    }


# ---------------------------------------------------------------------------
# Sessions (spec 5.3)
# ---------------------------------------------------------------------------
def _url(request: Request) -> str:
    # The public URL, not request.url: behind a hosting proxy the scheme and host differ.
    return f"{SKYLINE_URL}{request.url.path}"


def _bearer(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    return auth[7:] if auth.lower().startswith("bearer ") else None


async def session_for(request: Request, needs: str | None = None) -> tuple[SessionClaims, dict | None]:
    """Verify the Session header, then the token and the scope the route needs."""
    token = _bearer(request)
    claims = await verify_session_header(
        jwt=request.headers.get("poppy-session"),
        version=request.headers.get("poppy-version"),
        extensions_header=request.headers.get("poppy-extensions"),
        method=request.method,
        url=_url(request),
        audience=ISSUER,
        access_token=token,
    )
    grant = None
    if token:
        grant = access_tokens.get(token)
        if not grant or grant["exp"] < time.time() or grant["client_id"] != claims.client_id:
            raise Challenge("invalid_token", needs)
    key = (claims.client_id, claims.sid, claims.user_id)
    session = sessions.setdefault(key, {"started": time.time(), "account": None})
    if grant:
        session["account"] = grant["account"]
    record(
        "request",
        method=request.method,
        path=request.url.path,
        user_id=claims.user_id,
        sid=claims.sid[:8],
        account=grant["account"] if grant else None,
        scopes=grant["scopes"] if grant else [],
    )
    if needs:
        if not grant:
            raise Challenge(None, needs)
        if needs not in grant["scopes"]:
            raise Challenge("insufficient_scope", needs)
    return claims, grant


class Challenge(Exception):
    def __init__(self, error: str | None, scope: str | None):
        self.error, self.scope = error, scope


@app.exception_handler(Challenge)
async def challenge(_: Request, exc: Challenge):
    parts = []
    if exc.error:
        parts.append(f'error="{exc.error}"')
    if exc.scope:
        parts.append(f'scope="{exc.scope}"')
    status = 403 if exc.error == "insufficient_scope" else 401
    record("challenge", error=exc.error or "sign-in needed", scope=exc.scope)
    return JSONResponse(
        {"error": exc.error} if exc.error else {},
        status_code=status,
        headers={"WWW-Authenticate": "Bearer " + ", ".join(parts)},
    )


# ---------------------------------------------------------------------------
# API (spec 7)
# ---------------------------------------------------------------------------
@app.get("/api/flights")
async def search_flights(request: Request, origin: str, destination: str, date: str | None = None):
    await session_for(request)
    org, dst = data.match_airport(origin), data.match_airport(destination)
    if (origin and not org) or (destination and not dst):
        return {"flights": []}  # a place Skyline doesn't fly to
    results = [
        f for f in data.FLIGHTS.values()
        if (not org or f["origin"] == org) and (not dst or f["destination"] == dst)
        and (not date or f["date"] == date)
    ]
    return {"flights": results}


def _booking_view(b: dict) -> dict:
    return {**b, "flight_details": data.FLIGHTS[b["flight"]]}


@app.get("/api/bookings")
async def list_bookings(request: Request):
    _, grant = await session_for(request, needs="bookings:read")
    return {"bookings": [_booking_view(b) for b in data.BOOKINGS.values() if b["account"] == grant["account"]]}


def _terms(booking: dict, new_flight: str) -> tuple[dict, str]:
    old, new = data.FLIGHTS[booking["flight"]], data.FLIGHTS[new_flight]
    diff = max(0, int(float(new["fare"]["amount"])) - int(float(booking["fare_paid"]["amount"])))
    total = diff + data.CHANGE_FEE_EUR
    card = data.ACCOUNTS[booking["account"]]["card"]
    terms = {
        "booking_id": booking["booking_id"],
        "from_flight": old["flight"],
        "to_flight": new["flight"],
        "date": new["date"],
        "new_departure": new["departs"],
        "fare_difference": {"amount": f"{diff}.00", "currency": "EUR"},
        "change_fee": {"amount": f"{data.CHANGE_FEE_EUR}.00", "currency": "EUR"},
        "total": {"amount": f"{total}.00", "currency": "EUR"},
        "charged_to": card,
        "refundable": False,
    }
    day = data.FRIDAY.strftime("%A %-d %B")
    cost = (
        f"{diff} fare difference plus a {data.CHANGE_FEE_EUR} change fee"
        if diff
        else f"just the {data.CHANGE_FEE_EUR} change fee"
    )
    summary = (
        f"Move {booking['booking_id']} to {new['flight']} at {new['departs']} on {day}. "
        f"{total} euros, {cost}, on your {card}. Non-refundable."
    )
    return terms, summary


def _parse_approval(value: str | None) -> dict | None:
    """Poppy-Approval is an RFC 9651 Dictionary of Strings and one Integer."""
    if not value:
        return None
    out = {}
    for item in value.split(","):
        k, _, v = item.strip().partition("=")
        v = v.strip()
        out[k.strip()] = v[1:-1] if v.startswith('"') else int(v) if v.lstrip("-").isdigit() else v
    return out


def _operation_body(op: dict) -> dict:
    return {
        "error": "approval_required",
        "operation": {
            "operation_id": op["operation_id"],
            "revision": op["revision"],
            "summary": op["summary"],
            "terms": op["terms"],
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(op["expires_at"])),
        },
    }


def _same_flight(booking_id: str, flight: str) -> JSONResponse:
    return JSONResponse(
        {"error": "invalid_flight", "error_description": f"Booking {booking_id} is already on {flight}."},
        status_code=422,
    )


def _new_revision(op: dict, terms: dict, summary: str) -> None:
    digest = hashlib.sha256(json.dumps(terms, sort_keys=True).encode()).hexdigest()[:10]
    op.update(
        terms=terms,
        summary=summary,
        expires_at=time.time() + OPERATION_TTL,
        revision=f"{int(time.time())}-{digest}-{secrets.token_hex(3)}",
    )


@app.post("/api/bookings/{booking_id}/change")
async def change_booking(request: Request, booking_id: str):
    claims, grant = await session_for(request, needs="bookings:write")
    if claims.extensions.get("operations") != OPERATIONS_VERSION:
        raise PoppyError("extension_required", "booking changes need the operations extension", 403)
    body = await request.json()
    booking = data.BOOKINGS.get(booking_id)
    if not booking or booking["account"] != grant["account"]:
        return JSONResponse({"error": "not_found"}, status_code=404)
    new_flight = (body.get("new_flight") or "").upper()
    if new_flight not in data.FLIGHTS or data.FLIGHTS[new_flight]["destination"] != data.FLIGHTS[booking["flight"]]["destination"]:
        return JSONResponse({"error": "invalid_flight", "error_description": "Pick a flight on the same route."}, status_code=422)
    terms, summary = _terms(booking, new_flight)

    approval = _parse_approval(request.headers.get("poppy-approval"))
    op = operations.get(approval["operation_id"]) if approval else None
    # Check 1: only the same agent, User ID and account can approve it.
    if op and not (
        op["client_id"] == claims.client_id and op["user_id"] == claims.user_id and op["account"] == grant["account"]
    ):
        op, approval = None, None
    if op and approval:
        # Check 2: performed already? Same answer as the first time (Operations 7).
        if op.get("result"):
            record("operation", status="already performed", operation_id=op["operation_id"])
            return op["result"]
        # Check 3: the approved revision, unexpired, for exactly this request.
        if approval.get("revision") == op["revision"] and time.time() < op["expires_at"] and terms == op["terms"]:
            if new_flight == booking["flight"]:
                return JSONResponse({"error": "invalid_flight"}, status_code=422)
            booking["flight"] = new_flight
            booking["fare_paid"] = data.FLIGHTS[new_flight]["fare"]
            booking["seat"] = "21C"
            result = {"booking": _booking_view(booking), "charged": terms["total"], "charged_to": terms["charged_to"]}
            op["result"] = result
            record(
                "operation",
                status="performed",
                operation_id=op["operation_id"],
                approver=approval.get("approver"),
                input_type=approval.get("input_type"),
            )
            return result
        # Wrong or stale revision: new terms, never the revision it named.
        if new_flight == booking["flight"]:
            return _same_flight(booking_id, new_flight)
        _new_revision(op, terms, summary)
        record("operation", status="new revision", operation_id=op["operation_id"])
        return JSONResponse(_operation_body(op), status_code=403)

    # No approval: return the operation and perform nothing.
    if new_flight == booking["flight"]:
        return _same_flight(booking_id, new_flight)
    op = next(
        (o for o in operations.values()
         if o["booking_id"] == booking_id and not o.get("result") and o["account"] == grant["account"]
         and o["client_id"] == claims.client_id and o["user_id"] == claims.user_id),
        None,
    )
    if op is None:
        op = {
            "operation_id": "chg_" + secrets.token_urlsafe(6),
            "booking_id": booking_id,
            "client_id": claims.client_id,
            "user_id": claims.user_id,
            "account": grant["account"],
        }
        operations[op["operation_id"]] = op
        _new_revision(op, terms, summary)
    elif op["terms"] != terms or time.time() >= op["expires_at"]:
        _new_revision(op, terms, summary)
    record("operation", status="approval required", operation_id=op["operation_id"], total=terms["total"]["amount"])
    return JSONResponse(_operation_body(op), status_code=403)


@app.get("/poppy/tasks")
async def tasks(request: Request):
    await session_for(request)
    return {
        "excluded_tasks": [
            {
                "task": "Upgrade a seat with miles",
                "alternative": {
                    "instructions": "Miles upgrades are only available in the Skyline Air app, under Trips.",
                    "references": [{"type": "web", "url": f"{SKYLINE_URL}/trips"}],
                },
            },
            {"task": "Cancel a booking for a refund"},
        ]
    }


# ---------------------------------------------------------------------------
# OAuth: Device Sign-In (spec 4.3), refresh (4.4), revocation (4.6)
# ---------------------------------------------------------------------------
def _oauth_error(error: str, description: str = "", status: int = 400):
    body = {"error": error}
    if description:
        body["error_description"] = description
    return JSONResponse(body, status_code=status)


async def _client(form) -> str:
    if form.get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer":
        raise PoppyError("invalid_client", "private_key_jwt required", 401)
    info = await verify_client_assertion(form.get("client_assertion", ""), form.get("client_id", ""), ISSUER)
    return info.client_id


def _user_code() -> str:
    # Six digits, so a voice agent can read it out clearly. Short-lived and
    # single-use, with the consent page as the real gate.
    while True:
        code = f"{secrets.randbelow(1000):03d}-{secrets.randbelow(1000):03d}"
        if code not in user_codes:
            return code


@app.post("/oauth/device_authorization")
async def device_authorization(request: Request):
    form = await request.form()
    try:
        client_id = await _client(form)
    except PoppyError as e:
        return _oauth_error(e.error, e.description, 401)
    scopes = (form.get("scope") or "").split()
    if not scopes or any(s not in SCOPES for s in scopes):
        return _oauth_error("invalid_scope", f"known scopes: {' '.join(SCOPES)}")
    device_code = secrets.token_urlsafe(32)
    code = _user_code()
    device_grants[device_code] = {
        "client_id": client_id,
        "scopes": scopes,
        "user_code": code,
        "status": "pending",
        "expires": time.time() + 600,
        "account": None,
    }
    user_codes[code] = device_code
    record("sign-in started", client_id=client_id, scopes=scopes, user_code=code)
    return {
        "device_code": device_code,
        "user_code": code,
        "verification_uri": f"{ISSUER}/device",
        "verification_uri_complete": f"{ISSUER}/device?user_code={code}",
        "expires_in": 600,
        "interval": 3,
    }


def _issue(client_id: str, account: str, scopes: list[str], refresh: str | None = None) -> dict:
    access = "sat_" + secrets.token_urlsafe(24)
    access_tokens[access] = {"client_id": client_id, "account": account, "scopes": scopes, "exp": time.time() + ACCESS_TTL}
    body = {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TTL, "scope": " ".join(scopes)}
    if refresh is None:
        refresh = "srt_" + secrets.token_urlsafe(24)
        refresh_tokens[refresh] = {"client_id": client_id, "account": account, "scopes": scopes}
        body["refresh_token"] = refresh
    return body


@app.post("/oauth/token")
async def token(request: Request):
    form = await request.form()
    try:
        client_id = await _client(form)
    except PoppyError as e:
        return _oauth_error(e.error, e.description, 401)
    grant_type = form.get("grant_type")
    if grant_type == DEVICE_GRANT:
        grant = device_grants.get(form.get("device_code", ""))
        if not grant or grant["client_id"] != client_id:
            return _oauth_error("invalid_grant")
        if time.time() > grant["expires"]:
            return _oauth_error("expired_token")
        if grant["status"] == "pending":
            return _oauth_error("authorization_pending")
        if grant["status"] == "denied":
            return _oauth_error("access_denied")
        if grant["status"] == "used":
            return _oauth_error("invalid_grant")
        grant["status"] = "used"
        record("signed in", client_id=client_id, account=grant["account"], scopes=grant["granted"])
        return _issue(client_id, grant["account"], grant["granted"])
    if grant_type == "refresh_token":
        rt = refresh_tokens.get(form.get("refresh_token", ""))
        if not rt or rt["client_id"] != client_id:
            return _oauth_error("invalid_grant")
        scopes = (form.get("scope") or "").split() or rt["scopes"]
        if any(s not in rt["scopes"] for s in scopes):
            return _oauth_error("invalid_scope")
        return _issue(client_id, rt["account"], scopes, refresh=form["refresh_token"])
    return _oauth_error("unsupported_grant_type")


@app.post("/oauth/revoke")
async def revoke(request: Request):
    form = await request.form()
    try:
        client_id = await _client(form)
    except PoppyError as e:
        return _oauth_error(e.error, e.description, 401)
    rt = refresh_tokens.get(form.get("token", ""))
    if rt and rt["client_id"] == client_id:
        del refresh_tokens[form["token"]]
        for k, v in list(access_tokens.items()):
            if v["client_id"] == client_id and v["account"] == rt["account"]:
                del access_tokens[k]
        record("signed out", client_id=client_id, account=rt["account"])
    return JSONResponse({}, status_code=200)


# ---------------------------------------------------------------------------
# Skyline's own pages: device sign-in and consent (the agent never sees these)
# ---------------------------------------------------------------------------
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} · Skyline Air</title>
<style>
:root{{--ink:#0b1f3a;--sky:#2f80ed;--mist:#eef4fb;--line:#d5e1f0;--muted:#5b6b82}}
*{{box-sizing:border-box}}body{{margin:0;font:16px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif;color:var(--ink);background:linear-gradient(160deg,#dfeeff,#f7fbff 55%)}}
header{{display:flex;align-items:center;gap:10px;padding:20px 28px;font-weight:700;letter-spacing:.02em}}
header svg{{width:28px;height:28px}}main{{max-width:460px;margin:24px auto;padding:0 16px}}
.card{{background:#fff;border:1px solid var(--line);border-radius:16px;padding:28px;box-shadow:0 10px 30px rgba(11,31,58,.08)}}
h1{{font-size:22px;margin:0 0 6px}}p{{color:var(--muted);margin:0 0 16px}}label{{display:block;font-size:14px;font-weight:600;margin:14px 0 6px}}
input[type=text],input[type=email],input[type=password]{{width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:10px;font-size:16px}}
.code{{font-size:28px;letter-spacing:.12em;text-align:center;font-variant-numeric:tabular-nums}}
button{{margin-top:20px;width:100%;padding:13px;border:0;border-radius:10px;background:var(--sky);color:#fff;font-size:16px;font-weight:600;cursor:pointer}}
button.secondary{{background:#fff;color:var(--ink);border:1px solid var(--line);margin-top:10px}}
.agent{{display:flex;gap:12px;align-items:center;background:var(--mist);border-radius:12px;padding:12px 14px;margin:16px 0}}
.agent .mark{{flex:none;width:40px;height:40px;border-radius:10px;background:var(--ink);color:#fff;display:grid;place-items:center;font-weight:700}}
.scope{{border-top:1px solid var(--line);padding:12px 0}}.scope b{{display:block}}.scope span{{color:var(--muted);font-size:14px}}
.warn{{font-size:13px;color:#8a5a00;background:#fff6e0;border-radius:10px;padding:10px 12px;margin-top:16px}}
.hint{{font-size:13px;color:var(--muted);margin-top:10px}}.ok{{text-align:center}}.ok svg{{width:48px;height:48px;color:#1f9d55}}
</style></head><body><header>{logo} Skyline Air</header><main><div class="card">{body}</div></main></body></html>"""

LOGO = ('<svg viewBox="0 0 32 32" fill="none"><circle cx="16" cy="16" r="15" fill="#2f80ed"/>'
        '<path d="M7 18.5l18-7-5 11-3.5-3.5L13 22l.5-5L7 18.5z" fill="#fff"/></svg>')


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(PAGE.format(title=html.escape(title), logo=LOGO, body=body))


@app.get("/logo.svg")
async def logo():
    return fastapi.Response(LOGO, media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def home():
    return page("Home", "<h1>Skyline Air</h1><p>A made-up airline for a Personal Agent Protocol demo.</p>"
                "<p><a href='/console'>Company console</a> shows what Skyline sees from personal agents.</p>")


@app.get("/device", response_class=HTMLResponse)
async def device_page(user_code: str = ""):
    # Opening the link never approves anything by itself (spec 4.3).
    code = html.escape(user_code)
    return page("Connect an agent", f"""
<h1>Connect a personal agent</h1><p>Enter the code your agent read out to you.</p>
<form method="post" action="/device"><label for="c">Code</label>
<input class="code" id="c" name="user_code" type="text" value="{code}" autocomplete="off" required>
<button>Continue</button></form>""")


@app.post("/device", response_class=HTMLResponse)
async def device_code_entered(user_code: str = Form(...)):
    device_code = user_codes.get(user_code.strip())
    grant = device_grants.get(device_code or "")
    if not grant or grant["status"] != "pending" or time.time() > grant["expires"]:
        return page("Code not found", "<h1>That code didn't work</h1><p>It may have expired. Ask your agent for a new one.</p>"
                    "<a href='/device'><button class='secondary'>Try again</button></a>")
    return page("Sign in", f"""
<h1>Sign in to Skyline Air</h1><p>Your agent asked to connect to your account. Sign in here; the agent never sees your password.</p>
<form method="post" action="/device/login"><input type="hidden" name="user_code" value="{html.escape(user_code)}">
<label for="e">Email</label><input id="e" name="email" type="email" value="maya@example.com" required>
<label for="p">Password</label><input id="p" name="password" type="password" value="skyline-demo" required>
<button>Sign in</button><div class="hint">Demo account, filled in for you.</div></form>""")


@app.post("/device/login", response_class=HTMLResponse)
async def device_login(user_code: str = Form(...), email: str = Form(...), password: str = Form(...)):
    from poppy.verify import get_client

    device_code = user_codes.get(user_code)
    grant = device_grants.get(device_code or "")
    account = data.ACCOUNTS.get(email.lower())
    if not grant or grant["status"] != "pending":
        return page("Expired", "<h1>This sign-in has expired</h1><p>Ask your agent for a new code.</p>")
    if not account or not secrets.compare_digest(account["password"], password):
        return page("Sign in", "<h1>Wrong email or password</h1><a href='/device'><button class='secondary'>Back</button></a>")
    client = await get_client(grant["client_id"])
    consent_id = secrets.token_urlsafe(16)
    consents[consent_id] = {"device_code": device_code, "account": email.lower()}
    scopes = "".join(
        f"<div class='scope'><label style='margin:0;font-weight:400'><input type='checkbox' name='scope' value='{s}' checked> "
        f"<b style='display:inline'>{s}</b></label><span>{html.escape(SCOPES[s])}</span></div>"
        for s in grant["scopes"]
    )
    return page("Allow access", f"""
<h1>Allow access?</h1><p>Signed in as {html.escape(account['name'])}.</p>
<div class="agent"><span class="mark">{html.escape(client.client_name[:1].upper())}</span><div><b>{html.escape(client.client_name)}</b><br>
<span style="color:var(--muted);font-size:13px">{html.escape(host_of(client.client_id))}</span></div></div>
<form method="post" action="/device/consent"><input type="hidden" name="consent_id" value="{consent_id}">{scopes}
<div class="warn">Only allow this if you asked your own agent to sign in just now, with code {html.escape(user_code)}.</div>
<button name="decision" value="allow">Allow</button><button class="secondary" name="decision" value="deny">Don't allow</button></form>""")


@app.post("/device/consent", response_class=HTMLResponse)
async def device_consent(request: Request):
    form = await request.form()
    pending = consents.pop(form.get("consent_id", ""), None)
    grant = device_grants.get(pending["device_code"]) if pending else None
    if not grant or grant["status"] != "pending":
        return page("Expired", "<h1>This sign-in has expired</h1>")
    granted = [s for s in form.getlist("scope") if s in grant["scopes"]]
    if form.get("decision") != "allow" or not granted:
        grant["status"] = "denied"
        record("sign-in declined", user_code=grant["user_code"])
        return page("Not connected", "<h1>Not connected</h1><p>Your agent won't get access. You can close this tab.</p>")
    grant.update(status="approved", account=pending["account"], granted=granted)
    record("sign-in approved", account=pending["account"], scopes=granted)
    return page("Connected", """<div class="ok"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
<circle cx="12" cy="12" r="10"/><path d="M7 12.5l3 3 7-7"/></svg><h1>You're connected</h1>
<p>Go back to your agent. You can disconnect it any time in your Skyline account.</p></div>""")


@app.get("/trips", response_class=HTMLResponse)
async def trips():
    return page("Trips", "<h1>Trips</h1><p>Miles upgrades live in the Skyline Air app. (This is a demo page.)</p>")


# ---------------------------------------------------------------------------
# Company console: what Skyline sees
# ---------------------------------------------------------------------------
@app.get("/console/activity.json")
async def console_activity():
    return {"activity": activity[-80:], "bookings": copy.deepcopy(list(data.BOOKINGS.values()))}


@app.get("/console", response_class=HTMLResponse)
async def console():
    return HTMLResponse((pathlib.Path(__file__).parent / "console.html").read_text())
