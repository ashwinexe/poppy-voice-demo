"""Wren, a voice concierge that works with Skyline Air over Personal Agent Protocol.

Gradium handles the voice (STT and TTS through gradbot). Everything Wren does at
the airline goes through `poppy.agent.PoppyClient`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import pathlib
import time

import fastapi
import gradbot

from poppy.agent import AgentIdentity, PoppyClient, challenge_scopes, user_approval
from poppy.common import SKYLINE_URL

logger = logging.getLogger(__name__)

_DIR = pathlib.Path(__file__).parent
PROMPT = (_DIR / "prompts" / "main.txt").read_text()
# Gradium catalog voices Wren can use. The first is the default.
VOICES = [
    {"id": "vjFyp2BcCyTlUmYb", "name": "Everly", "note": "US, warm"},
    {"id": "NbpkqMVS3CJeq2j8", "name": "Zoey", "note": "US, bright"},
    {"id": "Bla6SbVMczYnOhfK", "name": "Marlowe", "note": "US, calm"},
    {"id": "6MFfc37kq0sBjBjy", "name": "Sterling", "note": "US, low"},
    {"id": "4rdlkbxRv4m3UQTW", "name": "Tilly", "note": "UK"},
    {"id": "I7GYfpcKbafFrYUv", "name": "Declan", "note": "Irish"},
]
VOICE_IDS = {v["id"] for v in VOICES}
SIGN_IN_SCOPES = ["bookings:read", "bookings:write"]

IDENTITY = AgentIdentity()


@dataclasses.dataclass
class CallState:
    client: PoppyClient
    excluded: list[dict] = dataclasses.field(default_factory=list)
    sign_in: dict | None = None  # the device grant while it's pending
    sign_in_task: asyncio.Task | None = None
    sign_in_result: str | None = None
    pending: dict | None = None  # {"booking_id", "new_flight", "operation"}
    api_base: str = ""
    typed_at: float = 0.0  # when the user last typed instead of speaking
    voice_id: str = VOICES[0]["id"]


TYPED_WINDOW_S = 20.0


def answered_by(state: CallState) -> str:
    """'typed' if the user's last turn was typed, else 'voice'. Sent to Skyline as input_type."""
    return "typed" if time.monotonic() - state.typed_at < TYPED_WINDOW_S else "voice"


def spoken_code(user_code: str) -> str:
    """'482-917' -> '4, 8, 2... 9, 1, 7' so TTS reads digits, not a number."""
    left, _, right = user_code.partition("-")
    return ", ".join(left) + "... " + ", ".join(right)


# ---------------------------------------------------------------------------
# Session setup
# ---------------------------------------------------------------------------
async def start(state: CallState, websocket: fastapi.WebSocket) -> None:
    """Discover Skyline and load what it won't do through agents."""
    company = await state.client.discover(SKYLINE_URL)
    openapi = (await state.client.http.get(company.poppy["apis"][0]["url"])).json()
    state.api_base = openapi["servers"][0]["url"]
    tasks = await state.client.tasks()
    state.excluded = tasks.get("excluded_tasks", [])
    await websocket.send_json(
        {
            "type": "company",
            "name": company.name,
            "domain": company.poppy["organization"]["domain"],
            "issuer": company.identifier,
            "user_id": state.client.user_id,
            "sid": state.client.sid,
            "scopes": company.scopes,
            "operations": company.operations,
            "device_sign_in": state.client.offers_device_sign_in(),
            "excluded": state.excluded,
        }
    )


def prompt(state: CallState) -> str:
    excluded = "\n".join(
        f"- {t['task']}"
        + (f" (alternative: {t['alternative'].get('instructions', '')})" if t.get("alternative") else "")
        for t in state.excluded
    ) or "- none"
    return PROMPT.replace("{excluded}", excluded)


def make_config(state: CallState, *, speaks_first: bool) -> gradbot.SessionConfig:
    cfg = gradbot.config.from_env()
    lang = gradbot.LANGUAGES["en"]
    return gradbot.SessionConfig(
        voice_id=state.voice_id,
        instructions=prompt(state),
        language=lang,
        tools=TOOLS,
        **{"rewrite_rules": lang.rewrite_rules, "assistant_speaks_first": speaks_first}
        | cfg.session_kwargs
        | {"silence_timeout_s": 0.0},
    )


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def _tool(name: str, description: str, properties: dict, required: list[str]) -> gradbot.ToolDef:
    return gradbot.ToolDef(
        name,
        description,
        json.dumps({"type": "object", "properties": properties, "required": required}),
    )


TOOLS = [
    _tool(
        "search_flights",
        "Search Skyline Air flights. Call when the user asks what flights exist. Works without signing in.",
        {
            "origin": {"type": "string", "description": "City or airport code, e.g. Paris or CDG"},
            "destination": {"type": "string", "description": "City or airport code, e.g. Lisbon or LIS"},
        },
        ["origin", "destination"],
    ),
    _tool(
        "get_my_bookings",
        "Look up the user's Skyline bookings. Call first whenever the user mentions their trip, booking or "
        "flight, or wants to change it, and again after they say they finished signing in. If they need to "
        "sign in, the result has the code to read out; there is no other source for it.",
        {},
        [],
    ),
    _tool(
        "change_booking",
        "Ask Skyline to move a booking to another flight. Skyline answers with exact terms that the user "
        "must approve first. Nothing changes yet.",
        {
            "booking_id": {"type": "string", "description": "Booking reference, e.g. BK7Q2M"},
            "new_flight": {"type": "string", "description": "Flight number to move to, e.g. SK422"},
        },
        ["booking_id", "new_flight"],
    ),
    _tool(
        "answer_approval",
        "Record the user's answer to the change terms you read out. Call ONLY after you read the terms "
        "and the user answered in their own words. Never call it on your own judgment.",
        {
            "approved": {"type": "boolean", "description": "true only if the user clearly said yes"},
            "user_words": {"type": "string", "description": "What the user said, word for word"},
        },
        ["approved", "user_words"],
    ),
]


async def on_tool_call(
    state: CallState,
    handle: gradbot.ToolHandle,
    input_handle: gradbot.SessionInputHandle,
    websocket: fastapi.WebSocket,
) -> None:
    del input_handle
    name, args = handle.name, handle.args or {}
    logger.info("tool %s %s", name, args)
    client = state.client

    if name == "search_flights":
        resp = await client.call(
            "GET",
            f"{state.api_base}/flights?origin={args.get('origin', '')}&destination={args.get('destination', '')}",
            note="search, signed out",
            signed_in=False,
        )
        flights = resp.json().get("flights", [])
        await websocket.send_json({"type": "flights", "flights": flights})
        await handle.send_json(
            {
                "flights": [
                    {k: f[k] for k in ("flight", "origin_city", "destination_city", "date", "departs", "arrives")}
                    | {"fare_eur": f["fare"]["amount"]}
                    for f in flights
                ],
                "note": "Signed out: Skyline only knows a pseudonymous user ID.",
            }
        )
        return

    if name == "get_my_bookings":
        resp = await client.call("GET", f"{state.api_base}/bookings", note="my bookings")
        if resp.status_code in (401, 403):
            await handle.send_json(await _need_sign_in(state, websocket, challenge_scopes(resp)))
            return
        bookings = resp.json().get("bookings", [])
        await websocket.send_json({"type": "bookings", "bookings": bookings})
        await handle.send_json(
            {
                "bookings": [
                    {
                        "booking_id": b["booking_id"],
                        "flight": b["flight"],
                        "route": f"{b['flight_details']['origin_city']} to {b['flight_details']['destination_city']}",
                        "date": b["flight_details"]["date"],
                        "departs": b["flight_details"]["departs"],
                        "seat": b["seat"],
                    }
                    for b in bookings
                ]
            }
        )
        return

    if name == "change_booking":
        booking_id = str(args.get("booking_id", "")).upper().replace(" ", "")
        new_flight = str(args.get("new_flight", "")).upper().replace(" ", "")
        resp = await client.call(
            "POST",
            f"{state.api_base}/bookings/{booking_id}/change",
            note="request change",
            json_body={"new_flight": new_flight},
        )
        body = resp.json()
        if resp.status_code in (401,) or body.get("error") == "insufficient_scope":
            await handle.send_json(await _need_sign_in(state, websocket, challenge_scopes(resp)))
            return
        if body.get("error") == "approval_required":
            op = body["operation"]
            state.pending = {"booking_id": booking_id, "new_flight": new_flight, "operation": op}
            await websocket.send_json({"type": "approval", "status": "asking", "operation": op})
            await handle.send_json(
                {
                    "status": "needs_user_approval",
                    "summary": op["summary"],
                    "instruction": "Read the summary to the user, word for word. Then ask: do you approve? "
                    "Wait for their answer. Nothing has changed yet.",
                }
            )
            return
        await handle.send_json({"status": "error", "detail": body})
        return

    if name == "answer_approval":
        if not state.pending:
            await handle.send_error("There are no terms waiting for approval.")
            return
        op = state.pending["operation"]
        if not args.get("approved"):
            await websocket.send_json({"type": "approval", "status": "declined_by_user", "operation": op})
            state.pending = None
            await handle.send_json({"status": "not_changed", "note": "The user said no. Nothing was changed."})
            return
        approval = user_approval(op, answered_by(state))
        await websocket.send_json(
            {"type": "approval", "status": "sending", "operation": op, "approval": approval,
             "user_words": args.get("user_words", "")}
        )
        resp = await client.call(
            "POST",
            f"{state.api_base}/bookings/{state.pending['booking_id']}/change",
            note="approved by voice",
            json_body={"new_flight": state.pending["new_flight"]},
            approval=approval,
        )
        body = resp.json()
        if resp.status_code == 200:
            state.pending = None
            await websocket.send_json({"type": "approval", "status": "done", "operation": op, "result": body})
            await websocket.send_json({"type": "bookings", "bookings": [body["booking"]]})
            await handle.send_json(
                {"status": "changed", "booking": body["booking"]["booking_id"], "new_flight": body["booking"]["flight"],
                 "new_seat": body["booking"]["seat"], "charged_eur": body["charged"]["amount"]}
            )
        elif body.get("error") == "approval_required":
            # The terms moved: the user has to hear and approve the new ones.
            state.pending["operation"] = body["operation"]
            await websocket.send_json({"type": "approval", "status": "asking", "operation": body["operation"]})
            await handle.send_json(
                {"status": "terms_changed", "summary": body["operation"]["summary"],
                 "instruction": "The terms changed. Read the new summary and ask again."}
            )
        else:
            state.pending = None
            await websocket.send_json({"type": "approval", "status": "failed", "operation": op, "result": body})
            await handle.send_json({"status": "not_changed", "detail": body.get("reason") or body.get("error")})
        return

    await handle.send_error(f"Unknown tool: {name}")


async def _need_sign_in(state: CallState, websocket: fastapi.WebSocket, scopes: list[str]) -> dict:
    """Start Device Sign-In, or report on the one in progress."""
    client = state.client
    if state.sign_in_result == "approved" and client.tokens:
        return {"status": "error", "detail": "Signed in, but Skyline still refused. Try again."}
    if not client.offers_device_sign_in():
        return {"status": "cannot_sign_in", "note": "Skyline offers no sign-in this agent supports."}
    if state.sign_in and not state.sign_in_task.done():
        return {
            "status": "waiting_for_user_to_sign_in",
            "spoken_code": spoken_code(state.sign_in["user_code"]),
            "instruction": "Remind the user to approve on Skyline's page, then tell you when they're done.",
        }
    wanted = sorted(set(SIGN_IN_SCOPES) | set(scopes))
    grant = await client.start_device_sign_in(wanted)
    state.sign_in, state.sign_in_result = grant, None
    await websocket.send_json(
        {"type": "sign_in", "status": "waiting", "user_code": grant["user_code"],
         "link": grant["verification_uri_complete"], "company": client.company.name, "scopes": wanted}
    )

    async def wait() -> None:
        result = await client.poll_device_sign_in(grant, wanted)
        state.sign_in_result = result
        await websocket.send_json(
            {"type": "sign_in", "status": result, "scope": client.tokens.scope if client.tokens else ""}
        )

    state.sign_in_task = asyncio.create_task(wait())
    return {
        "status": "user_must_sign_in",
        "spoken_code": spoken_code(grant["user_code"]),
        "instruction": "Tell the user: you need their OK at Skyline. Ask them to open the Skyline link on their "
        "screen and enter the code, reading the spoken_code exactly. Say you never see their password. "
        "Then ask them to tell you when they're done.",
    }
