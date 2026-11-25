"""Wren: a Gradium voice concierge that speaks Personal Agent Protocol.

Run with `just concierge` (https://wren.localhost:8444).
"""

from __future__ import annotations

import os
import pathlib
import time

import fastapi
import gradbot
import httpx
import pydantic

from concierge import agent
from poppy.agent import PoppyClient

# TTS model for Wren and for typed messages. gradbot reads this env var for each TTS stream.
# Defaults to the Gradium TTS public beta (Nov 2026). Set it to "default" for the current model.
TTS_MODEL = os.environ.setdefault("GRADIUM_TTS_MODEL_NAME", "gradium-tts-beta-202611")

gradbot.init_logging()
app = fastapi.FastAPI(title="Wren · Poppy voice concierge")
STATIC = pathlib.Path(__file__).parent / "static"
CONFIG = gradbot.config.from_env()
CALLER_VOICE = "r2sIQdqqoqgRJuXw"  # Marcus: speaks what you type, so Wren hears it like any other turn


# The Personal Agent's identity (spec 4.1). Skyline fetches these to verify
# client assertions and the delegations behind every Session JWT.
@app.get("/agent.json")
async def client_metadata():
    return agent.IDENTITY.metadata()


@app.get("/jwks.json")
async def jwks():
    return agent.IDENTITY.jwks()


CALLS: dict[str, agent.CallState] = {}  # by Poppy session ID, so /api/say can find the call


@app.get("/api/wren-voices")
async def wren_voices():
    return agent.VOICES


class Say(pydantic.BaseModel):
    text: str = pydantic.Field(min_length=1, max_length=300)
    sid: str = ""


@app.post("/api/say")
async def say(body: Say):
    """Speak typed text with Gradium TTS. The page mixes it into the call audio.

    gradbot sessions only take audio, so a typed message becomes a spoken one.
    """
    if call := CALLS.get(body.sid):
        call.typed_at = time.monotonic()
    key = CONFIG.gradium.api_key
    async with httpx.AsyncClient(timeout=20) as http:
        r = await http.post(
            CONFIG.gradium.base_url.rstrip("/") + "/speech/tts",
            headers={"x-api-key": key.get_secret_value() if key else ""},
            json={"text": body.text, "voice_id": CALLER_VOICE, "output_format": "wav", "only_audio": True,
                  "model_name": TTS_MODEL},
        )
    if r.status_code != 200:
        raise fastapi.HTTPException(502, "text to speech failed")
    return fastapi.Response(r.content, media_type="audio/wav")


@app.websocket("/ws/chat")
async def websocket_chat(websocket: fastapi.WebSocket):
    async def log(entry: dict) -> None:
        try:
            await websocket.send_json({"type": "poppy_log", **entry})
        except Exception:
            pass

    state = agent.CallState(client=PoppyClient(agent.IDENTITY, log))
    CALLS[state.client.sid] = state

    def pick_voice(msg: dict) -> None:
        if msg.get("voice_id") in agent.VOICE_IDS:
            state.voice_id = msg["voice_id"]

    async def on_start(msg: dict) -> gradbot.SessionConfig:
        pick_voice(msg)
        await agent.start(state, websocket)
        # A call started by typing skips the greeting so the first message isn't cut off.
        return agent.make_config(state, speaks_first=msg.get("speaks_first", True))

    async def on_config(msg: dict) -> gradbot.SessionConfig:
        pick_voice(msg)  # switching voices mid-call
        return agent.make_config(state, speaks_first=False)

    try:
        await gradbot.websocket.handle_session(
            websocket,
            config=CONFIG,
            on_start=on_start,
            on_config=on_config,
            on_tool_call=lambda *a: agent.on_tool_call(state, *a),
        )
    finally:
        CALLS.pop(state.client.sid, None)
        if state.sign_in_task:
            state.sign_in_task.cancel()
        await state.client.close()


gradbot.routes.setup(app, config=CONFIG, static_dir=STATIC)
