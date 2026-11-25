# Poppy voice demo

Wren is a voice personal agent built on Gradium's [gradbot](https://github.com/gradium-ai/gradbot). It talks to Skyline Air, a made-up airline, over [Personal Agent Protocol](https://personalagentprotocol.org) 1.0 ("Poppy"). Both run on your machine.

What the demo shows:

<img width="1582" height="940" alt="Screenshot 2026-11-25 at 1 33 12 PM" src="https://github.com/user-attachments/assets/2164ab5a-7bdf-4660-8bbb-175cb13a6a79" />

1. **Anonymous search.** "Any flights from Paris to Lisbon on Friday?" Skyline only sees a pseudonymous user ID.
2. **Device Sign-In.** "Move my booking to the evening flight." Wren reads out a code, you approve on Skyline's own page, and Wren never sees your password.
3. **Exact terms, spoken yes.** Skyline returns an operation with the exact price. Wren reads it aloud and sends your approval only after you say yes (`input_type: voice`).
4. **Refusal.** "Upgrade me with miles." Skyline lists that as a task agents can't do, so Wren says no and points to the app.

## Run it

Needs `uv` and `just`. macOS, Chrome.

```bash
echo "GRADIUM_API_KEY=..." >> .env   # plus OPENAI_API_KEY=... (or LLM_API_KEY and LLM_BASE_URL)
just trust                          # once: trusts the local HTTPS certificate
just demo
```

Open https://wren.localhost:8444 and press the mic, or type. Typed messages are spoken by a second Gradium voice and mixed into the call, so Wren hears them like any other turn and still answers out loud; an approval you type goes to Skyline as `input_type: typed`. Pick Wren's voice at the top, even mid-call. Open https://skyline.localhost:8443/console beside it to see what the airline sees. Restart `just demo` to reset the booking.

`just smoke` runs all four steps over Poppy without voice, to check the protocol side.

## Layout

- `poppy/`: the protocol code. `agent.py` is the personal agent side (discovery, Session JWTs with delegated keys, Device Sign-In, approvals), `verify.py` is the company side, `jose.py` signs and verifies JWTs.
- `skyline/`: the mock airline (FastAPI), its sign-in pages and the console.
- `concierge/`: Wren (gradbot), its prompt and web UI.

Skyline passes the official [company kit](https://personalagentprotocol.org/kit/company) validator's foundation checks and the interface checks for what it offers. Sign-in and Operations were checked with `just smoke`, since the validator doesn't cover them yet.

## Shortcuts

This is a demo, not a reference implementation. Skyline keeps everything in memory, uses 6-digit sign-in codes so they're easy to say, offers only Device Sign-In, and has no MCP server, conversations or browser join. `POPPY_ALLOW_LOOPBACK=1` (set by the `just` recipes) lets both sides talk to loopback addresses, which Poppy otherwise forbids.

## License

MIT. See [LICENSE](LICENSE).
