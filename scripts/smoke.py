"""Run the demo's Poppy flow end to end, without voice.

Needs `just demo` (or `just skyline` and `just concierge`) running. Plays the User's
part on Skyline's sign-in page over HTTP, which a real User does in a browser.
"""

import asyncio
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from poppy.agent import AgentIdentity, PoppyClient, challenge_scopes, user_approval  # noqa: E402
from poppy.common import SKYLINE_URL, http_client  # noqa: E402


def step(title: str) -> None:
    print(f"\n== {title}")


async def log(entry: dict) -> None:
    auth = " (signed in)" if entry["signed_in"] else ""
    print(f"   {entry['status']} {entry['method']} {entry['url']}{auth}  {entry['note']}")


async def approve_as_user(link: str) -> None:
    """What the User does on Skyline's page: enter code, sign in, allow."""
    code = link.split("user_code=")[1]
    async with http_client() as http:
        await http.post(f"{SKYLINE_URL}/device", data={"user_code": code})
        page = await http.post(
            f"{SKYLINE_URL}/device/login",
            data={"user_code": code, "email": "maya@example.com", "password": "skyline-demo"},
        )
        consent_id = re.search(r'name="consent_id" value="([^"]+)"', page.text).group(1)
        scopes = re.findall(r"name='scope' value='([^']+)'", page.text)
        done = await http.post(
            f"{SKYLINE_URL}/device/consent",
            data={"consent_id": consent_id, "decision": "allow", "scope": scopes},
        )
        assert "connected" in done.text, done.text


async def main() -> None:
    client = PoppyClient(AgentIdentity(), log)
    try:
        step("Discovery")
        company = await client.discover(SKYLINE_URL)
        print(f"   {company.name}, issuer {company.identifier}, user ID {client.user_id}, operations={company.operations}")
        api = (await client.http.get(company.poppy["apis"][0]["url"])).json()["servers"][0]["url"]
        excluded = (await client.tasks()).get("excluded_tasks", [])
        print(f"   excluded: {[t['task'] for t in excluded]}")

        step("Beat 1: anonymous flight search")
        resp = await client.call("GET", f"{api}/flights?origin=Paris&destination=Lisbon", signed_in=False)
        assert resp.status_code == 200, resp.text
        print(f"   {[f['flight'] for f in resp.json()['flights']]}")

        step("Beat 2: Device Sign-In")
        resp = await client.call("GET", f"{api}/bookings")
        assert resp.status_code == 401, resp.text
        scopes = challenge_scopes(resp)
        print(f"   challenge asks for {scopes}")
        grant = await client.start_device_sign_in(["bookings:read", "bookings:write"])
        print(f"   code {grant['user_code']} at {grant['verification_uri']}")
        poll = asyncio.create_task(client.poll_device_sign_in(grant, ["bookings:read", "bookings:write"]))
        await asyncio.sleep(1)
        await approve_as_user(grant["verification_uri_complete"])
        assert await poll == "approved"
        print(f"   signed in with {client.tokens.scope}")
        resp = await client.call("GET", f"{api}/bookings")
        assert resp.status_code == 200, resp.text
        booking = resp.json()["bookings"][0]
        print(f"   {booking['booking_id']} on {booking['flight']}")

        step("Beat 3: change with exact terms, approved by voice")
        url = f"{api}/bookings/{booking['booking_id']}/change"
        resp = await client.call("POST", url, json_body={"new_flight": "SK422"})
        assert resp.status_code == 403 and resp.json()["error"] == "approval_required", resp.text
        op = resp.json()["operation"]
        print(f"   terms: {op['summary']}")
        approval = user_approval(op)
        resp = await client.call("POST", url, json_body={"new_flight": "SK422"}, approval=approval)
        assert resp.status_code == 200, resp.text
        print(f"   changed: {resp.json()['booking']['flight']}, charged {resp.json()['charged']}")
        again = await client.call("POST", url, json_body={"new_flight": "SK422"}, approval=approval)
        assert again.json() == resp.json(), again.text
        print("   retry with the same approval returned the same result, performed once")

        resp = await client.call("POST", f"{api}/bookings/{booking['booking_id']}/change", json_body={"new_flight": "SK422"})
        assert resp.status_code == 422, resp.text
        print(f"   moving to the flight it's already on is refused: {resp.json()['error_description']}")

        step("Beat 4: excluded task")
        upgrade = next(t for t in excluded if "miles" in t["task"].lower())
        print(f"   '{upgrade['task']}' -> {upgrade['alternative']['instructions']}")

        step("Sign out")
        await client.sign_out()
        resp = await client.call("GET", f"{api}/bookings")
        assert resp.status_code == 401
        print("\nAll beats passed.")
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
