"""Skyline Air's made-up schedule, account and booking."""

from __future__ import annotations

import datetime as dt
import re


def next_friday(today: dt.date | None = None) -> dt.date:
    today = today or dt.date.today()
    days = (4 - today.weekday()) % 7 or 7
    return today + dt.timedelta(days=days)


FRIDAY = next_friday()
CHANGE_FEE_EUR = 45

# (flight number, origin, destination, departs, arrives, fare in EUR)
_SCHEDULE = [
    ("SK418", "CDG", "LIS", "07:40", "09:05", 129),
    ("SK420", "CDG", "LIS", "12:15", "13:40", 164),
    ("SK422", "CDG", "LIS", "18:10", "19:35", 167),
    ("SK311", "LHR", "LIS", "09:30", "12:15", 142),
    ("SK315", "LHR", "LIS", "16:45", "19:30", 155),
    ("SK207", "CDG", "BCN", "08:20", "10:00", 98),
]

AIRPORTS = {
    "CDG": "Paris",
    "LHR": "London",
    "LIS": "Lisbon",
    "BCN": "Barcelona",
}

FLIGHTS = {
    num: {
        "flight": num,
        "origin": org,
        "origin_city": AIRPORTS[org],
        "destination": dst,
        "destination_city": AIRPORTS[dst],
        "date": FRIDAY.isoformat(),
        "departs": dep,
        "arrives": arr,
        "fare": {"amount": f"{fare}.00", "currency": "EUR"},
    }
    for num, org, dst, dep, arr, fare in _SCHEDULE
}

# One demo traveller. The password exists only on Skyline's own sign-in page;
# the voice agent never sees it.
ACCOUNTS = {
    "maya@example.com": {"name": "Maya Chen", "password": "skyline-demo", "card": "Visa ending 4242"},
}

BOOKINGS = {
    "BK7Q2M": {
        "booking_id": "BK7Q2M",
        "account": "maya@example.com",
        "passenger": "Maya Chen",
        "flight": "SK418",
        "seat": "14A",
        "fare_paid": {"amount": "129.00", "currency": "EUR"},
    }
}


def match_airport(text: str) -> str | None:
    """'Lisbon', 'LIS' or 'Lisbon, Portugal' -> 'LIS'."""
    words = set(re.findall(r"[a-z]+", (text or "").lower()))
    for code, city in AIRPORTS.items():
        if code.lower() in words or city.lower() in words:
            return code
    return None
