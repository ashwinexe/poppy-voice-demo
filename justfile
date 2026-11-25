# Poppy voice demo: Wren (Gradium voice agent) <-> Skyline Air (mock company)

set dotenv-load := true

export POPPY_ALLOW_LOOPBACK := "1"
certs := ".poppy/certs"
tls := "--host :: --ssl-keyfile " + certs + "/localhost-key.pem --ssl-certfile " + certs + "/localhost.pem"

default:
    @just --list

# Create the local CA and localhost certificate (once)
certs:
    uv run python scripts/certs.py

# Trust the local CA in your login keychain so browsers accept the pages (once, asks for your password)
trust: certs
    security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db {{certs}}/ca.pem

# Run the mock airline on https://skyline.localhost:8443
skyline: certs
    uv run uvicorn skyline.app:app --port 8443 {{tls}}

# Run the voice concierge on https://wren.localhost:8444
concierge: certs
    uv run uvicorn concierge.main:app --port 8444 {{tls}}

# Run both
demo: certs
    #!/usr/bin/env bash
    set -euo pipefail
    trap 'kill 0' EXIT
    uv run uvicorn skyline.app:app --port 8443 {{tls}} &
    uv run uvicorn concierge.main:app --port 8444 {{tls}} &
    sleep 2
    echo "Wren:    https://wren.localhost:8444"
    echo "Skyline: https://skyline.localhost:8443/console"
    wait

# Run the four demo beats over Poppy without voice (needs `just demo` running)
smoke:
    uv run python scripts/smoke.py
