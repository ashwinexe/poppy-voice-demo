#!/bin/sh
# Hosted start command. APP is "skyline" or "concierge"; the host terminates TLS.
case "$APP" in
  skyline) mod=skyline.app:app ;;
  concierge) mod=concierge.main:app ;;
  *) echo "set APP to skyline or concierge" >&2; exit 1 ;;
esac
exec uv run uvicorn "$mod" --host 0.0.0.0 --port "${PORT:-8000}" --proxy-headers --forwarded-allow-ips '*'
