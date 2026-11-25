"""Company-side checks: Personal Agent identity, client assertions, Session headers."""

from __future__ import annotations

import dataclasses
import time

from . import jose
from .common import check_url, http_client, same_domain

CLIENT_CACHE_S = 300
IAT_WINDOW_S = 60
MAX_DELEGATION_S = 24 * 3600


class PoppyError(Exception):
    """An error the Company returns as JSON (spec 5.3, 7)."""

    def __init__(self, error: str, description: str = "", status: int = 400):
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status

    def body(self) -> dict:
        out = {"error": self.error}
        if self.description:
            out["error_description"] = self.description
        return out


@dataclasses.dataclass
class ClientInfo:
    client_id: str
    client_name: str
    logo_uri: str | None
    jwks: dict
    fetched_at: float


_clients: dict[str, ClientInfo] = {}
_seen_jti: dict[str, float] = {}


async def get_client(client_id: str) -> ClientInfo:
    """Fetch and check a Personal Agent's client metadata document (spec 4.1)."""
    cached = _clients.get(client_id)
    if cached and time.time() - cached.fetched_at < CLIENT_CACHE_S:
        return cached
    check_url(client_id)
    async with http_client() as http:
        resp = await http.get(client_id)  # no redirects (CIMD 5)
        if resp.status_code != 200:
            raise PoppyError("invalid_client", f"client metadata returned {resp.status_code}")
        meta = resp.json()
        if meta.get("client_id") != client_id:
            raise PoppyError("invalid_client", "client_id doesn't match the metadata URL")
        jwks_uri = meta.get("jwks_uri", "")
        if not same_domain(jwks_uri, client_id):
            raise PoppyError("invalid_client", "jwks_uri must be on the client_id's domain")
        if meta.get("token_endpoint_auth_method") != "private_key_jwt":
            raise PoppyError("invalid_client", "token_endpoint_auth_method must be private_key_jwt")
        jwks = (await http.get(check_url(jwks_uri))).json()
    info = ClientInfo(
        client_id=client_id,
        client_name=meta.get("client_name") or client_id,
        logo_uri=meta.get("logo_uri"),
        jwks=jwks,
        fetched_at=time.time(),
    )
    _clients[client_id] = info
    return info


def _jwks_key(info: ClientInfo, kid: str | None):
    for jwk in info.jwks.get("keys", []):
        if jwk.get("kid") == kid:
            return jwk
    raise PoppyError("invalid_session", f"no key {kid!r} in the agent's jwks_uri")


def _fresh_jti(jti: str | None, ttl: float) -> None:
    now = time.time()
    for k, exp in list(_seen_jti.items()):
        if exp < now:
            del _seen_jti[k]
    if not jti or jti in _seen_jti:
        raise PoppyError("invalid_session", "missing or replayed jti")
    _seen_jti[jti] = now + ttl


async def verify_client_assertion(assertion: str, client_id: str, issuer: str) -> ClientInfo:
    """RFC 7523 client assertion addressed to our issuer (spec 4.1)."""
    try:
        header, claims = jose.unverified_parts(assertion)
        info = await get_client(client_id)
        key = _jwks_key(info, header.get("kid"))
        _, claims = jose.verify_jwk(assertion, key)
    except PoppyError as e:
        raise PoppyError("invalid_client", e.description, 401) from e
    except Exception as e:  # bad signature, bad JSON, unreachable client
        raise PoppyError("invalid_client", f"client assertion failed: {e}", 401) from e
    now = time.time()
    if claims.get("iss") != client_id or claims.get("sub") != client_id:
        raise PoppyError("invalid_client", "iss and sub must be the client_id", 401)
    if claims.get("aud") != issuer:
        raise PoppyError("invalid_client", "aud must be our issuer, as a single string", 401)
    if not (claims.get("exp", 0) > now and claims["exp"] - claims.get("iat", 0) <= 300):
        raise PoppyError("invalid_client", "assertion expired or lasts over 5 minutes", 401)
    try:
        _fresh_jti(claims.get("jti"), 600)
    except PoppyError as e:
        raise PoppyError("invalid_client", e.description, 401) from e
    return info


@dataclasses.dataclass
class SessionClaims:
    client_id: str
    sid: str
    user_id: str
    agent_id: str | None
    extensions: dict[str, str]


async def verify_session_header(
    *,
    jwt: str | None,
    version: str | None,
    extensions_header: str | None,
    method: str,
    url: str,
    audience: str,
    access_token: str | None,
) -> SessionClaims:
    """Spec 5.2 and 5.3: delegation first, then the Session JWT and its claims."""
    if not jwt:
        raise PoppyError("invalid_session", "missing Poppy-Session header")
    if not version or version.split(".")[0] != "1":
        raise PoppyError("version_unsupported", "send Poppy-Version: 1.0")
    try:
        header, unverified = jose.unverified_parts(jwt)
    except Exception as e:
        raise PoppyError("invalid_session", f"malformed Session JWT: {e}") from e
    if header.get("typ") != "poppy-session+jwt":
        raise PoppyError("invalid_session", "typ must be poppy-session+jwt")
    dlg = header.get("poppy_dlg")
    if not dlg:
        raise PoppyError("invalid_session", "Session JWT has no delegation")
    client_id = unverified.get("iss", "")
    try:
        info = await get_client(client_id)
    except PoppyError as e:
        raise PoppyError("invalid_session", e.description) from e

    # 1-2. The delegation, signed by a key in the agent's jwks_uri.
    try:
        dlg_header, _ = jose.unverified_parts(dlg)
        dlg_header, dlg_claims = jose.verify_jwk(dlg, _jwks_key(info, dlg_header.get("kid")))
    except PoppyError:
        raise
    except Exception as e:
        raise PoppyError("invalid_session", f"delegation signature: {e}") from e
    now = time.time()
    if dlg_header.get("typ") != "poppy-delegation+jwt":
        raise PoppyError("invalid_session", "delegation typ must be poppy-delegation+jwt")
    if dlg_claims.get("iss") != client_id:
        raise PoppyError("invalid_session", "delegation iss doesn't match the Session JWT")
    if not (now < dlg_claims.get("exp", 0) and dlg_claims["exp"] - dlg_claims.get("iat", 0) <= MAX_DELEGATION_S):
        raise PoppyError("invalid_session", "delegation expired or lasts over 24 hours")

    # 3. The Session JWT, signed by the delegated key.
    cnf = (dlg_claims.get("cnf") or {}).get("jwk") or {}
    try:
        _, claims = jose.verify(jwt, jose.jwk_to_public_key(cnf))
    except Exception as e:
        raise PoppyError("invalid_session", f"Session JWT signature: {e}") from e
    if header.get("kid") != jose.thumbprint(cnf):
        raise PoppyError("invalid_session", "kid isn't the delegated key's thumbprint")

    if claims.get("aud") != audience:
        raise PoppyError("invalid_session", f"aud must be {audience}")
    if claims.get("htm") != method or claims.get("htu") != url:
        raise PoppyError("invalid_session", f"htm/htu don't match {method} {url}")
    if abs(now - claims.get("iat", 0)) > IAT_WINDOW_S:
        raise PoppyError("invalid_session", "iat outside the acceptance window")
    for claim in ("sid", "sub", "jti"):
        if not claims.get(claim):
            raise PoppyError("invalid_session", f"missing {claim}")
    _fresh_jti(claims["jti"], 2 * IAT_WINDOW_S)
    if access_token:
        if claims.get("ath") != jose.sha256_b64u(access_token):
            raise PoppyError("invalid_session", "ath doesn't match the access token")
    elif "ath" in claims:
        raise PoppyError("invalid_session", "ath present without an access token")

    return SessionClaims(
        client_id=client_id,
        sid=claims["sid"],
        user_id=claims["sub"],
        agent_id=claims.get("agent_id"),
        extensions=parse_extensions(extensions_header),
    )


def parse_extensions(value: str | None) -> dict[str, str]:
    """Tiny parser for `"operations";v="3", "links";v="1"` (an RFC 9651 List)."""
    out: dict[str, str] = {}
    for item in (value or "").split(","):
        item = item.strip()
        if not item.startswith('"'):
            continue
        name, _, params = item[1:].partition('"')
        for p in params.split(";"):
            k, _, v = p.strip().partition("=")
            if k == "v":
                out[name] = v.strip('"')
    return out
