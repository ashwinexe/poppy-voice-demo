"""Personal Agent side: identity, discovery, Sessions, Device Sign-In, approvals."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import time
import urllib.parse
from collections.abc import Awaitable, Callable

import httpx

from . import jose
from .common import (
    CONCIERGE_URL,
    OPERATIONS_VERSION,
    PROTOCOL_VERSION,
    STATE_DIR,
    check_url,
    host_of,
    http_client,
)

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

LogFn = Callable[[dict], Awaitable[None]]


async def _no_log(_: dict) -> None:
    pass


class AgentIdentity:
    """The Personal Agent's client metadata document and root key (spec 4.1)."""

    def __init__(self, base_url: str = CONCIERGE_URL):
        self.base_url = base_url
        self.client_id = f"{base_url}/agent.json"
        self.jwks_uri = f"{base_url}/jwks.json"
        self._key = jose.load_or_create_pem(STATE_DIR / "agent-key.pem")
        self._pub = jose.public_jwk(self._key)
        self.kid = jose.thumbprint(self._pub)

    def metadata(self) -> dict:
        return {
            "client_id": self.client_id,
            "client_name": "Wren, a Gradium voice concierge",
            "logo_uri": f"{self.base_url}/static/logo.svg",
            "jwks_uri": self.jwks_uri,
            "redirect_uris": [f"{self.base_url}/oauth/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
        }

    def jwks(self) -> dict:
        return {"keys": [{**self._pub, "kid": self.kid, "alg": "ES256", "use": "sig"}]}

    def client_assertion(self, issuer: str) -> str:
        now = int(time.time())
        return jose.sign(
            {"typ": "JWT", "kid": self.kid},
            {
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": issuer,
                "iat": now,
                "exp": now + 120,
                "jti": jose.random_id(),
            },
            self._key,
        )

    def delegate(self, public_jwk: dict, lifetime_s: int = 3600) -> tuple[str, int]:
        """Sign a delegation for a delegated key (spec 5.2). Names no User or Company."""
        now = int(time.time())
        exp = now + lifetime_s
        token = jose.sign(
            {"typ": "poppy-delegation+jwt", "kid": self.kid},
            {
                "iss": self.client_id,
                "cnf": {"jwk": public_jwk},
                "iat": now,
                "exp": exp,
                "jti": jose.random_id(),
            },
            self._key,
        )
        return token, exp


def _user_ids() -> dict:
    path = STATE_DIR / "user-ids.json"
    return json.loads(path.read_text()) if path.exists() else {}


def user_id_for(company_identifier: str) -> str:
    """A stable, opaque, per-Company User ID (spec 5.1). Random, never derived from PII."""
    ids = _user_ids()
    if company_identifier not in ids:
        ids[company_identifier] = "usr_" + jose.random_id(9)
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        (STATE_DIR / "user-ids.json").write_text(json.dumps(ids, indent=2))
    return ids[company_identifier]


@dataclasses.dataclass
class Company:
    domain_url: str
    name: str
    identifier: str  # issuer, or https://{domain} without one
    poppy: dict
    as_meta: dict | None
    operations: bool

    @property
    def scopes(self) -> dict:
        return (self.poppy.get("auth") or {}).get("scopes", {})


@dataclasses.dataclass
class Tokens:
    access_token: str
    refresh_token: str
    scope: str
    expires_at: float


class DiscoveryError(Exception):
    pass


class PoppyClient:
    """One User, one Company, one Session."""

    def __init__(self, identity: AgentIdentity, log: LogFn = _no_log):
        self.identity = identity
        self.log = log
        self.company: Company | None = None
        self.user_id: str | None = None
        self.sid = jose.random_id()
        self.tokens: Tokens | None = None
        self._dkey = None
        self._dlg: tuple[str, int] | None = None
        self.http = http_client()

    async def close(self) -> None:
        await self.http.aclose()

    # -- logging ---------------------------------------------------------------
    async def _send(self, method: str, url: str, note: str = "", **kw) -> httpx.Response:
        resp = await self.http.request(method, url, **kw)
        await self.log(
            {
                "method": method,
                "url": url,
                "status": resp.status_code,
                "note": note,
                "signed_in": "Authorization" in (kw.get("headers") or {}),
            }
        )
        return resp

    # -- discovery (spec 3) ---------------------------------------------------
    async def discover(self, domain_url: str) -> Company:
        base = check_url(domain_url.rstrip("/"))
        resp = await self._send("GET", f"{base}/.well-known/poppy.json", "discovery")
        if resp.status_code != 200:
            raise DiscoveryError(f"no poppy.json at {base} ({resp.status_code})")
        doc = resp.json()
        if str(doc.get("protocol_version", "")).split(".")[0] != PROTOCOL_VERSION.split(".")[0]:
            raise DiscoveryError(f"incompatible protocol_version {doc.get('protocol_version')}")
        org = doc.get("organization") or {}
        if (org.get("domain") or "").lower() != host_of(base):
            raise DiscoveryError("organization.domain isn't the host that served poppy.json")

        resource = f"https://{host_of(base)}"
        as_meta = None
        identifier = resource
        prm = await self._send("GET", f"{base}/.well-known/oauth-protected-resource", "find issuer")
        servers = prm.json().get("authorization_servers") if prm.status_code == 200 else None
        if prm.status_code == 200 and prm.json().get("resource") != resource:
            raise DiscoveryError("protected resource metadata names another resource")
        if servers:
            issuer = (doc.get("auth") or {}).get("issuer") or servers[0]
            if issuer not in servers:
                raise DiscoveryError("auth.issuer isn't in authorization_servers")
            meta = await self._send(
                "GET", f"{check_url(issuer)}/.well-known/oauth-authorization-server", "issuer metadata"
            )
            as_meta = meta.json()
            if as_meta.get("issuer") != issuer:
                raise DiscoveryError("issuer metadata doesn't match the issuer")
            if resource not in [r.lower() for r in as_meta.get("protected_resources", [])]:
                raise DiscoveryError("issuer doesn't list this domain in protected_resources")
            identifier = issuer
        elif prm.status_code not in (200, 404):
            raise DiscoveryError(f"protected resource metadata returned {prm.status_code}")

        ops = any(
            e.get("version") == OPERATIONS_VERSION
            for e in (doc.get("extensions") or {}).get("operations", [])
        )
        self.company = Company(base, org.get("name", base), identifier, doc, as_meta, ops)
        self.user_id = user_id_for(identifier)
        return self.company

    # -- Session header (spec 5.2) --------------------------------------------
    def _session_jwt(self, method: str, url: str, access_token: str | None) -> str:
        now = int(time.time())
        if self._dlg is None or self._dlg[1] - now < 120:
            # A fresh delegated key, used for this one User ID only.
            self._dkey = jose.generate_key()
            self._dlg = self.identity.delegate(jose.public_jwk(self._dkey))
        pub = jose.public_jwk(self._dkey)
        claims = {
            "iss": self.identity.client_id,
            "aud": self.company.identifier,
            "sid": self.sid,
            "sub": self.user_id,
            "htm": method,
            "htu": url.split("?")[0].split("#")[0],
            "iat": now,
            "jti": jose.random_id(),
        }
        if access_token:
            claims["ath"] = jose.sha256_b64u(access_token)
        return jose.sign(
            {"typ": "poppy-session+jwt", "kid": jose.thumbprint(pub), "poppy_dlg": self._dlg[0]},
            claims,
            self._dkey,
        )

    async def call(
        self,
        method: str,
        url: str,
        *,
        note: str = "",
        json_body: dict | None = None,
        signed_in: bool = True,
        approval: dict | None = None,
    ) -> httpx.Response:
        """A request to a Company endpoint, with the Session header and, if we have one, a token."""
        check_url(url)
        token = None
        if signed_in and self.tokens:
            if self.tokens.expires_at - time.time() < 30:
                await self.refresh()
            token = self.tokens.access_token if self.tokens else None
        headers = {
            "Poppy-Session": self._session_jwt(method, url, token),
            "Poppy-Version": PROTOCOL_VERSION,
        }
        if self.company.operations:
            headers["Poppy-Extensions"] = f'"operations";v="{OPERATIONS_VERSION}"'
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if approval:
            headers["Poppy-Approval"] = ", ".join(
                f"{k}={v}" if isinstance(v, int) else f'{k}="{v}"' for k, v in approval.items()
            )
        return await self._send(method, url, note, headers=headers, json=json_body)

    async def tasks(self) -> dict:
        endpoint = (self.company.poppy.get("tasks") or {}).get("endpoint")
        if not endpoint:
            return {}
        resp = await self.call("GET", endpoint, note="excluded tasks", signed_in=False)
        return resp.json() if resp.status_code == 200 else {}

    # -- Device Sign-In (spec 4.3) --------------------------------------------
    def _client_auth(self) -> dict:
        return {
            "client_id": self.identity.client_id,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": self.identity.client_assertion(self.company.as_meta["issuer"]),
        }

    def offers_device_sign_in(self) -> bool:
        meta = self.company.as_meta or {}
        auth = self.company.poppy.get("auth") or {}
        return (
            not auth.get("disabled")
            and DEVICE_GRANT in meta.get("grant_types_supported", [])
            and "device_authorization_endpoint" in meta
        )

    async def start_device_sign_in(self, scopes: list[str]) -> dict:
        meta = self.company.as_meta
        resp = await self._send(
            "POST",
            check_url(meta["device_authorization_endpoint"]),
            "device sign-in",
            data={**self._client_auth(), "scope": " ".join(scopes)},
        )
        resp.raise_for_status()
        grant = resp.json()
        # The link must be on the Company's issuer or domain (spec 4.3), so a
        # Company can't pass off another Company's sign-in page as its own.
        link = grant.get("verification_uri_complete") or grant["verification_uri"]
        link_host = host_of(link)
        allowed = {host_of(meta["issuer"]), host_of(self.company.domain_url)}
        if not any(link_host == h or link_host.endswith("." + h) for h in allowed):
            raise DiscoveryError(f"sign-in link {link} isn't on the Company's domain")
        return grant

    async def poll_device_sign_in(self, grant: dict, requested: list[str]) -> str:
        """Poll until the User approves or declines. Returns 'approved', 'declined' or 'expired'."""
        interval = grant.get("interval", 5)
        deadline = time.time() + grant.get("expires_in", 600)
        while time.time() < deadline:
            await asyncio.sleep(interval)
            resp = await self._send(
                "POST",
                self.company.as_meta["token_endpoint"],
                "poll for tokens",
                data={**self._client_auth(), "grant_type": DEVICE_GRANT, "device_code": grant["device_code"]},
            )
            body = resp.json()
            if resp.status_code == 200:
                self._store_tokens(body, requested)
                return "approved"
            err = body.get("error")
            if err == "slow_down":
                interval += 5
            elif err != "authorization_pending":
                return "declined" if err == "access_denied" else "expired"
        return "expired"

    def _store_tokens(self, body: dict, requested: list[str]) -> None:
        old_refresh = self.tokens.refresh_token if self.tokens else None
        self.tokens = Tokens(
            access_token=body["access_token"],
            refresh_token=body.get("refresh_token") or old_refresh,
            scope=body.get("scope") or " ".join(requested),
            expires_at=time.time() + body.get("expires_in", 3600),
        )

    async def refresh(self) -> None:
        resp = await self._send(
            "POST",
            self.company.as_meta["token_endpoint"],
            "refresh",
            data={**self._client_auth(), "grant_type": "refresh_token", "refresh_token": self.tokens.refresh_token},
        )
        if resp.status_code == 200:
            self._store_tokens(resp.json(), self.tokens.scope.split())
        else:
            self.tokens = None  # continue signed out (spec 5.5)

    async def sign_out(self) -> None:
        if not self.tokens:
            return
        await self._send(
            "POST",
            self.company.as_meta["revocation_endpoint"],
            "sign out",
            data={**self._client_auth(), "token": self.tokens.refresh_token, "token_type_hint": "refresh_token"},
        )
        self.tokens = None


def user_approval(operation: dict, input_type: str = "voice") -> dict:
    """A user approval of one revision (Operations 6). input_type says how they answered."""
    return {
        "operation_id": operation["operation_id"],
        "revision": operation["revision"],
        "approver": "user",
        "approved_at": int(time.time()),
        "input_type": input_type,
        "reference": "apr_" + jose.random_id(9),
    }


def challenge_scopes(resp: httpx.Response) -> list[str]:
    """Scopes named in a WWW-Authenticate challenge (spec 7)."""
    header = resp.headers.get("www-authenticate", "")
    for part in header.split(","):
        k, _, v = part.strip().partition("=")
        if k.endswith("scope"):
            return urllib.parse.unquote(v.strip('"')).split()
    return []
