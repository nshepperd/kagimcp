"""A minimal, single-user OAuth 2.1 authorization server for kagimcp.

This module makes the MCP server usable as a claude.ai "custom connector",
which only speaks OAuth. The moving parts, in the order a connection uses them:

 1. Discovery. Claude fetches /.well-known/oauth-protected-resource and
    /.well-known/oauth-authorization-server to learn where the authorize,
    token, and registration endpoints live. FastMCP generates these routes
    from the provider below — we never write them by hand.

 2. Dynamic Client Registration (RFC 7591). Claude POSTs to /register and
    receives a client_id. Our only job is `register_client`, where we PIN the
    allowed redirect URIs: registration is unauthenticated (anyone on the
    internet can mint a client_id), so the security boundary is that no
    registered client may ask for tokens to be delivered anywhere except
    Claude's own callback URL.

 3. Authorization. Claude opens a browser at /authorize. The SDK validates
    the request (client_id known, redirect_uri matches what was registered,
    PKCE challenge present) and then calls our `authorize()`, which parks the
    request as a "transaction" row and redirects the human to /consent.
    There the user proves who they are (login form -> signed session cookie)
    and clicks Allow, which mints a single-use authorization code and sends
    the browser back to Claude's redirect_uri with it.

 4. Token exchange. Claude's *backend* POSTs the code + PKCE verifier to
    /token. The SDK checks the verifier against the challenge from step 3
    (this is what makes a code stolen from the browser redirect useless) and
    calls our `exchange_authorization_code()`, which issues an opaque access
    token + refresh token.

 5. Requests. Every MCP call now carries `Authorization: Bearer <token>`.
    `load_access_token()` is the verifier. The token is an opaque random
    string mapped to state in SQLite — the Kagi API key itself never leaves
    this server; it is entered once on /settings and looked up per request.

Tokens, codes, clients and the API key live in one SQLite database. Opaque
random tokens in a table (rather than signed JWTs) are the right shape for a
single-user server: verification is a primary-key lookup, and revocation is
DELETE.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.auth import OAuthProvider
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

# Lifetimes. The access token is short-lived because it is the credential that
# travels on every request; Claude silently uses the refresh token to get a new
# one. The authorization code and the consent transaction only need to survive
# one browser round-trip.
ACCESS_TOKEN_TTL = 60 * 60  # 1 hour
REFRESH_TOKEN_TTL = 60 * 60 * 24 * 60  # 60 days
AUTH_CODE_TTL = 5 * 60
TXN_TTL = 10 * 60
SESSION_TTL = 60 * 60 * 24 * 7  # management-UI login, 7 days

SESSION_COOKIE = "kagimcp_session"

# Claude web's OAuth callback endpoints. Registration requests naming any
# other redirect URI are refused — see step 2 in the module docstring.
DEFAULT_ALLOWED_REDIRECTS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)

_PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, expected = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Credentials:
    """The one login that guards /consent and /settings."""

    username: str
    password_hash: str  # pbkdf2 string from hash_password()

    def check(self, username: str, password: str) -> bool:
        # compare_digest on the username too, so a wrong username costs the
        # same time as a wrong password.
        user_ok = hmac.compare_digest(username.encode(), self.username.encode())
        return verify_password(password, self.password_hash) and user_ok


class AuthStore:
    """SQLite persistence for clients, codes, tokens, and the Kagi API key.

    sqlite3 connections are not thread-safe by default and the HTTP server
    handles requests on a thread pool, hence the lock around every statement.
    """

    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS clients (
                    client_id TEXT PRIMARY KEY, data TEXT NOT NULL,
                    created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS txns (
                    id TEXT PRIMARY KEY, client_id TEXT NOT NULL,
                    params TEXT NOT NULL, expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS codes (
                    code TEXT PRIMARY KEY, client_id TEXT NOT NULL,
                    data TEXT NOT NULL, expires_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS tokens (
                    token TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK (kind IN ('access','refresh')),
                    client_id TEXT NOT NULL, scopes TEXT NOT NULL,
                    family TEXT NOT NULL, expires_at REAL NOT NULL,
                    created_at REAL NOT NULL);
                """
            )

    # -- config / key-value ------------------------------------------------

    def get_config(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM config WHERE key = ?", (key,)
            ).fetchone()
        return row[0] if row else None

    def set_config(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def session_secret(self) -> bytes:
        secret = self.get_config("session_secret")
        if secret is None:
            secret = secrets.token_hex(32)
            self.set_config("session_secret", secret)
        return bytes.fromhex(secret)

    def get_kagi_api_key(self) -> str | None:
        return self.get_config("kagi_api_key")

    def set_kagi_api_key(self, key: str) -> None:
        self.set_config("kagi_api_key", key)

    # -- OAuth clients (from Dynamic Client Registration) -------------------

    def save_client(self, info: OAuthClientInformationFull) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO clients (client_id, data, created_at) "
                "VALUES (?, ?, ?)",
                (info.client_id, info.model_dump_json(), time.time()),
            )

    def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM clients WHERE client_id = ?", (client_id,)
            ).fetchone()
        return OAuthClientInformationFull.model_validate_json(row[0]) if row else None

    # -- consent transactions (parked /authorize requests) ------------------

    def create_txn(self, client_id: str, params: AuthorizationParams) -> str:
        txn_id = secrets.token_urlsafe(32)
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO txns (id, client_id, params, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    txn_id,
                    client_id,
                    json.dumps(params.model_dump(mode="json")),
                    time.time() + TXN_TTL,
                ),
            )
        return txn_id

    def get_txn(self, txn_id: str) -> tuple[str, AuthorizationParams] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT client_id, params FROM txns WHERE id = ? AND expires_at > ?",
                (txn_id, time.time()),
            ).fetchone()
        if not row:
            return None
        return row[0], AuthorizationParams.model_validate(json.loads(row[1]))

    def delete_txn(self, txn_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM txns WHERE id = ?", (txn_id,))

    # -- authorization codes -------------------------------------------------

    def create_code(self, client_id: str, params: AuthorizationParams) -> str:
        # RFC 6749 §10.10 wants >=128 bits of entropy in a code; token_urlsafe(32)
        # is 256.
        code = secrets.token_urlsafe(32)
        data = {
            "scopes": params.scopes or [],
            "code_challenge": params.code_challenge,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "resource": params.resource,
        }
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO codes (code, client_id, data, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (code, client_id, json.dumps(data), time.time() + AUTH_CODE_TTL),
            )
        return code

    def get_code(self, code: str, client_id: str) -> AuthorizationCode | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT data, expires_at FROM codes "
                "WHERE code = ? AND client_id = ? AND expires_at > ?",
                (code, client_id, time.time()),
            ).fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        return AuthorizationCode(
            code=code, client_id=client_id, expires_at=row[1], **data
        )

    def consume_code(self, code: str) -> bool:
        """Delete the code; True if it existed. Codes are strictly single-use."""
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM codes WHERE code = ?", (code,))
        return cur.rowcount > 0

    # -- tokens ---------------------------------------------------------------

    def mint_tokens(self, client_id: str, scopes: list[str]) -> OAuthToken:
        """Create a fresh access+refresh pair.

        The two share a random `family` id so that revoking either one (or
        rotating the refresh token) kills both — a leaked-token cleanup knob
        the RFC recommends.
        """
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        family = secrets.token_urlsafe(16)
        now = time.time()
        with self._lock, self._conn:
            self._conn.executemany(
                "INSERT INTO tokens (token, kind, client_id, scopes, family, "
                "expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (access, "access", client_id, json.dumps(scopes), family,
                     now + ACCESS_TOKEN_TTL, now),
                    (refresh, "refresh", client_id, json.dumps(scopes), family,
                     now + REFRESH_TOKEN_TTL, now),
                ],
            )
            self._conn.execute("DELETE FROM tokens WHERE expires_at <= ?", (now,))
            self._conn.execute("DELETE FROM txns WHERE expires_at <= ?", (now,))
            self._conn.execute("DELETE FROM codes WHERE expires_at <= ?", (now,))
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(scopes) or None,
            refresh_token=refresh,
        )

    def get_token(
        self, token: str, kind: str
    ) -> tuple[str, list[str], float, str] | None:
        """Return (client_id, scopes, expires_at, family) for a live token."""
        with self._lock:
            row = self._conn.execute(
                "SELECT client_id, scopes, expires_at, family FROM tokens "
                "WHERE token = ? AND kind = ? AND expires_at > ?",
                (token, kind, time.time()),
            ).fetchone()
        if not row:
            return None
        return row[0], json.loads(row[1]), row[2], row[3]

    def revoke_family_of(self, token: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM tokens WHERE family IN "
                "(SELECT family FROM tokens WHERE token = ?)",
                (token,),
            )

    def count_active_grants(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(DISTINCT family) FROM tokens WHERE expires_at > ?",
                (time.time(),),
            ).fetchone()
        return row[0]

    def revoke_all_tokens(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM tokens")


class KagiOAuthProvider(OAuthProvider):
    """The authorization-server half: FastMCP provides the HTTP endpoints and
    protocol validation; these methods provide the decisions and the storage.
    """

    def __init__(self, *, base_url: str, store: AuthStore, allowed_redirects: list[str]):
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(enabled=True),
        )
        self.store = store
        self.allowed_redirects = allowed_redirects

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self.store.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # THE redirect-URI pin. Registration is open to the internet, so a
        # client is only as trustworthy as where it can receive codes: exact
        # string match against the allowlist, no wildcards, no prefixes.
        for uri in client_info.redirect_uris or []:
            if str(uri) not in self.allowed_redirects:
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=(
                        f"redirect_uri {uri} is not allowed on this server"
                    ),
                )
        if not client_info.redirect_uris:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="at least one redirect_uri is required",
            )
        self.store.save_client(client_info)

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        # The SDK has already validated client_id, redirect_uri (against the
        # registered ones) and the PKCE challenge. We cannot see cookies from
        # here, so we park the request and send the browser to /consent,
        # which can.
        txn_id = self.store.create_txn(client.client_id, params)
        return urljoin(str(self.base_url), f"/consent?txn={txn_id}")

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        return self.store.get_code(authorization_code, client.client_id)

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        # PKCE was already verified by the SDK's token handler. Consuming the
        # code here (single use) is what stops a replayed exchange.
        self.store.consume_code(authorization_code.code)
        return self.store.mint_tokens(client.client_id, authorization_code.scopes)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        row = self.store.get_token(refresh_token, "refresh")
        if row is None or row[0] != client.client_id:
            return None
        client_id, scopes, expires_at, _family = row
        return RefreshToken(
            token=refresh_token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(expires_at),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotation: the old pair dies with its family and a new pair is born.
        # A stolen refresh token therefore stops working the moment the
        # legitimate client refreshes.
        self.store.revoke_family_of(refresh_token.token)
        return self.store.mint_tokens(client.client_id, scopes or refresh_token.scopes)

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = self.store.get_token(token, "access")
        if row is None:
            return None
        client_id, scopes, expires_at, _family = row
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=int(expires_at),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        self.store.revoke_family_of(token.token)


# --------------------------------------------------------------------------
# The human-facing pages: login, consent, and the management UI.
# --------------------------------------------------------------------------


@dataclass
class _Runtime:
    store: AuthStore
    credentials: Credentials


_runtime: _Runtime | None = None


def _rt() -> _Runtime:
    if _runtime is None:
        raise RuntimeError("OAuth routes hit but setup_oauth() was never called")
    return _runtime


def _sign_session(secret: bytes, expires: int) -> str:
    sig = hmac.new(secret, f"kagimcp-session:{expires}".encode(), hashlib.sha256)
    return f"{expires}.{base64.urlsafe_b64encode(sig.digest()).decode().rstrip('=')}"


def _session_valid(request: Request) -> bool:
    cookie = request.cookies.get(SESSION_COOKIE, "")
    expires_str, _, _sig = cookie.partition(".")
    try:
        expires = int(expires_str)
    except ValueError:
        return False
    if expires < time.time():
        return False
    expected = _sign_session(_rt().store.session_secret(), expires)
    return hmac.compare_digest(cookie, expected)


def _set_session(response: Response) -> None:
    expires = int(time.time()) + SESSION_TTL
    response.set_cookie(
        SESSION_COOKIE,
        _sign_session(_rt().store.session_secret(), expires),
        max_age=SESSION_TTL,
        httponly=True,
        secure=True,
        # Lax still sends the cookie on top-level GET navigations (which is
        # how the /authorize redirect arrives at /consent) while withholding
        # it from cross-site POSTs, which is our CSRF protection.
        samesite="lax",
    )


def _page(title: str, body: str) -> HTMLResponse:
    # Auth pages must never render inside someone else's iframe (clickjacking:
    # an invisible frame over a decoy button could harvest an Allow click),
    # and must never come out of a shared cache.
    headers = {
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "frame-ancestors 'none'",
        "Cache-Control": "no-store",
    }
    return HTMLResponse(
        headers=headers,
        content=f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 26rem;
         margin: 4rem auto; padding: 0 1rem; }}
  h1 {{ font-size: 1.3rem; }}
  form {{ display: grid; gap: .7rem; }}
  input[type=text], input[type=password] {{
    font: inherit; padding: .45rem .6rem; border-radius: .4rem;
    border: 1px solid #8886; background: transparent; color: inherit; }}
  button {{ font: inherit; padding: .5rem .9rem; border-radius: .4rem;
           border: 1px solid #8886; cursor: pointer; }}
  button.primary {{ background: #4a7dff; border-color: #4a7dff; color: white; }}
  .error {{ color: #d33; }}
  .muted {{ opacity: .65; font-size: .9rem; }}
  .row {{ display: flex; gap: .6rem; }}
</style></head>
<body>{body}</body></html>"""
    )


def _login_page(next_url: str, error: str = "") -> HTMLResponse:
    err = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return _page(
        "kagimcp — sign in",
        f"""<h1>kagimcp</h1>
<p class="muted">sign in to continue ( ˘▽˘)っ</p>{err}
<form method="post" action="/login">
  <input type="hidden" name="next" value="{html.escape(next_url, quote=True)}">
  <input type="text" name="username" placeholder="username" autofocus
         autocomplete="username" required>
  <input type="password" name="password" placeholder="password"
         autocomplete="current-password" required>
  <button class="primary" type="submit">Sign in</button>
</form>""",
    )


def _safe_next(raw: str) -> str:
    # Only ever redirect within this site: an absolute URL here would make the
    # login form an open redirector, a favorite phishing primitive.
    if raw.startswith("/") and not raw.startswith("//"):
        return raw
    return "/settings"


async def _login(request: Request) -> Response:
    if request.method == "GET":
        next_url = _safe_next(request.query_params.get("next", "/settings"))
        return _login_page(next_url)
    form = await request.form()
    next_url = _safe_next(str(form.get("next", "/settings")))
    username = str(form.get("username", ""))
    password = str(form.get("password", ""))
    if not _rt().credentials.check(username, password):
        await asyncio.sleep(1.5)  # blunt brute-force throttle
        return _login_page(next_url, error="wrong username or password")
    response = RedirectResponse(next_url, status_code=303)
    _set_session(response)
    return response


async def _consent(request: Request) -> Response:
    rt = _rt()
    txn_id = (
        request.query_params.get("txn")
        if request.method == "GET"
        else str((await request.form()).get("txn", ""))
    )
    txn = rt.store.get_txn(txn_id or "")
    if txn is None:
        return _page(
            "kagimcp — expired",
            "<h1>Request expired</h1><p>Start the connection again from Claude.</p>",
        )
    client_id, params = txn

    if not _session_valid(request):
        return _login_page(f"/consent?txn={txn_id}")

    client = rt.store.get_client(client_id)
    client_name = (client and client.client_name) or client_id
    dest = urlsplit(str(params.redirect_uri)).netloc

    if request.method == "GET":
        return _page(
            "kagimcp — authorize",
            f"""<h1>Allow access?</h1>
<p><strong>{html.escape(client_name)}</strong> is asking to use your Kagi
search through this server.</p>
<p class="muted">Tokens will be delivered to <code>{html.escape(dest)}</code>.</p>
<form method="post" action="/consent" class="row">
  <input type="hidden" name="txn" value="{html.escape(txn_id, quote=True)}">
  <button class="primary" name="action" value="allow">Allow</button>
  <button name="action" value="deny">Deny</button>
</form>""",
        )

    form = await request.form()
    rt.store.delete_txn(txn_id)  # one decision per transaction
    if form.get("action") != "allow":
        return RedirectResponse(
            construct_redirect_uri(
                str(params.redirect_uri), error="access_denied", state=params.state
            ),
            status_code=302,
        )
    code = rt.store.create_code(client_id, params)
    return RedirectResponse(
        construct_redirect_uri(
            str(params.redirect_uri), code=code, state=params.state
        ),
        status_code=302,
    )


async def _settings(request: Request) -> Response:
    rt = _rt()
    if not _session_valid(request):
        return RedirectResponse("/login?next=/settings", status_code=303)

    saved = ""
    if request.method == "POST":
        form = await request.form()
        if form.get("action") == "revoke_all":
            rt.store.revoke_all_tokens()
            saved = "<p>All tokens revoked. Reconnect from Claude to continue.</p>"
        elif key := str(form.get("kagi_api_key", "")).strip():
            rt.store.set_kagi_api_key(key)
            saved = "<p>API key saved. ( ˘▽˘)っ♨</p>"

    key = rt.store.get_kagi_api_key()
    key_status = (
        f"a key ending in <code>…{html.escape(key[-4:])}</code> is configured"
        if key
        else '<strong class="error">no API key configured yet</strong>'
    )
    grants = rt.store.count_active_grants()
    return _page(
        "kagimcp — settings",
        f"""<h1>kagimcp settings</h1>{saved}
<p>Kagi API key: {key_status}.</p>
<form method="post" action="/settings">
  <input type="password" name="kagi_api_key"
         placeholder="paste a new Kagi API key" autocomplete="off">
  <button class="primary" type="submit">Save key</button>
</form>
<p class="muted">Active OAuth grants: {grants}</p>
<form method="post" action="/settings">
  <button name="action" value="revoke_all">Revoke all tokens</button>
</form>
<form method="post" action="/logout"><button>Log out</button></form>""",
    )


async def _logout(_request: Request) -> Response:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


async def _root(_request: Request) -> Response:
    return RedirectResponse("/settings", status_code=302)


def setup_oauth(
    mcp,
    *,
    base_url: str,
    db_path: str,
    credentials: Credentials,
    allowed_redirects: list[str] | None = None,
) -> AuthStore:
    """Install the OAuth provider and its pages on a FastMCP server.

    Returns the AuthStore so the tools can look up the stored Kagi API key.
    """
    global _runtime
    store = AuthStore(db_path)
    _runtime = _Runtime(store=store, credentials=credentials)
    mcp.auth = KagiOAuthProvider(
        base_url=base_url,
        store=store,
        allowed_redirects=list(allowed_redirects or DEFAULT_ALLOWED_REDIRECTS),
    )
    mcp.custom_route("/login", methods=["GET", "POST"])(_login)
    mcp.custom_route("/consent", methods=["GET", "POST"])(_consent)
    mcp.custom_route("/settings", methods=["GET", "POST"])(_settings)
    mcp.custom_route("/logout", methods=["POST"])(_logout)
    mcp.custom_route("/", methods=["GET"])(_root)
    return store
