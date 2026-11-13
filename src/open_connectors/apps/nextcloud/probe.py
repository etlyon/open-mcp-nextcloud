"""Nextcloud: is this address a usable Nextcloud (step B), and who granted this app password (step C)?

Step B never needs a password: ``GET /status.php`` must answer JSON with
``installed`` true, ``maintenance`` and ``needsDbUpgrade`` false and a major
version of at least :data:`MIN_MAJOR`. Version 1 supports Nextcloud installed
at the root of its host only: any page path a person pastes is dropped.

Step C is Nextcloud's own Login Flow v2. The connector starts it, shows the
person the approval page, and polls until the person grants access. From
Nextcloud's answers it keeps only two tokens, each checked against a strict
pattern, and rebuilds every address from the checked server: a host or a
``server`` field in an answer is never followed. The poll token is a secret
(whoever holds it receives the app password); the caller keeps it encrypted.

The fallback is a pasted user name and app password. Either way the
credential is checked by asking Nextcloud who it belongs to
(``GET /ocs/v1.php/cloud/user``), and deleted in Nextcloud on disconnect
(``DELETE /ocs/v2.php/core/apppassword`` as itself).

Every request goes through the guarded road in :mod:`open_connectors.net`.
Nothing here logs, and no error carries a token, a user name or a password.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from open_connectors import net

MIN_MAJOR = 28
USER_AGENT = "Assistant connector"          # Nextcloud names the app password after it
OCS_HEADERS = {"OCS-APIRequest": "true", "Accept": "application/json"}
STATUS_PATH = "/status.php"
LOGIN_START_PATH = "/index.php/login/v2"
LOGIN_POLL_PATH = "/index.php/login/v2/poll"
LOGIN_FLOW_PATH = "/index.php/login/v2/flow/"
OCS_USER_PATH = "/ocs/v1.php/cloud/user?format=json"
OCS_APP_PASSWORD_PATH = "/ocs/v2.php/core/apppassword?format=json"
LOGIN_FLOW_SECONDS = 20 * 60                # Nextcloud forgets an unfinished login flow after 20 minutes

# v1 uses Nextcloud at the host root: path, query and fragment of a pasted page address (e.g. the
# Files page, /apps/files/files?dir=/) are dropped, only the host is kept.
ROOT_ONLY = True

_TOKEN = re.compile(r"[A-Za-z0-9]{32,256}")
_LOGIN_PATH = re.compile(r"(?:/index\.php)?/login/v2/flow/([A-Za-z0-9]{32,256})")
_POLL_PATHS = ("/index.php/login/v2/poll", "/login/v2/poll")   # with or without pretty URLs


class NextcloudCheckError(Exception):
    """A plain, person-facing refusal. ``code`` selects the words; ``detail`` fills them."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class NextcloudServer:
    origin: net.Origin
    version: str              # e.g. "30.0.2"
    online_hint: bool = False

    @property
    def url(self) -> str:
        return self.origin.url


@dataclass(frozen=True)
class LoginStart:
    """One started Login Flow v2: the token for the approval page and the (secret) poll token."""

    flow_token: str
    poll_token: str


@dataclass(frozen=True)
class NextcloudIdentity:
    user_id: str               # the Nextcloud user the credential acts as (WebDAV files root)
    login_name: str            # what HTTP Basic sends; may differ from user_id
    name: str
    email: str


def root_origin(raw: str) -> net.Origin:
    """The checked origin of a typed address, always at the host root (v1): a pasted page address keeps its host."""
    return net.normalize_address(raw, root_only=ROOT_ONLY)


def login_url(server_url: str, flow_token: str) -> str:
    """The approval page, rebuilt from the checked server and the checked token only."""
    if not _TOKEN.fullmatch(flow_token or ""):
        raise NextcloudCheckError("login_failed")
    return root_origin(server_url).join(LOGIN_FLOW_PATH + flow_token)


def _json_or_none(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _client(*, denied_hosts: frozenset[str], transport: httpx.AsyncBaseTransport | None,
            timeout: float = net.DEFAULT_TIMEOUT, headers: dict[str, str] | None = None) -> httpx.AsyncClient:
    return net.client_for(timeout=timeout, denied_hosts=denied_hosts, transport=transport,
                          headers={"User-Agent": USER_AGENT, **(headers or {})})


async def _send(client: httpx.AsyncClient, method: str, url: str, *, max_bytes: int = net.PROBE_MAX_BYTES,
                **kwargs: Any) -> tuple[int, bytes]:
    try:
        async with client.stream(method, url, **kwargs) as response:
            body = await net.read_capped(response, max_bytes)
            return response.status_code, body
    except httpx.TimeoutException:
        raise NextcloudCheckError("timeout") from None
    except httpx.TransportError:
        raise NextcloudCheckError("unreachable") from None


def _major(version: object) -> int | None:
    if not isinstance(version, str):
        return None
    head = version.strip().split(".", 1)[0]
    return int(head) if head.isdigit() else None


async def check_address(raw: str, *, transport: httpx.AsyncBaseTransport | None = None,
                        denied_hosts: frozenset[str] = frozenset()) -> NextcloudServer:
    """Step B for Nextcloud. Raises :class:`net.AddressError` or :class:`NextcloudCheckError`."""
    origin = root_origin(raw)
    async with _client(denied_hosts=denied_hosts, transport=transport, timeout=net.PROBE_TIMEOUT,
                       headers={"Accept": "application/json"}) as client:
        status, body = await _send(client, "GET", origin.join(STATUS_PATH))
    if 300 <= status < 400:
        raise NextcloudCheckError("redirect")
    payload = _json_or_none(body) if status == 200 else None
    if not isinstance(payload, dict) or "installed" not in payload or "version" not in payload:
        raise NextcloudCheckError("not_nextcloud")
    if payload.get("installed") is not True:
        raise NextcloudCheckError("not_nextcloud")
    if payload.get("maintenance") is not False or payload.get("needsDbUpgrade") is not False:
        raise NextcloudCheckError("maintenance")
    label = str(payload.get("versionstring") or payload.get("version") or "")[:20]
    major = _major(payload.get("version"))
    if major is None:
        raise NextcloudCheckError("not_nextcloud")
    if major < MIN_MAJOR:
        raise NextcloudCheckError("nc_too_old", label)
    return NextcloudServer(origin=origin, version=label)


def _same_server(url: object, origin: net.Origin, paths: tuple[str, ...]) -> bool:
    """True when ``url`` names this very server and one of ``paths`` (any scheme: it is never used)."""
    if not isinstance(url, str) or len(url) > 2000:
        return False
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    host = (parts.hostname or "").rstrip(".").lower()
    return (parts.scheme in ("https", "http") and host == origin.host and port in (None, 443, 80)
            and not parts.query and not parts.fragment and parts.username is None and parts.path in paths)


async def start_login(server_url: str, *, transport: httpx.AsyncBaseTransport | None = None,
                      denied_hosts: frozenset[str] = frozenset()) -> LoginStart:
    """Start one Login Flow v2 on the checked server. Raises :class:`NextcloudCheckError`."""
    origin = root_origin(server_url)
    async with _client(denied_hosts=denied_hosts, transport=transport, headers={"Accept": "application/json"}) as client:
        status, body = await _send(client, "POST", origin.join(LOGIN_START_PATH))
    if 300 <= status < 400:
        raise NextcloudCheckError("redirect")
    payload = _json_or_none(body) if status == 200 else None
    try:
        poll = payload["poll"]
        poll_token, endpoint, login = poll["token"], poll["endpoint"], payload["login"]
    except (TypeError, KeyError):
        raise NextcloudCheckError("login_failed") from None
    if not isinstance(poll_token, str) or not _TOKEN.fullmatch(poll_token):
        raise NextcloudCheckError("login_failed")
    # The poll address must be this server's own: an answer pointing elsewhere is refused.
    if not _same_server(endpoint, origin, _POLL_PATHS):
        raise NextcloudCheckError("login_failed")
    # Only the token is taken from the login address; its host is never used.
    if not isinstance(login, str) or len(login) > 2000:
        raise NextcloudCheckError("login_failed")
    try:
        match = _LOGIN_PATH.fullmatch(urlsplit(login).path)
    except ValueError:
        match = None
    if not match:
        raise NextcloudCheckError("login_failed")
    return LoginStart(flow_token=match.group(1), poll_token=poll_token)


def _clean_login_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    name = value.strip()
    if not name or len(name) > 255 or ":" in name or any(not ch.isprintable() for ch in name):
        return None
    return name


def _clean_app_password(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    password = value.strip()
    if not password or len(password) > 512 or any(ch.isspace() or not ch.isprintable() for ch in password):
        return None
    return password


async def poll_login(server_url: str, poll_token: str, *, transport: httpx.AsyncBaseTransport | None = None,
                     denied_hosts: frozenset[str] = frozenset()) -> tuple[str, str] | None:
    """``(loginName, appPassword)`` once the person granted access; None while they have not.

    Nextcloud answers 200 exactly once. Its ``server`` field is ignored: the
    credential is used only with the server the person typed.
    """
    if not _TOKEN.fullmatch(poll_token or ""):
        raise NextcloudCheckError("login_failed")
    origin = root_origin(server_url)
    async with _client(denied_hosts=denied_hosts, transport=transport, headers={"Accept": "application/json"}) as client:
        status, body = await _send(client, "POST", origin.join(LOGIN_POLL_PATH), data={"token": poll_token})
    if status == 404:
        return None
    if status != 200:
        raise NextcloudCheckError("login_failed")
    payload = _json_or_none(body)
    if not isinstance(payload, dict):
        raise NextcloudCheckError("login_failed")
    login_name = _clean_login_name(payload.get("loginName"))
    app_password = _clean_app_password(payload.get("appPassword"))
    if login_name is None or app_password is None:
        raise NextcloudCheckError("login_failed")
    return login_name, app_password


async def identify(server_url: str, app_password: str, login_name: str, *,
                   transport: httpx.AsyncBaseTransport | None = None,
                   denied_hosts: frozenset[str] = frozenset()) -> NextcloudIdentity:
    """Who does this credential act as? Raises :class:`NextcloudCheckError`."""
    name = _clean_login_name(login_name)
    if name is None:
        raise NextcloudCheckError("bad_user")
    password = _clean_app_password(app_password)
    if password is None:
        raise NextcloudCheckError("bad_password")
    origin = root_origin(server_url)
    async with _client(denied_hosts=denied_hosts, transport=transport, headers=OCS_HEADERS) as client:
        client.auth = httpx.BasicAuth(name, password)
        status, body = await _send(client, "GET", origin.join(OCS_USER_PATH), max_bytes=256 * 1024)
    if status in (401, 403):
        raise NextcloudCheckError("password_refused")
    if 300 <= status < 400:
        raise NextcloudCheckError("redirect")
    if status != 200:
        raise NextcloudCheckError("server_error", str(status))
    payload = _json_or_none(body)
    try:
        meta = payload["ocs"].get("meta") or {}
        data = payload["ocs"]["data"]
    except (TypeError, KeyError, AttributeError):
        raise NextcloudCheckError("not_nextcloud") from None
    code = meta.get("statuscode") if isinstance(meta, dict) else None
    if code is not None and code not in (100, 200):
        raise NextcloudCheckError("password_refused" if code == 997 else "server_error", str(code))
    user_id = data.get("id") if isinstance(data, dict) else None
    if not isinstance(user_id, str) or not user_id or len(user_id) > 255 or "/" in user_id:
        raise NextcloudCheckError("not_nextcloud")
    display = data.get("displayname") or data.get("display-name") or ""
    email = data.get("email") or ""
    return NextcloudIdentity(user_id=user_id, login_name=name,
                             name=str(display).strip()[:200] if isinstance(display, str) else "",
                             email=str(email).strip()[:200] if isinstance(email, str) else "")


async def delete_app_password(server_url: str, login_name: str, app_password: str, *,
                              transport: httpx.AsyncBaseTransport | None = None,
                              denied_hosts: frozenset[str] = frozenset()) -> bool:
    """Delete this app password in Nextcloud (the request authenticates with it). True when gone.

    Never raises: a disconnect goes ahead whatever Nextcloud answers.
    """
    try:
        origin = root_origin(server_url)
        async with _client(denied_hosts=denied_hosts, transport=transport, headers=OCS_HEADERS) as client:
            client.auth = httpx.BasicAuth(login_name, app_password)
            status, _ = await _send(client, "DELETE", origin.join(OCS_APP_PASSWORD_PATH))
    except (NextcloudCheckError, net.AddressError, httpx.HTTPError, ValueError):
        return False
    return status == 200
