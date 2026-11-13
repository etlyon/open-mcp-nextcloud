"""Nextcloud's part of the sign-in (people read "Hub"): what the pages call for steps B and C.

Step C is Nextcloud Login Flow v2 (``LOGIN_FLOW``): the person grants access in
their own Nextcloud and the connector receives an app password of its own. The
fallback is a pasted user name and app password (``EXTRA_FIELD`` names the
second box). The app password is deleted in Nextcloud when the connection is
revoked (``on_disconnect``).
"""

from __future__ import annotations

from typing import Any

import httpx

from open_connectors.apps.nextcloud import probe

NAME = "nextcloud"
CheckError = probe.NextcloudCheckError
ROOT_ONLY = probe.ROOT_ONLY             # a pasted page address (with ?dir=… and all) keeps only its host
LOGIN_FLOW = True                       # step C: Grant access in Nextcloud, paste as the fallback
LOGIN_FLOW_SECONDS = probe.LOGIN_FLOW_SECONDS
EXTRA_FIELD = "user"                    # the paste fallback's second box: the user name
TRANSPORT: httpx.AsyncBaseTransport | None = None   # tests only (an in-process fake Nextcloud)


async def check_address(typed: str, *, denied_hosts: frozenset[str] = frozenset()) -> probe.NextcloudServer:
    return await probe.check_address(typed, denied_hosts=denied_hosts, transport=TRANSPORT)


async def start_login(server_url: str, *, denied_hosts: frozenset[str] = frozenset()) -> probe.LoginStart:
    return await probe.start_login(server_url, denied_hosts=denied_hosts, transport=TRANSPORT)


async def poll_login(server_url: str, poll_token: str, *,
                     denied_hosts: frozenset[str] = frozenset()) -> tuple[str, str] | None:
    return await probe.poll_login(server_url, poll_token, denied_hosts=denied_hosts, transport=TRANSPORT)


def login_url(server_url: str, flow_token: str) -> str:
    return probe.login_url(server_url, flow_token)


async def identify(server_url: str, key: str, user: str, *,
                   denied_hosts: frozenset[str] = frozenset()) -> probe.NextcloudIdentity:
    """``key`` is the app password, ``user`` the login name (pasted, or granted by the login flow)."""
    return await probe.identify(server_url, key, user, denied_hosts=denied_hosts, transport=TRANSPORT)


async def on_disconnect(server_url: str, secret: dict[str, Any], *,
                        denied_hosts: frozenset[str] = frozenset()) -> bool:
    """Delete this connection's app password in Nextcloud. Never raises."""
    login_name, app_password = secret.get("login_name"), secret.get("app_password")
    if not isinstance(login_name, str) or not isinstance(app_password, str):
        return False
    return await probe.delete_app_password(server_url, login_name, app_password, denied_hosts=denied_hosts, transport=TRANSPORT)


def open_url(server_url: str) -> str:
    """Where "Open Hub" goes for the paste fallback: the person's own Nextcloud, nothing else."""
    return probe.root_origin(server_url).url + "/"


def secret(key: str, identity: probe.NextcloudIdentity) -> dict[str, Any]:
    return {"login_name": identity.login_name, "app_password": key.strip()}


def display(identity: probe.NextcloudIdentity) -> dict[str, Any]:
    label = identity.name or identity.email
    if identity.name and identity.email:
        label = f"{identity.name} ({identity.email})"
    return {"name": identity.name, "email": identity.email, "label": label}


def remote_user(identity: probe.NextcloudIdentity) -> str:
    return identity.user_id
