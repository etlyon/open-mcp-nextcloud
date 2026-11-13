"""An in-process fake Nextcloud (no network): status, Login Flow v2, OCS user, app passwords, WebDAV.

One user, ``alice`` (login name ``alice@example.org``). ``FakeNextcloud.mode``
switches the answers a test needs (maintenance, too old, hostile login flow…).
Every request is recorded, so a test can prove nothing went to another host.
``OTHER_HOST`` is a second Nextcloud (status only, no user): it records what it receives.
Like the real one, the app password is made when the person clicks Grant access
(``granted = True``), not when the connector polls.
"""

from __future__ import annotations

import base64

import re
from urllib.parse import parse_qs, quote, unquote, urlsplit
from xml.sax.saxutils import escape

import httpx

HOST = "cloud.example.org"
USER_ID = "alice"
LOGIN_NAME = "alice@example.org"
FLOW_TOKEN = "F" * 64
POLL_TOKEN = "P" * 64
OTHER_HOST = "other.example.net"
DAV_PREFIX = f"/remote.php/dav/files/{USER_ID}"


class FakeNextcloud:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.mode: set[str] = set()
        self.version = "30.0.2.2"
        self.counter = 0
        self.granted_password: str | None = None   # made by Grant access
        self.handed_out = False         # the poll answered 200 once
        self.passwords: set[str] = {"pasted-" + "p" * 40}   # app passwords that work
        self.deleted: list[str] = []
        self.requests: list[httpx.Request] = []
        self.files: dict[str, tuple[bytes, str]] = {}
        self.dirs: set[str] = {""}
        self.puts = 0

    @property
    def granted(self) -> bool:
        """The person clicked Grant access."""
        return self.granted_password is not None

    @granted.setter
    def granted(self, value: bool) -> None:
        if value and self.granted_password is None:
            self.counter += 1
            self.granted_password = f"granted{self.counter}-" + "g" * 40
            self.passwords.add(self.granted_password)     # Nextcloud makes the app password now
        elif not value:
            self.granted_password = None

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    # ------------------------------------------------------------------ helpers
    def _auth_ok(self, request: httpx.Request) -> str | None:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("basic "):
            return None
        login, _, password = base64.b64decode(header[6:]).decode().partition(":")
        if login in (LOGIN_NAME, USER_ID) and password in self.passwords:
            return password
        return None

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == OTHER_HOST and request.url.path == "/status.php":
            return httpx.Response(200, json={"installed": True, "maintenance": False, "needsDbUpgrade": False,
                                             "version": self.version, "versionstring": "30.0.2", "productname": "Nextcloud"})
        if request.url.host != HOST:
            return httpx.Response(599, text="wrong host")
        path = request.url.path
        if path == "/status.php":
            if "not_nextcloud" in self.mode:
                return httpx.Response(200, html="<html>hello</html>")
            return httpx.Response(200, json={
                "installed": True, "maintenance": "maintenance" in self.mode, "needsDbUpgrade": False,
                "version": self.version, "versionstring": self.version.rsplit(".", 1)[0], "productname": "Nextcloud"})
        if path == "/index.php/login/v2" and request.method == "POST":
            if request.headers.get("user-agent") != "Assistant connector":
                return httpx.Response(400)
            endpoint = f"https://{HOST}/login/v2/poll"
            login = f"https://{HOST}/login/v2/flow/{FLOW_TOKEN}"
            if "hostile_poll" in self.mode:
                endpoint = "https://evil.example/index.php/login/v2/poll"
            if "hostile_login" in self.mode:
                login = f"https://evil.example/login/v2/flow/{FLOW_TOKEN}"
            if "bad_token" in self.mode:
                login = f"https://{HOST}/login/v2/flow/abc$%25def"
            return httpx.Response(200, json={"poll": {"token": POLL_TOKEN, "endpoint": endpoint}, "login": login})
        if path == "/index.php/login/v2/poll" and request.method == "POST":
            token = parse_qs(request.content.decode()).get("token", [""])[0]
            if token != POLL_TOKEN or not self.granted or self.handed_out:
                return httpx.Response(404, json=[])
            self.handed_out = True
            return httpx.Response(200, json={"server": "https://evil.example", "loginName": LOGIN_NAME,
                                             "appPassword": self.granted_password})
        if path == "/ocs/v1.php/cloud/user":
            if request.headers.get("ocs-apirequest") != "true" or not self._auth_ok(request):
                return httpx.Response(401, json={"ocs": {"meta": {"statuscode": 997}, "data": []}})
            return httpx.Response(200, json={"ocs": {"meta": {"status": "ok", "statuscode": 100},
                                                     "data": {"id": USER_ID, "displayname": "Alice Example",
                                                              "email": "alice@example.org"}}})
        if path == "/ocs/v2.php/core/apppassword" and request.method == "DELETE":
            password = self._auth_ok(request)
            if not password or request.headers.get("ocs-apirequest") != "true":
                return httpx.Response(401)
            self.passwords.discard(password)
            self.deleted.append(password)
            return httpx.Response(200, json={"ocs": {"meta": {"statuscode": 200}, "data": []}})
        if path.startswith("/remote.php/dav/"):
            if not self._auth_ok(request):
                return httpx.Response(401)
            return self._dav(request)
        return httpx.Response(404, text="not found")

    # ------------------------------------------------------------------ WebDAV
    def _rel(self, path: str) -> str:
        return unquote(path[len(DAV_PREFIX):]).strip("/")

    def _entry(self, rel: str) -> str:
        href = DAV_PREFIX + "/" + "/".join(quote(p) for p in rel.split("/")) if rel else DAV_PREFIX + "/"
        if rel in self.dirs:
            props = "<d:resourcetype><d:collection/></d:resourcetype>"
        else:
            data, kind = self.files[rel]
            props = (f"<d:resourcetype/><d:getcontentlength>{len(data)}</d:getcontentlength>"
                     f"<d:getcontenttype>{escape(kind)}</d:getcontenttype>")
        name = rel.rsplit("/", 1)[-1] if rel else ""
        return (f"<d:response><d:href>{escape(href)}</d:href><d:propstat><d:prop>"
                f"<d:displayname>{escape(name)}</d:displayname>{props}"
                f"<d:getlastmodified>Mon, 09 Nov 2026 10:00:00 GMT</d:getlastmodified>"
                f"</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>")

    def _multistatus(self, rels: list[str]) -> httpx.Response:
        body = ('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">'
                + "".join(self._entry(r) for r in rels) + "</d:multistatus>")
        return httpx.Response(207, content=body.encode(), headers={"Content-Type": "application/xml"})

    def _exists(self, rel: str) -> bool:
        return rel in self.dirs or rel in self.files

    def _dav(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        if method == "SEARCH" and path == "/remote.php/dav/":
            if "xxe" in self.mode:
                return httpx.Response(207, content=b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "y">]><d:multistatus xmlns:d="DAV:"/>')
            literal = re.search(rb"<d:literal>%(.*?)%</d:literal>", request.content).group(1).decode().lower()
            hits = [r for r in sorted(self.dirs | set(self.files)) if r and literal in r.rsplit("/", 1)[-1].lower()]
            return self._multistatus(hits)
        if not path.startswith(DAV_PREFIX):
            return httpx.Response(403)
        rel = self._rel(path)
        if method == "PROPFIND":
            if not self._exists(rel):
                return httpx.Response(404)
            rels = [rel]
            if request.headers.get("depth") == "1" and rel in self.dirs:
                prefix = rel + "/" if rel else ""
                rels += [r for r in sorted(self.dirs | set(self.files))
                         if r and r.startswith(prefix) and "/" not in r[len(prefix):]]
            return self._multistatus(rels)
        if method == "GET":
            if rel not in self.files:
                return httpx.Response(404)
            data, kind = self.files[rel]
            return httpx.Response(200, content=data, headers={"Content-Type": kind})
        if method == "PUT":
            self.puts += 1
            self.files[rel] = (request.content, request.headers.get("content-type", "application/octet-stream"))
            return httpx.Response(201)
        if method == "MKCOL":
            if self._exists(rel):
                return httpx.Response(405)
            self.dirs.add(rel)
            return httpx.Response(201)
        if method == "MOVE":
            target = urlsplit(request.headers["destination"])
            if target.hostname != HOST:
                return httpx.Response(502)
            dest = self._rel(target.path)
            if rel not in self.files:
                return httpx.Response(404)
            if dest in self.files and request.headers.get("overwrite") == "F":
                return httpx.Response(412)
            self.files[dest] = self.files.pop(rel)
            return httpx.Response(201)
        if method == "DELETE":
            if rel in self.files:
                del self.files[rel]
                return httpx.Response(204)
            if rel in self.dirs:
                self.dirs.discard(rel)
                return httpx.Response(204)
            return httpx.Response(404)
        return httpx.Response(405)

    def other_hosts(self) -> set[str]:
        return {r.url.host for r in self.requests} - {HOST}

    def json_requests(self, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == path]


