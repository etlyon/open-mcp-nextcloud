"""Against a REAL Nextcloud (a throwaway test instance), when one is given.

Set:
- OC_TEST_NEXTCLOUD: the test server, e.g. http://192.0.2.10:8080 (private, plain http);
- OC_TEST_NEXTCLOUD_USER_FILE: a file (mode 0600) holding the test person's own password,
  used only by the grant helper to click "Grant access" in a headless browser;
- OC_TEST_NEXTCLOUD_APP_FILE: a file (mode 0600) holding an app password made for that person,
  used for the paste path and the tools;
- OC_TEST_NEXTCLOUD_LOGIN: the test person's login name (default "testperson");
- OC_TEST_NEXTCLOUD_GRANT: a script that grants one Login Flow v2 (``node <script> <login url>``,
  reading NC_GRANT_USER / NC_GRANT_PASS_FILE); without it the grant tests are skipped;
- optionally OC_TEST_NEXTCLOUD_NAME / OC_TEST_NEXTCLOUD_EMAIL, the person's display name and email.

The test person's files hold Documents/hello.txt, Documents/sample.pdf and Documents/sample.docx.

The connector only ever calls public https servers, so this test reaches the private test server
through a transport that maps https://nextcloud.test to it, like tests/test_real_odoo.py. The test
server names itself by its private address in what it answers (the Login Flow v2 poll address); the
transport rewrites that address to nextcloud.test, exactly what a server published under that name
answers (overwritehost). The scheme the server reports is kept, so a server behind a proxy that
reports http is exercised too. The address safety itself is tested elsewhere. Skipped when not configured.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

TEST_URL = os.environ.get("OC_TEST_NEXTCLOUD", "").rstrip("/")
USER_FILE = os.environ.get("OC_TEST_NEXTCLOUD_USER_FILE", "")
APP_FILE = os.environ.get("OC_TEST_NEXTCLOUD_APP_FILE", "")
LOGIN = os.environ.get("OC_TEST_NEXTCLOUD_LOGIN", "testperson")
GRANT = os.environ.get("OC_TEST_NEXTCLOUD_GRANT", "")
NAME = os.environ.get("OC_TEST_NEXTCLOUD_NAME", "Test Person")
EMAIL = os.environ.get("OC_TEST_NEXTCLOUD_EMAIL", "test.person@example.org")
FAKE_HOST = "nextcloud.test"
PUBLIC = "https://hub.connector.test"
CLAUDE_CB = "https://claude.ai/api/mcp/auth_callback"
CONFIGURED = bool(TEST_URL and USER_FILE and APP_FILE)


class MapToTestServer(httpx.AsyncBaseTransport):
    """https://nextcloud.test/... → OC_TEST_NEXTCLOUD/... (test only); JSON answers name nextcloud.test."""

    def __init__(self, target: str):
        self.target = httpx.URL(target)
        self.authority = f"{self.target.host}:{self.target.port}" if self.target.port else self.target.host
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        assert request.url.host == FAKE_HOST, request.url
        self.requests.append(request)
        url = request.url.copy_with(scheme=self.target.scheme, host=self.target.host, port=self.target.port)
        headers = httpx.Headers(request.headers)
        headers["host"] = self.authority
        # One plain transport per request: the connector and the app under test run on different event loops.
        async with httpx.AsyncHTTPTransport(retries=0) as inner:
            response = await inner.handle_async_request(
                httpx.Request(request.method, url, headers=headers, stream=request.stream, extensions=request.extensions))
            body = await response.aread()
        out = httpx.Headers(response.headers)
        for name in ("content-length", "content-encoding", "transfer-encoding"):
            out.pop(name, None)
        if "json" in out.get("content-type", ""):
            body = body.replace(self.authority.encode(), FAKE_HOST.encode())
        return httpx.Response(response.status_code, headers=out, content=body)


def lab_url(url: str) -> str:
    """The connector's rebuilt https://nextcloud.test/... address, as the test browser reaches it."""
    parts = urlsplit(url)
    assert parts.scheme == "https" and parts.hostname == FAKE_HOST, url
    return TEST_URL + parts.path


def grant(login_url: str) -> None:
    """The person clicks Grant access in their own Nextcloud (a headless browser, the test's grant helper)."""
    env = {**os.environ, "NC_GRANT_USER": LOGIN, "NC_GRANT_PASS_FILE": USER_FILE}
    done = subprocess.run(["node", GRANT, lab_url(login_url)], env=env, capture_output=True, text=True, timeout=120)
    if done.returncode != 0 or "grant: ok" not in done.stdout:
        raise AssertionError(f"grant helper failed: {done.stderr.strip()[-300:]}")


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def csrf_of(page: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def visible(page: str) -> str:
    page = re.sub(r'<p class="foot">.*?</p>', " ", page, flags=re.S)
    return " ".join(re.sub(r"<style>.*?</style>|<[^>]+>", " ", page, flags=re.S).split())


@unittest.skipUnless(CONFIGURED, "no test Nextcloud configured")
class RealNextcloudProbe(unittest.IsolatedAsyncioTestCase):
    """The probe and the adapter, one call at a time, against the real server."""

    async def asyncSetUp(self):
        from open_connectors.apps.nextcloud import adapter, probe
        self.probe, self.adapter = probe, adapter
        self.transport = MapToTestServer(TEST_URL)
        self.app_password = Path(APP_FILE).read_text().strip()

    async def test_status_check(self):
        server = await self.probe.check_address(f"https://{FAKE_HOST}/apps/files", transport=self.transport)
        self.assertEqual(server.url, f"https://{FAKE_HOST}")
        self.assertGreaterEqual(self.probe._major(server.version) or 0, self.probe.MIN_MAJOR, server.version)

    async def test_paste_identity(self):
        server = await self.probe.check_address(FAKE_HOST, transport=self.transport)
        who = await self.probe.identify(server.url, self.app_password, LOGIN, transport=self.transport)
        self.assertEqual((who.user_id, who.name, who.email), (LOGIN, NAME, EMAIL))
        self.assertEqual(self.adapter.display(who)["label"], f"{NAME} ({EMAIL})")

    async def test_grant_words_are_nextclouds_own(self):
        """Step 2 names Nextcloud's own buttons in the person's language: Log in, then Grant access.

        The login page (rendered by the server up to 32, by a script from 33 on) loads Nextcloud's
        translations for the browser's language; step 2 must use exactly those words. The English
        buttons and their order are what the grant helper clicks in the grant tests.
        """
        import re
        from open_connectors.pages import flow as pages
        url = f"https://{FAKE_HOST}"
        started = await self.probe.start_login(url, transport=self.transport)
        self.assertIn("Log in", pages.t("step.grant.nextcloud", "en"))
        self.assertIn("Grant access", pages.t("step.grant.nextcloud", "en"))
        for lang in ("fr", "de"):
            async with httpx.AsyncClient(follow_redirects=True) as browser:              # a fresh, signed-out browser
                page = await browser.get(lab_url(self.probe.login_url(url, started.flow_token)), headers={"Accept-Language": lang})
                self.assertEqual(page.status_code, 200)
                self.assertIn(f"/core/l10n/{lang}.js", page.text)                      # the page speaks this language …
                words = (await browser.get(f"{TEST_URL}/core/l10n/{lang}.js")).content.decode("utf-8")
            for button in ("Log in", "Grant access"):
                with self.subTest(lang=lang, button=button):
                    found = re.search(rf'"{button}" : "([^"]+)"', words)
                    self.assertIsNotNone(found, button)
                    self.assertIn(found.group(1).replace("'", "’"), pages.t("step.grant.nextcloud", lang))   # … step 2 too

    async def test_wrong_password_refused(self):
        with self.assertRaises(self.probe.NextcloudCheckError) as ctx:
            await self.probe.identify(f"https://{FAKE_HOST}", "W" * 72, LOGIN, transport=self.transport)
        self.assertEqual(ctx.exception.code, "password_refused")

    @unittest.skipUnless(GRANT, "no grant helper configured")
    async def test_login_flow_grant_identity_and_disconnect(self):
        """Login Flow v2 by the connector code; the grant by a real browser; disconnect deletes the app password."""
        url = f"https://{FAKE_HOST}"
        started = await self.probe.start_login(url, transport=self.transport)
        login_url = self.probe.login_url(url, started.flow_token)
        self.assertEqual(login_url, f"https://{FAKE_HOST}/index.php/login/v2/flow/{started.flow_token}")
        self.assertIsNone(await self.probe.poll_login(url, started.poll_token, transport=self.transport))   # 404: waiting
        grant(login_url)
        got = None
        for _ in range(10):
            got = await self.probe.poll_login(url, started.poll_token, transport=self.transport)
            if got:
                break
            time.sleep(1)
        self.assertIsNotNone(got, "the grant never reached the poll")
        login_name, app_password = got
        self.assertNotEqual(app_password, self.app_password)
        # Nextcloud hands the credential out once only.
        with self.assertRaises(self.probe.NextcloudCheckError):
            again = await self.probe.poll_login(url, started.poll_token, transport=self.transport)
            if again is None:
                raise self.probe.NextcloudCheckError("login_failed")
        who = await self.probe.identify(url, app_password, login_name, transport=self.transport)
        self.assertEqual((who.user_id, who.name, who.email), (LOGIN, NAME, EMAIL))
        secret = self.adapter.secret(app_password, who)
        # Disconnect: the app password is deleted in Nextcloud, and WebDAV refuses it from then on.
        saved = self.adapter.TRANSPORT
        self.adapter.TRANSPORT = self.transport
        try:
            self.assertTrue(await self.adapter.on_disconnect(url, secret))
        finally:
            self.adapter.TRANSPORT = saved
        async with httpx.AsyncClient(transport=self.transport, auth=(login_name, app_password)) as client:
            r = await client.request("PROPFIND", f"{url}/remote.php/dav/files/{who.user_id}/", headers={"Depth": "0"})
        self.assertEqual(r.status_code, 401)
        with self.assertRaises(self.probe.NextcloudCheckError) as ctx:
            await self.probe.identify(url, app_password, login_name, transport=self.transport)
        self.assertEqual(ctx.exception.code, "password_refused")
        # Nothing went anywhere but the person's own server.
        self.assertEqual({r.url.host for r in self.transport.requests}, {FAKE_HOST})


@unittest.skipUnless(CONFIGURED, "no test Nextcloud configured")
class RealNextcloudSignIn(unittest.TestCase):
    """The whole sign-in, page by page, through the connector app, against the real server."""

    @classmethod
    def setUpClass(cls):
        from starlette.testclient import TestClient
        cls.tmp = tempfile.TemporaryDirectory()
        conf = Path(cls.tmp.name) / "config.toml"
        conf.write_text(f'public_url = "{PUBLIC}"\napp = "nextcloud"\nstate_dir = "{cls.tmp.name}/state"\n'
                        f'source_url = "https://code.example.org/open-connectors"\n')
        cls.saved_journal = os.environ.get("OPEN_CONNECTORS_JOURNAL")
        os.environ["OPEN_CONNECTORS_JOURNAL"] = f"{cls.tmp.name}/journal.sqlite"
        from open_connectors import config, server
        from open_connectors.apps.nextcloud import adapter, tools
        cls.transport = MapToTestServer(TEST_URL)
        cls.saved = (adapter.TRANSPORT, tools.TRANSPORT)
        adapter.TRANSPORT = cls.transport
        tools.TRANSPORT = cls.transport
        cls.application = server.Application(config.load(conf))
        cls.client = TestClient(cls.application, base_url=PUBLIC, follow_redirects=False)
        cls.client.__enter__()
        cls.app_password = Path(APP_FILE).read_text().strip()

    @classmethod
    def tearDownClass(cls):
        from open_connectors.apps.nextcloud import adapter, tools
        adapter.TRANSPORT, tools.TRANSPORT = cls.saved
        cls.client.__exit__(None, None, None)
        cls.tmp.cleanup()
        if cls.saved_journal is None:
            os.environ.pop("OPEN_CONNECTORS_JOURNAL", None)
        else:
            os.environ["OPEN_CONNECTORS_JOURNAL"] = cls.saved_journal

    def register(self):
        r = self.client.post("/register", json={"redirect_uris": [CLAUDE_CB], "client_name": "Claude",
                                                "token_endpoint_auth_method": "none",
                                                "grant_types": ["authorization_code", "refresh_token"]})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["client_id"]

    def to_key_step(self, client_id):
        verifier, challenge = pkce()
        r = self.client.get("/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": CLAUDE_CB,
                                                  "code_challenge": challenge, "code_challenge_method": "S256",
                                                  "state": "st-1", "resource": f"{PUBLIC}/mcp"})
        self.assertEqual(r.status_code, 302, r.text)
        path = r.headers["location"]
        page = self.client.get(path).text
        r = self.client.post(path + "/server", data={"csrf": csrf_of(page), "address": f"https://{FAKE_HOST}/apps/files/files?dir=/"})
        self.assertEqual(r.status_code, 303, r.text)
        return verifier, path, csrf_of(page)

    def tokens(self, client_id, page, verifier):
        import html as htmllib
        back = htmllib.unescape(re.search(r'<a class="primary" href="([^"]+)"', page).group(1))
        q = parse_qs(urlsplit(back).query)
        r = self.client.post("/token", data={"grant_type": "authorization_code", "code": q["code"][0],
                                             "redirect_uri": CLAUDE_CB, "code_verifier": verifier, "client_id": client_id})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def mcp(self, token, method, params=None, rid=1):
        return self.client.post("/mcp", json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                                headers={"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream",
                                         "MCP-Protocol-Version": "2025-11-25"})

    def call(self, token, name, arguments, rid):
        answer = self.mcp(token, "tools/call", {"name": name, "arguments": arguments}, rid=rid).json()
        return json.loads(answer["result"]["content"][0]["text"])

    @unittest.skipUnless(GRANT, "no grant helper configured")
    def test_grant_access_end_to_end(self):
        """Address → Grant access in the real Nextcloud → connected → tools → revoke deletes the app password."""
        client_id = self.register()
        verifier, path, _ = self.to_key_step(client_id)
        waiting = self.client.get(path)
        self.assertEqual(waiting.status_code, 200, waiting.text)
        self.assertIn("Click Log in, then Grant access", visible(waiting.text))
        self.assertIn('http-equiv="refresh"', waiting.text)
        link = re.search(rf'href="(https://{re.escape(FAKE_HOST)}/index\.php/login/v2/flow/[A-Za-z0-9]+)" target="_blank"',
                         waiting.text)
        self.assertIsNotNone(link, "the waiting page names no rebuilt login address")
        grant(link.group(1))
        done = None
        for _ in range(10):                      # the page refreshes itself; the server polls at most every 2 s
            time.sleep(2.1)
            page = self.client.get(path)
            if 'class="ok"' in page.text:
                done = page
                break
            self.assertEqual(page.status_code, 200, page.text)
        self.assertIsNotNone(done, "the connector never saw the grant")
        self.assertIn("Hub is connected to Claude.", done.text)
        self.assertIn(f"Signed in as {NAME} ({EMAIL})", done.text)
        tok = self.tokens(client_id, done.text, verifier)
        self.assertEqual(self.mcp(tok["access_token"], "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}).status_code, 200)
        status = self.call(tok["access_token"], "nextcloud_connection_status", {}, 2)
        self.assertTrue(status["connected"], status)
        self.assertEqual(status["identity"]["user"], LOGIN)
        listed = self.call(tok["access_token"], "nextcloud_list", {"params": {"path": "Documents"}}, 3)
        self.assertIn("Documents/hello.txt", {i["path"] for i in listed})
        # Revoke = disconnect: the connector's own app password is deleted in Nextcloud.
        r = self.client.post("/revoke", data={"token": tok["refresh_token"], "client_id": client_id})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.mcp(tok["access_token"], "tools/list", rid=5).status_code, 401)
        deletes = [q for q in self.transport.requests if q.method == "DELETE" and q.url.path == "/ocs/v2.php/core/apppassword"]
        self.assertEqual(len(deletes), 1)
        login_name, app_password = base64.b64decode(deletes[0].headers["authorization"][6:]).decode().split(":", 1)
        self.assertEqual(login_name, LOGIN)
        self.assertNotEqual(app_password, self.app_password)
        with httpx.Client() as plain:                      # straight to the test server: the deleted password is refused
            r = plain.request("PROPFIND", f"{TEST_URL}/remote.php/dav/files/{LOGIN}/", headers={"Depth": "0"},
                              auth=(login_name, app_password))
        self.assertEqual(r.status_code, 401)
        self.assertEqual({q.url.host for q in self.transport.requests}, {FAKE_HOST})

    @unittest.skipUnless(GRANT, "no grant helper configured")
    def test_not_now_right_after_grant_access_deletes_the_app_password(self):
        """The person clicks Grant access, then Not now before the page refreshed: nothing stays in Nextcloud."""
        before = len(self.transport.requests)
        client_id = self.register()
        _, path, csrf = self.to_key_step(client_id)
        waiting = self.client.get(path)
        link = re.search(rf'href="(https://{re.escape(FAKE_HOST)}/index\.php/login/v2/flow/[A-Za-z0-9]+)" target="_blank"',
                         waiting.text)
        self.assertIsNotNone(link, "the waiting page names no rebuilt login address")
        grant(link.group(1))                                 # Nextcloud makes the app password now
        r = self.client.post(path + "/cancel", data={"csrf": csrf})
        self.assertEqual(r.status_code, 303)
        self.assertIn("error=access_denied", r.headers["location"])
        deletes = [q for q in self.transport.requests[before:]
                   if q.method == "DELETE" and q.url.path == "/ocs/v2.php/core/apppassword"]
        self.assertEqual(len(deletes), 1)
        login_name, app_password = base64.b64decode(deletes[-1].headers["authorization"][6:]).decode().split(":", 1)
        self.assertEqual(login_name, LOGIN)
        with httpx.Client() as plain:                      # straight to the test server: the password is gone
            r = plain.request("PROPFIND", f"{TEST_URL}/remote.php/dav/files/{LOGIN}/", headers={"Depth": "0"},
                              auth=(login_name, app_password))
        self.assertEqual(r.status_code, 401)

    def test_paste_app_password(self):
        """The fallback: a pasted user name and app password (not deleted: the person may use it elsewhere)."""
        client_id = self.register()
        verifier, path, csrf = self.to_key_step(client_id)
        page = self.client.get(path + "?how=paste")
        self.assertIn('placeholder="Paste your app password here"', page.text)
        self.assertIn(f'href="https://{FAKE_HOST}/" target="_blank"', page.text)
        bad = self.client.post(path + "/key", data={"csrf": csrf, "user": LOGIN, "key": "W" * 72})
        self.assertEqual(bad.status_code, 400)
        self.assertIn("Hub refused this user name and app password.", bad.text)
        self.client.get(path)
        ok = self.client.post(path + "/key", data={"csrf": csrf, "user": LOGIN, "key": self.app_password})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertIn(f"Signed in as {NAME} ({EMAIL})", ok.text)
        tok = self.tokens(client_id, ok.text, verifier)
        self.assertEqual(self.mcp(tok["access_token"], "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}).status_code, 200)
        read = self.call(tok["access_token"], "nextcloud_read", {"params": {"path": "Documents/hello.txt"}}, 2)
        self.assertTrue(read["text"].strip(), read)


@unittest.skipUnless(CONFIGURED, "no test Nextcloud configured")
class RealNextcloudTools(unittest.IsolatedAsyncioTestCase):
    """Each tool, as one pasted connection, on the real WebDAV."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.saved_journal = os.environ.get("OPEN_CONNECTORS_JOURNAL")
        os.environ["OPEN_CONNECTORS_JOURNAL"] = f"{cls.tmp.name}/journal.sqlite"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()
        if cls.saved_journal is None:
            os.environ.pop("OPEN_CONNECTORS_JOURNAL", None)
        else:
            os.environ["OPEN_CONNECTORS_JOURNAL"] = cls.saved_journal

    async def asyncSetUp(self):
        from open_connectors.apps.nextcloud import tools
        from open_connectors.oauth.server import CURRENT
        from open_connectors.store import Connection
        self.tools = tools
        self.transport = MapToTestServer(TEST_URL)
        self.saved = tools.TRANSPORT
        tools.TRANSPORT = self.transport
        conn = Connection(conn_id="real-hub", app="nextcloud", server=f"https://{FAKE_HOST}", remote_user=LOGIN,
                          client_id="t", resource="r", display={},
                          secret={"login_name": LOGIN, "app_password": Path(APP_FILE).read_text().strip()})
        self.CURRENT = CURRENT
        self.token = CURRENT.set(conn)

    async def asyncTearDown(self):
        self.CURRENT.reset(self.token)
        self.tools.TRANSPORT = self.saved
        self.assertLessEqual({r.url.host for r in self.transport.requests}, {FAKE_HOST})

    async def test_connection_status(self):
        status = json.loads(await self.tools.nextcloud_connection_status())
        self.assertTrue(status["connected"], status)
        self.assertEqual((status["identity"]["user"], status["identity"]["display_name"], status["identity"]["email"]),
                         (LOGIN, NAME, EMAIL))
        self.assertNotIn(Path(APP_FILE).read_text().strip(), json.dumps(status))

    async def test_list_documents(self):
        items = json.loads(await self.tools.nextcloud_list(self.tools.ListInput(path="Documents")))
        paths = {i["path"] for i in items}
        self.assertTrue({"Documents/hello.txt", "Documents/sample.pdf", "Documents/sample.docx"} <= paths, paths)
        info = json.loads(await self.tools.nextcloud_info(self.tools.PathInput(path="Documents/hello.txt")))
        self.assertEqual(info["type"], "file", info)

    async def test_search_hello(self):
        found = json.loads(await self.tools.nextcloud_search(self.tools.SearchInput(query="hello")))
        self.assertIn("Documents/hello.txt", [m["path"] for m in found["matches"]], found)

    async def test_read_text_pdf_docx(self):
        texts = {}
        for name in ("hello.txt", "sample.pdf", "sample.docx"):
            with self.subTest(name=name):
                doc = json.loads(await self.tools.nextcloud_read(self.tools.ReadInput(path=f"Documents/{name}")))
                self.assertIn("text", doc, doc)
                self.assertTrue(doc["text"].strip(), doc)
                texts[name] = doc
        self.assertEqual(texts["sample.pdf"]["format"], "pdf")
        self.assertEqual(texts["sample.docx"]["format"], "docx")

    async def test_idempotent_write_and_cleanup(self):
        tools = self.tools
        run = secrets.token_hex(4)
        path = f"Documents/connector-test-{run}.txt"
        params = tools.WriteInput(path=path, content="written by the real-server test", idempotency_key=f"k-{run}")
        try:
            first = json.loads(await tools.nextcloud_write(params))
            self.assertTrue(first["written"], first)
            self.assertFalse(first["idempotent_replay"])
            again = json.loads(await tools.nextcloud_write(params))
            self.assertTrue(again["idempotent_replay"], again)
            puts = [r for r in self.transport.requests if r.method == "PUT"]
            self.assertEqual(len(puts), 1)                                  # written once
            other = json.loads(await tools.nextcloud_write(tools.WriteInput(
                path=path, content="something else", idempotency_key=f"k-{run}")))
            self.assertIn("error", other)                                   # same key, other arguments: refused
            back = json.loads(await tools.nextcloud_read(tools.ReadInput(path=path)))
            self.assertEqual(back["text"], "written by the real-server test")
        finally:
            gone = json.loads(await tools.nextcloud_delete(tools.PathWriteInput(path=path, idempotency_key=f"d-{run}")))
        self.assertTrue(gone["deleted_to_trash"], gone)
        missing = await tools.nextcloud_read(tools.ReadInput(path=path))
        self.assertTrue(missing.startswith("Error 404"), missing)


if __name__ == "__main__":
    unittest.main()
