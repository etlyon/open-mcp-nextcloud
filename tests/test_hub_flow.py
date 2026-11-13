"""Hub (Nextcloud) end to end in one process: address → Grant access (Login Flow v2) or a pasted
app password → connected → tools → revoke deletes the app password.

The person's Nextcloud is the in-process fake in tests/fake_nextcloud.py (no network).
"""

from __future__ import annotations

import base64
import hashlib
import html as htmllib
import json
import os
import re
import secrets
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from starlette.testclient import TestClient

from tests.fake_nextcloud import FLOW_TOKEN, HOST, LOGIN_NAME, OTHER_HOST, POLL_TOKEN, FakeNextcloud

PUBLIC = "https://hub.connector.test"
CLAUDE_CB = "https://claude.ai/api/mcp/auth_callback"
PASTED = "pasted-" + "p" * 40
FAKE = FakeNextcloud()


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def csrf_of(page: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def back_link(page: str) -> str:
    return htmllib.unescape(re.search(r'<a class="primary" href="([^"]+)"', page).group(1))


def visible(page: str) -> str:
    page = re.sub(r'<p class="foot">.*?</p>', " ", page, flags=re.S)
    return " ".join(re.sub(r"<style>.*?</style>|<[^>]+>", " ", page, flags=re.S).split())


class HubFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        conf = Path(cls.tmp.name) / "config.toml"
        conf.write_text(f'public_url = "{PUBLIC}"\napp = "nextcloud"\nstate_dir = "{cls.tmp.name}/state"\n'
                        f'source_url = "https://code.example.org/open-connectors"\n')
        os.environ["OPEN_CONNECTORS_JOURNAL"] = f"{cls.tmp.name}/journal.sqlite"
        from open_connectors import config, server
        from open_connectors.apps.nextcloud import adapter, tools
        from open_connectors.oauth import server as oauth_server
        cls.oauth = oauth_server
        cls.saved = (adapter.TRANSPORT, tools.TRANSPORT, oauth_server.POLL_SECONDS, oauth_server.POLL_PER_HOST)
        adapter.TRANSPORT = FAKE.transport
        tools.TRANSPORT = FAKE.transport
        oauth_server.POLL_SECONDS = 0.0
        oauth_server.POLL_PER_HOST = 10 ** 9
        cls.application = server.Application(config.load(conf))
        cls.client = TestClient(cls.application, base_url=PUBLIC, follow_redirects=False)
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        from open_connectors.apps.nextcloud import adapter, tools
        adapter.TRANSPORT, tools.TRANSPORT, cls.oauth.POLL_SECONDS, cls.oauth.POLL_PER_HOST = cls.saved
        cls.client.__exit__(None, None, None)
        cls.tmp.cleanup()

    def setUp(self):
        FAKE.reset()
        self.application.auth.limits = self.oauth.RateLimiter()
        self.application.auth._waiting.clear()

    # ------------------------------------------------------------------ helpers
    def register(self, redirect=CLAUDE_CB, name="Claude"):
        r = self.client.post("/register", json={"redirect_uris": [redirect], "client_name": name,
                                                "token_endpoint_auth_method": "none",
                                                "grant_types": ["authorization_code", "refresh_token"]})
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()["client_id"]

    def start(self, client_id, redirect=CLAUDE_CB, resource=f"{PUBLIC}/mcp"):
        verifier, challenge = pkce()
        r = self.client.get("/authorize", params={"response_type": "code", "client_id": client_id, "redirect_uri": redirect,
                                                  "code_challenge": challenge, "code_challenge_method": "S256",
                                                  "state": "st-1", "resource": resource, "scope": "read write send"})
        self.assertEqual(r.status_code, 302, r.text)
        return verifier, r.headers["location"]

    def to_key_step(self, client_id, address=f"https://{HOST}/apps/files/files?dir=/&fileid=2"):
        verifier, path = self.start(client_id)
        page = self.client.get(path)
        self.assertIn('placeholder="cloud.example.com"', page.text)
        self.assertIn("Hub web address", page.text)
        r = self.client.post(path + "/server", data={"csrf": csrf_of(page.text), "address": address})
        self.assertEqual(r.status_code, 303, r.text)
        return verifier, path, csrf_of(page.text)

    def tokens(self, client_id, page, verifier):
        q = parse_qs(urlsplit(back_link(page)).query)
        self.assertEqual(q["iss"], [PUBLIC])
        r = self.client.post("/token", data={"grant_type": "authorization_code", "code": q["code"][0],
                                             "redirect_uri": CLAUDE_CB, "code_verifier": verifier, "client_id": client_id})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def mcp(self, token, method, params=None, rid=1):
        return self.client.post("/mcp", json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
                                headers={"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream",
                                         "MCP-Protocol-Version": "2025-11-25"})

    # ------------------------------------------------------------------ Grant access (Login Flow v2)
    def test_grant_access_end_to_end(self):
        client_id = self.register()
        verifier, path, _ = self.to_key_step(client_id)
        waiting = self.client.get(path)
        self.assertEqual(waiting.status_code, 200, waiting.text)
        text = visible(waiting.text)
        self.assertIn("Connect Hub to Claude", text)
        self.assertIn(f"Connecting to {HOST}", text)
        self.assertIn("Click Log in, then Grant access", text)
        self.assertIn("Come back here", text)
        self.assertIn("Paste an app password instead", text)
        self.assertNotRegex(text.lower(), r"\bmcp\b|plugin|connector|expir|month")
        # The login address is rebuilt from the checked server; the page refreshes itself, no script.
        self.assertIn(f'href="https://{HOST}/index.php/login/v2/flow/{FLOW_TOKEN}" target="_blank" rel="noopener noreferrer"',
                      waiting.text)
        self.assertIn(f'http-equiv="refresh" content="3;url=/connect/', waiting.text)
        self.assertNotIn("<script", waiting.text)
        # Nextcloud's own labels, in each language: "Log in" first, then "Grant access".
        for lang, words in (("fr", "Cliquez sur Se connecter, puis sur Autoriser l’accès"),
                            ("de", "Klicken Sie auf Anmelden, dann auf Zugriff gewähren"), ("en", "Click Log in, then Grant access")):
            self.assertIn(words, htmllib.unescape(visible(self.client.get(f"{path}?lang={lang}").text)))
        self.assertIn("default-src 'none'", waiting.headers["content-security-policy"])
        self.assertNotIn(POLL_TOKEN, waiting.text)                  # the poll token is a secret
        flow = self.application.store.get_flow(path.rsplit("/", 1)[-1])
        self.assertNotIn(POLL_TOKEN, json.dumps(flow))               # kept only sealed under the cookie key
        start = FAKE.json_requests("/index.php/login/v2")[0]
        self.assertEqual(start.headers["user-agent"], "Assistant connector")
        # Still waiting: Nextcloud answers 404, the page stays.
        again = self.client.get(path)
        self.assertEqual(again.status_code, 200)
        self.assertIn("Click Log in, then Grant access", again.text)
        # The person clicks Grant access in Nextcloud; the next refresh connects.
        FAKE.granted = True
        done = self.client.get(path)
        self.assertEqual(done.status_code, 200, done.text)
        self.assertIn('class="ok"', done.text)
        self.assertIn("Hub is connected to Claude.", done.text)
        self.assertIn("Signed in as Alice Example (alice@example.org)", done.text)
        self.assertIn("Delete the app password in Hub", done.text)
        self.assertEqual(FAKE.other_hosts(), set())                 # the answer's 'server' was ignored
        tok = self.tokens(client_id, done.text, verifier)
        # The tools work as that person, on that server.
        FAKE.files["Notes/todo.txt"] = (b"buy milk", "text/plain")
        FAKE.dirs.add("Notes")
        self.assertEqual(self.mcp(tok["access_token"], "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}).status_code, 200)
        names = {t["name"] for t in self.mcp(tok["access_token"], "tools/list", rid=2).json()["result"]["tools"]}
        self.assertTrue({"nextcloud_list", "nextcloud_search", "nextcloud_read", "nextcloud_write",
                         "nextcloud_connection_status"} <= names, names)
        self.assertNotIn("nextcloud_connect", names)
        call = self.mcp(tok["access_token"], "tools/call", {"name": "nextcloud_read", "arguments": {"params": {"path": "Notes/todo.txt"}}}, rid=3).json()
        self.assertEqual(json.loads(call["result"]["content"][0]["text"])["text"], "buy milk")
        status = self.mcp(tok["access_token"], "tools/call", {"name": "nextcloud_connection_status", "arguments": {}}, rid=4).json()
        body = json.loads(status["result"]["content"][0]["text"])
        self.assertEqual(body["identity"]["user"], "alice")
        self.assertFalse(body["credential_material_exposed"])
        self.assertEqual(len(status["result"]["content"]), 1)          # no key-ending reminder for app passwords
        # Revoke = disconnect: the app password is deleted in Nextcloud too.
        granted = sorted(FAKE.passwords - {PASTED})
        self.assertEqual(len(granted), 1)
        r = self.client.post("/revoke", data={"token": tok["refresh_token"], "client_id": client_id})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(FAKE.deleted, granted)
        self.assertEqual(self.mcp(tok["access_token"], "tools/list", rid=5).status_code, 401)

    def test_revoke_goes_ahead_when_nextcloud_fails(self):
        client_id = self.register()
        verifier, path, _ = self.to_key_step(client_id)
        self.client.get(path)
        FAKE.granted = True
        tok = self.tokens(client_id, self.client.get(path).text, verifier)
        saved = FAKE.handle
        FAKE.handle = lambda request: (_ for _ in ()).throw(RuntimeError("down"))
        try:
            from open_connectors.apps.nextcloud import adapter
            adapter.TRANSPORT = FAKE.transport
            r = self.client.post("/revoke", data={"token": tok["access_token"], "client_id": client_id})
        finally:
            FAKE.handle = saved
            adapter.TRANSPORT = FAKE.transport
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.mcp(tok["access_token"], "tools/list").status_code, 401)

    def test_login_flow_expiry_shows_try_again(self):
        client_id = self.register()
        _, path, _ = self.to_key_step(client_id)
        self.client.get(path)
        flow_id = path.rsplit("/", 1)[-1]
        flow = self.application.store.get_flow(flow_id)
        flow["login"]["started"] = time.time() - 21 * 60          # Nextcloud forgot the login flow
        self.application.store.update_flow(flow_id, flow)
        failed = self.client.get(path)
        self.assertEqual(failed.status_code, 400)
        self.assertIn('class="fail"', failed.text)
        self.assertIn("Hub didn’t connect. Nothing was changed.".replace("’", "&#x27;"), failed.text.replace("’", "&#x27;"))
        self.assertIn("Access was not granted in time. Try again.", failed.text)
        self.assertIn(f'href="{path}"', failed.text)                 # Try again …
        self.client.get(path)                                        # … starts a new login flow
        self.assertEqual(len(FAKE.json_requests("/index.php/login/v2")), 2)

    def test_sign_in_stays_open_as_long_as_the_login_flow(self):
        client_id = self.register()
        _, path, _ = self.to_key_step(client_id)
        before = self.application.store._db.execute("SELECT expires FROM flows WHERE flow_id=?",
                                                    (path.rsplit("/", 1)[-1],)).fetchone()[0]
        r = self.client.get(path)
        after = self.application.store._db.execute("SELECT expires FROM flows WHERE flow_id=?",
                                                   (path.rsplit("/", 1)[-1],)).fetchone()[0]
        self.assertGreater(after, before)
        self.assertIn("__Host-oc-", r.headers.get("set-cookie", ""))

    def test_hostile_login_answers_refused(self):
        for mode in ("hostile_poll", "bad_token"):
            with self.subTest(mode=mode):
                FAKE.reset()
                FAKE.mode.add(mode)
                client_id = self.register()
                _, path, _ = self.to_key_step(client_id)
                r = self.client.get(path)
                self.assertEqual(r.status_code, 400)
                self.assertIn("Hub did not start the sign-in.", r.text)
                self.assertNotIn("evil.example", r.text)
                self.assertEqual(FAKE.other_hosts(), set())

    def test_hostile_login_host_is_ignored(self):
        FAKE.mode.add("hostile_login")
        client_id = self.register()
        _, path, _ = self.to_key_step(client_id)
        r = self.client.get(path)
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("evil.example", r.text)                     # rebuilt from the checked server
        self.assertIn(f"https://{HOST}/index.php/login/v2/flow/{FLOW_TOKEN}", r.text)

    def test_cancel_after_grant_deletes_the_app_password(self):
        # An assistant we do not know: Grant access, then "Allow?", then Not now.
        client_id = self.register(redirect="https://assistant.example/cb", name="Helper")
        verifier, challenge = pkce()
        r = self.client.get("/authorize", params={"response_type": "code", "client_id": client_id,
                                                  "redirect_uri": "https://assistant.example/cb", "code_challenge": challenge,
                                                  "code_challenge_method": "S256"})
        path = r.headers["location"]
        page = self.client.get(path).text
        self.client.post(path + "/server", data={"csrf": csrf_of(page), "address": HOST})
        self.client.get(path)
        FAKE.granted = True
        moved = self.client.get(path)
        self.assertEqual(moved.status_code, 303)
        allow = self.client.get(path).text
        self.assertIn("Allow “Helper”?", allow)
        self.assertIn("as Alice Example (alice@example.org)", allow)
        granted = sorted(FAKE.passwords - {PASTED})
        r = self.client.post(path + "/cancel", data={"csrf": csrf_of(allow)})
        self.assertEqual(r.status_code, 303)
        self.assertIn("error=access_denied", r.headers["location"])
        self.assertEqual(FAKE.deleted, granted)

    def test_cancel_while_waiting_deletes_nothing(self):
        client_id = self.register()
        _, path, csrf = self.to_key_step(client_id)
        self.client.get(path)
        r = self.client.post(path + "/cancel", data={"csrf": csrf})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(FAKE.deleted, [])

    def unknown_assistant_waiting(self):
        """An assistant we do not know (it stops at "Allow?"), waiting for Grant access on HOST."""
        client_id = self.register(redirect="https://assistant.example/cb", name="Helper")
        verifier, challenge = pkce()
        r = self.client.get("/authorize", params={"response_type": "code", "client_id": client_id,
                                                  "redirect_uri": "https://assistant.example/cb", "code_challenge": challenge,
                                                  "code_challenge_method": "S256"})
        path = r.headers["location"]
        page = self.client.get(path).text
        self.client.post(path + "/server", data={"csrf": csrf_of(page), "address": HOST})
        self.client.get(path)
        return path, csrf_of(page)

    def test_change_after_grant_never_sends_the_password_elsewhere(self):
        # A stale page of the same sign-in posts Change after the grant, then another server, then Not now.
        path, csrf = self.unknown_assistant_waiting()
        FAKE.granted = True
        self.assertEqual(self.client.get(path).status_code, 303)        # granted → "Allow?"
        granted = FAKE.granted_password
        self.assertEqual(self.client.post(path + "/change", data={"csrf": csrf}).status_code, 303)
        self.assertIn("Allow “Helper”?", self.client.get(path).text)    # Change does nothing on "Allow?"
        self.client.post(path + "/server", data={"csrf": csrf, "address": OTHER_HOST})
        self.client.get(path + "?how=paste")
        self.client.post(path + "/key", data={"csrf": csrf, "user": LOGIN_NAME, "key": PASTED})
        r = self.client.post(path + "/cancel", data={"csrf": csrf})
        self.assertEqual(r.status_code, 303)
        self.assertEqual(FAKE.deleted, [granted])                       # deleted on the server that made it …
        self.assertEqual([q.url.path for q in FAKE.requests if q.url.host == OTHER_HOST], [])   # … never elsewhere
        self.assertIn(PASTED, FAKE.passwords)                           # a pasted password is never deleted

    def test_leaving_right_after_grant_access_deletes_the_app_password(self):
        # The person clicks Grant access, then Not now (or Change) before the next refresh asked.
        for action in ("cancel", "change"):
            with self.subTest(action=action):
                FAKE.reset()
                client_id = self.register()
                _, path, csrf = self.to_key_step(client_id)
                self.client.get(path)
                FAKE.granted = True
                granted = FAKE.granted_password
                r = self.client.post(path + "/" + action, data={"csrf": csrf})
                self.assertEqual(r.status_code, 303)
                self.assertEqual(FAKE.deleted, [granted])
                self.assertNotIn(granted, FAKE.passwords)
                if action == "change":
                    self.assertIn("Hub web address", self.client.get(path).text)

    def test_paste_after_grant_access_deletes_only_the_granted_one(self):
        # Grant access was clicked in Nextcloud, but the person pasted an app password instead.
        path, csrf = self.unknown_assistant_waiting()
        FAKE.granted = True
        granted = FAKE.granted_password
        self.client.get(path + "?how=paste")
        ok = self.client.post(path + "/key", data={"csrf": csrf, "user": LOGIN_NAME, "key": PASTED})
        self.assertEqual(ok.status_code, 303)                            # → "Allow?"
        self.assertEqual(FAKE.deleted, [granted])                        # the unused grant does not stay behind
        self.client.post(path + "/cancel", data={"csrf": csrf})
        self.assertEqual(FAKE.deleted, [granted])                        # the pasted password is the person's own
        self.assertIn(PASTED, FAKE.passwords)

    def test_revoke_with_an_expired_access_token_deletes_the_app_password(self):
        client_id = self.register()
        verifier, path, _ = self.to_key_step(client_id)
        self.client.get(path)
        FAKE.granted = True
        granted = FAKE.granted_password
        tok = self.tokens(client_id, self.client.get(path).text, verifier)
        self.application.store._db.execute("UPDATE tokens SET expires=? WHERE kind='access'", (time.time() - 10,))
        r = self.client.post("/revoke", data={"token": tok["access_token"], "client_id": client_id})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(FAKE.deleted, [granted])

    def test_refused_code_exchange_deletes_the_app_password(self):
        for case in ("pkce", "resource"):
            with self.subTest(case=case):
                FAKE.reset()
                client_id = self.register()
                verifier, path, _ = self.to_key_step(client_id)
                self.client.get(path)
                FAKE.granted = True
                done = self.client.get(path).text
                code = parse_qs(urlsplit(back_link(done)).query)["code"][0]
                data = {"grant_type": "authorization_code", "code": code, "redirect_uri": CLAUDE_CB,
                        "code_verifier": verifier, "client_id": client_id}
                if case == "pkce":
                    data["code_verifier"] = "x" * 50
                else:
                    data["resource"] = f"{PUBLIC}/other.example.com/mcp"
                r = self.client.post("/token", data=data)
                self.assertEqual(r.status_code, 400)
                self.assertEqual(FAKE.deleted, [FAKE.granted_password])

    def test_waiting_sign_ins_share_the_server_fairly(self):
        # A server's poll budget is shared: sign-ins that used it up never starve another one.
        self.oauth.POLL_PER_HOST = 2
        try:
            a = self.to_key_step(self.register())[1]
            b = self.to_key_step(self.register())[1]
            self.client.get(a)
            self.client.get(b)
            store = self.application.store
            for _ in range(5):                                           # A refreshes again and again
                fa = store.get_flow(a.rsplit("/", 1)[-1])
                fa["login"]["polled"] = 0
                store.update_flow(a.rsplit("/", 1)[-1], fa)
                self.client.get(a)
            polls = len(FAKE.json_requests("/index.php/login/v2/poll"))
            fb = store.get_flow(b.rsplit("/", 1)[-1])
            fb["login"]["polled"] = time.time() - 61                     # B's fair share: one ask a minute
            store.update_flow(b.rsplit("/", 1)[-1], fb)
            FAKE.granted = True
            done = self.client.get(b)
            self.assertEqual(len(FAKE.json_requests("/index.php/login/v2/poll")), polls + 1)
            self.assertIn('class="ok"', done.text)
        finally:
            self.oauth.POLL_PER_HOST = 10 ** 9

    def test_other_sign_ins_never_use_up_a_servers_starts(self):
        # Many sign-ins, from many visitors, start and restart login flows on the same server …
        client_id = self.register()
        main = self.client
        try:
            for n in range(31):
                # Each visitor arrives from its own address, as the proxy-header handling presents it.
                self.client = TestClient(self.application, base_url=PUBLIC, follow_redirects=False,
                                         client=(f"198.51.100.{n + 1}", 50000))
                _, path, csrf = self.to_key_step(client_id)
                for _ in range(self.oauth.MAX_LOGIN_STARTS):
                    self.assertEqual(self.client.get(path).status_code, 200)
                    self.client.post(path + "/change", data={"csrf": csrf})
                    self.client.post(path + "/server", data={"csrf": csrf, "address": HOST})
        finally:
            self.client = main
        self.assertGreater(len(FAKE.json_requests("/index.php/login/v2")), 90)
        # … another person's start, and restart, still go through.
        _, path, csrf = self.to_key_step(client_id)
        for _ in range(2):
            r = self.client.get(path)
            self.assertEqual(r.status_code, 200, r.text)
            self.assertIn("Click Log in, then Grant access", r.text)
            self.client.post(path + "/change", data={"csrf": csrf})
            self.client.post(path + "/server", data={"csrf": csrf, "address": HOST})

    def test_after_the_last_login_start_the_paste_fallback_stays_open(self):
        _, path, csrf = self.to_key_step(self.register())
        for _ in range(self.oauth.MAX_LOGIN_STARTS):
            self.client.get(path)                                        # a login flow starts
            self.client.post(path + "/change", data={"csrf": csrf})
            self.client.post(path + "/server", data={"csrf": csrf, "address": HOST})
        r = self.client.get(path)
        self.assertEqual(r.status_code, 429)
        text = visible(r.text)
        self.assertIn("Too many tries. Paste an app password instead.", text)
        self.assertNotIn("Try again", text)
        self.assertIn('placeholder="Paste your app password here"', r.text)
        self.assertEqual(len(FAKE.json_requests("/index.php/login/v2")), self.oauth.MAX_LOGIN_STARTS)
        ok = self.client.post(path + "/key", data={"csrf": csrf, "user": LOGIN_NAME, "key": PASTED})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertIn("Signed in as Alice Example", ok.text)

    # ------------------------------------------------------------------ paste fallback
    def test_paste_fallback(self):
        client_id = self.register()
        verifier, path, csrf = self.to_key_step(client_id)
        self.client.get(path)
        page = self.client.get(path + "?how=paste")
        text = visible(page.text)
        self.assertIn("Your picture › Settings › Security › Create new app password", text)
        self.assertIn("User name", text)
        self.assertIn("App password", text)
        self.assertIn('placeholder="Paste your app password here"', page.text)
        self.assertIn('placeholder="alice"', page.text)                # an example inside every box
        self.assertIn("Paste both below", text)                         # Nextcloud shows name + password together
        self.assertIn(f'href="https://{HOST}/" target="_blank"', page.text)
        self.assertNotIn("http-equiv=\"refresh\"", page.text)
        fr = self.client.get(path + "?lang=fr").text                  # the language switch keeps the step
        self.assertIn("Nom d’utilisateur".replace("’", "&#x27;"), fr.replace("’", "&#x27;"))
        self.assertIn("Créer un nouveau mot de passe d’application".replace("’", "&#x27;"), fr.replace("’", "&#x27;"))
        self.assertIn("Collez-les ci-dessous", fr)
        self.assertIn("Beide unten einfügen", self.client.get(path + "?lang=de").text)
        self.client.get(path + "?lang=en")
        bad = self.client.post(path + "/key", data={"csrf": csrf, "user": LOGIN_NAME, "key": "wrong-" + "w" * 40})
        self.assertEqual(bad.status_code, 400)
        self.assertIn('class="fail"', bad.text)
        self.assertIn("Hub refused this user name and app password.", bad.text)
        self.assertIn(f'href="{path}"', bad.text)
        again = self.client.get(path).text                            # Try again = the paste step, name kept
        self.assertIn(f'value="{LOGIN_NAME}"', again)
        ok = self.client.post(path + "/key", data={"csrf": csrf, "user": LOGIN_NAME, "key": PASTED})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertIn("Signed in as Alice Example (alice@example.org)", ok.text)
        tok = self.tokens(client_id, ok.text, verifier)
        self.client.post("/revoke", data={"token": tok["access_token"], "client_id": client_id})
        self.assertEqual(FAKE.deleted, [PASTED])

    # ------------------------------------------------------------------ the address step
    def test_address_check_refusals(self):
        cases = [("maintenance", "This Hub is being updated."), ("old", "This Hub is version 27.1.0. It needs version 28 or newer."),
                 ("not_nextcloud", "This address is not a Hub.")]
        for mode, words in cases:
            with self.subTest(mode=mode):
                FAKE.reset()
                if mode == "old":
                    FAKE.version = "27.1.0.4"
                else:
                    FAKE.mode.add(mode)
                client_id = self.register()
                _, path = self.start(client_id)
                page = self.client.get(path).text
                r = self.client.post(path + "/server", data={"csrf": csrf_of(page), "address": HOST})
                self.assertEqual(r.status_code, 400)
                self.assertIn(words, r.text)
                self.assertIn('aria-invalid="true"', r.text)

    def test_odoo_words_unchanged_for_hub_free_pages(self):
        from open_connectors.pages import flow as pages
        self.assertEqual(pages.t("ok.wrong", "en", app="Odoo"), "Not the right account? Delete the key in Odoo, then connect again.")
        for key in ("step.grant.nextcloud", "step.back", "paste.instead", "step.add.nextcloud", "step.paste.nextcloud",
                    "user.label", "password.label", "password.placeholder", "ok.wrong.nextcloud"):
            self.assertEqual(set(pages.T[key]), {"en", "fr", "de"}, key)
        for key in ("not_nextcloud", "nc_too_old", "maintenance", "login_failed", "login_limit", "login_expired",
                    "password_refused", "bad_password", "bad_user", "server_error"):
            self.assertEqual(set(pages.ERRORS[key]), {"en", "fr", "de"}, key)


if __name__ == "__main__":
    unittest.main()
