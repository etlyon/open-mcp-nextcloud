"""Hub (Nextcloud) sign-in pieces against the fake Nextcloud: address check, Login Flow v2,
identity, app password deletion, listed servers; and Odoo left exactly as it was."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from open_connectors import net
from open_connectors.apps.nextcloud import probe
from tests.fake_nextcloud import FLOW_TOKEN, HOST, LOGIN_NAME, POLL_TOKEN, FakeNextcloud

FAKE = FakeNextcloud()
PASTED = "pasted-" + "p" * 40


class Probe(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        FAKE.reset()
        self.t = FAKE.transport

    async def test_address_good_and_page_paths_dropped(self):
        for typed in (HOST, f"https://{HOST}/", f"https://{HOST}/apps/files", f"https://{HOST}/index.php/login",
                      f"https://{HOST}/apps/files/files/12", f"https://{HOST}/apps/files/files?dir=/",
                      f"https://{HOST}/index.php/apps/files/?dir=/&fileid=2", f"https://{HOST}/apps/files/#top"):
            with self.subTest(typed=typed):
                server = await probe.check_address(typed, transport=self.t)
                self.assertEqual(server.url, f"https://{HOST}")
                self.assertEqual(server.version, "30.0.2")
        self.assertEqual(FAKE.requests[0].url.path, "/status.php")

    async def test_address_refusals(self):
        for mode, code in (("maintenance", "maintenance"), ("not_nextcloud", "not_nextcloud")):
            FAKE.reset()
            FAKE.mode.add(mode)
            with self.subTest(mode=mode), self.assertRaises(probe.NextcloudCheckError) as ctx:
                await probe.check_address(HOST, transport=self.t)
            self.assertEqual(ctx.exception.code, code)
        FAKE.reset()
        FAKE.version = "27.1.11.2"
        with self.assertRaises(probe.NextcloudCheckError) as ctx:
            await probe.check_address(HOST, transport=self.t)
        self.assertEqual((ctx.exception.code, ctx.exception.detail), ("nc_too_old", "27.1.11"))
        for typed, code in (("http://" + HOST, "not_https"), ("198.51.100.7", "ip_literal"), (HOST + ":8443", "port"),
                            (f"https://user@{HOST}/?dir=/", "userinfo")):
            with self.subTest(typed=typed), self.assertRaises(net.AddressError) as ctx2:
                await probe.check_address(typed, transport=self.t)
            self.assertEqual(ctx2.exception.code, code)

    async def test_login_flow_start_poll_grant(self):
        started = await probe.start_login(f"https://{HOST}", transport=self.t)
        self.assertEqual((started.flow_token, started.poll_token), (FLOW_TOKEN, POLL_TOKEN))
        self.assertEqual(probe.login_url(f"https://{HOST}", started.flow_token),
                         f"https://{HOST}/index.php/login/v2/flow/{FLOW_TOKEN}")
        self.assertIsNone(await probe.poll_login(f"https://{HOST}", started.poll_token, transport=self.t))
        FAKE.granted = True
        login_name, password = await probe.poll_login(f"https://{HOST}", started.poll_token, transport=self.t)
        self.assertEqual(login_name, LOGIN_NAME)
        self.assertIsNone(await probe.poll_login(f"https://{HOST}", started.poll_token, transport=self.t))  # once
        who = await probe.identify(f"https://{HOST}", password, login_name, transport=self.t)
        self.assertEqual((who.user_id, who.name, who.email), ("alice", "Alice Example", "alice@example.org"))
        self.assertEqual(FAKE.other_hosts(), set())                  # the 'server' field was never followed
        self.assertTrue(await probe.delete_app_password(f"https://{HOST}", login_name, password, transport=self.t))
        with self.assertRaises(probe.NextcloudCheckError) as ctx:
            await probe.identify(f"https://{HOST}", password, login_name, transport=self.t)
        self.assertEqual(ctx.exception.code, "password_refused")

    async def test_hostile_login_answers(self):
        for mode in ("hostile_poll", "bad_token"):
            FAKE.reset()
            FAKE.mode.add(mode)
            with self.subTest(mode=mode), self.assertRaises(probe.NextcloudCheckError) as ctx:
                await probe.start_login(f"https://{HOST}", transport=self.t)
            self.assertEqual(ctx.exception.code, "login_failed")
        FAKE.reset()
        FAKE.mode.add("hostile_login")                               # only the token is taken; the host is dropped
        started = await probe.start_login(f"https://{HOST}", transport=self.t)
        self.assertTrue(probe.login_url(f"https://{HOST}", started.flow_token).startswith(f"https://{HOST}/"))
        with self.assertRaises(probe.NextcloudCheckError):
            probe.login_url(f"https://{HOST}", "../../evil")
        with self.assertRaises(probe.NextcloudCheckError):
            await probe.poll_login(f"https://{HOST}", "short", transport=self.t)

    async def test_pasted_password(self):
        who = await probe.identify(f"https://{HOST}", f"  {PASTED} ", LOGIN_NAME, transport=self.t)
        self.assertEqual(who.user_id, "alice")
        for password, user, code in (("wrong-" + "w" * 30, LOGIN_NAME, "password_refused"), ("a b", LOGIN_NAME, "bad_password"),
                                     (PASTED, "", "bad_user"), (PASTED, "a:b", "bad_user")):
            with self.subTest(code=code), self.assertRaises(probe.NextcloudCheckError) as ctx:
                await probe.identify(f"https://{HOST}", password, user, transport=self.t)
            self.assertEqual(ctx.exception.code, code)

    async def test_delete_never_raises(self):
        self.assertFalse(await probe.delete_app_password(f"https://{HOST}", LOGIN_NAME, "unknown-" + "u" * 30, transport=self.t))
        self.assertFalse(await probe.delete_app_password("not an address", LOGIN_NAME, PASTED, transport=self.t))

    def test_app_passwords_never_get_a_reminder(self):
        from open_connectors.apps.nextcloud import adapter
        from open_connectors.reminder import reminder_text
        who = probe.NextcloudIdentity(user_id="alice", login_name=LOGIN_NAME, name="A", email="")
        self.assertIsNone(reminder_text("nextcloud", adapter.secret(PASTED, who)))
        self.assertEqual(adapter.display(who)["label"], "A")
        self.assertEqual(adapter.remote_user(who), "alice")


class ListedHubServers(unittest.TestCase):
    """allowed_servers is checked before any contact with the typed host, as for Odoo."""

    def test_unlisted_refused_without_contact(self):
        FAKE.reset()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        conf = Path(tmp.name) / "config.toml"
        conf.write_text(f'public_url = "https://hub.connector.test"\napp = "nextcloud"\nstate_dir = "{tmp.name}/state"\n'
                        f'source_url = "https://code.example.org/x"\nallowed_servers = ["files.example.net"]\n')
        os.environ["OPEN_CONNECTORS_JOURNAL"] = f"{tmp.name}/journal.sqlite"
        from open_connectors import config, server
        from open_connectors.apps.nextcloud import adapter
        saved = adapter.TRANSPORT
        adapter.TRANSPORT = FAKE.transport
        self.addCleanup(setattr, adapter, "TRANSPORT", saved)
        with TestClient(server.Application(config.load(conf)), base_url="https://hub.connector.test",
                        follow_redirects=False) as client:
            from tests.test_hub_flow import HubFlow, csrf_of
            t = HubFlow()
            t.client = client
            client_id = t.register()
            _, path = t.start(client_id)
            page = client.get(path).text
            r = client.post(path + "/server", data={"csrf": csrf_of(page), "address": HOST})
        self.assertEqual(r.status_code, 403)
        self.assertIn("works only with the servers its operator lists", r.text)
        self.assertEqual(FAKE.requests, [])




if __name__ == "__main__":
    unittest.main()
