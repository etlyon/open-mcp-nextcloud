"""The Hub (Nextcloud) tools on a fake WebDAV: list, search, read with extraction, writes with
idempotency; always the calling connection's own server and credentials, never a local file, and
nothing (write keys, confirmations, the search lock) shared between two people's connections."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from io import BytesIO

from fastmcp import Client

from open_connectors.apps.nextcloud import tools
from open_connectors.oauth.server import CURRENT
from open_connectors.store import Connection
from tests.fake_nextcloud import HOST, LOGIN_NAME, FakeNextcloud

FAKE = FakeNextcloud()
PASTED = "pasted-" + "p" * 40


def docx_bytes(text: str) -> bytes:
    from docx import Document
    document = Document()
    document.add_paragraph(text)
    out = BytesIO()
    document.save(out)
    return out.getvalue()


class HubTools(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["OPEN_CONNECTORS_JOURNAL"] = f"{cls.tmp.name}/journal.sqlite"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        FAKE.reset()
        FAKE.dirs |= {"Projects", "Projects/Alpha"}
        FAKE.files["Projects/Alpha/plan.docx"] = (docx_bytes("Launch on Monday"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        FAKE.files["Projects/notes.txt"] = (b"hello  world\r\n\r\n\r\nbye", "text/plain")
        self.saved = tools.TRANSPORT
        tools.TRANSPORT = FAKE.transport
        conn = Connection(conn_id="c-hub-1", app="nextcloud", server=f"https://{HOST}", remote_user="alice",
                          client_id="t", resource="r", display={}, secret={"login_name": LOGIN_NAME, "app_password": PASTED},
                          scope="read write send")
        self.token = CURRENT.set(conn)

    def tearDown(self):
        CURRENT.reset(self.token)
        tools.TRANSPORT = self.saved

    async def test_list(self):
        items = json.loads(await tools.nextcloud_list(tools.ListInput(path="Projects")))
        self.assertEqual({(i["path"], i["type"]) for i in items},
                         {("Projects/Alpha", "directory"), ("Projects/notes.txt", "file")})
        root = json.loads(await tools.nextcloud_list(tools.ListInput()))
        self.assertEqual([i["path"] for i in root], ["Projects"])
        self.assertTrue(all(r.headers["authorization"].startswith("Basic ") for r in FAKE.requests))
        self.assertTrue(all(r.headers["ocs-apirequest"] == "true" for r in FAKE.requests))

    async def test_search(self):
        found = json.loads(await tools.nextcloud_search(tools.SearchInput(query="PLAN")))
        self.assertEqual([m["path"] for m in found["matches"]], ["Projects/Alpha/plan.docx"])
        only_dirs = json.loads(await tools.nextcloud_search(tools.SearchInput(query="a", item_type="directory")))
        self.assertTrue(all(m["type"] == "directory" for m in only_dirs["matches"]))

    async def test_read_with_extraction(self):
        doc = json.loads(await tools.nextcloud_read(tools.ReadInput(path="/Projects/Alpha/plan.docx")))
        self.assertEqual((doc["format"], doc["text"]), ("docx", "Launch on Monday"))
        txt = json.loads(await tools.nextcloud_read(tools.ReadInput(path="Projects/notes.txt")))
        self.assertEqual(txt["text"], "hello world\n\nbye")
        self.assertFalse(txt["truncated"])

    async def test_write_with_idempotency(self):
        params = tools.WriteInput(path="Projects/out.txt", content="v1", idempotency_key="k-1")
        first = json.loads(await tools.nextcloud_write(params))
        again = json.loads(await tools.nextcloud_write(params))
        self.assertTrue(first["written"])
        self.assertFalse(first["idempotent_replay"])
        self.assertTrue(again["idempotent_replay"])
        self.assertEqual(FAKE.puts, 1)                                     # written once
        other = await tools.nextcloud_write(tools.WriteInput(path="Projects/out.txt", content="v2", idempotency_key="k-1"))
        self.assertEqual(FAKE.puts, 1)                                     # same key, other arguments: refused
        self.assertIn("error", json.loads(other))
        binary = json.loads(await tools.nextcloud_write(tools.WriteInput(
            path="Projects/b.bin", content_base64=base64.b64encode(b"\x00\x01").decode())))
        self.assertEqual(binary["bytes"], 2)

    async def test_mkdir_move_delete(self):
        made = json.loads(await tools.nextcloud_mkdir(tools.PathWriteInput(path="New", idempotency_key="m-1")))
        self.assertTrue(made["created"])
        exists = json.loads(await tools.nextcloud_mkdir(tools.PathWriteInput(path="New")))
        self.assertTrue(exists["already_exists"])
        moved = json.loads(await tools.nextcloud_move(tools.MoveInput(source="Projects/notes.txt", destination="New/notes.txt")))
        self.assertTrue(moved["moved"])
        self.assertIn("New/notes.txt", FAKE.files)
        gone = json.loads(await tools.nextcloud_delete(tools.PathWriteInput(path="New/notes.txt", idempotency_key="d-1")))
        self.assertTrue(gone["deleted_to_trash"])

    def test_policy_marks_reads_and_changes(self):
        """Reads run; mkdir (undoable) runs; overwrite, move and delete ask the person first."""
        from open_connectors.policy import Policy
        marks = {"nextcloud_search": tools.READ_ONLY, "nextcloud_list": tools.READ_ONLY, "nextcloud_read": tools.READ_ONLY,
                 "nextcloud_info": tools.READ_ONLY, "nextcloud_connection_status": tools.READ_ONLY,
                 "nextcloud_write": tools.OVERWRITE_ACTION, "nextcloud_mkdir": tools.WRITE_ACTION,
                 "nextcloud_move": tools.DESTRUCTIVE_ACTION, "nextcloud_delete": tools.DESTRUCTIVE_ACTION}
        asks = {"nextcloud_write", "nextcloud_move", "nextcloud_delete"}
        for name, annotations in marks.items():
            self.assertEqual(Policy().decide(name, annotations, tools.CONNECT_TOOL), "ask" if name in asks else "allowed", name)

    async def test_refusals_and_no_local_files(self):
        for path in ("../etc/passwd", "a/../../b", "./x"):
            with self.subTest(path=path):
                refused = await tools.nextcloud_read(tools.ReadInput(path=path))
                self.assertEqual(refused, "Error: ValueError: the call failed.")
                self.assertNotIn(path, refused)
        # An absolute-looking path is a path on the person's own Nextcloud, never on this machine.
        missing = await tools.nextcloud_read(tools.ReadInput(path="/etc/passwd"))
        self.assertTrue(missing.startswith("Error 404"))
        self.assertEqual(FAKE.requests[-1].url.path, "/remote.php/dav/files/alice/etc/passwd")
        from pydantic import ValidationError
        for extra in ({"file_path": "/etc/hosts"}, {"local": "/tmp/x"}):
            with self.subTest(extra=extra), self.assertRaises(ValidationError):
                tools.WriteInput(path="x.txt", content="a", **extra)
        FAKE.mode.add("xxe")
        xml_refused = await tools.nextcloud_search(tools.SearchInput(query="x"))
        self.assertEqual(xml_refused, "Error: _DocumentType: the call failed.")
        self.assertEqual(FAKE.other_hosts(), set())

    def test_document_type_refused_in_any_encoding(self):
        """The XML guard is the parser itself: a UTF-16 answer with entities is refused, never expanded."""
        doc = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE d [<!ENTITY x "EXPANDED">]>'
               '<d:multistatus xmlns:d="DAV:"><d:response><d:href>/remote.php/dav/files/alice/&x;</d:href>'
               '</d:response></d:multistatus>').encode("utf-16")
        self.assertNotIn(b"<!DOCTYPE", doc)
        with self.assertRaises(ValueError) as ctx:
            tools._parse_multistatus(doc)
        self.assertIn("document type", str(ctx.exception))
        plain = '<?xml version="1.0" encoding="UTF-16"?><d:multistatus xmlns:d="DAV:"/>'.encode("utf-16")
        self.assertEqual(tools._parse_multistatus(plain), [])

    def as_connection(self, conn_id: str) -> None:
        CURRENT.reset(self.token)
        self.token = CURRENT.set(Connection(conn_id=conn_id, app="nextcloud", server=f"https://{HOST}", remote_user="alice",
                                            client_id="t", resource="r", display={},
                                            secret={"login_name": LOGIN_NAME, "app_password": PASTED},
                                            scope="read write send"))

    async def test_idempotency_keys_are_per_connection(self):
        """Two people using the same idempotency key never replay each other's writes."""
        params = tools.WriteInput(path="Projects/shared.txt", content="v1", idempotency_key="same-key")
        self.as_connection("c-person-a")
        first = json.loads(await tools.nextcloud_write(params))
        self.as_connection("c-person-b")
        second = json.loads(await tools.nextcloud_write(params))
        self.assertFalse(first["idempotent_replay"])
        self.assertFalse(second["idempotent_replay"])
        self.assertEqual(FAKE.puts, 2)
        replay = json.loads(await tools.nextcloud_write(params))          # the same person again: replayed
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(FAKE.puts, 2)

    async def test_confirmations_are_per_connection(self):
        """A token the model can copy never deletes. The person's own form does, for that connection only."""
        args = {"params": {"path": "Projects/notes.txt"}}

        async def delete(conn_id, *, confirm=False, **extra):
            self.as_connection(conn_id)

            async def accept(message, response_type, params, ctx):
                return {"confirm": True}

            async with Client(tools.mcp, elicitation_handler=accept if confirm else None) as client:
                result = await client.call_tool("nextcloud_delete", {**args, **extra}, raise_on_error=False)
            text = result.content[0].text
            try:
                return json.loads(text)
            except ValueError:
                return text

        asked = await delete("c-person-a")
        asked_text = json.dumps(asked) if isinstance(asked, dict) else str(asked)
        self.assertNotIn("confirm_token", asked_text)
        self.assertIn("nothing ran", asked_text)
        other = await delete("c-person-b", confirm_token="1." + "ab" * 32)
        self.assertIn("confirm_token", json.dumps(other) if isinstance(other, dict) else str(other))
        self.assertIn("Projects/notes.txt", FAKE.files)
        done = await delete("c-person-a", confirm=True)
        self.assertTrue(done["deleted_to_trash"])
        self.assertNotIn("Projects/notes.txt", FAKE.files)

    async def test_one_persons_search_never_blocks_another(self):
        """One search at a time and the pause after a timeout are per person, not per server."""
        import asyncio
        import httpx
        release = asyncio.Event()
        state = {"slow": True, "timeout": False}

        async def answer(request):
            if request.method == "SEARCH" and state["timeout"]:
                raise httpx.ReadTimeout("slow index", request=request)
            if request.method == "SEARCH" and state["slow"]:
                state["slow"] = False
                await release.wait()                                       # A's search is still running …
            return FAKE.handle(request)

        tools.TRANSPORT = httpx.MockTransport(answer)
        try:
            self.as_connection("c-person-a")
            running = asyncio.ensure_future(tools.nextcloud_search(tools.SearchInput(query="plan")))
            await asyncio.sleep(0.05)
            self.assertIn("already running", await tools.nextcloud_search(tools.SearchInput(query="plan")))
            self.as_connection("c-person-b")                               # … B's search runs anyway
            found = await tools.nextcloud_search(tools.SearchInput(query="plan"))
            self.assertNotIn("Not searched", found)
            self.assertEqual([m["path"] for m in json.loads(found)["matches"]], ["Projects/Alpha/plan.docx"])
            release.set()
            self.assertIn("plan.docx", await running)
            state["timeout"] = True                                        # A's next search times out …
            self.as_connection("c-person-a")
            self.assertIn("timed out", await tools.nextcloud_search(tools.SearchInput(query="plan")))
            state["timeout"] = False
            self.assertIn("paused", await tools.nextcloud_search(tools.SearchInput(query="plan")))
            self.as_connection("c-person-b")                               # … and B is not paused
            found = await tools.nextcloud_search(tools.SearchInput(query="plan"))
            self.assertNotIn("Not searched", found)
            self.assertEqual([m["path"] for m in json.loads(found)["matches"]], ["Projects/Alpha/plan.docx"])
        finally:
            release.set()
            tools._search_locks.clear()
            tools._search_quiet_until.clear()

    async def test_refused_password_says_connect_again(self):
        FAKE.passwords.clear()
        result = await tools.nextcloud_list(tools.ListInput())
        self.assertTrue(result.startswith("Error 401"))
        self.assertIn("connect the Hub again", result)
        status = json.loads(await tools.nextcloud_connection_status())
        self.assertFalse(status["connected"])

    async def test_no_connection_no_call(self):
        CURRENT.reset(self.token)
        self.token = CURRENT.set(None)
        self.assertIn("HubCredentialError", await tools.nextcloud_list(tools.ListInput()))
        self.assertEqual(FAKE.requests, [])


if __name__ == "__main__":
    unittest.main()
