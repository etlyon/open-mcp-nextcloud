"""Hub (Nextcloud) tools over WebDAV, per connection.

The eight file tools' logic, annotations, path rules and size caps are carried
over from an earlier private implementation. Around them:

- every request authenticates as the calling connection's own Nextcloud login
  name and app password (HTTP Basic, ``OCS-APIRequest: true``), read from the
  connection on every call, and goes to that connection's own server only,
  through the guarded road in :mod:`open_connectors.net` (checked public IP,
  no proxy, no redirect, capped answers);
- the WebDAV files root is ``/remote.php/dav/files/<user id>``, the user id
  Nextcloud named when the person connected;
- the person connects on the sign-in pages (Grant access, or a pasted app
  password), so there is no connect tool; ``nextcloud_connection_status``
  checks the connection instead;
- keyed writes are journaled under (connection, tool, key);
- the policy middleware asks the person before overwriting, moving or
  deleting, whatever the assistant shows;
- no tool reads a file from the connector's own machine: content travels only
  as text or base64 bytes.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import mimetypes
import posixpath
import re
import time
import xml.etree.ElementTree as ET
from xml.parsers import expat
from io import BytesIO
from typing import Annotated, Any, Literal
from urllib.parse import quote, unquote, urlsplit
from zipfile import BadZipFile, ZipFile

import httpx
from fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, field_validator

from open_connectors import identity, net
from open_connectors.apps.nextcloud import probe
from open_connectors.journal import run_keyed
from open_connectors.policy import AccountToolPolicy

LOGGER = logging.getLogger("open_connectors.apps.nextcloud")

APP = "nextcloud"
CONNECT_TOOL = "nextcloud_connect"           # never registered: people connect on the sign-in pages

DENIED_HOSTS: frozenset[str] = frozenset()   # set once at start from the settings
TRANSPORT: httpx.AsyncBaseTransport | None = None   # tests only (an in-process fake Nextcloud)

DAV_FILES_PREFIX = "/remote.php/dav/files/"
DAV_HEADERS = {"OCS-APIRequest": "true", "User-Agent": probe.USER_AGENT}

MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024
MAX_LISTING_BYTES = 8 * 1024 * 1024
MAX_TEXT_CHARS = 50_000
DEFAULT_READ_CHARS = 20_000
MAX_PDF_PAGES = 75
MAX_OFFICE_UNCOMPRESSED_BYTES = 200 * 1024 * 1024

DAV_NS = "DAV:"
OC_NS = "http://owncloud.org/ns"
NS = {"d": DAV_NS, "oc": OC_NS}
ET.register_namespace("d", DAV_NS)
ET.register_namespace("oc", OC_NS)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)
WRITE_ACTION = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
OVERWRITE_ACTION = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True)
DESTRUCTIVE_ACTION = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True)

mcp = FastMCP(
    name="Hub",
    instructions=(
        "Search before listing folders manually. Read only the relevant files. "
        "nextcloud_read extracts common document formats in memory and returns provenance metadata. "
        "When next_start_char is not null, continue from that offset only if the task needs more text. "
        "Every call acts as the connected person's own Nextcloud user, with that user's rights; "
        "nextcloud_connection_status names that user. "
        "If Nextcloud refuses the app password, tell the person to connect the Hub again in their assistant."
    ),
    middleware=[AccountToolPolicy(app=APP, connect_tool=CONNECT_TOOL)],
)

# A keyed write waits at most its own upstream timeout for an earlier call with
# the same key; at startup, older unfinished claims are marked uncertain.
KEYED_TOOL_TIMEOUTS: dict[str, float] = {
    "nextcloud_write": 300.0,
    "nextcloud_mkdir": 30.0,
    "nextcloud_move": 30.0,
    "nextcloud_delete": 30.0,
}

IdempotencyKey = Annotated[
    str | None,
    Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9._:-]+$",
        json_schema_extra={"x-ebot-bookkeeping": "idempotency"},
        description=(
            "Optional caller-chosen key (1-128 characters: A-Z a-z 0-9 . _ : -). "
            "Repeating the call with the same key and arguments returns the recorded "
            "result without writing again; the same key with other arguments is refused."
        ),
    ),
]

REFUSED_STORED_PASSWORD = (
    "Nextcloud refused this connection's app password; it has probably been deleted in Nextcloud "
    "(Settings, Security). Ask the person to connect the Hub again in their assistant."
)


class HubCredentialError(RuntimeError):
    """This connection holds no usable Nextcloud credential; the message never carries it."""


def startup_check() -> None:
    """Nothing to configure per operator: each connection names its own server."""
    if not callable(nextcloud_connection_status):
        raise ValueError("nextcloud_connection_status is not registered.")


# --- The calling connection: its server, its WebDAV root and its own credential ---


def _connection() -> Any:
    try:
        return identity.current_connection()
    except identity.IdentityRefused as exc:
        raise HubCredentialError(str(exc)) from None


def _base() -> str:
    return probe.root_origin(_connection().server).url


def _dav_user() -> str:
    """The Nextcloud user whose files this call addresses: the one named at connect time."""
    user = _connection().remote_user
    if not user or "/" in user:
        raise HubCredentialError("This connection names no Nextcloud user; connect the Hub again.")
    return user


def _auth() -> httpx.BasicAuth:
    secret = _connection().secret
    login_name, app_password = secret.get("login_name"), secret.get("app_password")
    if not isinstance(login_name, str) or not login_name or not isinstance(app_password, str) or not app_password:
        raise HubCredentialError("This connection holds no Nextcloud app password; connect the Hub again.")
    return httpx.BasicAuth(login_name, app_password)


def _client(timeout: float) -> httpx.AsyncClient:
    auth = _auth()
    client = net.client_for(timeout=timeout, denied_hosts=DENIED_HOSTS, headers=dict(DAV_HEADERS),
                            transport=TRANSPORT)
    client.auth = auth
    return client


async def _request(method: str, url: str, *, timeout: float = 30.0, headers: dict[str, str] | None = None,
                   content: bytes | None = None, max_bytes: int = MAX_LISTING_BYTES) -> bytes:
    """One request to the connection's own server; raises httpx.HTTPStatusError on any non-2xx answer."""
    async with _client(timeout) as client:
        async with client.stream(method, url, headers=headers, content=content) as response:
            body = await net.read_capped(response, max_bytes)
            response.raise_for_status()
            return body


# --- Paths (logic carried over) -------------------------------------------------


def _parts(value: str) -> list[str]:
    parts = [part for part in value.split("/") if part != ""]
    if any(part in {".", ".."} for part in parts):
        raise ValueError("Path must be relative to the Nextcloud user root and may not contain '.' or '..'.")
    return parts


def _clean_path(path: str) -> str:
    raw_value = path.strip()
    is_canonical_dav_path = raw_value.startswith(DAV_FILES_PREFIX)
    value = raw_value[len(DAV_FILES_PREFIX):] if is_canonical_dav_path else raw_value.strip("/")
    value = unquote(value).strip("/")
    if not value:
        return ""
    if "\x00" in value:
        raise ValueError("Path contains an invalid null byte.")
    clean = "/".join(_parts(value))
    return f"{DAV_FILES_PREFIX}{clean}" if is_canonical_dav_path else clean


def _encoded_path(path: str) -> str:
    clean = _clean_path(path)
    if clean.startswith(DAV_FILES_PREFIX):
        clean = clean[len(DAV_FILES_PREFIX):]
    return "/".join(quote(segment, safe="") for segment in clean.split("/")) if clean else ""


def _dav_root() -> str:
    return f"{_base()}/remote.php/dav/"


def _webdav_base() -> str:
    return f"{_base()}/remote.php/dav/files/{quote(_dav_user(), safe='')}"


def _url(path: str) -> str:
    clean = _clean_path(path)
    encoded = _encoded_path(clean)
    if clean.startswith(DAV_FILES_PREFIX):
        return f"{_base()}{DAV_FILES_PREFIX}{encoded}"
    webdav_base = _webdav_base()
    return f"{webdav_base}/{encoded}" if encoded else f"{webdav_base}/"


def _relative_href(href: str) -> str:
    href_path = unquote(urlsplit(href).path).rstrip("/")
    prefix = f"/remote.php/dav/files/{_dav_user()}"
    if href_path == prefix:
        return "/"
    if href_path.startswith(prefix + "/"):
        return href_path[len(prefix) + 1:]
    if href_path.startswith(DAV_FILES_PREFIX) and len(href_path) > len(DAV_FILES_PREFIX):
        # WebDAV SEARCH can return canonical paths in the namespace of a
        # share's owner. Keep that server-issued path intact so a later list
        # or read can address the shared result directly with the same ACLs.
        return href_path
    raise ValueError("Nextcloud returned a path outside the DAV files namespace.")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _handle_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        if exc.response.status_code == 401:
            return f"Error 401: Nextcloud rejected the request. {REFUSED_STORED_PASSWORD}"
        return f"Error {exc.response.status_code}: Nextcloud rejected the request."
    if isinstance(exc, net.AddressError):
        return f"Error: AddressError: this connection's server cannot be reached safely ({exc.code})."
    return f"Error: {type(exc).__name__}: {exc}"


class _DocumentType(ValueError):
    pass


def _refuse_document_type(*_: Any) -> None:
    raise _DocumentType("Nextcloud returned XML with a document type; refused.")


def _xml(content: bytes) -> ET.Element:
    """Parse a WebDAV answer or an ODF part; a document type (entity tricks) is refused before any entity is read.

    The check is made by the XML parser itself (any encoding, e.g. UTF-16), not by searching the bytes.
    """
    scan = expat.ParserCreate()
    scan.StartDoctypeDeclHandler = _refuse_document_type
    scan.EntityDeclHandler = _refuse_document_type
    try:
        scan.Parse(content, True)
    except expat.ExpatError:
        raise ValueError("Nextcloud returned XML that cannot be read.") from None
    return ET.fromstring(content)


def _successful_props(response: ET.Element) -> ET.Element | None:
    for propstat in response.findall("d:propstat", NS):
        status = propstat.findtext("d:status", "", NS)
        if " 200 " in status:
            return propstat.find("d:prop", NS)
    return response.find(".//d:prop", NS)


def _parse_multistatus(content: bytes) -> list[dict[str, Any]]:
    root = _xml(content)
    items: list[dict[str, Any]] = []
    for response in root.findall("d:response", NS):
        href = response.findtext("d:href", "", NS)
        props = _successful_props(response)
        if not href or props is None:
            continue
        is_dir = props.find("d:resourcetype/d:collection", NS) is not None
        size_text = props.findtext("d:getcontentlength", "", NS) or props.findtext("oc:size", "", NS)
        try:
            size = int(size_text) if size_text else None
        except ValueError:
            size = None
        relative = _relative_href(href)
        items.append(
            {
                "path": relative,
                "name": props.findtext("d:displayname", "", NS) or posixpath.basename(relative.rstrip("/")),
                "type": "directory" if is_dir else "file",
                "size": size,
                "modified": props.findtext("d:getlastmodified", None, NS),
                "content_type": props.findtext("d:getcontenttype", None, NS),
            }
        )
    return items


def _build_search_body(query: str, root_path: str) -> bytes:
    search_request = ET.Element(f"{{{DAV_NS}}}searchrequest")
    basic = ET.SubElement(search_request, f"{{{DAV_NS}}}basicsearch")
    select = ET.SubElement(basic, f"{{{DAV_NS}}}select")
    prop = ET.SubElement(select, f"{{{DAV_NS}}}prop")
    for namespace, name in (
        (OC_NS, "fileid"),
        (DAV_NS, "displayname"),
        (DAV_NS, "resourcetype"),
        (DAV_NS, "getcontenttype"),
        (DAV_NS, "getcontentlength"),
        (DAV_NS, "getlastmodified"),
    ):
        ET.SubElement(prop, f"{{{namespace}}}{name}")

    from_el = ET.SubElement(basic, f"{{{DAV_NS}}}from")
    scope = ET.SubElement(from_el, f"{{{DAV_NS}}}scope")
    clean_root = _clean_path(root_path)
    encoded_root = _encoded_path(clean_root)
    scope_path = f"/files/{quote(_dav_user(), safe='')}"
    # SEARCH rejects a shared owner's canonical namespace even though the
    # same account can PROPFIND/GET it. Search the account's accessible root
    # and filter those server-issued canonical results after parsing instead.
    if encoded_root and not clean_root.startswith(DAV_FILES_PREFIX):
        scope_path += f"/{encoded_root}"
    ET.SubElement(scope, f"{{{DAV_NS}}}href").text = scope_path
    ET.SubElement(scope, f"{{{DAV_NS}}}depth").text = "infinity"

    where = ET.SubElement(basic, f"{{{DAV_NS}}}where")
    like = ET.SubElement(where, f"{{{DAV_NS}}}like")
    like_prop = ET.SubElement(like, f"{{{DAV_NS}}}prop")
    ET.SubElement(like_prop, f"{{{DAV_NS}}}displayname")
    ET.SubElement(like, f"{{{DAV_NS}}}literal").text = f"%{query}%"
    ET.SubElement(basic, f"{{{DAV_NS}}}orderby")
    return ET.tostring(search_request, encoding="utf-8", xml_declaration=True)


# --- Document extraction, in memory (logic carried over) ----------------------


def _validate_office_package(data: bytes) -> None:
    try:
        with ZipFile(BytesIO(data)) as archive:
            total = sum(item.file_size for item in archive.infolist())
    except BadZipFile as exc:
        raise ValueError("The office document is not a valid ZIP-based package.") from exc
    if total > MAX_OFFICE_UNCOMPRESSED_BYTES:
        raise ValueError("The expanded office document exceeds the configured safety limit.")


def _normalize_text(text: str) -> str:
    text = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r" +", " ", line).strip() for line in text.splitlines()]
    compact: list[str] = []
    blank = False
    for line in lines:
        if line:
            compact.append(line)
            blank = False
        elif compact and not blank:
            compact.append("")
            blank = True
    return "\n".join(compact).strip()


def _extract_pdf(data: bytes) -> tuple[str, dict[str, Any], list[str]]:
    from pypdf import PdfReader

    reader = PdfReader(BytesIO(data))
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception as exc:
            raise ValueError("The PDF is encrypted and cannot be read without a password.") from exc
    total_pages = len(reader.pages)
    page_limit = min(total_pages, MAX_PDF_PAGES)
    parts: list[str] = []
    warnings: list[str] = []
    for index in range(page_limit):
        try:
            page_text = reader.pages[index].extract_text() or ""
        except Exception:
            warnings.append(f"Page {index + 1} could not be extracted.")
            continue
        if page_text.strip():
            parts.append(f"[Page {index + 1}]\n{page_text}")
    if total_pages > page_limit:
        warnings.append(f"Only the first {page_limit} of {total_pages} pages were processed.")
    if not parts:
        warnings.append("No embedded text was found; this document may require OCR.")
    return "\n\n".join(parts), {"pages_total": total_pages, "pages_processed": page_limit}, warnings


def _extract_docx(data: bytes) -> tuple[str, dict[str, Any], list[str]]:
    from docx import Document

    _validate_office_package(data)
    document = Document(BytesIO(data))
    parts = [paragraph.text for paragraph in document.paragraphs if paragraph.text.strip()]
    table_rows = 0
    for table in document.tables:
        for row in table.rows:
            values = [cell.text.strip() for cell in row.cells]
            if any(values):
                parts.append("\t".join(values))
                table_rows += 1
    return "\n".join(parts), {"paragraphs": len(document.paragraphs), "table_rows": table_rows}, []


def _extract_xlsx(data: bytes, max_chars: int) -> tuple[str, dict[str, Any], list[str]]:
    from openpyxl import load_workbook

    _validate_office_package(data)
    workbook = load_workbook(BytesIO(data), read_only=True, data_only=True)
    sheet_count = len(workbook.sheetnames)
    parts: list[str] = []
    cells_read = 0
    truncated = False
    try:
        for worksheet in workbook.worksheets:
            parts.append(f"[Sheet: {worksheet.title}]")
            for row in worksheet.iter_rows(values_only=True):
                values = ["" if value is None else str(value) for value in row]
                while values and values[-1] == "":
                    values.pop()
                if not values:
                    continue
                parts.append("\t".join(values))
                cells_read += len(values)
                if sum(len(part) + 1 for part in parts) > max_chars * 2:
                    truncated = True
                    break
            if truncated:
                break
    finally:
        workbook.close()
    warnings = ["Spreadsheet processing stopped after reaching the extraction limit."] if truncated else []
    return "\n".join(parts), {"sheets": sheet_count, "cells_read": cells_read, "extraction_truncated": truncated}, warnings


def _extract_pptx(data: bytes) -> tuple[str, dict[str, Any], list[str]]:
    from pptx import Presentation

    _validate_office_package(data)
    presentation = Presentation(BytesIO(data))
    parts: list[str] = []
    for index, slide in enumerate(presentation.slides, start=1):
        slide_parts: list[str] = []
        for shape in slide.shapes:
            text = getattr(shape, "text", "")
            if text and text.strip():
                slide_parts.append(text.strip())
        if slide_parts:
            parts.append(f"[Slide {index}]\n" + "\n".join(slide_parts))
    return "\n\n".join(parts), {"slides": len(presentation.slides)}, []


def _extract_odf(data: bytes) -> tuple[str, dict[str, Any], list[str]]:
    _validate_office_package(data)
    with ZipFile(BytesIO(data)) as archive:
        try:
            content = archive.read("content.xml")
        except KeyError as exc:
            raise ValueError("The OpenDocument package does not contain content.xml.") from exc
    root = _xml(content)
    paragraphs: list[str] = []
    for element in root.iter():
        if element.tag.endswith("}p") or element.tag.endswith("}h"):
            text = "".join(element.itertext()).strip()
            if text:
                paragraphs.append(text)
    return "\n".join(paragraphs), {"paragraphs": len(paragraphs)}, []


TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".yaml", ".yml",
    ".xml", ".html", ".htm", ".css", ".js", ".py", ".sql", ".log", ".rtf",
}


def _extract_document(data: bytes, path: str, content_type: str | None, max_chars: int,
                      start_char: int = 0) -> dict[str, Any]:
    extension = posixpath.splitext(path)[1].lower()
    guessed_type = mimetypes.guess_type(path)[0]
    media_type = (content_type or guessed_type or "application/octet-stream").split(";", 1)[0].lower()
    warnings: list[str] = []
    stats: dict[str, Any] = {}

    if media_type.startswith("text/") or extension in TEXT_EXTENSIONS or media_type in {
        "application/json", "application/xml", "application/javascript",
    }:
        text = data.decode("utf-8-sig", errors="replace")
        document_format = "text"
    elif extension == ".pdf" or media_type == "application/pdf":
        text, stats, warnings = _extract_pdf(data)
        document_format = "pdf"
    elif extension in {".docx", ".dotx", ".docm"} or "wordprocessingml" in media_type:
        text, stats, warnings = _extract_docx(data)
        document_format = "docx"
    elif extension in {".xlsx", ".xlsm", ".xltx"} or "spreadsheetml" in media_type:
        text, stats, warnings = _extract_xlsx(data, start_char + max_chars)
        document_format = "xlsx"
    elif extension in {".pptx", ".potx", ".ppsx"} or "presentationml" in media_type:
        text, stats, warnings = _extract_pptx(data)
        document_format = "pptx"
    elif extension in {".odt", ".ods", ".odp", ".ott", ".ots", ".otp"} or "opendocument" in media_type:
        text, stats, warnings = _extract_odf(data)
        document_format = "opendocument"
    else:
        raise ValueError(
            f"Unsupported document format '{extension or media_type}'. "
            "Supported formats include text, PDF, DOCX, XLSX, PPTX, and OpenDocument."
        )

    text = _normalize_text(text)
    total_characters = len(text)
    end_char = min(total_characters, start_char + max_chars)
    chunk = text[start_char:end_char]
    extraction_truncated = bool(stats.get("extraction_truncated"))
    truncated = end_char < total_characters or extraction_truncated
    next_start_char = end_char if truncated else None
    if start_char >= total_characters and total_characters:
        warnings.append(f"start_char {start_char} is beyond the extracted text length {total_characters}.")
    elif truncated:
        warnings.append(f"Returned characters {start_char}-{end_char}; continue with start_char={end_char}.")
    return {
        "path": _clean_path(path),
        "format": document_format,
        "content_type": media_type,
        "source_bytes": len(data),
        "characters": len(chunk),
        "total_characters_extracted": total_characters,
        "start_char": start_char,
        "end_char": end_char,
        "next_start_char": next_start_char,
        "truncated": truncated,
        "warnings": warnings,
        "stats": stats,
        "text": chunk,
    }


async def _fetch_document(path: str) -> tuple[bytes, str | None]:
    chunks: list[bytes] = []
    received = 0
    async with _client(timeout=90.0) as client:
        async with client.stream("GET", _url(path)) as response:
            response.raise_for_status()
            content_length = response.headers.get("Content-Length")
            if content_length and content_length.isdigit() and int(content_length) > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"Document exceeds the {MAX_DOWNLOAD_BYTES:,}-byte download limit.")
            async for chunk in response.aiter_bytes():
                received += len(chunk)
                if received > MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"Document exceeds the {MAX_DOWNLOAD_BYTES:,}-byte download limit.")
                chunks.append(chunk)
            return b"".join(chunks), response.headers.get("Content-Type")


# --- Inputs: only paths on the person's own Nextcloud, and content as text or bytes ---


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PathInput(_Input):
    path: str = Field(max_length=4096, description="Relative path, or the canonical DAV path returned by search/list")


class ReadInput(PathInput):
    start_char: int = Field(default=0, ge=0, le=1_000_000,
                            description="Character offset for continuing a previously truncated read")
    max_chars: int = Field(default=DEFAULT_READ_CHARS, ge=1_000, le=200_000,
                           description="Maximum extracted characters returned to the model")


class ListInput(_Input):
    path: str = Field(default="", max_length=4096, description="Exact relative/canonical directory path; empty means user root")
    depth: Literal[0, 1] = Field(default=1, description="0 returns only metadata; 1 lists immediate children")


class SearchInput(_Input):
    query: str = Field(min_length=1, max_length=200, description="Case-insensitive partial file or folder name")
    root_path: str = Field(default="", max_length=4096, description="Optional relative/canonical directory scope")
    item_type: Literal["any", "directory", "file"] = Field(default="any")
    limit: int = Field(default=25, ge=1, le=100)

    @field_validator("query")
    @classmethod
    def clean_query(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Search query may not be blank.")
        return value


class WriteInput(_Input):
    path: str = Field(max_length=4096, description="Destination path on Nextcloud")
    content: str | None = Field(default=None, description="Text content to write")
    content_base64: str | None = Field(default=None, description="Base64-encoded binary content")
    mime_type: str | None = Field(default=None, max_length=200, description="MIME type for binary content")
    idempotency_key: IdempotencyKey = None


class MoveInput(_Input):
    source: str = Field(max_length=4096, description="Current path")
    destination: str = Field(max_length=4096, description="New path")
    overwrite: bool = Field(default=False, description="Overwrite if destination exists")
    idempotency_key: IdempotencyKey = None


class PathWriteInput(PathInput):
    idempotency_key: IdempotencyKey = None


# --- Keyed writes: the outcome classification, journaled per connection ---------

# Error texts come from _handle_error ("Error <status>: ..." and
# "Error: <ExceptionName>: ...") or from a tool's own checks before any request.
_HTTP_STATUS_ERROR = re.compile(r"^Error (\d{3}): ")
_EXCEPTION_ERROR = re.compile(r"^Error: ([A-Za-z_][A-Za-z0-9_]*): ")
# httpx failures after which the request may already have reached Nextcloud.
_MAYBE_DELIVERED = frozenset(
    {
        "NetworkError",
        "ProtocolError",
        "ReadError",
        "ReadTimeout",
        "RemoteProtocolError",
        "TimeoutException",
        "TransportError",
        "WriteError",
        "WriteTimeout",
    }
)


def classify_hub_result(result: str) -> str:
    """Return "success", "definitive" (nothing was written) or "uncertain"."""
    if not result.startswith("Error"):
        return "success"
    status = _HTTP_STATUS_ERROR.match(result)
    if status:
        return "uncertain" if int(status.group(1)) >= 500 else "definitive"
    exception = _EXCEPTION_ERROR.match(result)
    if exception and exception.group(1) in _MAYBE_DELIVERED:
        return "uncertain"
    return "definitive"


def _keyed_arguments(params: BaseModel) -> dict[str, Any]:
    return params.model_dump(mode="json", exclude={"idempotency_key"})


async def _keyed(tool: str, params: Any, *, execute: Any, already_done: Any = None, describe: Any = None) -> str:
    """Run one keyed write at most once per (connection, tool, key)."""
    try:
        account = identity.current_account()
    except identity.IdentityRefused as exc:
        return _handle_error(exc)
    return await run_keyed(
        account=account,
        tool=tool,
        key=params.idempotency_key,
        arguments=_keyed_arguments(params),
        timeout=KEYED_TOOL_TIMEOUTS[tool],
        execute=execute,
        classify=classify_hub_result,
        already_done=already_done,
        describe=describe,
        upstream="Nextcloud",
    )


async def _ref_state(path: str) -> dict[str, Any]:
    """Read-only PROPFIND Depth 0 used by the idempotency layer (check-by-ref)."""
    try:
        content = await _request("PROPFIND", _url(path), headers={"Depth": "0"})
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {"exists": False}
        raise
    items = _parse_multistatus(content)
    return {"exists": True, "type": items[0]["type"] if items else None}


async def _ref_states(**paths: str) -> dict[str, Any]:
    states: dict[str, Any] = {}
    for label, path in paths.items():
        try:
            states[label] = await _ref_state(path)
        except Exception as exc:
            states[label] = {"error": type(exc).__name__}
    return states


async def _mkdir_already_done(params: PathWriteInput) -> str | None:
    try:
        path = _clean_path(params.path)
    except ValueError:
        return None  # the tool body reports an invalid path exactly as before
    state = await _ref_state(path)
    if state["exists"] and state["type"] == "directory":
        return _json({"created": False, "already_exists": True, "path": path})
    return None


async def _move_already_done(params: MoveInput) -> str | None:
    try:
        source, destination = _clean_path(params.source), _clean_path(params.destination)
    except ValueError:
        return None
    if (await _ref_state(source))["exists"]:
        return None
    if (await _ref_state(destination))["exists"]:
        return _json({"moved": False, "already_at_destination": True, "source": source, "destination": destination})
    return None


async def _delete_already_done(params: PathWriteInput) -> str | None:
    try:
        path = _clean_path(params.path)
    except ValueError:
        return None
    if not (await _ref_state(path))["exists"]:
        return _json({"deleted_to_trash": False, "already_absent": True, "path": path})
    return None


# --- The connection itself --------------------------------------------------------


@mcp.tool(name="nextcloud_connection_status", annotations=READ_ONLY)
async def nextcloud_connection_status() -> str:
    """Verify this connection's app password and show whose it is (user, name, email).

    Read-only; never returns credential material.
    """
    try:
        content = await _request("GET", _base() + probe.OCS_USER_PATH, headers={"Accept": "application/json"},
                                 max_bytes=256 * 1024)
        payload = json.loads(content.decode("utf-8"))
        data = payload["ocs"]["data"]
        user_id = data.get("id")
        if not isinstance(user_id, str) or user_id != _dav_user():
            raise ValueError("Nextcloud named another user for this app password.")
        return _json({
            "status": "connected",
            "connected": True,
            "credential_verified_for_this_call": True,
            "identity": {"user": user_id, "display_name": data.get("displayname") or data.get("display-name"),
                         "email": data.get("email")},
            "credential_expires": False,
            "credential_material_exposed": False,
        })
    except Exception as exc:
        return _json({"status": "not_working", "connected": False, "error": _handle_error(exc),
                      "credential_material_exposed": False})


# --- The name search: one at a time per server, and a fast answer after a timeout ---
# One name search is one WebDAV SEARCH over the whole tree. On a large Nextcloud this
# makes its database read the whole file index, which can take longer than
# SEARCH_TIMEOUT; Nextcloud keeps the query running after we give up, so retried
# searches pile up and make the next one slower still. So: one name search at a
# time per server; a timeout answers at once that the assistant should use the
# file's path, and for SEARCH_COOLDOWN after it every name search on that server
# answers that at once without asking Nextcloud.
SEARCH_TIMEOUT = 30.0
SEARCH_COOLDOWN = 180.0
SEARCH_USE_PATH = (
    "Not searched: the Hub's file-name search {why} Do not retry it. Use the file's path instead: nextcloud_list on "
    "the folder you expect it in, then nextcloud_read or nextcloud_info on the file."
)
# One search at a time and the pause after a timeout are per connection (one person on one server):
# a search by one person never blocks another person's search on the same Hub.
_search_locks: dict[tuple[str, str], asyncio.Lock] = {}
_search_quiet_until: dict[tuple[str, str], float] = {}


# --- The eight file tools (logic carried over) ---------------------------------------


@mcp.tool(name="nextcloud_search", annotations=READ_ONLY)
async def nextcloud_search(params: SearchInput) -> str:
    """Search accessible Nextcloud file and folder names, over the whole tree. On a large Hub it is slow and may
    answer that you should use the path: when you know where a file is, use nextcloud_list, nextcloud_info or
    nextcloud_read."""
    started = time.monotonic()
    try:
        key = (urlsplit(_base()).hostname or "", identity.current_account())
    except Exception as exc:
        return _handle_error(exc)
    for old in [k for k, until in _search_quiet_until.items() if until <= started]:
        del _search_quiet_until[old]
    if started < _search_quiet_until.get(key, 0.0):
        LOGGER.info("search not run reason=cooldown")
        return SEARCH_USE_PATH.format(why="is paused for a few minutes after a search that timed out.")
    lock = _search_locks.setdefault(key, asyncio.Lock())
    if lock.locked():
        LOGGER.info("search not run reason=busy")
        return SEARCH_USE_PATH.format(why="is already running for another request (one at a time).")
    try:
        body = _build_search_body(params.query, params.root_path)
        try:
            async with lock:
                content = await _request("SEARCH", _dav_root(), timeout=SEARCH_TIMEOUT,
                                         headers={"Content-Type": "text/xml; charset=utf-8"}, content=body)
        finally:
            if not lock.locked() and _search_locks.get(key) is lock:
                del _search_locks[key]
        items = _parse_multistatus(content)
        clean_root = _clean_path(params.root_path)
        if clean_root.startswith(DAV_FILES_PREFIX):
            items = [item for item in items
                     if item["path"] == clean_root or item["path"].startswith(clean_root.rstrip("/") + "/")]
        if params.item_type != "any":
            items = [item for item in items if item["type"] == params.item_type]
        items = items[: params.limit]
        LOGGER.info("search completed matches=%d item_type=%s duration_ms=%d",
                    len(items), params.item_type, int((time.monotonic() - started) * 1000))
        return _json({"query": params.query, "root_path": _clean_path(params.root_path) or "/", "matches": items})
    except httpx.TimeoutException:
        _search_quiet_until[key] = time.monotonic() + SEARCH_COOLDOWN
        LOGGER.warning("search failed error=timeout quiet_s=%d", int(SEARCH_COOLDOWN))
        return SEARCH_USE_PATH.format(why="timed out: the Hub's file index is very large.")
    except Exception as exc:
        LOGGER.warning("search failed error=%s", type(exc).__name__)
        return _handle_error(exc)


@mcp.tool(name="nextcloud_list", annotations=READ_ONLY)
async def nextcloud_list(params: ListInput) -> str:
    """List one exact Nextcloud directory; use nextcloud_search when the path is unknown."""
    started = time.monotonic()
    try:
        clean_path = _clean_path(params.path)
        content = await _request("PROPFIND", _url(clean_path), headers={"Depth": str(params.depth)})
        items = _parse_multistatus(content)
        if params.depth == 1 and items and items[0]["path"] == (clean_path or "/"):
            items = items[1:]
        LOGGER.info("list completed items=%d duration_ms=%d", len(items), int((time.monotonic() - started) * 1000))
        return _json(items)
    except Exception as exc:
        LOGGER.warning("list failed error=%s", type(exc).__name__)
        return _handle_error(exc)


@mcp.tool(name="nextcloud_read", annotations=READ_ONLY)
async def nextcloud_read(params: ReadInput) -> str:
    """Extract one file in bounded chunks; use next_start_char to continue long text."""
    started = time.monotonic()
    try:
        clean_path = _clean_path(params.path)
        max_chars = min(params.max_chars, MAX_TEXT_CHARS)
        data, content_type = await _fetch_document(clean_path)
        result = _extract_document(data, clean_path, content_type, max_chars, params.start_char)
        LOGGER.info(
            "read completed format=%s bytes=%d chars=%d truncated=%s duration_ms=%d",
            result["format"], result["source_bytes"], result["characters"], result["truncated"],
            int((time.monotonic() - started) * 1000),
        )
        return _json(result)
    except Exception as exc:
        LOGGER.warning("read failed error=%s", type(exc).__name__)
        return _handle_error(exc)


@mcp.tool(name="nextcloud_info", annotations=READ_ONLY)
async def nextcloud_info(params: PathInput) -> str:
    """Get metadata for one exact Nextcloud file or folder path."""
    try:
        clean_path = _clean_path(params.path)
        content = await _request("PROPFIND", _url(clean_path), headers={"Depth": "0"})
        items = _parse_multistatus(content)
        return _json(items[0] if items else {"error": "No metadata returned."})
    except Exception as exc:
        return _handle_error(exc)


@mcp.tool(name="nextcloud_write", annotations=OVERWRITE_ACTION)
async def nextcloud_write(params: WriteInput) -> str:
    """Write text or base64 content to a Nextcloud file; this creates or overwrites the destination."""
    if params.idempotency_key is None:
        return await _nextcloud_write(params)
    return await _keyed("nextcloud_write", params, execute=lambda: _nextcloud_write(params),
                        describe=lambda: _ref_states(path=params.path))


async def _nextcloud_write(params: WriteInput) -> str:
    try:
        clean_path = _clean_path(params.path)
        has_text = params.content is not None
        has_binary = params.content_base64 is not None
        if has_text == has_binary:
            return "Error: Provide exactly one of content or content_base64."
        if has_text:
            data = params.content.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            try:
                data = base64.b64decode(params.content_base64, validate=True)
            except Exception:
                return "Error: Invalid base64 encoding in content_base64."
            content_type = params.mime_type or "application/octet-stream"
        if len(data) > MAX_DOWNLOAD_BYTES:
            return f"Error: Upload exceeds the {MAX_DOWNLOAD_BYTES:,}-byte safety limit."
        await _request("PUT", _url(clean_path), timeout=300.0, headers={"Content-Type": content_type}, content=data)
        LOGGER.info("write completed bytes=%d", len(data))
        return _json({"written": True, "path": clean_path, "bytes": len(data), "content_type": content_type})
    except Exception as exc:
        return _handle_error(exc)


@mcp.tool(name="nextcloud_mkdir", annotations=WRITE_ACTION)
async def nextcloud_mkdir(params: PathWriteInput) -> str:
    """Create a Nextcloud directory."""
    if params.idempotency_key is None:
        return await _nextcloud_mkdir(params)
    return await _keyed("nextcloud_mkdir", params, execute=lambda: _nextcloud_mkdir(params),
                        already_done=lambda: _mkdir_already_done(params),
                        describe=lambda: _ref_states(path=params.path))


async def _nextcloud_mkdir(params: PathWriteInput) -> str:
    try:
        clean_path = _clean_path(params.path)
        await _request("MKCOL", _url(clean_path))
        return _json({"created": True, "path": clean_path, "type": "directory"})
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 405:
            return _json({"created": False, "already_exists": True, "path": _clean_path(params.path)})
        return _handle_error(exc)
    except Exception as exc:
        return _handle_error(exc)


@mcp.tool(name="nextcloud_move", annotations=DESTRUCTIVE_ACTION)
async def nextcloud_move(params: MoveInput) -> str:
    """Move or rename a Nextcloud file or folder."""
    if params.idempotency_key is None:
        return await _nextcloud_move(params)
    return await _keyed("nextcloud_move", params, execute=lambda: _nextcloud_move(params),
                        already_done=lambda: _move_already_done(params),
                        describe=lambda: _ref_states(source=params.source, destination=params.destination))


async def _nextcloud_move(params: MoveInput) -> str:
    try:
        source = _clean_path(params.source)
        destination = _clean_path(params.destination)
        headers = {"Destination": _url(destination), "Overwrite": "T" if params.overwrite else "F"}
        await _request("MOVE", _url(source), headers=headers)
        return _json({"moved": True, "source": source, "destination": destination})
    except Exception as exc:
        return _handle_error(exc)


@mcp.tool(name="nextcloud_delete", annotations=DESTRUCTIVE_ACTION)
async def nextcloud_delete(params: PathWriteInput) -> str:
    """Move a Nextcloud file or folder to trash."""
    if params.idempotency_key is None:
        return await _nextcloud_delete(params)
    return await _keyed("nextcloud_delete", params, execute=lambda: _nextcloud_delete(params),
                        already_done=lambda: _delete_already_done(params),
                        describe=lambda: _ref_states(path=params.path))


async def _nextcloud_delete(params: PathWriteInput) -> str:
    try:
        clean_path = _clean_path(params.path)
        await _request("DELETE", _url(clean_path))
        return _json({"deleted_to_trash": True, "path": clean_path})
    except Exception as exc:
        return _handle_error(exc)
