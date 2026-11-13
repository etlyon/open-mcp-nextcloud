"""Hub-only security fixes (SECFIX13). No network. No credential file."""

from __future__ import annotations

import unittest
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

from pypdf import PdfWriter

from open_connectors.apps.nextcloud import tools
from open_connectors.pdf_text import PdfTextError, extract_office_text, extract_pdf_text


class HubSecurity(unittest.TestCase):
    def test_errors_do_not_return_exception_text(self):
        class Boom(Exception):
            def __str__(self) -> str:
                return "upstream said the password is hunter2"

        text = tools._handle_error(Boom())
        self.assertEqual(text, "Error: Boom: the call failed.")
        self.assertNotIn("hunter2", text)
        value = tools._handle_error(ValueError("upstream returned secret-token"))
        self.assertEqual(value, "Error: ValueError: the call failed.")
        self.assertNotIn("secret-token", value)

    def test_pdf_text_runs_in_a_child_and_refuses_oversize(self):
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        buf = BytesIO()
        writer.write(buf)
        text, stats, _warnings = extract_pdf_text(buf.getvalue())
        self.assertIsInstance(text, str)
        self.assertEqual(stats["pages_processed"], 1)
        with self.assertRaises(PdfTextError):
            extract_pdf_text(b"%PDF-1.4\n" + b"x" * (10 * 1024 * 1024))

    def test_every_office_reader_runs_through_the_capped_child(self):
        from docx import Document
        from openpyxl import Workbook
        from pptx import Presentation

        docx = BytesIO()
        document = Document()
        document.add_paragraph("word child")
        document.save(docx)
        xlsx = BytesIO()
        workbook = Workbook()
        workbook.active.append(["sheet child"])
        workbook.save(xlsx)
        pptx = BytesIO()
        presentation = Presentation()
        slide = presentation.slides.add_slide(presentation.slide_layouts[5])
        slide.shapes.title.text = "slides child"
        presentation.save(pptx)
        odf = BytesIO()
        with ZipFile(odf, "w", ZIP_DEFLATED) as archive:
            archive.writestr("content.xml", (
                b"<office:document-content xmlns:office='urn:oasis:names:tc:opendocument:xmlns:office:1.0' "
                b"xmlns:text='urn:oasis:names:tc:opendocument:xmlns:text:1.0'>"
                b"<text:p>odf child</text:p></office:document-content>"
            ))
        cases = {
            "docx": (docx.getvalue(), "word child"),
            "xlsx": (xlsx.getvalue(), "sheet child"),
            "pptx": (pptx.getvalue(), "slides child"),
            "odf": (odf.getvalue(), "odf child"),
        }
        for kind, (data, expected) in cases.items():
            with self.subTest(kind=kind):
                text, stats, warnings = extract_office_text(data, kind, 20_000)
                self.assertIn(expected, text)
                self.assertIsInstance(stats, dict)
                self.assertIsInstance(warnings, list)


if __name__ == "__main__":
    unittest.main()
