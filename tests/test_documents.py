from __future__ import annotations

from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from docx import Document
from pypdf import PdfWriter
from reportlab.pdfgen import canvas

from pii_airlock.documents import extract_bytes
from pii_airlock.models import AirlockError


def test_txt_and_markdown() -> None:
    assert extract_bytes("Привет".encode(), ".txt") == "Привет"
    assert extract_bytes(b"# Heading", ".md") == "# Heading"


def test_docx_paragraphs_and_tables() -> None:
    doc = Document()
    doc.add_paragraph("Alice Carter")
    table = doc.add_table(rows=1, cols=1)
    table.cell(0, 0).text = "alice@example.test"
    buffer = BytesIO()
    doc.save(buffer)
    text = extract_bytes(buffer.getvalue(), ".docx")
    assert "Alice Carter" in text
    assert "alice@example.test" in text


def test_pdf_without_text_layer_is_rejected() -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    buffer = BytesIO()
    writer.write(buffer)
    with pytest.raises(AirlockError, match="OCR"):
        extract_bytes(buffer.getvalue(), ".pdf")


def test_pdf_with_text_layer_is_extracted() -> None:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer)
    pdf.drawString(72, 720, "Alice Carter")
    pdf.save()
    assert "Alice Carter" in extract_bytes(buffer.getvalue(), ".pdf")


def test_empty_damaged_and_oversized_inputs() -> None:
    with pytest.raises(AirlockError, match="empty"):
        extract_bytes(b"", ".txt")
    with pytest.raises(AirlockError, match="parser"):
        extract_bytes(b"not a zip", ".docx")
    with pytest.raises(AirlockError, match="20,000"):
        extract_bytes(("x" * 20_001).encode(), ".txt")


def test_docx_archive_expansion_is_bounded() -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "content types")
        archive.writestr("word/document.xml", "x" * (25 * 1024 * 1024 + 1))
    with pytest.raises(AirlockError, match="expanded size"):
        extract_bytes(buffer.getvalue(), ".docx")


def test_pdf_page_count_is_bounded() -> None:
    writer = PdfWriter()
    for _ in range(101):
        writer.add_blank_page(width=200, height=200)
    buffer = BytesIO()
    writer.write(buffer)
    with pytest.raises(AirlockError, match="100-page"):
        extract_bytes(buffer.getvalue(), ".pdf")
