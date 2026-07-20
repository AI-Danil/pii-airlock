from __future__ import annotations

from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from .models import AirlockError

MAX_BYTES = 5 * 1024 * 1024
MAX_CHARACTERS = 20_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 25 * 1024 * 1024
MAX_PDF_PAGES = 100
SUPPORTED_SUFFIXES = {".txt", ".md", ".docx", ".pdf"}


def extract_path(path: Path) -> str:
    if not path.exists() or not path.is_file():
        raise AirlockError(f"Document does not exist: {path}")
    return extract_bytes(path.read_bytes(), path.suffix)


def extract_bytes(data: bytes, suffix: str) -> str:
    normalized_suffix = suffix.lower()
    if normalized_suffix not in SUPPORTED_SUFFIXES:
        raise AirlockError(f"Unsupported document type: {normalized_suffix or 'unknown'}")
    if not data:
        raise AirlockError("Document is empty.")
    if len(data) > MAX_BYTES:
        raise AirlockError("Document exceeds the 5 MB limit.")

    try:
        if normalized_suffix in {".txt", ".md"}:
            text = data.decode("utf-8")
        elif normalized_suffix == ".docx":
            from docx import Document

            _validate_docx_archive(data)
            document = Document(BytesIO(data))
            chunks = [paragraph.text for paragraph in document.paragraphs]
            for table in document.tables:
                for row in table.rows:
                    chunks.append("\t".join(cell.text for cell in row.cells))
            text = "\n".join(chunks)
        else:
            from pypdf import PdfReader

            reader = PdfReader(BytesIO(data))
            if len(reader.pages) > MAX_PDF_PAGES:
                raise AirlockError(f"PDF exceeds the {MAX_PDF_PAGES}-page V1 limit.")
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
    except AirlockError:
        raise
    except (UnicodeDecodeError, ValueError, KeyError, OSError) as exc:
        raise AirlockError("Document is damaged or cannot be decoded.") from exc
    except Exception as exc:
        raise AirlockError("Document parser rejected the file.") from exc

    cleaned = text.strip()
    if not cleaned:
        raise AirlockError("Document has no extractable text; OCR is outside V1.")
    if len(cleaned) > MAX_CHARACTERS:
        raise AirlockError("Extracted text exceeds the 20,000 character V1 limit.")
    return cleaned


def _validate_docx_archive(data: bytes) -> None:
    try:
        with ZipFile(BytesIO(data)) as archive:
            members = archive.infolist()
            names = {member.filename for member in members}
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                raise AirlockError("DOCX package is missing required document parts.")
            total_uncompressed = sum(member.file_size for member in members)
            if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise AirlockError("DOCX expanded size exceeds the 25 MB safety limit.")
    except BadZipFile as exc:
        raise AirlockError("Document parser rejected the file.") from exc
