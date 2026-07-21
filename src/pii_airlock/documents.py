from __future__ import annotations

import multiprocessing
import os
import threading
from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from .models import AirlockError, ServiceBusyError

MAX_BYTES = 5 * 1024 * 1024
MAX_CHARACTERS = 20_000
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 512
MAX_COMPRESSION_RATIO = 200
MAX_PDF_PAGES = 100
MAX_PDF_OBJECTS = 10_000
PARSER_TIMEOUT_SECONDS = 8.0
PARSER_MEMORY_BYTES = 512 * 1024 * 1024
PARSER_CPU_SECONDS = 6
SUPPORTED_SUFFIXES = {".txt", ".md", ".docx", ".pdf"}
_PARSER_SLOTS = threading.BoundedSemaphore(2)


def extract_path(path: Path) -> str:
    if not path.exists() or not path.is_file():
        raise AirlockError(f"Document does not exist: {path}")
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    return extract_bytes(data, path.suffix)


def extract_bytes(data: bytes, suffix: str) -> str:
    normalized_suffix = suffix.lower()
    if normalized_suffix not in SUPPORTED_SUFFIXES:
        raise AirlockError(f"Unsupported document type: {normalized_suffix or 'unknown'}")
    if not data:
        raise AirlockError("Document is empty.")
    if len(data) > MAX_BYTES:
        raise AirlockError("Document exceeds the 5 MB limit.")

    if normalized_suffix in {".txt", ".md"}:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AirlockError("Document is damaged or cannot be decoded.") from exc
    else:
        text = _extract_isolated(data, normalized_suffix)

    cleaned = text.strip()
    if not cleaned:
        raise AirlockError("Document has no extractable text; OCR is outside V1.")
    if len(cleaned) > MAX_CHARACTERS:
        raise AirlockError("Extracted text exceeds the 20,000 character V1 limit.")
    return cleaned


def _extract_binary_in_process(data: bytes, normalized_suffix: str) -> str:
    try:
        if normalized_suffix == ".docx":
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
            if reader.is_encrypted:
                raise AirlockError("Encrypted PDF documents are outside V1.")
            if len(reader.pages) > MAX_PDF_PAGES:
                raise AirlockError(f"PDF exceeds the {MAX_PDF_PAGES}-page V1 limit.")
            object_count = sum(len(objects) for objects in getattr(reader, "xref", {}).values())
            if object_count > MAX_PDF_OBJECTS:
                raise AirlockError(f"PDF exceeds the {MAX_PDF_OBJECTS}-object safety limit.")
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
    except AirlockError:
        raise
    except (UnicodeDecodeError, ValueError, KeyError, OSError) as exc:
        raise AirlockError("Document is damaged or cannot be decoded.") from exc
    except Exception as exc:
        raise AirlockError("Document parser rejected the file.") from exc
    return text


def _extract_isolated(data: bytes, normalized_suffix: str) -> str:
    if not _PARSER_SLOTS.acquire(blocking=False):
        raise ServiceBusyError("All isolated document parser slots are busy; retry later.")
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_parser_worker, args=(child, data, normalized_suffix), daemon=True)
    try:
        process.start()
        child.close()
        if not parent.poll(PARSER_TIMEOUT_SECONDS):
            process.terminate()
            process.join(timeout=2)
            raise AirlockError("Document parser exceeded its time limit.")
        status, payload = parent.recv()
        process.join(timeout=2)
        if status == "ok":
            return str(payload)
        message, code = payload
        if code == ServiceBusyError.code:
            raise ServiceBusyError(message)
        raise AirlockError(message)
    except EOFError as exc:
        raise AirlockError("Isolated document parser exited without a result.") from exc
    finally:
        parent.close()
        if process.is_alive():
            process.terminate()
            process.join(timeout=2)
        _PARSER_SLOTS.release()


def _parser_worker(connection, data: bytes, normalized_suffix: str) -> None:
    try:
        _apply_resource_limits()
        connection.send(("ok", _extract_binary_in_process(data, normalized_suffix)))
    except AirlockError as exc:
        connection.send(("error", (str(exc), getattr(exc, "code", "airlock_error"))))
    except BaseException:
        connection.send(("error", ("Document parser failed inside its isolation boundary.", "parser_failed")))
    finally:
        connection.close()


def _apply_resource_limits() -> None:
    if os.name != "posix":
        return
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (PARSER_CPU_SECONDS, PARSER_CPU_SECONDS))
        if hasattr(resource, "RLIMIT_AS"):
            resource.setrlimit(resource.RLIMIT_AS, (PARSER_MEMORY_BYTES, PARSER_MEMORY_BYTES))
    except (ImportError, OSError, ValueError):
        # The parent still enforces wall-clock termination and bounded input.
        return


def _validate_docx_archive(data: bytes) -> None:
    try:
        with ZipFile(BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise AirlockError(f"DOCX contains more than {MAX_ARCHIVE_MEMBERS} archive members.")
            names = {member.filename for member in members}
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                raise AirlockError("DOCX package is missing required document parts.")
            total_uncompressed = sum(member.file_size for member in members)
            if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise AirlockError("DOCX expanded size exceeds the 25 MB safety limit.")
            for member in members:
                if member.flag_bits & 0x1:
                    raise AirlockError("Encrypted DOCX archive members are outside V1.")
                if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise AirlockError("A DOCX archive member exceeds the 10 MB safety limit.")
                ratio = member.file_size / max(1, member.compress_size)
                if member.file_size > 1024 * 1024 and ratio > MAX_COMPRESSION_RATIO:
                    raise AirlockError("DOCX compression ratio exceeds the safety limit.")
    except BadZipFile as exc:
        raise AirlockError("Document parser rejected the file.") from exc
