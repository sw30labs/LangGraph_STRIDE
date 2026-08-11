"""Build printable PDF reports from STRIDE assessments and scenarios.

I turn saved JSON artifacts into multi-page PDFs under output/exports/. I do
not call the LLM here — I only layout fields and prose that are already in the
JSON (including Threat_Report / CTI_Report / CVE_Report when present). The PDF
writer is pure Python so the test gate stays dependency-light.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from src.config import PathConfig
from src.threat_model import STRIDE_CATEGORIES

# Basic page geometry in PDF points (1/72 inch).
PAGE_WIDTH = 612
PAGE_HEIGHT = 792
MARGIN = 48
LINE_HEIGHT = 12
TITLE_SIZE = 16
HEADING_SIZE = 12
BODY_SIZE = 10


def _escape_pdf(text: str) -> str:
    return (
        text.replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("\r", "")
    )


def _wrap(text: str, width: int = 90) -> list[str]:
    """Wrap text to roughly `width` characters for a fixed-width layout."""
    lines: list[str] = []
    for paragraph in str(text or "").splitlines() or [""]:
        paragraph = paragraph.replace("\t", " ")
        if not paragraph.strip():
            lines.append("")
            continue
        words = paragraph.split()
        current = ""
        for word in words:
            trial = f"{current} {word}".strip()
            if len(trial) <= width:
                current = trial
            else:
                if current:
                    lines.append(current)
                current = word
        if current:
            lines.append(current)
    return lines or [""]


class _PdfBuilder:
    """I accumulate text lines and emit a simple multi-page PDF."""

    def __init__(self) -> None:
        self._pages: list[list[tuple[str, int, bool]]] = [[]]
        self._y = PAGE_HEIGHT - MARGIN

    def _new_page(self) -> None:
        self._pages.append([])
        self._y = PAGE_HEIGHT - MARGIN

    def add_line(self, text: str, *, size: int = BODY_SIZE, bold: bool = False) -> None:
        height = size + 4
        if self._y - height < MARGIN:
            self._new_page()
        self._pages[-1].append((text, size, bold))
        self._y -= height

    def add_heading(self, text: str) -> None:
        self.add_line("")
        self.add_line(text, size=HEADING_SIZE, bold=True)

    def add_paragraph(self, text: str, *, size: int = BODY_SIZE) -> None:
        for line in _wrap(text, width=92 if size <= BODY_SIZE else 80):
            self.add_line(line, size=size)

    def add_key_value(self, key: str, value: Any) -> None:
        self.add_paragraph(f"{key}: {value}")

    def build(self) -> bytes:
        objects: list[bytes] = []
        # 1: catalog, 2: pages tree filled later
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        page_object_ids: list[int] = []
        content_object_ids: list[int] = []

        # We'll assign ids: 1 catalog, 2 pages, then pairs of page/content.
        next_id = 3
        page_entries: list[tuple[int, int, list[tuple[str, int, bool]]]] = []
        for page_lines in self._pages:
            page_id = next_id
            content_id = next_id + 1
            next_id += 2
            page_object_ids.append(page_id)
            content_object_ids.append(content_id)
            page_entries.append((page_id, content_id, page_lines))

        kids = " ".join(f"{pid} 0 R" for pid in page_object_ids) or "3 0 R"
        objects.append(
            f"<< /Type /Pages /Kids [{kids}] /Count {max(len(page_object_ids), 1)} >>".encode()
        )

        # Ensure at least one blank page if empty.
        if not page_entries:
            page_entries.append((3, 4, [("", BODY_SIZE, False)]))
            objects[1] = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"

        # Interleave page and content objects in id order.
        # objects currently has ids 1 and 2; remaining must be sequential.
        built: list[bytes] = list(objects)
        for page_id, content_id, page_lines in page_entries:
            built.append(
                (
                    f"<< /Type /Page /Parent 2 0 R "
                    f"/MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
                    f"/Contents {content_id} 0 R "
                    f"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> "
                    f"/F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> >> >> >>"
                ).encode()
            )
            y = PAGE_HEIGHT - MARGIN
            stream_lines = ["BT"]
            for text, size, bold in page_lines:
                font = "F2" if bold else "F1"
                stream_lines.append(f"/{font} {size} Tf")
                stream_lines.append(f"1 0 0 1 {MARGIN} {y} Tm")
                stream_lines.append(f"({_escape_pdf(text)}) Tj")
                y -= size + 4
            stream_lines.append("ET")
            stream = "\n".join(stream_lines).encode("latin-1", errors="replace")
            built.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")

        # Assemble xref
        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, obj in enumerate(built, start=1):
            offsets.append(len(out))
            out.extend(f"{index} 0 obj\n".encode())
            out.extend(obj)
            out.extend(b"\nendobj\n")
        xref_pos = len(out)
        out.extend(f"xref\n0 {len(built) + 1}\n".encode())
        out.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            out.extend(f"{offset:010d} 00000 n \n".encode())
        out.extend(
            (
                f"trailer\n<< /Size {len(built) + 1} /Root 1 0 R >>\n"
                f"startxref\n{xref_pos}\n%%EOF\n"
            ).encode()
        )
        return bytes(out)


def _load_artifact(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Artifact must be a JSON object")
    return payload


def _detect_kind(data: dict[str, Any], kind: str | None) -> str:
    if kind in {"threat_model", "scenario"}:
        return kind
    meta = data.get("_meta") if isinstance(data.get("_meta"), dict) else {}
    artifact_type = meta.get("artifact_type")
    if artifact_type in {"threat_model", "scenario"}:
        return str(artifact_type)
    if "Attack_Template" in data or "Threat_Report" in data:
        return "scenario"
    return "threat_model"


def _render_threat_model(builder: _PdfBuilder, data: dict[str, Any]) -> None:
    meta = data.get("_meta") if isinstance(data.get("_meta"), dict) else {}
    system = data.get("system_metadata") if isinstance(data.get("system_metadata"), dict) else {}
    aa_id = meta.get("aa_id") or system.get("aa_id") or system.get("AA ID") or ""
    name = system.get("Application Name") or system.get("name") or ""

    builder.add_line("STRIDE Threat Model", size=TITLE_SIZE, bold=True)
    builder.add_paragraph(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    builder.add_heading("System")
    builder.add_key_value("AA ID", aa_id)
    builder.add_key_value("Application", name)
    for key in (
        "Confidentiality",
        "Integrity",
        "Externally facing",
        "Platform",
        "Development Category",
    ):
        if system.get(key) not in (None, ""):
            builder.add_key_value(key, system.get(key))
    if meta:
        builder.add_key_value("Provider", meta.get("provider"))
        builder.add_key_value("Model", meta.get("model"))
        if meta.get("thinking_enabled"):
            builder.add_key_value("Reasoning strength", meta.get("reasoning_strength"))

    builder.add_heading("STRIDE categories")
    for category in STRIDE_CATEGORIES:
        rows = data.get(category)
        if not isinstance(rows, list) or not rows:
            continue
        builder.add_heading(category)
        for index, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                continue
            builder.add_paragraph(
                f"{index}. {row.get('threat_name') or 'Threat'}",
                size=BODY_SIZE,
            )
            if row.get("description"):
                builder.add_paragraph(f"   Description: {row['description']}")
            if row.get("impact"):
                builder.add_paragraph(f"   Impact: {row['impact']}")
            if row.get("mitigation"):
                builder.add_paragraph(f"   Mitigation: {row['mitigation']}")

    dread = data.get("dread_assessment")
    if isinstance(dread, list) and dread:
        builder.add_heading("DREAD assessment")
        for row in dread:
            if not isinstance(row, dict):
                continue
            title = row.get("Scenario") or row.get("threat") or row.get("Threat Type") or "Risk"
            builder.add_paragraph(str(title), size=BODY_SIZE)
            parts = []
            for key in (
                "Threat Type",
                "Damage Potential",
                "Reproducibility",
                "Exploitability",
                "Affected Users",
                "Discoverability",
                "score",
            ):
                if key in row:
                    parts.append(f"{key}={row[key]}")
            if parts:
                builder.add_paragraph("   " + "; ".join(parts))


def _render_scenario(builder: _PdfBuilder, data: dict[str, Any]) -> None:
    meta = data.get("_meta") if isinstance(data.get("_meta"), dict) else {}
    builder.add_line("Threat Scenario Report", size=TITLE_SIZE, bold=True)
    builder.add_paragraph(f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    builder.add_heading("Context")
    for key, label in (
        ("SWC_ID", "AA ID"),
        ("SWC_NAME", "Application"),
        ("Attack_Template", "Attack chain"),
        ("CVSS_Tshld", "Minimum CVSS"),
        ("Provider", "Provider"),
        ("Threat_Report_Date", "Report date"),
    ):
        if data.get(key) not in (None, ""):
            builder.add_key_value(label, data.get(key))
    if meta.get("source_threat_model_path"):
        builder.add_key_value("Source threat model", meta.get("source_threat_model_path"))

    for key, title in (
        ("Threat_Report", "Threat narrative"),
        ("CTI_Report", "CTI report"),
        ("CVE_Report", "CVE report"),
    ):
        body = data.get(key)
        if body:
            builder.add_heading(title)
            builder.add_paragraph(str(body))


def export_artifact_pdf(
    artifact_path: Path | str,
    *,
    paths: PathConfig | None = None,
    kind: str | None = None,
    output_path: Path | str | None = None,
) -> Path:
    """Render one assessment or scenario JSON file to a PDF path."""
    source = Path(artifact_path)
    if not source.is_file():
        raise ValueError(f"Artifact not found: {source}")
    data = _load_artifact(source)
    detected = _detect_kind(data, kind)
    builder = _PdfBuilder()
    if detected == "scenario":
        _render_scenario(builder, data)
    else:
        _render_threat_model(builder, data)

    if output_path is not None:
        target = Path(output_path)
    else:
        base = paths.output_dir if paths is not None else source.parent.parent
        export_dir = Path(base) / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        stem = re.sub(r"[^A-Za-z0-9._-]+", "_", source.stem).strip("_")
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        target = export_dir / f"{stem}_{stamp}.pdf"

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(builder.build())
    return target
