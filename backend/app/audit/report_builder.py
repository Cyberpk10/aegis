"""Renders an Audit Mode evidence pack as JSON and PDF from the same ReportContext —
a cover page/section (framework, period, generated-at, methodology, integrity line),
then a per-control evidence table. Uses reportlab for the PDF (BSD-licensed, pure-pip
install, no system binary dependency like weasyprint/wkhtmltopdf would need).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.audit.aggregation import ControlEvidence

NAVY = colors.HexColor("#0f172a")
SLATE_BORDER = colors.HexColor("#cbd5e1")
SLATE_ROW = colors.HexColor("#f8fafc")

METHODOLOGY_NOTE = (
    "This evidence pack aggregates Aegis case analyses whose automated, rule-based indicators "
    "map to each control in the selected framework, for the stated period. A control is marked "
    '"Operating" if at least one supporting case was detected in this period. Sample case '
    "references are the most recent supporting cases (up to 5), included for auditor "
    "spot-checking. Indicator-to-control mappings are defined in "
    "backend/app/mapping/frameworks/. This reflects automated detections only and is not a "
    "substitute for full control testing or manual review."
)


@dataclass(frozen=True)
class ReportContext:
    framework_key: str
    framework_name: str
    framework_version: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    controls: list[ControlEvidence]
    total_controls: int
    operating_controls: int
    total_supporting_cases: int


def _integrity_text(ctx: ReportContext) -> str:
    return (
        f"Integrity: generated at {ctx.generated_at:%Y-%m-%d %H:%M:%S} UTC · "
        f"{ctx.total_controls} controls evaluated · {ctx.operating_controls} operating · "
        f"{ctx.total_supporting_cases} supporting cases referenced."
    )


def build_json_report(ctx: ReportContext) -> bytes:
    payload = {
        "aegis_audit_evidence_pack": {
            "framework_key": ctx.framework_key,
            "framework_name": ctx.framework_name,
            "framework_version": ctx.framework_version,
            "period_start": ctx.period_start.isoformat(),
            "period_end": ctx.period_end.isoformat(),
            "generated_at": ctx.generated_at.isoformat(),
            "methodology": METHODOLOGY_NOTE,
            "integrity": {
                "generated_at": ctx.generated_at.isoformat(),
                "total_controls": ctx.total_controls,
                "operating_controls": ctx.operating_controls,
                "total_supporting_cases": ctx.total_supporting_cases,
            },
            "controls": [
                {
                    "control_id": control.control_id,
                    "control_name": control.control_name,
                    "detection_count": control.detection_count,
                    "operating": control.operating,
                    "sample_cases": [
                        {
                            "id": sample.id,
                            "verdict": sample.verdict,
                            "created_at": sample.created_at.isoformat(),
                        }
                        for sample in control.sample_cases
                    ],
                }
                for control in ctx.controls
            ],
        }
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def build_pdf_report(ctx: ReportContext) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        title=f"Aegis Audit Evidence Pack - {ctx.framework_name}",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("AegisTitle", parent=styles["Title"], textColor=NAVY)
    heading_style = ParagraphStyle("AegisHeading", parent=styles["Heading2"], textColor=NAVY)

    elements = [
        Paragraph("Aegis — Threat &amp; Compliance Evidence Pack", title_style),
        Spacer(1, 0.15 * inch),
        Paragraph(
            f"Framework: {xml_escape(ctx.framework_name)} (v{xml_escape(ctx.framework_version)})",
            styles["Heading3"],
        ),
        Paragraph(f"Period: {ctx.period_start:%Y-%m-%d} – {ctx.period_end:%Y-%m-%d}", styles["Normal"]),
        Paragraph(f"Generated: {ctx.generated_at:%Y-%m-%d %H:%M:%S} UTC", styles["Normal"]),
        Spacer(1, 0.2 * inch),
        Paragraph("Methodology", heading_style),
        Paragraph(METHODOLOGY_NOTE, styles["Normal"]),
        Spacer(1, 0.2 * inch),
        Paragraph(f"<b>{_integrity_text(ctx)}</b>", styles["Normal"]),
        PageBreak(),
        Paragraph("Per-Control Evidence", heading_style),
        Spacer(1, 0.1 * inch),
    ]

    table_data = [["Control ID", "Control Name", "Detections", "Status", "Sample Cases"]]
    for control in ctx.controls:
        sample_text = (
            ", ".join(f"{sample.id[:8]} ({sample.verdict})" for sample in control.sample_cases) or "—"
        )
        table_data.append(
            [
                control.control_id,
                # control_name comes from framework YAML and may contain characters
                # (e.g. "&") that reportlab's Paragraph markup parser would otherwise
                # choke on — same reason framework_name is escaped above.
                Paragraph(xml_escape(control.control_name), styles["BodyText"]),
                str(control.detection_count),
                "Operating" if control.operating else "No evidence",
                Paragraph(xml_escape(sample_text), styles["BodyText"]),
            ]
        )

    table = Table(
        table_data,
        colWidths=[0.9 * inch, 2.2 * inch, 0.7 * inch, 0.9 * inch, 1.8 * inch],
        repeatRows=1,
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, SLATE_BORDER),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SLATE_ROW]),
            ]
        )
    )
    elements.append(table)

    doc.build(elements)
    return buffer.getvalue()
