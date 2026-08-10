"""Attachment-based risk indicators: risky extensions, double extensions, macro-enabled documents."""

from __future__ import annotations

import re

from app.indicators.base import make_indicator
from app.models.schemas import Indicator, Severity
from app.channels.message import Message
from app.parsing.eml_parser import is_macro_enabled_filename

_RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".wsh", ".ps1", ".msi", ".jar", ".lnk", ".hta", ".cpl", ".reg", ".apk", ".chm",
}

_BENIGN_LOOKING_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "csv"}

_DOUBLE_EXT_RE = re.compile(r"^.+\.([a-z0-9]{2,5})\.([a-z0-9]{2,5})$", re.IGNORECASE)


def _extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()


def evaluate(email: Message) -> list[Indicator]:
    risky_evidence: list[str] = []
    double_ext_evidence: list[str] = []
    macro_evidence: list[str] = []

    for attachment in email.attachments:
        filename = attachment.filename
        ext = _extension(filename)

        if ext in _RISKY_EXTENSIONS:
            risky_evidence.append(f"{filename} ({attachment.content_type or 'unknown type'})")

        match = _DOUBLE_EXT_RE.match(filename)
        if match:
            first_ext, second_ext = match.group(1).lower(), match.group(2).lower()
            if first_ext in _BENIGN_LOOKING_EXTENSIONS and f".{second_ext}" in _RISKY_EXTENSIONS:
                double_ext_evidence.append(filename)

        if is_macro_enabled_filename(filename):
            macro_evidence.append(filename)

    indicators: list[Indicator] = []

    if risky_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_RISKY_EXTENSION",
                category="attachment",
                title="Attachment has an executable/script file extension",
                description=(
                    "One or more attachments use a file extension commonly used to deliver "
                    "malware (executables, scripts, or installers)."
                ),
                evidence=risky_evidence,
                severity=Severity.HIGH,
                score=20,
            )
        )

    if double_ext_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_DOUBLE_EXTENSION",
                category="attachment",
                title="Attachment uses a disguised double extension",
                description=(
                    "An attachment's filename ends in a benign-looking extension followed by an "
                    "executable/script extension (e.g. 'invoice.pdf.exe'), a technique used to "
                    "trick recipients into opening malware."
                ),
                evidence=double_ext_evidence,
                severity=Severity.HIGH,
                score=15,
            )
        )

    if macro_evidence:
        indicators.append(
            make_indicator(
                id="ATTACHMENT_MACRO_ENABLED",
                category="attachment",
                title="Macro-enabled Office document attached",
                description=(
                    "One or more attachments are macro-enabled Office documents (.docm/.xlsm/"
                    ".pptm), a common vector for delivering malicious macros."
                ),
                evidence=macro_evidence,
                severity=Severity.MEDIUM,
                score=15,
            )
        )

    return indicators
