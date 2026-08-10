"""Extracts the ORIGINAL forwarded email from a forwarding wrapper (M8 Stage 3) — when a user
forwards a phishing email, we want to analyze what they forwarded, not their own forwarding
message. Pure function, no I/O, same convention as app.autonomy.policy.

Three-tier strategy, in order of fidelity:

1. **MIME-attachment forward** (e.g. Outlook's "Forward as Attachment"): the original message
   is attached as a `message/rfc822` part. Its raw bytes are returned as-is — original headers,
   including whatever `Authentication-Results` the original mail server stamped, survive intact.
2. **Text-marker forward** (the common "hit Forward in Gmail/Outlook/Apple Mail" case): the
   wrapper's plain-text body contains a standard marker ("---------- Forwarded message
   ---------", "Begin forwarded message:", "-----Original Message-----") followed by a
   From/Date/Subject/To header block and then the original body. We parse that block and
   synthesize a minimal raw email from it. This is explicitly heuristic and lossy: there is no
   original `Authentication-Results` header to recover, so auth-based indicators (SPF/DKIM/
   DMARC) on a text-unwrapped case reflect the *forwarder's* mail server, not the original
   sender's — an inherent limitation of forwarded-email analysis, not a bug.
3. **No marker found**: the raw bytes are returned unchanged (covers a report that's already
   just the raw phishing email, with no forwarding wrapper at all).
"""

from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

_FORWARD_MARKER_RE = re.compile(
    r"^[-_]{2,}\s*(forwarded message|original message)\s*[-_]{2,}\s*$"
    r"|^begin forwarded message:?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# Matches a "From: ..." / "Date: ..." / "Sent: ..." / "To: ..." / "Subject: ..." header line
# within the forwarded block (Outlook uses "Sent:", Gmail/Apple Mail use "Date:").
_HEADER_LINE_RE = re.compile(
    r"^(From|Date|Sent|To|Subject)\s*:\s*(.*)$", re.IGNORECASE | re.MULTILINE
)
# How many lines after the marker we'll scan for header lines before giving up and treating
# the rest as body — bounds a pathological input from scanning the whole message as "headers".
_MAX_HEADER_BLOCK_LINES = 12


def _extract_message_rfc822_part(raw_bytes: bytes) -> bytes | None:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    for part in msg.walk():
        if part.get_content_type() != "message/rfc822":
            continue
        nested = part.get_payload(0)
        if nested is None:
            continue
        try:
            return nested.as_bytes()
        except Exception:  # noqa: BLE001 - malformed nested message, fall through to next tier
            continue
    return None


def _plain_text_body(raw_bytes: bytes) -> str:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.get_content_type() != "text/plain":
            continue
        try:
            parts.append(part.get_content())
        except Exception:  # noqa: BLE001 - undecodable part, skip it
            continue
    return "\n".join(parts)


def _extract_text_marker_forward(raw_bytes: bytes) -> bytes | None:
    body_text = _plain_text_body(raw_bytes)
    if not body_text:
        return None

    match = _FORWARD_MARKER_RE.search(body_text)
    if match is None:
        return None

    after_marker = body_text[match.end():].lstrip("\n")
    lines = after_marker.split("\n")

    headers: dict[str, str] = {}
    body_start_line = 0
    for i, line in enumerate(lines[:_MAX_HEADER_BLOCK_LINES]):
        if not line.strip():
            body_start_line = i + 1
            break
        header_match = _HEADER_LINE_RE.match(line)
        if header_match:
            key = header_match.group(1).lower()
            key = "date" if key == "sent" else key
            headers[key] = header_match.group(2).strip()
            body_start_line = i + 1
        else:
            # Not a header line and not blank — the header block ended without a trailing
            # blank line (seen in some clients); treat this line as the start of the body.
            body_start_line = i
            break

    if "from" not in headers and "subject" not in headers:
        # Found a marker but couldn't parse a recognizable header block after it — too
        # unreliable to synthesize from; fall back to the next tier instead of guessing.
        return None

    original_body = "\n".join(lines[body_start_line:]).strip()

    synthetic = EmailMessage()
    synthetic["From"] = headers.get("from", "unknown@unknown.invalid")
    synthetic["To"] = headers.get("to", "")
    synthetic["Subject"] = headers.get("subject", "")
    synthetic["Date"] = headers.get("date", "")
    synthetic.set_content(original_body)
    return synthetic.as_bytes()


def unwrap_forwarded_email(raw_bytes: bytes) -> bytes:
    """Returns the best available raw bytes for the ORIGINAL message inside `raw_bytes`,
    falling through the three tiers documented above. Never raises on a malformed/unparseable
    input — worst case, the input is returned unchanged and the existing parse_eml()/pipeline
    error handling takes over from there."""
    try:
        attached = _extract_message_rfc822_part(raw_bytes)
        if attached is not None:
            return attached

        text_marker = _extract_text_marker_forward(raw_bytes)
        if text_marker is not None:
            return text_marker
    except Exception:  # noqa: BLE001 - any parsing hiccup falls back to the raw input as-is
        pass

    return raw_bytes
