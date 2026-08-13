"""The common schema every source is normalized into before dedupe/split.

Binary ground truth only (`phishing` | `benign`) — that's what these public corpora actually
label; there's no public source for a `suspicious` middle class. Mapping to Aegis's runtime
three-way verdict is a concern for a later M3 stage, not corpus assembly.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class Label(str, Enum):
    PHISHING = "phishing"
    BENIGN = "benign"


class Source(str, Enum):
    NAZARIO = "nazario"
    SPAMASSASSIN = "spamassassin"
    ENRON = "enron"


EMAIL_RECORD_COLUMNS = [
    "id",
    "raw_headers",
    "subject",
    "body_text",
    "from_addr",
    "label",
    "source",
    "raw_bytes",
]


@dataclass(frozen=True)
class EmailRecord:
    id: str
    raw_headers: str
    subject: str
    body_text: str
    from_addr: str | None
    label: Label
    source: Source
    # The actual original message bytes (or, for true mbox sources, a faithful
    # email.message.Message.as_bytes() re-serialization — see mbox_parser.iter_mbox_records)
    # — added so a later M3 stage can re-parse each record through the real backend
    # app.parsing.eml_parser.parse_eml(), instead of this module's own lossy
    # header-string/flattened-body reconstruction. Without this, indicator-engine features
    # computed from the corpus would silently diverge from what the same email produces at
    # real inference time (train/serve skew).
    raw_bytes: bytes

    def to_dict(self) -> dict:
        d = asdict(self)
        d["label"] = self.label.value
        d["source"] = self.source.value
        return d
