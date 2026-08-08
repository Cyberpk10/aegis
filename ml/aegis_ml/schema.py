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

    def to_dict(self) -> dict:
        d = asdict(self)
        d["label"] = self.label.value
        d["source"] = self.source.value
        return d
