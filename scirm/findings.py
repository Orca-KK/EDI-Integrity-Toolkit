"""Shared Finding type and access to the detector's loader."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("detector", "generator"):
    if str(ROOT / sub) not in sys.path:
        sys.path.insert(0, str(ROOT / sub))

import edi_detect

Doc = edi_detect.Doc
el = edi_detect.el
load_docs = edi_detect.load


@dataclass
class Finding:
    """Something a person may need to act on."""
    key: str
    file: str
    partner: str
    doc_no: str
    detail: str
    ts: datetime | None = None
    trace: str = ""
    group: str = ""


def gs_ctrl(d: Doc) -> str:
    return el(d.first("GS"), 6)


def doc_number(d: Doc) -> str:
    """The business number a person would search for."""
    if d.st == "850":
        return el(d.first("BEG"), 3)
    if d.st == "855":
        return el(d.first("BAK"), 3)
    if d.st == "856":
        return el(d.first("BSN"), 2)
    if d.st == "810":
        return el(d.first("BIG"), 2)
    if d.st == "997":
        return f"ACK of group {el(d.first('AK1'), 2)}"
    return ""


def trace_id(d: Doc) -> str:
    """sender:group control number:document number -- one search finds the document at every hop."""
    return f"{d.sender}:{gs_ctrl(d)}:{doc_number(d)}"


def detector_findings(docs: list[Doc]) -> list[Finding]:
    """Convert the detector's (rule, severity, detail) tuples into Findings."""
    out = []
    for d in docs:
        for rule, _sev, detail in d.findings:
            out.append(Finding(f"detector:{rule}", d.file, d.sender, doc_number(d), detail, d.ts, trace_id(d)))
    return out
