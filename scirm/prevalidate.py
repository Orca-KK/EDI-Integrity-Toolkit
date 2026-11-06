"""Checks that run before transformation, so bad master data is caught at receipt, with a clear
reason, instead of surfacing later as a coded hold.

    ship-to cross-reference   is the order's ship-to location mapped to a distribution center?
                              (with ID normalization, so zero-padding is not mistaken for a new location)
    delivery date             is the requested date at least the agreed lead time after the order date?
"""
from __future__ import annotations

from datetime import date, datetime

from findings import Doc, Finding, doc_number, el, trace_id


# --------------------------------------------------------------------------------------
# Identifier helpers
# --------------------------------------------------------------------------------------
def gs1_check_digit(body: str) -> int:
    """GS1 mod-10 check digit for the digits before the check digit (GTIN, GLN, SSCC)."""
    total = sum(int(c) * (3 if i % 2 == 0 else 1) for i, c in enumerate(reversed(body)))
    return (10 - total % 10) % 10


def gs1_valid(code: str) -> bool:
    return code.isdigit() and len(code) in (8, 12, 13, 14) and gs1_check_digit(code[:-1]) == int(code[-1])


def describe_id(code: str) -> str:
    """Plain-language guess at what kind of identifier this is; helps whoever fixes the mapping."""
    c = code.strip()
    if not c.isdigit():
        return "alphanumeric code (partner- or buyer-assigned)"
    if len(c) == 13:
        return ("valid GS1 location number (GLN)" if gs1_valid(c) else
                "13 digits but fails the GS1 check digit, so not a GLN; possibly DUNS+4 or a zero-padded partner code")
    if len(c) == 9:
        return "9 digits, the length of a DUNS number"
    return f"{len(c)}-digit numeric code"


def normalize_id(code: str) -> str:
    """Canonical form for lookups: trimmed, leading zeros removed."""
    return code.strip().lstrip("0") or "0"


# --------------------------------------------------------------------------------------
# Ship-to cross-reference
# --------------------------------------------------------------------------------------
def build_xref(master: dict) -> dict[str, dict]:
    """Normalized ID -> {id, qualifier, dc}. Includes the buyer's approved ship-to codes."""
    xref = {}
    for a in master.get("approved_ship_to", []):
        xref[normalize_id(a["code"])] = {"id": a["code"], "qualifier": "92", "dc": a.get("name", a["code"])}
    for x in master.get("ship_to_xref", []):
        xref[normalize_id(x["id"])] = x
    return xref


def check_ship_to(qualifier: str, loc_id: str, xref: dict[str, dict]) -> tuple[str | None, str]:
    """Returns (dictionary key or None, detail)."""
    hit = xref.get(normalize_id(loc_id))
    if hit is None:
        return ("prevalidation:shipto_xref_missing",
                f"ship-to {qualifier}:{loc_id} has no cross-reference ({describe_id(loc_id)}); "
                f"also checked without leading zeros")
    if hit["id"] != loc_id.strip():
        return ("prevalidation:shipto_id_format",
                f"ship-to {loc_id} matches {hit['id']} ({hit['dc']}) only after removing padding")
    return None, f"ship-to {loc_id} -> {hit['dc']}"


# --------------------------------------------------------------------------------------
# Delivery date vs lead time
# --------------------------------------------------------------------------------------
def business_days_between(start: date, end: date) -> int:
    days, d = 0, start
    while d < end:
        d = date.fromordinal(d.toordinal() + 1)
        if d.weekday() < 5:
            days += 1
    return days


def check_delivery_date(order_day: date, requested: date, lead_days: int) -> tuple[str | None, str]:
    have = business_days_between(order_day, requested)
    if have < lead_days:
        return ("prevalidation:delivery_date_inside_lead_time",
                f"requested {requested:%Y-%m-%d} is {have} business days after the order; lead time is {lead_days}")
    return None, ""


# --------------------------------------------------------------------------------------
# Run over documents
# --------------------------------------------------------------------------------------
def prevalidate(docs: list[Doc], master: dict) -> list[Finding]:
    """Checks every purchase order (850) that carries a ship-to (N1*ST)."""
    xref = build_xref(master)
    lead = {c["id"]: c.get("lead_time_days", 0) for c in master.get("customers", [])}
    out = []
    for d in docs:
        if d.st != "850":
            continue
        n1 = next((s for s in d.all("N1") if el(s, 1) == "ST"), None)
        if n1 is not None and el(n1, 4):
            key, detail = check_ship_to(el(n1, 3), el(n1, 4), xref)
            if key:
                out.append(Finding(key, d.file, d.sender, doc_number(d), detail, d.ts, trace_id(d)))
        dtm = next((s for s in d.all("DTM") if el(s, 1) == "002"), None)  # 002 = delivery requested
        if dtm is not None and d.sender in lead:
            order_day = datetime.strptime(el(d.first("BEG"), 5), "%Y%m%d").date()
            requested = datetime.strptime(el(dtm, 2), "%Y%m%d").date()
            key, detail = check_delivery_date(order_day, requested, lead[d.sender])
            if key:
                out.append(Finding(key, d.file, d.sender, doc_number(d), detail, d.ts, trace_id(d)))
    return out
