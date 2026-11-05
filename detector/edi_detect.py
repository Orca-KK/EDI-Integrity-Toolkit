#!/usr/bin/env python3
"""
edi_detect.py - Rule-based integrity checks for X12 supply-chain EDI (layers 1-3).

Part of the EDI Transaction Integrity Toolkit.

Layer 1  Structure:   envelope validity, known senders, reused interchange control numbers
Layer 2  Business:    invoice vs purchase order vs ship notice (prices, quantities, shipment
                      exists), duplicate invoices
Layer 3  Changes:     remit-to and ship-to changes against trusted master data, purchase
                      orders entered off-hours with abnormal quantities

It reads a folder of .edi files plus the buyer's trusted master data (master_data.json),
and writes findings.csv. With --labels it also scores itself against a labeled dataset
(such as one made by generator/edi_synth.py) and reports precision and recall.

Usage:
    python detector/edi_detect.py --edi sample/edi --master sample/master_data.json --out results
    python detector/edi_detect.py --edi sample/edi --master sample/master_data.json --out results --labels sample/labels.csv

Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

PRICE_TOLERANCE = 0.03      # legitimate price corrections stay within 3%
UNUSUAL_QTY_FACTOR = 3      # PO quantity this many times the item's median is abnormal
BUSINESS_HOURS = (6, 20)    # orders outside 06:00-20:00 or on weekends are off-hours

# Which anomaly type each rule is evidence of (used only for scoring)
RULE_TYPE = {
    "envelope_invalid": "structure_error",
    "unknown_sender": "unknown_sender",
    "replayed_control_number": "replayed_control_number",
    "invoice_no_po": "invoice_without_shipment",
    "invoice_without_shipment": "invoice_without_shipment",
    "price_above_po": "price_inflation",
    "quantity_over_shipped": "quantity_overbilled",
    "duplicate_invoice": "duplicate_invoice",
    "remit_to_changed": "remit_to_change",
    "ship_to_not_approved": "ship_to_diverted",
    "unusual_purchase_order": "unusual_purchase_order",
}

# When a file triggers several rules, the most specific one names the finding
PRIORITY = ["unknown_sender", "replayed_control_number", "duplicate_invoice",
            "remit_to_changed", "ship_to_not_approved", "invoice_without_shipment",
            "invoice_no_po", "price_above_po", "quantity_over_shipped",
            "unusual_purchase_order", "envelope_invalid"]


@dataclass
class Doc:
    file: str
    segs: list[list[str]]
    raw_first_line: str
    sender: str = ""
    receiver: str = ""
    isa_ctrl: str = ""
    st: str = ""
    ts: datetime | None = None
    findings: list[tuple[str, str, str]] = field(default_factory=list)  # (rule, severity, detail)

    def first(self, tag: str) -> list[str] | None:
        return next((s for s in self.segs if s[0] == tag), None)

    def all(self, tag: str) -> list[list[str]]:
        return [s for s in self.segs if s[0] == tag]

    def flag(self, rule: str, severity: str, detail: str) -> None:
        self.findings.append((rule, severity, detail))


def el(seg: list[str] | None, i: int, default: str = "") -> str:
    return seg[i] if seg is not None and len(seg) > i else default


# --------------------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------------------
def load(edi_dir: Path) -> list[Doc]:
    docs = []
    for p in sorted(edi_dir.glob("*.edi")):
        text = p.read_text(encoding="ascii", errors="replace")
        first_line = text.splitlines()[0] if text else ""
        segs = [s.split("*") for s in text.replace("\r", "").replace("\n", "").split("~") if s]
        d = Doc(file=p.name, segs=segs, raw_first_line=first_line)
        isa, gs, st = d.first("ISA"), d.first("GS"), d.first("ST")
        d.sender, d.receiver = el(isa, 6).strip(), el(isa, 8).strip()
        d.isa_ctrl, d.st = el(isa, 13), el(st, 1)
        try:
            d.ts = datetime.strptime(el(gs, 4) + el(gs, 5), "%Y%m%d%H%M")
        except ValueError:
            d.ts = None
        docs.append(d)
    docs.sort(key=lambda d: (d.ts or datetime.min, d.file))
    return docs


# --------------------------------------------------------------------------------------
# Layer 1: structure
# --------------------------------------------------------------------------------------
def check_structure(docs: list[Doc], master: dict) -> None:
    known = {s["id"] for s in master["suppliers"]} | {master["buyer"]["id"]}
    seen_ctrl: dict[str, set[str]] = defaultdict(set)
    for d in docs:
        problems = []
        tags = [s[0] for s in d.segs]
        if len(d.raw_first_line) != 106:
            problems.append("ISA segment is not 106 characters")
        if tags[:2] != ["ISA", "GS"] or tags[-2:] != ["GE", "IEA"]:
            problems.append("envelope segments missing or out of order")
        st, se = d.first("ST"), d.first("SE")
        if st is None or se is None:
            problems.append("ST/SE missing")
        else:
            if el(st, 2) != el(se, 2):
                problems.append("ST/SE control numbers differ")
            body_len = tags.index("SE") - tags.index("ST") + 1
            if el(se, 1) != str(body_len):
                problems.append(f"SE count {el(se, 1)} but {body_len} segments")
        if el(d.first("GS"), 6) != el(d.first("GE"), 2):
            problems.append("GS/GE control numbers differ")
        if d.isa_ctrl != el(d.first("IEA"), 2):
            problems.append("ISA/IEA control numbers differ")
        if problems:
            d.flag("envelope_invalid", "high", "; ".join(problems))

        if d.sender not in known:
            d.flag("unknown_sender", "high", f"sender {d.sender} is not a registered partner")
        elif d.isa_ctrl in seen_ctrl[d.sender]:
            d.flag("replayed_control_number", "high",
                   f"interchange {d.isa_ctrl} from {d.sender} was already received")
        seen_ctrl[d.sender].add(d.isa_ctrl)


# --------------------------------------------------------------------------------------
# Layers 2 and 3: business rules and change alerts
# --------------------------------------------------------------------------------------
def check_business(docs: list[Doc], master: dict) -> None:
    buyer = master["buyer"]["id"]
    remit = {s["id"]: s["remit_to"] for s in master["suppliers"]}
    approved_streets = {a["street"] for a in master["approved_ship_to"]}

    # Purchase orders and shipments (batch view of the whole folder)
    po_lines: dict[str, dict[str, dict]] = {}
    po_doc: dict[str, Doc] = {}
    shipped: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    ship_events: dict[str, list[tuple]] = defaultdict(list)  # po -> [(ship date, sku, qty)]
    ship_sets: dict[str, list[tuple]] = defaultdict(list)    # po -> line sets of each shipment
    for d in docs:
        if d.st == "850" and d.sender == buyer:
            po = el(d.first("BEG"), 3)
            po_doc[po] = d
            po_lines[po] = {el(s, 7): {"qty": int(el(s, 2) or 0), "price": float(el(s, 4) or 0)}
                            for s in d.all("PO1")}
        elif d.st == "856":
            po = el(d.first("PRF"), 1)
            ship_day = el(d.first("BSN"), 3)  # YYYYMMDD
            for lin, sn1 in zip(d.all("LIN"), d.all("SN1")):
                qty = int(el(sn1, 2) or 0)
                shipped[po][el(lin, 3)] += qty
                ship_events[po].append((ship_day, el(lin, 3), qty))
            ship_sets[po].append(tuple(sorted((el(l, 3), int(el(s, 2) or 0))
                                              for l, s in zip(d.all("LIN"), d.all("SN1")))))
            n3 = d.first("N3")
            if el(n3, 1) not in approved_streets:
                d.flag("ship_to_not_approved", "high",
                       f"ship-to street '{el(n3, 1)}' is not an approved location")

    # Unusual purchase orders: off-hours AND quantity far above the item's normal
    qty_history: dict[str, list[int]] = defaultdict(list)
    for lines in po_lines.values():
        for sku, l in lines.items():
            qty_history[sku].append(l["qty"])
    median_qty = {sku: statistics.median(q) for sku, q in qty_history.items()}
    for po, d in po_doc.items():
        if d.ts is None:
            continue
        off_hours = d.ts.weekday() >= 5 or not (BUSINESS_HOURS[0] <= d.ts.hour < BUSINESS_HOURS[1])
        for sku, l in po_lines[po].items():
            if off_hours and l["qty"] > UNUSUAL_QTY_FACTOR * median_qty[sku]:
                d.flag("unusual_purchase_order", "medium",
                       f"{sku} qty {l['qty']} vs median {median_qty[sku]:g}, entered {d.ts:%a %H:%M}")

    # Invoices
    billed: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    seen_invoices: dict[tuple, list[str]] = {}
    for d in docs:
        if d.st != "810":
            continue
        big = d.first("BIG")
        inv, po = el(big, 2), el(big, 4)
        lines = [(el(s, 7), int(el(s, 2) or 0), float(el(s, 4) or 0)) for s in d.all("IT1")]

        # Layer 3: remit-to must match master data
        if d.sender in remit:
            expected = remit[d.sender]
            got = (el(d.first("N3"), 1), el(d.first("N4"), 1), el(d.first("N4"), 2))
            if got != (expected["street"], expected["city"], expected["state"]):
                d.flag("remit_to_changed", "high",
                       f"remit-to {', '.join(got)} differs from registered {expected['street']}, "
                       f"{expected['city']} {expected['state']}")

        # Duplicate: same supplier, same PO, same lines as an earlier invoice. Identical invoices
        # are legitimate only when an equal number of identical shipments was received
        # (a partial shipment can split an order into two equal halves).
        key = (d.sender, po, tuple(sorted(lines)))
        qty_set = tuple(sorted((sku, qty) for sku, qty, _ in lines))
        allowed = max(1, ship_sets[po].count(qty_set))
        seen_invoices.setdefault(key, []).append(inv)
        is_duplicate = len(seen_invoices[key]) > allowed
        if is_duplicate:
            d.flag("duplicate_invoice", "high", f"{inv} repeats the charges of {seen_invoices[key][0]}")

        if po not in po_lines:
            d.flag("invoice_no_po", "high", f"{inv} references unknown purchase order {po}")
            continue
        if po not in shipped:
            d.flag("invoice_without_shipment", "high", f"{inv} bills {po}, but no ship notice was received")

        for sku, qty, price in lines:
            ordered = po_lines[po].get(sku)
            if ordered is None:
                d.flag("price_above_po", "high", f"{inv} bills {sku}, which is not on {po}")
                continue
            if price > ordered["price"] * (1 + PRICE_TOLERANCE):
                d.flag("price_above_po", "high",
                       f"{sku} billed {price:.2f} vs PO {ordered['price']:.2f} "
                       f"(+{(price / ordered['price'] - 1) * 100:.0f}%)")
            if is_duplicate or po not in shipped:
                continue  # already flagged; don't let it distort the running totals
            # Compare everything billed so far with what had shipped by the invoice date
            inv_day = el(big, 1)
            shipped_by_now = sum(q for day, s, q in ship_events[po] if s == sku and day <= inv_day)
            if billed[po][sku] + qty > shipped_by_now:
                d.flag("quantity_over_shipped", "high",
                       f"{sku}: {billed[po][sku] + qty} billed in total vs {shipped_by_now} shipped by {inv_day}")
                continue  # keep the overbilled amount out of the totals
            billed[po][sku] += qty


# --------------------------------------------------------------------------------------
# Output and scoring
# --------------------------------------------------------------------------------------
def primary(d: Doc) -> str:
    rules = {r for r, sev, _ in d.findings if sev in ("high", "medium")}
    return next((r for r in PRIORITY if r in rules), "")


def write_findings(docs: list[Doc], out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out / "findings.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file", "transaction_set", "sender", "rule", "severity", "detail"])
        for d in docs:
            for rule, sev, detail in d.findings:
                w.writerow([d.file, d.st, d.sender, rule, sev, detail])
                n += 1
    return n


def score(docs: list[Doc], labels_path: Path, out: Path) -> dict:
    with open(labels_path) as f:
        labels = {Path(r["file"]).name: r for r in csv.DictReader(f)}
    tp = fp = fn = tn = 0
    per_type: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "detected": 0})
    misses, false_alarms = [], []
    for d in docs:
        truth = labels.get(d.file)
        if truth is None:
            continue
        flagged = bool(primary(d))
        is_anom = truth["is_anomaly"] == "1"
        if is_anom:
            per_type[truth["anomaly_type"]]["total"] += 1
            if flagged:
                tp += 1
                per_type[truth["anomaly_type"]]["detected"] += 1
            else:
                fn += 1
                misses.append((d.file, truth["anomaly_type"]))
        elif flagged:
            fp += 1
            false_alarms.append((d.file, primary(d)))
        else:
            tn += 1
    total = tp + fp + fn + tn
    result = {
        "documents_scored": total,
        "anomalies": tp + fn,
        "detected": tp,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_alarms": fp,
        "false_alarms_per_1000_documents": round(fp * 1000 / total, 2) if total else None,
        "recall_by_type": {t: f"{v['detected']}/{v['total']}" for t, v in sorted(per_type.items())},
        "missed": misses[:20],
        "false_alarm_examples": false_alarms[:20],
    }
    (out / "evaluation.json").write_text(json.dumps(result, indent=2))
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--edi", required=True, help="folder of .edi files")
    ap.add_argument("--master", required=True, help="trusted master data (JSON)")
    ap.add_argument("--out", default="results", help="output folder (default ./results)")
    ap.add_argument("--labels", help="optional labels.csv to score the results")
    args = ap.parse_args()

    master = json.loads(Path(args.master).read_text())
    docs = load(Path(args.edi))
    if not docs:
        raise SystemExit(f"No .edi files found in {args.edi}")
    check_structure(docs, master)
    check_business(docs, master)
    out = Path(args.out)
    n = write_findings(docs, out)
    flagged = sum(1 for d in docs if primary(d))
    print(f"Checked {len(docs)} documents: {flagged} flagged, {n} findings -> {out / 'findings.csv'}")
    if args.labels:
        print(json.dumps(score(docs, Path(args.labels), out), indent=2))


if __name__ == "__main__":
    main()
