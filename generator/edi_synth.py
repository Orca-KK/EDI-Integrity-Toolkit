#!/usr/bin/env python3
"""Synthetic X12 004010 supply-chain EDI with labeled anomalies. All data is fictitious.

Usage: python generator/edi_synth.py --out sample --seed 42
"""

from __future__ import annotations

import argparse
import copy
import csv
import json
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

ELEM = "*"
SEG = "~"
SUBELEM = ">"
VERSION_GS = "004010"
VERSION_ISA = "00401"
USAGE = "T"  # ISA15: T = test data. This generator never produces production data.

FUNCTIONAL_ID = {"850": "PO", "855": "PR", "856": "SH", "810": "IN", "997": "FA"}

ANOMALY_TYPES = [
    "remit_to_change",          # invoice asks for payment to a new remit-to address
    "price_inflation",          # invoice unit price well above the purchase order price
    "quantity_overbilled",      # invoice bills more units than were shipped
    "invoice_without_shipment", # invoice for goods that were never shipped
    "duplicate_invoice",        # same charges billed again under a new invoice number
    "unknown_sender",           # document arrives from a look-alike, unregistered sender ID
    "replayed_control_number",  # interchange control number reused from an earlier file
    "ship_to_diverted",         # ship notice shows goods going to an unapproved address
    "unusual_purchase_order",   # buyer's own PO at an odd hour with an abnormal quantity
]

BUYER = {
    "id": "LAKESHOREMFG",
    "name": "Lakeshore Fabrication Co (fictitious)",
    "ship_to": {
        "code": "LSF01",
        "name": "Lakeshore Fabrication Plant 1",
        "street": "100 Example Industrial Dr",
        "city": "Sampleton",
        "state": "MI",
        "zip": "49000",
    },
}

SUPPLIER_NAMES = [
    ("NORTHSTEEL", "North Bay Steel Supply"),
    ("PINEFASTEN", "Pine Ridge Fasteners"),
    ("CEDARPACK", "Cedar Packaging Works"),
    ("RIVERELEC", "River Valley Electrical Parts"),
    ("SUMMITPOLY", "Summit Polymer Components"),
    ("GRANITETOOL", "Granite Tooling Supply"),
    ("HARBORCHEM", "Harbor Industrial Coatings"),
    ("MAPLEBEAR", "Maple Bearing Distributors"),
    ("ORCHARDCAST", "Orchard Castings"),
    ("PRAIRIEWIRE", "Prairie Wire and Cable"),
]

CITIES = [
    ("Exampleville", "OH", "43000"), ("Testburg", "IN", "46000"), ("Mockton", "IL", "60000"),
    ("Demoport", "WI", "53000"), ("Fakeston", "PA", "15000"), ("Sampleford", "MN", "55000"),
]

FRAUD_REMIT = [
    ("Accounts Receivable Dept", "PO Box 4471", "Elsewhere", "FL", "33000"),
    ("Remittance Processing Ctr", "88 Unknown Plaza Ste 900", "Faraway", "NV", "89000"),
    ("AR Lockbox Services", "PO Box 9012", "Otherplace", "TX", "75000"),
]

DIVERSION_SITES = [
    ("Overflow Storage Annex", "9 Nowhere Rd Unit 14", "Distant", "GA", "30000"),
    ("Temporary Receiving", "512 Unlisted Ave", "Farfield", "AZ", "85000"),
]

ITEM_WORDS = ["BRKT", "BOLT", "PLATE", "BOX", "RELAY", "GASKET", "BEARING", "WIRE",
              "BUSHING", "PANEL", "HOSE", "FILTER", "SPRING", "CLAMP", "COAT"]


@dataclass
class Supplier:
    id: str
    name: str
    remit_to: dict
    cadence_days: int
    lead_days: tuple[int, int]
    partial_ship_prob: float
    items: dict  # sku -> {"price": float, "qty": (lo, hi), "uom": str}


@dataclass
class Doc:
    ts: datetime
    st: str                 # transaction set: 850, 855, 856, 810, 997
    sender: str
    receiver: str
    payload: dict
    doc_no: str = ""        # PO number, shipment ID, invoice number, etc.
    label: str = ""         # anomaly type, or "" for normal
    detail: str = ""
    replay_from: int | None = None   # set when the ISA control number should be replayed
    isa_ctrl: int = 0
    gs_ctrl: int = 0
    file: str = ""
    refs: dict = field(default_factory=dict)  # links between documents


def money(x: float) -> str:
    return f"{x:.2f}"


def make_suppliers(n: int, rng: random.Random) -> list[Supplier]:
    if n > len(SUPPLIER_NAMES):
        raise SystemExit(f"--suppliers must be <= {len(SUPPLIER_NAMES)}")
    suppliers = []
    for i, (sid, name) in enumerate(SUPPLIER_NAMES[:n]):
        city, state, zip_ = CITIES[i % len(CITIES)]
        items = {}
        for _ in range(rng.randint(3, 7)):
            sku = f"{rng.choice(ITEM_WORDS)}-{rng.randint(100, 999)}"
            lo = rng.choice([5, 10, 20, 50, 100])
            items[sku] = {
                "price": round(rng.uniform(0.5, 250.0), 2),
                "qty": (lo, lo * rng.randint(3, 8)),
                "uom": "EA",
            }
        suppliers.append(Supplier(
            id=sid,
            name=f"{name} (fictitious)",
            remit_to={"name": f"{name} (fictitious)",
                      "street": f"{rng.randint(10, 9999)} Commerce St",
                      "city": city, "state": state, "zip": zip_},
            cadence_days=rng.choice([2, 3, 5, 7, 7, 14]),
            lead_days=rng.choice([(2, 5), (3, 7), (5, 10), (7, 14)]),
            partial_ship_prob=rng.choice([0.05, 0.1, 0.2]),
            items=items,
        ))
    return suppliers


def business_time(d: date, rng: random.Random) -> datetime:
    """A timestamp during business hours on the given day."""
    return datetime(d.year, d.month, d.day, rng.randint(7, 16), rng.randint(0, 59))


def next_business_day(d: date) -> date:
    while d.weekday() >= 5:
        d += timedelta(days=1)
    return d


def simulate(suppliers: list[Supplier], start: date, months: int, rng: random.Random) -> list[Doc]:
    end = start + timedelta(days=int(months * 30.4))
    docs: list[Doc] = []
    po_seq = 450000
    ship_seq = 700000
    inv_seq = {s.id: rng.randint(10000, 90000) for s in suppliers}

    for s in suppliers:
        d = start + timedelta(days=rng.randint(0, s.cadence_days))
        while d < end:
            d = next_business_day(d)
            if d >= end:
                break
            po_seq += 1
            po_no = f"PO{po_seq}"
            po_ts = business_time(d, rng)

            # Purchase order lines
            skus = rng.sample(list(s.items), k=rng.randint(1, min(4, len(s.items))))
            lines = []
            for n, sku in enumerate(skus, start=1):
                lo, hi = s.items[sku]["qty"]
                lines.append({"line": n, "sku": sku, "qty": rng.randint(lo, hi),
                              "price": s.items[sku]["price"], "uom": "EA"})
            docs.append(Doc(po_ts, "850", BUYER["id"], s.id,
                            {"po": po_no, "date": d, "lines": lines, "ship_to": BUYER["ship_to"]},
                            doc_no=po_no))

            # PO acknowledgment (855): usually 0-2 days, occasionally late
            ack_lag = rng.choice([0, 1, 1, 2]) if rng.random() > 0.08 else rng.randint(3, 6)
            ack_ts = business_time(next_business_day(d + timedelta(days=ack_lag)), rng)
            docs.append(Doc(ack_ts, "855", s.id, BUYER["id"],
                            {"po": po_no, "date": ack_ts.date(), "lines": copy.deepcopy(lines)},
                            doc_no=po_no))

            # Shipments (856): one, or two partial shipments
            lead = rng.randint(*s.lead_days)
            ship_day = next_business_day(d + timedelta(days=lead))
            if rng.random() < s.partial_ship_prob and any(l["qty"] > 1 for l in lines):
                first = []
                second = []
                for l in lines:
                    q1 = max(1, int(l["qty"] * rng.uniform(0.4, 0.7))) if l["qty"] > 1 else l["qty"]
                    first.append({**l, "qty": q1})
                    if l["qty"] - q1 > 0:
                        second.append({**l, "qty": l["qty"] - q1})
                splits = [(ship_day, first),
                          (next_business_day(ship_day + timedelta(days=rng.randint(3, 8))), second)]
            else:
                splits = [(ship_day, copy.deepcopy(lines))]

            for sday, slines in splits:
                if not slines:
                    continue
                ship_seq += 1
                ship_id = f"SH{ship_seq}"
                sts = business_time(sday, rng)
                docs.append(Doc(sts, "856", s.id, BUYER["id"],
                                {"shipment": ship_id, "po": po_no, "date": sday,
                                 "bol": f"BOL{rng.randint(10**7, 10**8 - 1)}",
                                 "ship_to": BUYER["ship_to"], "lines": slines},
                                doc_no=ship_id, refs={"po": po_no}))

                # Invoice (810) for that shipment, 0-3 days later
                inv_seq[s.id] += 1
                inv_no = f"INV{inv_seq[s.id]}"
                iday = next_business_day(sday + timedelta(days=rng.randint(0, 3)))
                ilines = copy.deepcopy(slines)
                # Noise: occasional small, legitimate price correction (within 2%)
                if rng.random() < 0.05:
                    l = rng.choice(ilines)
                    l["price"] = round(l["price"] * rng.uniform(0.98, 1.02), 2)
                docs.append(Doc(business_time(iday, rng), "810", s.id, BUYER["id"],
                                {"invoice": inv_no, "po": po_no, "date": iday,
                                 "remit_to": s.remit_to, "lines": ilines},
                                doc_no=inv_no, refs={"po": po_no, "shipment": ship_id}))

            d = d + timedelta(days=max(1, int(rng.gauss(s.cadence_days, s.cadence_days * 0.2))))
    return docs


def inject(docs: list[Doc], suppliers: list[Supplier], rate: float, rng: random.Random) -> list[Doc]:
    by_id = {s.id: s for s in suppliers}
    target = max(len(ANOMALY_TYPES), round(rate * len(docs)))
    per_type = {t: target // len(ANOMALY_TYPES) for t in ANOMALY_TYPES}
    for t in rng.sample(ANOMALY_TYPES, target % len(ANOMALY_TYPES)):
        per_type[t] += 1

    def pick(st: str, n: int, extra=lambda d: True) -> list[Doc]:
        pool = [d for d in docs if d.st == st and not d.label and extra(d)]
        return rng.sample(pool, min(n, len(pool)))

    # Invoices whose shipment is the only one for that PO (needed for invoice_without_shipment)
    ship_count: dict[str, int] = {}
    for d in docs:
        if d.st == "856":
            ship_count[d.refs["po"]] = ship_count.get(d.refs["po"], 0) + 1

    for d in pick("810", per_type["remit_to_change"]):
        name, street, city, state, zip_ = rng.choice(FRAUD_REMIT)
        d.payload["remit_to"] = {"name": f"{by_id[d.sender].remit_to['name']} {name}",
                                 "street": street, "city": city, "state": state, "zip": zip_}
        d.label, d.detail = "remit_to_change", f"remit-to changed to {street}, {city} {state}"

    for d in pick("810", per_type["price_inflation"]):
        l = rng.choice(d.payload["lines"])
        old = l["price"]
        l["price"] = round(old * rng.uniform(1.15, 1.45), 2)
        d.label, d.detail = "price_inflation", f"{l['sku']} billed {money(l['price'])} vs PO {money(old)}"

    for d in pick("810", per_type["quantity_overbilled"]):
        l = rng.choice(d.payload["lines"])
        old = l["qty"]
        l["qty"] = old + max(1, int(old * rng.uniform(0.1, 0.5)))
        d.label, d.detail = "quantity_overbilled", f"{l['sku']} billed {l['qty']} vs shipped {old}"

    for d in pick("810", per_type["invoice_without_shipment"],
                  extra=lambda d: ship_count.get(d.refs.get("po"), 0) == 1):
        ship_id = d.refs["shipment"]
        docs[:] = [x for x in docs if not (x.st == "856" and x.doc_no == ship_id)]
        d.label, d.detail = "invoice_without_shipment", f"shipment {ship_id} for {d.refs['po']} never sent"

    used_inv = {d.doc_no for d in docs if d.st == "810"}
    for d in pick("810", per_type["duplicate_invoice"]):
        dup = copy.deepcopy(d)
        sup = by_id[d.sender]
        # Altered copy of the original number, or the supplier's next number
        if rng.random() < 0.5:
            new_no = d.doc_no + rng.choice(["A", "R", "-1", "-2"])
        else:
            top = max(int(x.doc_no[3:]) for x in docs
                      if x.st == "810" and x.sender == d.sender and x.doc_no[3:].isdigit())
            new_no = f"INV{top + rng.randint(1, 40)}"
        if new_no in used_inv:
            continue
        used_inv.add(new_no)
        dup.payload["invoice"] = new_no
        dup.doc_no = new_no
        dup.ts = d.ts + timedelta(days=rng.randint(3, 20), minutes=rng.randint(0, 300))
        dup.payload["date"] = dup.ts.date()
        dup.label, dup.detail = "duplicate_invoice", f"duplicates {d.doc_no} from {sup.id}"
        d.refs["has_duplicate"] = True  # keep the original untouched by later injections
        docs.append(dup)

    for d in pick("810", per_type["unknown_sender"], extra=lambda d: "has_duplicate" not in d.refs):
        real = d.sender
        fake = (real[:-1] + ("X" if real[-1] != "X" else "Y"))
        d.sender = fake
        d.label, d.detail = "unknown_sender", f"sender {fake} imitates {real}"

    inbound = lambda d: d.receiver == BUYER["id"] and d.st in ("855", "856", "810")
    for d in pick("810", per_type["replayed_control_number"],
                  extra=lambda d: inbound(d) and "has_duplicate" not in d.refs):
        d.replay_from = 1  # resolved during rendering
        d.label, d.detail = "replayed_control_number", "ISA control number reused"

    for d in pick("856", per_type["ship_to_diverted"]):
        name, street, city, state, zip_ = rng.choice(DIVERSION_SITES)
        d.payload["ship_to"] = {"code": "TMP99", "name": name, "street": street,
                                "city": city, "state": state, "zip": zip_}
        d.label, d.detail = "ship_to_diverted", f"ship-to changed to {street}, {city} {state}"

    # Rogue PO: weekend night, abnormal quantity; the supplier still sends an 855
    max_po = max(int(d.doc_no[2:]) for d in docs if d.st == "850")
    first_day = min(d.ts for d in docs).date()
    for k, base in enumerate(pick("850", per_type["unusual_purchase_order"]), start=1):
        sat = base.ts.date() - timedelta(days=(base.ts.weekday() + 2) % 7)  # previous Saturday
        if sat < first_day:
            sat += timedelta(days=7)  # keep it inside the simulated period
        ts = datetime(sat.year, sat.month, sat.day, rng.randint(1, 4), rng.randint(0, 59))
        po_no = f"PO{max_po + k}"
        line = copy.deepcopy(rng.choice(base.payload["lines"]))
        normal = line["qty"]
        line["line"], line["qty"] = 1, normal * rng.randint(8, 15)
        rogue = Doc(ts, "850", BUYER["id"], base.receiver,
                    {"po": po_no, "date": sat, "lines": [line], "ship_to": BUYER["ship_to"]},
                    doc_no=po_no, label="unusual_purchase_order",
                    detail=f"{line['sku']} qty {line['qty']} (normal ~{normal}) at {ts:%a %H:%M}")
        ack_ts = business_time(next_business_day(sat + timedelta(days=2)), rng)
        ack = Doc(ack_ts, "855", base.receiver, BUYER["id"],
                  {"po": po_no, "date": ack_ts.date(), "lines": [copy.deepcopy(line)]}, doc_no=po_no)
        docs += [rogue, ack]

    return docs


def add_functional_acks(docs: list[Doc], rng: random.Random) -> list[Doc]:
    """Every received group is acknowledged with a 997 by the receiver."""
    acks = []
    for d in docs:
        if d.st == "997":
            continue
        ack_ts = d.ts + timedelta(minutes=rng.randint(2, 90))
        acks.append(Doc(ack_ts, "997", d.receiver, d.sender,
                        {"ack_of": d}, doc_no=f"ACK-{d.doc_no}"))
    return docs + acks


def seg(*elements) -> str:
    return ELEM.join(str(e) for e in elements) + SEG


def isa(sender: str, receiver: str, ts: datetime, ctrl: int) -> str:
    s = (f"ISA{ELEM}00{ELEM}{'':10}{ELEM}00{ELEM}{'':10}{ELEM}ZZ{ELEM}{sender:<15}{ELEM}"
         f"ZZ{ELEM}{receiver:<15}{ELEM}{ts:%y%m%d}{ELEM}{ts:%H%M}{ELEM}U{ELEM}{VERSION_ISA}{ELEM}"
         f"{ctrl:09d}{ELEM}0{ELEM}{USAGE}{ELEM}{SUBELEM}{SEG}")
    assert len(s) == 106, f"ISA must be 106 characters, got {len(s)}"
    return s


def body(d: Doc) -> list[str]:
    p = d.payload
    out: list[str] = []
    if d.st == "850":
        out.append(seg("BEG", "00", "SA", p["po"], "", f"{p['date']:%Y%m%d}"))
        st = p["ship_to"]
        out += [seg("N1", "ST", st["name"], "92", st["code"]), seg("N3", st["street"]),
                seg("N4", st["city"], st["state"], st["zip"])]
        for l in p["lines"]:
            out.append(seg("PO1", l["line"], l["qty"], l["uom"], money(l["price"]), "", "BP", l["sku"]))
        out.append(seg("CTT", len(p["lines"])))
    elif d.st == "855":
        out.append(seg("BAK", "00", "AC", p["po"], f"{p['date']:%Y%m%d}"))
        for l in p["lines"]:
            out += [seg("PO1", l["line"], l["qty"], l["uom"], money(l["price"]), "", "BP", l["sku"]),
                    seg("ACK", "IA", l["qty"], l["uom"])]
        out.append(seg("CTT", len(p["lines"])))
    elif d.st == "856":
        out.append(seg("BSN", "00", p["shipment"], f"{p['date']:%Y%m%d}", "1200"))
        hl = 1
        out += [seg("HL", hl, "", "S"), seg("REF", "BM", p["bol"]),
                seg("DTM", "011", f"{p['date']:%Y%m%d}")]
        st = p["ship_to"]
        out += [seg("N1", "ST", st["name"], "92", st["code"]), seg("N3", st["street"]),
                seg("N4", st["city"], st["state"], st["zip"])]
        hl += 1
        order_hl = hl
        out += [seg("HL", hl, 1, "O"), seg("PRF", p["po"])]
        for l in p["lines"]:
            hl += 1
            out += [seg("HL", hl, order_hl, "I"), seg("LIN", l["line"], "BP", l["sku"]),
                    seg("SN1", "", l["qty"], l["uom"])]
        out.append(seg("CTT", hl))
    elif d.st == "810":
        out.append(seg("BIG", f"{p['date']:%Y%m%d}", p["invoice"], "", p["po"]))
        rt = p["remit_to"]
        out += [seg("N1", "RE", rt["name"]), seg("N3", rt["street"]), seg("N4", rt["city"], rt["state"], rt["zip"])]
        total = 0.0
        for l in p["lines"]:
            out.append(seg("IT1", l["line"], l["qty"], l["uom"], money(l["price"]), "", "BP", l["sku"]))
            total += l["qty"] * l["price"]
        out += [seg("TDS", int(round(total * 100))), seg("CTT", len(p["lines"]))]
    elif d.st == "997":
        a: Doc = p["ack_of"]
        out += [seg("AK1", FUNCTIONAL_ID[a.st], a.gs_ctrl), seg("AK9", "A", 1, 1, 1)]
    return out


def render(docs: list[Doc], out_dir: Path) -> None:
    edi_dir = out_dir / "edi"
    edi_dir.mkdir(parents=True, exist_ok=True)
    docs.sort(key=lambda d: d.ts)
    isa_seq: dict[str, int] = {}
    gs_seq: dict[str, int] = {}
    used: dict[str, list[int]] = {}

    # Pass 1: control numbers (997s must know the GS number of what they acknowledge)
    for d in docs:
        gs_seq[d.sender] = gs_seq.get(d.sender, 0) + 1
        d.gs_ctrl = gs_seq[d.sender]
        if d.replay_from is not None and used.get(d.sender):
            # Reuse an interchange number this sender already sent
            d.isa_ctrl = rng_global.choice(used[d.sender])
            d.detail += f" ({d.isa_ctrl:09d})"
        else:
            if d.replay_from is not None:
                # No earlier number exists for this sender: keep the document normal, unlabeled
                d.replay_from, d.label, d.detail = None, "", ""
            isa_seq[d.sender] = isa_seq.get(d.sender, 0) + 1
            d.isa_ctrl = isa_seq[d.sender]
            used.setdefault(d.sender, []).append(d.isa_ctrl)

    # Pass 2: write files
    for i, d in enumerate(docs, start=1):
        st_ctrl = f"{d.gs_ctrl:04d}"
        segs = [seg("ST", d.st, st_ctrl)] + body(d)
        segs.append(seg("SE", len(segs) + 1, st_ctrl))
        text = "\n".join([
            isa(d.sender, d.receiver, d.ts, d.isa_ctrl),
            seg("GS", FUNCTIONAL_ID[d.st], d.sender, d.receiver, f"{d.ts:%Y%m%d}", f"{d.ts:%H%M}",
                d.gs_ctrl, "X", VERSION_GS),
            *segs,
            seg("GE", 1, d.gs_ctrl),
            seg("IEA", 1, f"{d.isa_ctrl:09d}"),
        ]) + "\n"
        name = f"{d.ts:%Y%m%d_%H%M}_{i:06d}_{d.sender}_{d.st}.edi"
        (edi_dir / name).write_text(text, encoding="ascii")
        d.file = f"edi/{name}"


def write_outputs(docs: list[Doc], suppliers: list[Supplier], out_dir: Path, args) -> dict:
    with open(out_dir / "labels.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file", "transaction_set", "sender", "document_number", "isa_control",
                    "is_anomaly", "anomaly_type", "detail"])
        for d in docs:
            w.writerow([d.file, d.st, d.sender, d.doc_no, f"{d.isa_ctrl:09d}",
                        int(bool(d.label)), d.label, d.detail])

    master = {
        "note": "Fictitious master data the buyer's ERP would hold. Use it as the trusted reference.",
        "buyer": BUYER,
        "approved_ship_to": [BUYER["ship_to"]],
        "suppliers": [
            {"id": s.id, "name": s.name, "remit_to": s.remit_to,
             "items": {k: {"price": v["price"], "uom": v["uom"]} for k, v in s.items.items()}}
            for s in suppliers
        ],
    }
    (out_dir / "master_data.json").write_text(json.dumps(master, indent=2))

    counts: dict[str, int] = {}
    for d in docs:
        if d.label:
            counts[d.label] = counts.get(d.label, 0) + 1
    by_set: dict[str, int] = {}
    for d in docs:
        by_set[d.st] = by_set.get(d.st, 0) + 1
    summary = {
        "generated_with": {"months": args.months, "suppliers": args.suppliers,
                           "anomaly_rate": args.anomaly_rate, "seed": args.seed, "start": args.start},
        "documents": len(docs),
        "documents_by_transaction_set": dict(sorted(by_set.items())),
        "anomalies": sum(counts.values()),
        "anomalies_by_type": dict(sorted(counts.items())),
        "note": "Anomaly counts cover documents only; 997 acknowledgments are never labeled.",
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


rng_global = random.Random(0)


def main() -> None:
    global rng_global
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="./sample", help="output folder (default ./sample)")
    ap.add_argument("--months", type=int, default=6, help="months of trading to simulate (default 6)")
    ap.add_argument("--suppliers", type=int, default=6, help="number of suppliers, max 10 (default 6)")
    ap.add_argument("--anomaly-rate", type=float, default=0.03,
                    help="share of business documents to alter, 0-0.2 (default 0.03)")
    ap.add_argument("--start", default="2026-01-05", help="first trading day, YYYY-MM-DD")
    ap.add_argument("--seed", type=int, default=42, help="random seed for repeatable output")
    args = ap.parse_args()
    if not 0 <= args.anomaly_rate <= 0.2:
        raise SystemExit("--anomaly-rate must be between 0 and 0.2")

    rng = random.Random(args.seed)
    rng_global = random.Random(args.seed + 1)
    out_dir = Path(args.out)
    if (out_dir / "edi").exists() and any((out_dir / "edi").iterdir()):
        raise SystemExit(f"{out_dir / 'edi'} is not empty; choose a new --out folder")

    suppliers = make_suppliers(args.suppliers, rng)
    docs = simulate(suppliers, date.fromisoformat(args.start), args.months, rng)
    docs = inject(docs, suppliers, args.anomaly_rate, rng)
    docs = add_functional_acks(docs, rng)
    render(docs, out_dir)
    summary = write_outputs(docs, suppliers, out_dir, args)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
