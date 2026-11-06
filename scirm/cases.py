#!/usr/bin/env python3
"""
cases.py - Write a small synthetic folder that reproduces common real-world integration failures.

The patterns come from day-to-day EDI and warehouse operations; every name, ID and value here is
made up. Use the folder to see the whole SCIRM loop work end to end:

    C1  inbound PO whose ship-to ID is zero-padded             -> prevalidation:shipto_id_format
    C2  inbound PO whose ship-to is sent as a GLN but isn't one -> prevalidation:shipto_xref_missing
    C3  inbound PO requesting delivery inside the lead time    -> prevalidation:delivery_date_inside_lead_time
    C4  supplier 997 rejecting our PO (AK3/AK4 codes)           -> x12:AK5:R, x12:AK3:8, x12:AK4:1, x12:AK4:7
    C5  supplier 997 accepted with errors (bad date)            -> x12:AK5:E, x12:AK4:8
    C6  translator error log: a site-specific code mapped in local_codes, reported with
        'documents: 0' although one document failed            -> decoded + flagged as a source alert defect
    C7  translator error log: a code nobody has decoded yet     -> alert + automatic issue-register entry
    C8  a user who can change remit-to addresses and approve payments -> iam:sod_conflict
    C9  a privileged account unused for months                  -> iam:dormant_privileged
    C10 an analyst tries to release a security hold; later an audit entry is edited
                                                                -> iam:unauthorized_release, iam:audit_log_tampered

Usage:
    python scirm/cases.py --master sample/master_data.json --out cases
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "generator"))
import edi_synth as gen
import access
from prevalidate import gs1_check_digit

ACCESS = {
    "permissions": {
        "ap_clerk": ["enter_invoice", "approve_payment"],
        "vendor_admin": ["create_vendor", "change_remit_to"],
        "edi_analyst": ["manage_xref", "edit_edi_order", "release_hold"],
        "security_lead": ["release_hold", "release_security_hold"],
        "buyer": ["create_po"],
    },
    "users": [
        {"id": "ap.clerk1", "roles": ["ap_clerk"], "last_sign_in": "2026-07-06"},
        {"id": "vendor.admin1", "roles": ["vendor_admin", "ap_clerk"], "last_sign_in": "2026-07-07"},
        {"id": "edi.analyst1", "roles": ["edi_analyst"], "last_sign_in": "2026-07-07"},
        {"id": "sec.lead1", "roles": ["security_lead"], "last_sign_in": "2026-07-01"},
        {"id": "old.admin", "roles": ["vendor_admin"], "last_sign_in": "2026-02-02"},
    ],
    "sod_rules": [
        ["change_remit_to", "approve_payment", "could redirect a supplier payment and approve it"],
        ["create_vendor", "approve_payment", "could create a fake supplier and pay it"],
    ],
    "privileged": ["create_vendor", "change_remit_to", "approve_payment", "release_security_hold"],
    "dormant_days": 90,
}

CUSTOMER = {"id": "RETAILCO", "name": "Retail Customer Co (fictitious)", "lead_time_days": 5}
XREF = [
    {"id": "4900012340", "qualifier": "92", "dc": "DC-EAST (fictitious)"},
    {"id": "DCWEST01", "qualifier": "92", "dc": "DC-WEST (fictitious)"},
]


def not_a_gln() -> str:
    body = "001234567890"
    return body + str((gs1_check_digit(body) + 5) % 10)  # deliberately wrong check digit


def interchange(sender: str, receiver: str, ts: datetime, ctrl: int, st: str, body: list[str]) -> str:
    st_ctrl = f"{ctrl:04d}"
    segs = [gen.seg("ST", st, st_ctrl)] + body
    segs.append(gen.seg("SE", len(segs) + 1, st_ctrl))
    return "\n".join([
        gen.isa(sender, receiver, ts, ctrl),
        gen.seg("GS", gen.FUNCTIONAL_ID[st], sender, receiver, f"{ts:%Y%m%d}", f"{ts:%H%M}", ctrl, "X", gen.VERSION_GS),
        *segs,
        gen.seg("GE", 1, ctrl),
        gen.seg("IEA", 1, f"{ctrl:09d}"),
    ]) + "\n"


def customer_po(po: str, day: datetime, ship_qual: str, ship_id: str, requested: str | None) -> list[str]:
    body = [gen.seg("BEG", "00", "SA", po, "", f"{day:%Y%m%d}")]
    if requested:
        body.append(gen.seg("DTM", "002", requested))
    body += [gen.seg("N1", "ST", "Store receiving (fictitious)", ship_qual, ship_id),
             gen.seg("PO1", 1, 40, "CS", "12.50", "", "BP", "SNACK-100"),
             gen.seg("CTT", 1)]
    return body


def write(master_path: Path, out: Path) -> None:
    edi = out / "edi"
    edi.mkdir(parents=True, exist_ok=True)
    master = json.loads(master_path.read_text())
    buyer = master["buyer"]["id"]
    master["customers"] = [CUSTOMER]
    master["ship_to_xref"] = XREF
    (out / "master_data.json").write_text(json.dumps(master, indent=2))

    s1, s2 = master["suppliers"][0]["id"], master["suppliers"][1]["id"]
    files = {
        "C1_850_padded_shipto.edi": interchange(CUSTOMER["id"], buyer, datetime(2026, 7, 6, 9, 5), 9101, "850",
                                                customer_po("C1001", datetime(2026, 7, 6), "92", "0004900012340", "20260720")),
        "C2_850_unmapped_shipto.edi": interchange(CUSTOMER["id"], buyer, datetime(2026, 7, 6, 18, 50), 9102, "850",
                                                  customer_po("C1002", datetime(2026, 7, 6), "UL", not_a_gln(), "20260720")),
        "C3_850_date_inside_lead.edi": interchange(CUSTOMER["id"], buyer, datetime(2026, 7, 7, 10, 0), 9103, "850",
                                                   customer_po("C1003", datetime(2026, 7, 7), "92", "DCWEST01", "20260709")),
        "C4_997_rejected.edi": interchange(s1, buyer, datetime(2026, 7, 7, 11, 30), 9201, "997", [
            gen.seg("AK1", "PO", 812), gen.seg("AK2", "850", "0812"),
            gen.seg("AK3", "N1", 5, "", 8), gen.seg("AK4", 4, 67, 1),
            gen.seg("AK3", "PO1", 6, "", 8), gen.seg("AK4", 3, 355, 7, "BX"),
            gen.seg("AK5", "R", 5), gen.seg("AK9", "R", 1, 1, 0)]),
        "C5_997_accepted_with_errors.edi": interchange(s2, buyer, datetime(2026, 7, 7, 12, 10), 9301, "997", [
            gen.seg("AK1", "PO", 813), gen.seg("AK2", "850", "0813"),
            gen.seg("AK3", "DTM", 3, "", 8), gen.seg("AK4", 2, 373, 8, "20261340"),
            gen.seg("AK5", "E"), gen.seg("AK9", "E", 1, 1, 1)]),
    }
    for name, text in files.items():
        (edi / name).write_text(text, encoding="ascii")

    log = [
        {"time": "2026-07-06 18:50", "code": "900", "transformation": "po_inbound", "document_group": "PO",
         "partner": CUSTOMER["id"], "data_key": "C1002", "data_error": not_a_gln(),
         "documents_reported": 0, "message": "SHIP TO XREF NOT FOUND OR MISSING/INVALID DC"},
        {"time": "2026-07-07 09:15", "code": "777", "transformation": "po_inbound", "document_group": "PO",
         "partner": CUSTOMER["id"], "data_key": "C1004", "data_error": "UOM CS",
         "documents_reported": 1, "message": "UNIT CONVERSION NOT FOUND"},
    ]
    (out / "translator_errors.jsonl").write_text("\n".join(json.dumps(r) for r in log) + "\n")

    (out / "access.json").write_text(json.dumps(ACCESS, indent=2))
    audit = out / "audit.jsonl"
    audit.unlink(missing_ok=True)
    access.release(ACCESS, audit, "edi.analyst1", "C1002", "P2", "ship-to mapping added", "2026-07-07 08:30:00")
    access.release(ACCESS, audit, "edi.analyst1", "INV-HOLD-7", "P1", "vendor says it is fine", "2026-07-07 09:10:00")
    access.record_change(audit, "edi.analyst1", "C1003", "requested_date", "20260709", "20260714",
                         "moved to agreed lead time", "2026-07-07 10:05:00")
    lines = audit.read_text().splitlines()
    lines[2] = lines[2].replace("20260714", "20260710")  # an edit made after the fact
    audit.write_text("\n".join(lines) + "\n")
    print(f"Wrote {len(files)} EDI files, master data, a translator error log, an access model "
          f"and an audit log to {out}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--master", required=True, help="base master_data.json from the generator")
    ap.add_argument("--out", default="cases", help="output folder (default ./cases)")
    a = ap.parse_args()
    write(Path(a.master), Path(a.out))


if __name__ == "__main__":
    main()
