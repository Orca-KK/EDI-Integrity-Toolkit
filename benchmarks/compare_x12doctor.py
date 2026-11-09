"""Score the detector and x12-doctor on the same generated datasets. Requires x12-doctor.

Usage: python benchmarks/compare_x12doctor.py --seeds 101-116 --anomaly-rate 0.04
"""

import argparse
import collections
import csv
import json
import os
import re
import subprocess
import sys
import tempfile

try:
    import x12doctor
    from x12doctor.scan import scan
except ImportError:
    sys.exit("x12-doctor is not installed: pip install x12-doctor")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATOR = os.path.join(ROOT, "generator", "edi_synth.py")
DETECTOR = os.path.join(ROOT, "detector", "edi_detect.py")

TYPE_NAMES = {
    "remit_to_change": "Remit-to (bank) address changed",
    "duplicate_invoice": "Duplicate invoice",
    "price_inflation": "Price above the PO",
    "quantity_overbilled": "Billed more than shipped",
    "invoice_without_shipment": "Invoice with no shipment",
    "ship_to_diverted": "Shipment diverted",
    "unknown_sender": "Look-alike sender",
    "replayed_control_number": "Replayed file",
    "unusual_purchase_order": "Unusual purchase order",
}

NOISE = {"B04", "C06"}


def parse_seeds(text):
    seeds = []
    for part in text.split(","):
        if "-" in part:
            a, b = part.split("-")
            seeds.extend(range(int(a), int(b) + 1))
        else:
            seeds.append(int(part))
    return seeds


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def labels(path):
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    docs = [r for r in rows if r["transaction_set"] != "997"]
    planted = {os.path.basename(r["file"]): r["anomaly_type"] for r in docs if r["is_anomaly"] == "1"}
    clean = {os.path.basename(r["file"]) for r in docs if r["is_anomaly"] != "1"}
    controls = collections.defaultdict(set)
    for r in rows:
        controls[(r["sender"], r["isa_control"])].add(os.path.basename(r["file"]))
    return planted, clean, controls, len(rows)


def detector_flags(edi, master, out):
    run([sys.executable, DETECTOR, "--edi", edi, "--master", master, "--out", out])
    with open(os.path.join(out, "findings.csv"), newline="") as f:
        return {r["file"] for r in csv.DictReader(f)}


def file_names(value):
    names = set()
    if isinstance(value, dict):
        for v in value.values():
            names |= file_names(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            names |= file_names(v)
    elif isinstance(value, str):
        for token in re.findall(r"[^\s'\"]+?\.edi", value):
            names.add(re.split(r"[\\/]", token)[-1])
    return names


def x12doctor_flags(edi, controls):
    result = scan(edi)
    every, relevant = collections.defaultdict(set), collections.defaultdict(set)

    def credit(names, code):
        for name in names:
            every[name].add(code)
            if code not in NOISE:
                relevant[name].add(code)

    for entry in result.entries:
        for x in entry.report.findings:
            credit({entry.path.name}, x.code)
    for x in result.findings:
        names = file_names([x.source or "", x.message, x.context or {}])
        if x.code == "A04":
            ctx = x.context or {}
            names |= controls.get((ctx.get("sender"), ctx.get("isa13")), set())
        credit(names, x.code)
    return every, relevant


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="101-116")
    ap.add_argument("--anomaly-rate", default="0.04")
    ap.add_argument("--out", default=os.path.join("benchmarks", "comparison"))
    args = ap.parse_args()

    version = f"x12-doctor {x12doctor.__version__}"

    os.makedirs(args.out, exist_ok=True)
    per_type = collections.defaultdict(lambda: [0, 0, 0, 0])
    totals = collections.Counter()
    clean_codes = collections.Counter()
    examples = []

    for seed in parse_seeds(args.seeds):
        with tempfile.TemporaryDirectory() as tmp:
            data = os.path.join(tmp, "data")
            run([sys.executable, GENERATOR, "--out", data, "--seed", str(seed),
                 "--anomaly-rate", args.anomaly_rate])
            edi = os.path.join(data, "edi")
            planted, clean, controls, files = labels(os.path.join(data, "labels.csv"))
            ours = detector_flags(edi, os.path.join(data, "master_data.json"), os.path.join(tmp, "det"))
            every, relevant = x12doctor_flags(edi, controls)

            totals["documents"] += files
            totals["planted"] += len(planted)
            for name, kind in planted.items():
                row = per_type[kind]
                row[0] += 1
                row[1] += name in ours
                row[2] += name in every
                row[3] += name in relevant
                if name in ours and name not in relevant and len(examples) < 40:
                    examples.append({"seed": seed, "file": name, "type": kind,
                                     "text": open(os.path.join(edi, name)).read()})
            totals["ours_caught"] += sum(n in ours for n in planted)
            totals["xd_caught_any"] += sum(n in every for n in planted)
            totals["xd_caught_relevant"] += sum(n in relevant for n in planted)
            totals["xd_passed_clean"] += sum(n not in every for n in planted)
            totals["xd_missed_relevant"] += sum(n not in relevant for n in planted)
            totals["ours_false_alarms"] += sum(n in ours for n in clean)
            totals["xd_clean_flagged"] += sum(n in every for n in clean)
            for n in clean:
                clean_codes.update(every.get(n, ()))
        print(f"seed {seed} done")

    rows = [{"type": k, "label": TYPE_NAMES.get(k, k), "planted": v[0], "detector": v[1],
             "x12doctor_any_finding": v[2], "x12doctor_relevant_finding": v[3]}
            for k, v in sorted(per_type.items(), key=lambda kv: TYPE_NAMES.get(kv[0], kv[0]))]
    result = {
        "seeds": args.seeds,
        "anomaly_rate": float(args.anomaly_rate),
        "x12doctor_version": version,
        "totals": dict(totals),
        "by_type": rows,
        "x12doctor_codes_on_clean_documents": dict(clean_codes),
    }
    with open(os.path.join(args.out, "comparison.json"), "w") as f:
        json.dump(result, f, indent=2)
    with open(os.path.join(args.out, "examples.json"), "w") as f:
        json.dump(examples, f, indent=2)

    t = totals
    print()
    print(f"Datasets: seeds {args.seeds}, anomaly rate {args.anomaly_rate}, {version}")
    print(f"Documents: {t['documents']:,}   Planted problems: {t['planted']}")
    print()
    print("x12-doctor columns: 'related' counts findings other than the CTT01 count")
    print("and document-timing checks, which also fire on clean files in this data.")
    print()
    print(f"{'Problem type':34}{'Planted':>9}{'Detector':>10}{'x12-doctor':>12}{'(any)':>8}")
    for r in rows:
        print(f"{r['label']:34}{r['planted']:>9}{r['detector']:>10}"
              f"{r['x12doctor_relevant_finding']:>12}{r['x12doctor_any_finding']:>8}")
    print(f"{'Total':34}{t['planted']:>9}{t['ours_caught']:>10}"
          f"{t['xd_caught_relevant']:>12}{t['xd_caught_any']:>8}")
    print()
    print(f"Detector false alarms on clean documents: {t['ours_false_alarms']}")
    print(f"Wrote {os.path.join(args.out, 'comparison.json')}")


if __name__ == "__main__":
    main()
