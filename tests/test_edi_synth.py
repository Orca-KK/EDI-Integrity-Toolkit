"""Generated EDI is structurally valid and every label matches the data."""
import csv
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "generator" / "edi_synth.py"


def generate(out: Path, seed: int = 7, rate: float = 0.05) -> None:
    subprocess.run([sys.executable, str(GEN), "--out", str(out), "--months", "4",
                    "--suppliers", "5", "--anomaly-rate", str(rate), "--seed", str(seed)],
                   check=True, capture_output=True)


def parse(path: Path) -> list[list[str]]:
    text = path.read_text(encoding="ascii").replace("\n", "")
    return [s.split("*") for s in text.split("~") if s]


class GeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "run"
        generate(cls.out)
        with open(cls.out / "labels.csv") as f:
            cls.labels = list(csv.DictReader(f))
        cls.files = sorted((cls.out / "edi").glob("*.edi"))
        cls.parsed = {f"edi/{p.name}": parse(p) for p in cls.files}
        cls.master = json.loads((cls.out / "master_data.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_every_file_has_a_label_row(self):
        self.assertEqual(len(self.labels), len(self.files))
        self.assertEqual({r["file"] for r in self.labels}, set(self.parsed))

    def test_envelopes_are_valid(self):
        for name, segs in self.parsed.items():
            raw = (self.out / name).read_text(encoding="ascii").splitlines()[0]
            self.assertEqual(len(raw), 106, f"{name}: ISA length")
            tags = [s[0] for s in segs]
            self.assertEqual(tags[:3], ["ISA", "GS", "ST"], name)
            self.assertEqual(tags[-3:], ["SE", "GE", "IEA"], name)
            self.assertEqual(tags.count("ST"), 1, name)
            isa, gs, st, se, ge, iea = segs[0], segs[1], segs[2], segs[-3], segs[-2], segs[-1]
            self.assertEqual(isa[13], iea[2], f"{name}: ISA13/IEA02")
            self.assertEqual(isa[15], "T", f"{name}: must be marked test data")
            self.assertEqual(gs[6], ge[2], f"{name}: GS06/GE02")
            self.assertEqual(st[2], se[2], f"{name}: ST02/SE02")
            self.assertEqual(int(se[1]), len(segs) - 4, f"{name}: SE01 segment count")

    def test_invoice_totals_match_lines(self):
        for name, segs in self.parsed.items():
            if segs[2][1] != "810":
                continue
            total = sum(int(s[2]) * float(s[4]) for s in segs if s[0] == "IT1")
            tds = next(int(s[1]) for s in segs if s[0] == "TDS")
            self.assertEqual(tds, int(round(total * 100)), name)

    def test_all_anomaly_types_present(self):
        types = {r["anomaly_type"] for r in self.labels if r["is_anomaly"] == "1"}
        expected = {"remit_to_change", "price_inflation", "quantity_overbilled",
                    "invoice_without_shipment", "duplicate_invoice", "unknown_sender",
                    "replayed_control_number", "ship_to_diverted", "unusual_purchase_order"}
        self.assertEqual(types, expected)

    def test_acknowledgments_are_never_labeled(self):
        for r in self.labels:
            if r["transaction_set"] == "997":
                self.assertEqual(r["is_anomaly"], "0")

    def test_labels_match_the_data(self):
        known_senders = {s["id"] for s in self.master["suppliers"]} | {self.master["buyer"]["id"]}
        remit = {s["id"]: s["remit_to"]["street"] for s in self.master["suppliers"]}
        approved_street = self.master["approved_ship_to"][0]["street"]
        shipped_pos = {next(s[1] for s in segs if s[0] == "PRF")
                       for segs in self.parsed.values() if segs[2][1] == "856"}
        isa_seen = Counter((segs[0][6].strip(), segs[0][13]) for segs in self.parsed.values())

        for r in self.labels:
            if r["is_anomaly"] != "1":
                continue
            segs = self.parsed[r["file"]]
            kind = r["anomaly_type"]
            if kind == "unknown_sender":
                self.assertNotIn(r["sender"], known_senders, r["file"])
            elif kind == "remit_to_change":
                street = next(s[1] for s in segs if s[0] == "N3")
                self.assertNotEqual(street, remit[r["sender"]], r["file"])
            elif kind == "ship_to_diverted":
                street = next(s[1] for s in segs if s[0] == "N3")
                self.assertNotEqual(street, approved_street, r["file"])
            elif kind == "invoice_without_shipment":
                po = next(s[4] for s in segs if s[0] == "BIG")
                self.assertNotIn(po, shipped_pos, r["file"])
            elif kind == "replayed_control_number":
                key = (segs[0][6].strip(), segs[0][13])
                self.assertGreaterEqual(isa_seen[key], 2, r["file"])
            elif kind == "unusual_purchase_order":
                ts = datetime.strptime(segs[1][4] + segs[1][5], "%Y%m%d%H%M")
                self.assertGreaterEqual(ts.weekday(), 5, r["file"])
                self.assertLess(ts.hour, 5, r["file"])

    def test_normal_invoices_use_registered_remit_to(self):
        remit = {s["id"]: s["remit_to"]["street"] for s in self.master["suppliers"]}
        for r in self.labels:
            if r["transaction_set"] == "810" and r["is_anomaly"] == "0":
                street = next(s[1] for s in self.parsed[r["file"]] if s[0] == "N3")
                self.assertEqual(street, remit[r["sender"]], r["file"])

    def test_no_unlabeled_control_number_reuse(self):
        by_key = defaultdict(list)
        for r in self.labels:
            segs = self.parsed[r["file"]]
            by_key[(segs[0][6].strip(), segs[0][13])].append(r)
        for key, rows in by_key.items():
            if len(rows) > 1:
                # every reuse beyond the first must be labeled as a replay
                self.assertTrue(any(x["anomaly_type"] == "replayed_control_number" for x in rows), key)

    def test_same_seed_gives_same_output(self):
        with tempfile.TemporaryDirectory() as t:
            again = Path(t) / "again"
            generate(again)
            self.assertEqual((again / "labels.csv").read_text(), (self.out / "labels.csv").read_text())


if __name__ == "__main__":
    unittest.main()
