"""SCIRM layer tests, including both end-to-end runs."""
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scirm"))

import access
import notify
import prevalidate as pv
import register
import trace
from decode import Dictionary
from findings import Finding, load_docs

GEN = ROOT / "generator" / "edi_synth.py"
CASES = ROOT / "scirm" / "cases.py"
RUN = ROOT / "scirm" / "run.py"
LOCAL = ROOT / "scirm" / "local_codes.example.json"


def run(cmd):
    subprocess.run([sys.executable, *map(str, cmd)], check=True, capture_output=True)


class IdentifierTests(unittest.TestCase):
    def test_gs1_check_digit(self):
        self.assertTrue(pv.gs1_valid("4006381333931"))   # published EAN-13 example
        self.assertTrue(pv.gs1_valid("036000291452"))    # published UPC-A example
        self.assertFalse(pv.gs1_valid("4006381333932"))

    def test_describe_id_flags_fake_gln(self):
        self.assertIn("fails the GS1 check digit", pv.describe_id("4006381333932"))
        self.assertIn("valid GS1", pv.describe_id("4006381333931"))
        self.assertIn("DUNS", pv.describe_id("123456789"))


class ShipToTests(unittest.TestCase):
    xref = pv.build_xref({"approved_ship_to": [], "ship_to_xref": [
        {"id": "4900012340", "qualifier": "92", "dc": "DC-EAST"}]})

    def test_exact_match_passes(self):
        self.assertIsNone(pv.check_ship_to("92", "4900012340", self.xref)[0])

    def test_zero_padding_is_a_format_issue_not_a_missing_location(self):
        key, detail = pv.check_ship_to("92", "0004900012340", self.xref)
        self.assertEqual(key, "prevalidation:shipto_id_format")
        self.assertIn("DC-EAST", detail)

    def test_unmapped_location_is_missing(self):
        key, _ = pv.check_ship_to("UL", "0012345678909", self.xref)
        self.assertEqual(key, "prevalidation:shipto_xref_missing")


class DeliveryDateTests(unittest.TestCase):
    def test_inside_lead_time(self):
        key, _ = pv.check_delivery_date(date(2026, 7, 7), date(2026, 7, 9), 5)
        self.assertEqual(key, "prevalidation:delivery_date_inside_lead_time")

    def test_weekends_do_not_count(self):
        # Fri -> next Fri is 5 business days
        self.assertIsNone(pv.check_delivery_date(date(2026, 7, 3), date(2026, 7, 10), 5)[0])


class DictionaryTests(unittest.TestCase):
    def test_known_and_unknown_codes(self):
        d = Dictionary()
        self.assertEqual(d.decode("x12:AK4:1").meaning, "Mandatory data element missing")
        unknown = d.decode("translator:12345")
        self.assertFalse(unknown.known)
        self.assertEqual(unknown.tier, "P2")

    def test_local_code_overlay(self):
        d = Dictionary(local_codes=LOCAL)
        self.assertIn("translator:900", d)
        self.assertEqual(d.canonical("translator:900"), "prevalidation:shipto_xref_missing")

    def test_every_entry_is_complete(self):
        d = Dictionary()
        for key, e in d.entries.items():
            self.assertIn(e["tier"], d.tiers, key)
            if e["tier"] in ("P1", "P2"):
                self.assertTrue(e["fix"], f"{key} has no fix steps")
                self.assertTrue(e["owner"], f"{key} has no owner")


class AlertTests(unittest.TestCase):
    def test_repeats_become_one_alert(self):
        t = datetime(2026, 7, 6, 9, 0)
        fs = [Finding("detector:remit_to_changed", f"f{i}.edi", "SUPPLIERA", f"INV{i}", "changed", t) for i in range(4)]
        alerts = notify.build_alerts(fs, Dictionary())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 4)
        self.assertTrue(alerts[0].copy_to_security)
        self.assertEqual(alerts[0].problems, [])

    def test_site_code_and_prevalidation_merge(self):
        t = datetime(2026, 7, 6, 9, 0)
        fs = [Finding("prevalidation:shipto_xref_missing", "a.edi", "CUST", "C1002", "no xref", t),
              Finding("translator:900", "log:1", "CUST", "C1002", "SHIP TO XREF NOT FOUND", t)]
        alerts = notify.build_alerts(fs, Dictionary(local_codes=LOCAL))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].count, 1)

    def test_contradictory_alert_is_held(self):
        a = notify.Alert(tier="P2", title="t", what="w", why="y", impact="i", fix=["f"], owner="o",
                         trace=[], key="k", partner="p", count=0, documents=["C1002"])
        self.assertTrue(notify.check_alert(a))


class RegisterTests(unittest.TestCase):
    def test_intake_requires_five_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "issues.csv"
            with self.assertRaises(ValueError):
                register.add(path, source_system="EDI")
            row = register.add(path, source_system="EDI", raw_evidence="screenshot",
                               reported_symptom="PO held")
            self.assertEqual(row["issue_id"], "SC-0001")
            self.assertEqual(row["status"], "Open")

    def test_unknown_codes_are_registered_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "issues.csv"
            register.register_unknown_codes(path, {"translator:777": "UNIT CONVERSION"})
            register.register_unknown_codes(path, {"translator:777": "UNIT CONVERSION"})
            self.assertEqual(len(register.load(path)), 1)


class AccessTests(unittest.TestCase):
    model = {
        "permissions": {"ap": ["approve_payment"], "vendor": ["change_remit_to"],
                        "edi": ["release_hold"], "sec": ["release_hold", "release_security_hold"]},
        "users": [{"id": "a", "roles": ["ap", "vendor"], "last_sign_in": "2026-07-01"},
                  {"id": "e", "roles": ["edi"], "last_sign_in": "2026-07-01"},
                  {"id": "s", "roles": ["sec"], "last_sign_in": "2026-01-01"}],
        "sod_rules": [["change_remit_to", "approve_payment", "redirect and approve"]],
        "privileged": ["approve_payment", "release_security_hold"],
        "dormant_days": 90,
    }

    def test_separation_of_duties_and_dormant_accounts(self):
        keys = [(f.key, f.partner) for f in access.review(self.model, date(2026, 7, 7))]
        self.assertIn(("iam:sod_conflict", "a"), keys)
        self.assertIn(("iam:dormant_privileged", "s"), keys)
        self.assertNotIn(("iam:sod_conflict", "e"), keys)

    def test_security_hold_needs_higher_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            self.assertTrue(access.release(self.model, log, "e", "X1", "P2", "mapping fixed"))
            self.assertFalse(access.release(self.model, log, "e", "X2", "P1", "looks fine"))
            self.assertTrue(access.release(self.model, log, "s", "X2", "P1", "verified with supplier"))
            self.assertFalse(access.release(self.model, log, "s", "X3", "P2", "  "))
            keys = [f.key for f in access.log_findings(log)]
            self.assertEqual(keys.count("iam:unauthorized_release"), 2)
            self.assertNotIn("iam:audit_log_tampered", keys)

    def test_edited_audit_entry_breaks_the_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            access.record_change(log, "e", "PO1", "date", "20260709", "20260714", "lead time")
            access.record_change(log, "e", "PO2", "date", "20260710", "20260715", "lead time")
            self.assertEqual(access.verify(log), [])
            lines = log.read_text().splitlines()
            lines[0] = lines[0].replace("20260714", "20260712")
            log.write_text("\n".join(lines) + "\n")
            self.assertEqual(access.verify(log)[0].key, "iam:audit_log_tampered")

    def test_change_without_reason_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                access.record_change(Path(tmp) / "a.jsonl", "e", "PO1", "date", "1", "2", "")


class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        b = Path(cls.tmp.name)
        cls.sample, cls.cases = b / "sample", b / "cases"
        run([GEN, "--out", cls.sample, "--seed", 7, "--months", 3])
        run([CASES, "--master", cls.sample / "master_data.json", "--out", cls.cases])
        cls.out_sample, cls.out_cases = b / "out_sample", b / "out_cases"
        run([RUN, "--edi", cls.sample / "edi", "--master", cls.sample / "master_data.json",
             "--out", cls.out_sample, "--labels", cls.sample / "labels.csv"])
        run([RUN, "--edi", cls.cases / "edi", "--master", cls.cases / "master_data.json", "--out", cls.out_cases,
             "--translator-errors", cls.cases / "translator_errors.jsonl", "--local-codes", LOCAL,
             "--register", b / "issues.csv", "--access", cls.cases / "access.json",
             "--audit-log", cls.cases / "audit.jsonl"])
        cls.issues = b / "issues.csv"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_synthetic_data_fully_decoded_and_detector_unchanged(self):
        m = json.loads((self.out_sample / "metrics.json").read_text())
        self.assertEqual(m["decode_coverage_pct"], 100.0)
        self.assertEqual(m["alerts_held"], 0)
        self.assertGreaterEqual(m["detector_evaluation"]["recall"], 0.95)

    def test_every_document_is_acknowledged(self):
        rows = json.loads((self.out_sample / "metrics.json").read_text())["lag"]
        self.assertEqual(sum(r["missing"] for r in rows if r["pair"].endswith("997")), 0)

    def test_cases_produce_expected_findings(self):
        keys = (self.out_cases / "findings.csv").read_text()
        for k in ("prevalidation:shipto_id_format", "prevalidation:shipto_xref_missing",
                  "prevalidation:delivery_date_inside_lead_time", "x12:AK5:R", "x12:AK4:1",
                  "x12:AK4:7", "x12:AK5:E", "x12:AK4:8", "translator:900", "translator:777",
                  "iam:sod_conflict", "iam:dormant_privileged", "iam:unauthorized_release",
                  "iam:audit_log_tampered"):
            self.assertIn(k, keys)

    def test_cases_flag_source_defect_and_register_unknown_code(self):
        m = json.loads((self.out_cases / "metrics.json").read_text())
        self.assertEqual(m["source_alert_defects"], 1)
        self.assertEqual(m["unknown_codes"], 1)
        self.assertEqual(register.load(self.issues)[0]["error_code"], "translator:777")

    def test_rejected_997_is_one_alert(self):
        alerts = json.loads((self.out_cases / "alerts.json").read_text())
        rejected = [a for a in alerts if a["key"] == "x12:AK5:R"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(len(rejected[0]["trace"]), 5)  # AK5 + 2 AK3 + 2 AK4


class LagTests(unittest.TestCase):
    def test_late_and_missing_acknowledgments(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "d"
            run([GEN, "--out", data, "--seed", 11, "--months", 2])
            docs = load_docs(data / "edi")
            rows, _ = trace.measure(docs, {"855": timedelta(hours=1)})
            self.assertTrue(any(r["late"] for r in rows if r["pair"] == "850 -> 855"))
            # drop every 997: documents older than the window become missing
            no_acks = [d for d in docs if d.st != "997"]
            rows, findings = trace.measure(no_acks)
            self.assertTrue(any(f.key == "lag:ack_997_missing" for f in findings))


if __name__ == "__main__":
    unittest.main()
