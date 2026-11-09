"""Detector finds the labeled anomalies with few false alarms and catches broken envelopes."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "generator" / "edi_synth.py"
DET = ROOT / "detector" / "edi_detect.py"


def run(cmd: list[str]) -> None:
    subprocess.run([sys.executable, *cmd], check=True, capture_output=True)


class DetectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.tmp.name)
        cls.results = []
        # Seeds the detector was not tuned on
        for seed in (301, 302, 303):
            data, out = cls.base / f"data{seed}", cls.base / f"out{seed}"
            run([str(GEN), "--out", str(data), "--seed", str(seed), "--anomaly-rate", "0.05"])
            run([str(DET), "--edi", str(data / "edi"), "--master", str(data / "master_data.json"),
                 "--out", str(out), "--labels", str(data / "labels.csv")])
            cls.results.append(json.loads((out / "evaluation.json").read_text()))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_recall_and_precision(self):
        detected = sum(r["detected"] for r in self.results)
        anomalies = sum(r["anomalies"] for r in self.results)
        false_alarms = sum(r["false_alarms"] for r in self.results)
        self.assertGreaterEqual(detected / anomalies, 0.95)
        self.assertGreaterEqual(detected / (detected + false_alarms), 0.95)

    def test_every_anomaly_type_is_detected_at_least_once(self):
        for r in self.results:
            for kind, frac in r["recall_by_type"].items():
                found, total = map(int, frac.split("/"))
                if total:
                    self.assertGreater(found, 0, f"{kind} never detected")

    def test_broken_envelope_is_flagged(self):
        data = self.base / "data301"
        target = next(p for p in sorted((data / "edi").glob("*_810.edi")))
        broken_dir = self.base / "broken" / "edi"
        broken_dir.mkdir(parents=True)
        text = target.read_text().replace("SE*", "SE*99", 1)  # wrong segment count
        (broken_dir / target.name).write_text(text)
        out = self.base / "broken_out"
        run([str(DET), "--edi", str(broken_dir), "--master", str(data / "master_data.json"),
             "--out", str(out)])
        findings = (out / "findings.csv").read_text()
        self.assertIn("envelope_invalid", findings)


if __name__ == "__main__":
    unittest.main()
