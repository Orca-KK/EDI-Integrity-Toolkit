"""Time the detector and x12-doctor on the same generated datasets.

Each tool is run from the command line on every dataset, the way a user would
run it, and the total wall-clock time is recorded. The median of several rounds
is reported.

Requires: pip install x12-doctor

Usage:
    python benchmarks/speed_x12doctor.py --seeds 101-116 --anomaly-rate 0.04 --rounds 3
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import sysconfig
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENERATOR = os.path.join(ROOT, "generator", "edi_synth.py")
DETECTOR = os.path.join(ROOT, "detector", "edi_detect.py")


def parse_seeds(text):
    seeds = []
    for part in text.split(","):
        if "-" in part:
            a, b = part.split("-")
            seeds.extend(range(int(a), int(b) + 1))
        else:
            seeds.append(int(part))
    return seeds


def timed(cmd):
    start = time.perf_counter()
    res = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.perf_counter() - start
    if res.returncode not in (0, 1):
        sys.exit(f"command failed: {' '.join(cmd)}\n{res.stderr}")
    return elapsed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", default="101-116")
    ap.add_argument("--anomaly-rate", default="0.04")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--out", default=os.path.join("benchmarks", "comparison"))
    args = ap.parse_args()

    x12doctor = shutil.which("x12doctor") or shutil.which(
        "x12doctor", path=sysconfig.get_path("scripts"))
    if not x12doctor:
        sys.exit("x12-doctor is not installed: pip install x12-doctor")

    seeds = parse_seeds(args.seeds)
    with tempfile.TemporaryDirectory() as tmp:
        files = 0
        for seed in seeds:
            data = os.path.join(tmp, f"s{seed}")
            subprocess.run([sys.executable, GENERATOR, "--out", data, "--seed", str(seed),
                            "--anomaly-rate", args.anomaly_rate], capture_output=True)
            files += len(os.listdir(os.path.join(data, "edi")))

        detector, doctor = [], []
        for r in range(args.rounds):
            d = sum(timed([sys.executable, DETECTOR, "--edi", os.path.join(tmp, f"s{s}", "edi"),
                           "--master", os.path.join(tmp, f"s{s}", "master_data.json"),
                           "--out", os.path.join(tmp, f"out{s}")]) for s in seeds)
            x = sum(timed([x12doctor, "scan", os.path.join(tmp, f"s{s}", "edi"),
                           "--format", "json", "--all"]) for s in seeds)
            detector.append(d)
            doctor.append(x)
            print(f"round {r + 1}: detector {d:.2f}s, x12-doctor {x:.2f}s")

    d, x = statistics.median(detector), statistics.median(doctor)
    result = {
        "seeds": args.seeds,
        "files": files,
        "rounds": args.rounds,
        "detector_seconds": round(d, 2),
        "x12doctor_seconds": round(x, 2),
        "detector_files_per_second": round(files / d),
        "x12doctor_files_per_second": round(files / x),
        "all_rounds": {"detector": [round(v, 2) for v in detector],
                       "x12doctor": [round(v, 2) for v in doctor]},
    }
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "speed.json"), "w") as f:
        json.dump(result, f, indent=2)

    print()
    print(f"{files:,} files, median of {args.rounds} rounds")
    print(f"Detector:   {d:6.2f} s   {files / d:8,.0f} files per second")
    print(f"x12-doctor: {x:6.2f} s   {files / x:8,.0f} files per second")
    print(f"Wrote {os.path.join(args.out, 'speed.json')}")


if __name__ == "__main__":
    main()
