#!/usr/bin/env python3
"""
run.py - Run the SCIRM loop over a folder of X12 files.

    1. Intake       load the .edi files (and, optionally, a translator error log)
    2. Validate     detector layers 1-3 + pre-validation (ship-to cross-reference, delivery dates)
    3. Decode       every finding and every 997 code through the error dictionary
    4. Measure      trace IDs and lag (any document -> 997, 850 -> 855)
    5. Notify       group into tiered, seven-part alerts; hold any alert that contradicts itself
    6. Access       separation-of-duties review, dormant privileged accounts, audit-log integrity
    7. Learn        add unknown codes to the issue register

Usage:
    python scirm/run.py --edi sample/edi --master sample/master_data.json --out results
    python scirm/run.py --edi cases/edi --master cases/master_data.json --out results_cases \\
        --translator-errors cases/translator_errors.jsonl --local-codes scirm/local_codes.example.json \\
        --register results_cases/issues.csv --access cases/access.json --audit-log cases/audit.jsonl

Outputs (in --out)
    report.md            one-page summary for people
    alerts.md / .json    alerts by tier, ready to send (or held, with the reason)
    findings.csv         every finding with its decoded meaning, owner and tier
    lag.csv              acknowledgment lag by partner: median, 95th percentile, late, missing
    metrics.json         the model's scorecard
"""
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

import access
import ack997
import notify
import prevalidate
import register
import trace
from decode import Dictionary
from findings import Finding, detector_findings, edi_detect, load_docs


def translator_findings(path: Path) -> tuple[list[Finding], list[str]]:
    """Read an EDI product's error log (one JSON object per line). Also flags log lines whose
    document count contradicts the error they report."""
    out, defects = [], []
    for n, line in enumerate(Path(path).read_text().splitlines(), start=1):
        if not line.strip():
            continue
        r = json.loads(line)
        ts = datetime.strptime(r["time"], "%Y-%m-%d %H:%M")
        detail = (f"{r.get('message', '')} | transformation {r.get('transformation', '?')}, "
                  f"data key {r.get('data_key', '?')}, data error {r.get('data_error', '?')}")
        out.append(Finding(f"translator:{r['code']}", f"{Path(path).name}:{n}", r.get("partner", ""),
                           r.get("data_key", ""), detail, ts, f"translator:{r.get('data_key', '')}"))
        if r.get("documents_reported") is not None and int(r["documents_reported"]) < 1:
            defects.append(f"line {n}: reports {r['documents_reported']} documents while describing a failed "
                           f"document (data key {r.get('data_key')}); the source alert understates the problem")
    return out, defects


def write_findings(findings: list[Finding], dictionary: Dictionary, path: Path) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tier", "key", "meaning", "owner", "partner", "document", "detail", "time", "trace", "file"])
        for x in findings:
            d = dictionary.decode(x.key)
            w.writerow([d.tier, x.key, d.meaning, d.owner, x.partner, x.doc_no, x.detail,
                        f"{x.ts:%Y-%m-%d %H:%M}" if x.ts else "", x.trace, x.file])


def write_lag(rows: list[dict], path: Path) -> None:
    with open(path, "w", newline="") as f:
        cols = ["pair", "partner", "documents", "median_hours", "p95_hours", "late", "missing", "pending"]
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k) for k in cols})


def report(metrics: dict, alerts: list, lag_rows: list[dict], defects: list[str], added: list[dict]) -> str:
    m = metrics
    lines = [
        "# SCIRM run report", "",
        f"Checked **{m['documents']:,} documents**; **{m['documents_with_findings']}** had at least one finding "
        f"({m['error_rate_per_1000']} per 1,000). Decode coverage: **{m['decode_coverage_pct']}%** of findings "
        "came with a meaning, fix and owner"
        + (f"; {m['unknown_codes']} unknown code(s) went to the issue register." if m['unknown_codes'] else "."),
        "",
        "## Alerts", "",
        "| Tier | Alerts | Documents |", "| --- | --- | --- |",
    ]
    for t in notify.TIER_ORDER:
        group = [a for a in alerts if a.tier == t and not a.problems]
        if group:
            lines.append(f"| {t} | {len(group)} | {sum(a.count for a in group)} |")
    lines += ["", f"{m['findings']} findings became {m['alerts_ready']} alerts "
                  f"({m['alerts_held']} held for defects); {m['alerts_to_security']} copied to Security.", ""]
    lines += ["## Acknowledgment lag", "",
              "| Pair | Responder | Docs | Median h | 95th pct h | Late | Missing |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in lag_rows:
        lines.append(f"| {r['pair']} | {r['partner']} | {r['documents']} | {r['median_hours']} | "
                     f"{r['p95_hours']} | {r['late']} | {r['missing']} |")
    if defects:
        lines += ["", "## Source alert defects", ""] + [f"- {d}" for d in defects]
    if added:
        lines += ["", "## New issue-register entries", ""] + \
                 [f"- {r['issue_id']}: {r['reported_symptom']}" for r in added]
    if "detector_evaluation" in m:
        e = m["detector_evaluation"]
        lines += ["", "## Detector score against labels", "",
                  f"Recall {e['recall']}, precision {e['precision']}, false alarms {e['false_alarms']}."]
    lines += ["", "See alerts.md for each alert in full, and findings.csv for every finding."]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--edi", required=True, help="folder of .edi files")
    ap.add_argument("--master", required=True, help="trusted master data (JSON)")
    ap.add_argument("--out", default="results", help="output folder (default ./results)")
    ap.add_argument("--translator-errors", help="optional EDI product error log (JSON lines)")
    ap.add_argument("--local-codes", help="optional site code overlay (see local_codes.example.json)")
    ap.add_argument("--register", help="issue register CSV; unknown codes are appended to it")
    ap.add_argument("--access", help="optional access model (JSON) for the separation-of-duties review")
    ap.add_argument("--audit-log", help="optional audit log (JSON lines) to verify and check for denied releases")
    ap.add_argument("--labels", help="optional labels.csv to score the detector")
    ap.add_argument("--sla-997-hours", type=float, default=24)
    ap.add_argument("--sla-855-hours", type=float, default=48)
    a = ap.parse_args()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    dictionary = Dictionary(local_codes=Path(a.local_codes) if a.local_codes else None)
    master = json.loads(Path(a.master).read_text())

    # Intake and validate
    docs = load_docs(Path(a.edi))
    if not docs:
        raise SystemExit(f"No .edi files found in {a.edi}")
    edi_detect.check_structure(docs, master)
    edi_detect.check_business(docs, master)
    findings = detector_findings(docs)
    findings += prevalidate.prevalidate(docs, master)
    findings += ack997.acknowledgment_findings(docs)
    defects: list[str] = []
    if a.translator_errors:
        tf, defects = translator_findings(Path(a.translator_errors))
        findings += tf

    # Access review and audit log
    if a.access:
        as_of = max(d.ts for d in docs if d.ts).date()
        findings += access.review(json.loads(Path(a.access).read_text()), as_of)
    if a.audit_log:
        findings += access.log_findings(Path(a.audit_log))

    # Measure lag
    lag_rows, lag_findings = trace.measure(docs, {"997": timedelta(hours=a.sla_997_hours),
                                                  "855": timedelta(hours=a.sla_855_hours)})
    findings += lag_findings

    # Decode and notify
    alerts = notify.build_alerts(findings, dictionary)
    notify.write_alerts(alerts, out / "alerts.md", out / "alerts.json")
    write_findings(findings, dictionary, out / "findings.csv")
    write_lag(lag_rows, out / "lag.csv")

    # Unknown codes go to the register
    unknown = {}
    for f in findings:
        if f.key not in dictionary:
            unknown.setdefault(f.key, f.detail)
    added = register.register_unknown_codes(Path(a.register), unknown) if a.register and unknown else []

    flagged_files = {f.file for f in findings if f.file}
    metrics = {
        "run_at": f"{datetime.now():%Y-%m-%d %H:%M}",
        "documents": len(docs),
        "documents_with_findings": len(flagged_files & {d.file for d in docs}),
        "error_rate_per_1000": round(len(flagged_files & {d.file for d in docs}) * 1000 / len(docs), 1),
        "findings": len(findings),
        "findings_by_source": {s: sum(1 for f in findings if f.key.startswith(s + ":"))
                               for s in ("detector", "prevalidation", "x12", "lag", "translator", "iam")},
        "decode_coverage_pct": round(100 * sum(1 for f in findings if f.key in dictionary) / len(findings), 1)
        if findings else 100.0,
        "unknown_codes": len(unknown),
        "alerts_ready": sum(1 for x in alerts if not x.problems),
        "alerts_held": sum(1 for x in alerts if x.problems),
        "alerts_by_tier": {t: sum(1 for x in alerts if x.tier == t and not x.problems) for t in notify.TIER_ORDER},
        "alerts_to_security": sum(1 for x in alerts if x.copy_to_security and not x.problems),
        "source_alert_defects": len(defects),
        "lag": lag_rows,
    }
    if a.labels:
        metrics["detector_evaluation"] = {k: v for k, v in edi_detect.score(docs, Path(a.labels), out).items()
                                          if k in ("recall", "precision", "false_alarms", "recall_by_type")}
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
    (out / "report.md").write_text(report(metrics, alerts, lag_rows, defects, added))

    print(f"Checked {len(docs)} documents: {len(findings)} findings -> {metrics['alerts_ready']} alerts "
          f"(P1 {metrics['alerts_by_tier']['P1']}, P2 {metrics['alerts_by_tier']['P2']}, "
          f"P3 {metrics['alerts_by_tier']['P3']}, P4 {metrics['alerts_by_tier']['P4']}); "
          f"decode coverage {metrics['decode_coverage_pct']}%; report -> {out / 'report.md'}")


if __name__ == "__main__":
    main()
