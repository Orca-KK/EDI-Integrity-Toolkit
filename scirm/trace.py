"""Acknowledgment lag per partner (document to 997, 850 to 855) as median and 95th percentile."""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta

from findings import Doc, Finding, doc_number, el, gs_ctrl, trace_id

DEFAULT_SLA = {"997": timedelta(hours=24), "855": timedelta(hours=48)}


def p95(values: list[float]) -> float:
    if len(values) == 1:
        return values[0]
    return statistics.quantiles(values, n=20, method="inclusive")[18]


def measure(docs: list[Doc], sla: dict | None = None, as_of: datetime | None = None
            ) -> tuple[list[dict], list[Finding]]:
    sla = {**DEFAULT_SLA, **(sla or {})}
    timed = [d for d in docs if d.ts]
    as_of = as_of or max(d.ts for d in timed)

    acks = {}  # (original sender, group control) -> first 997 time
    for d in timed:
        if d.st == "997":
            key = (d.receiver, el(d.first("AK1"), 2))
            acks[key] = min(acks.get(key, d.ts), d.ts)
    po_acks = {}
    for d in timed:
        if d.st == "855":
            po = el(d.first("BAK"), 3)
            po_acks[po] = min(po_acks.get(po, d.ts), d.ts)

    lags: dict[tuple[str, str], list[float]] = {}
    counts: dict[tuple[str, str], dict[str, int]] = {}
    findings: list[Finding] = []

    def record(pair: str, d: Doc, partner: str, got: datetime | None, window: timedelta, key: str):
        c = counts.setdefault((pair, partner), {"documents": 0, "late": 0, "missing": 0, "pending": 0})
        c["documents"] += 1
        if got is None:
            if d.ts + window > as_of:
                c["pending"] += 1
                return
            c["missing"] += 1
            findings.append(Finding(f"lag:{key}_missing", d.file, partner, doc_number(d),
                                    f"no {pair.split(' -> ')[1]} within {window.total_seconds() / 3600:g} h "
                                    f"of {d.ts:%Y-%m-%d %H:%M}",
                                    d.ts, trace_id(d)))
            return
        hours = (got - d.ts).total_seconds() / 3600
        lags.setdefault((pair, partner), []).append(hours)
        if got - d.ts > window:
            c["late"] += 1
            findings.append(Finding(f"lag:{key}_late", d.file, partner, doc_number(d),
                                    f"{pair} took {hours:.1f} h (window {window.total_seconds() / 3600:g} h)",
                                    d.ts, trace_id(d)))

    for d in timed:
        if d.st == "997":
            continue
        record(f"{d.st} -> 997", d, d.receiver, acks.get((d.sender, gs_ctrl(d))), sla["997"], "ack_997")
        if d.st == "850":
            record("850 -> 855", d, d.receiver, po_acks.get(doc_number(d)), sla["855"], "po_ack_855")

    rows = []
    for (pair, partner), c in sorted(counts.items()):
        v = lags.get((pair, partner), [])
        rows.append({"pair": pair, "partner": partner, **c,
                     "median_hours": round(statistics.median(v), 2) if v else None,
                     "p95_hours": round(p95(v), 2) if v else None})
    return rows, findings
