"""The issue register.

Five fields are required when an issue is first seen, so logging an issue stays quick.
Everything else is filled in as the root cause becomes clear. Unknown error codes found by a
run are added automatically, once each, so nothing unexplained is silently dropped.
"""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

REQUIRED = ["issue_id", "date_seen", "source_system", "raw_evidence", "reported_symptom"]
ENRICH = ["document_type", "error_code", "decoded_meaning", "category", "root_cause", "fix_applied",
          "preventive_control", "business_impact", "security_relevance", "owner", "status"]
FIELDS = REQUIRED + ENRICH
STATUSES = ["Open", "Decoded", "Fixed", "Prevented"]


def load(path: Path) -> list[dict]:
    if not Path(path).exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def save(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})


def next_id(rows: list[dict]) -> str:
    nums = [int(r["issue_id"].split("-")[1]) for r in rows if r.get("issue_id", "").startswith("SC-")]
    return f"SC-{(max(nums) + 1 if nums else 1):04d}"


def add(path: Path, **issue) -> dict:
    """Log a new issue. Only the intake fields are required; issue_id is assigned if omitted."""
    rows = load(path)
    issue.setdefault("issue_id", next_id(rows))
    issue.setdefault("date_seen", f"{datetime.now():%Y-%m-%d %H:%M}")
    issue.setdefault("status", "Open")
    missing = [k for k in REQUIRED if not issue.get(k)]
    if missing:
        raise ValueError(f"missing intake fields: {', '.join(missing)}")
    rows.append(issue)
    save(path, rows)
    return issue


def register_unknown_codes(path: Path, unknown: dict[str, str]) -> list[dict]:
    """unknown: {code key: example detail}. Adds one Open row per code not already in the register."""
    rows = load(path)
    have = {r.get("error_code") for r in rows}
    added = []
    for key, example in sorted(unknown.items()):
        if key in have:
            continue
        added.append(add(path, source_system=key.split(":")[0], raw_evidence=example,
                         reported_symptom=f"Error code {key} with no dictionary entry",
                         error_code=key, owner="EDI analyst"))
    return added
