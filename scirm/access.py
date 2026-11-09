#!/usr/bin/env python3
"""Separation of duties, dormant accounts, role-based release and a hash-chained audit log.

Usage: python scirm/access.py {review,release,verify} --help
Example access model: the access.json written by scirm/cases.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import date, datetime
from pathlib import Path

from findings import Finding

GENESIS = "0" * 64
SECURITY_TIERS = ("P1",)


def permissions_of(user: dict, model: dict) -> set[str]:
    perms = set()
    for role in user.get("roles", []):
        perms |= set(model["permissions"].get(role, []))
    return perms


def review(model: dict, as_of: date | None = None) -> list[Finding]:
    as_of = as_of or date.today()
    out = []
    for u in model["users"]:
        perms = permissions_of(u, model)
        for a, b, why in model.get("sod_rules", []):
            if a in perms and b in perms:
                out.append(Finding("iam:sod_conflict", "", u["id"], ",".join(u["roles"]),
                                   f"{u['id']} can both {a} and {b}: {why}"))
        held = perms & set(model.get("privileged", []))
        last = u.get("last_sign_in")
        if held and last:
            idle = (as_of - date.fromisoformat(last)).days
            if idle > model.get("dormant_days", 90):
                out.append(Finding("iam:dormant_privileged", "", u["id"], ",".join(u["roles"]),
                                   f"{u['id']} holds {', '.join(sorted(held))} but last signed in {idle} days ago"))
    return out


def _digest(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def _last_hash(log: Path) -> str:
    if not log.exists():
        return GENESIS
    lines = [x for x in log.read_text().splitlines() if x.strip()]
    return json.loads(lines[-1])["hash"] if lines else GENESIS


def append(log: Path, **event) -> dict:
    entry = {"time": event.pop("time", f"{datetime.now():%Y-%m-%d %H:%M:%S}"), **event,
             "prev": _last_hash(log)}
    entry["hash"] = _digest(entry)
    with open(log, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def verify(log: Path) -> list[Finding]:
    """Recompute the chain. Any edited, inserted or deleted line breaks it from that point on."""
    out, prev = [], GENESIS
    for n, line in enumerate(Path(log).read_text().splitlines(), start=1):
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("prev") != prev or e.get("hash") != _digest(e):
            out.append(Finding("iam:audit_log_tampered", f"{Path(log).name}:{n}", e.get("user", ""),
                               e.get("item", ""), f"entry {n} does not match the hash chain"))
            break
        prev = e["hash"]
    return out


def release(model: dict, log: Path, user: str, item: str, tier: str, reason: str,
            time: str | None = None) -> bool:
    """Release a held document or alert. Security (P1) holds need 'release_security_hold'."""
    needed = "release_security_hold" if tier in SECURITY_TIERS else "release_hold"
    u = next((x for x in model["users"] if x["id"] == user), None)
    allowed = bool(u) and needed in permissions_of(u, model) and bool(reason.strip())
    extra = {"time": time} if time else {}
    append(log, action="release", user=user, item=item, tier=tier, needs=needed,
           reason=reason, allowed=allowed, **extra)
    return allowed


def record_change(log: Path, user: str, item: str, field: str, old: str, new: str, reason: str,
                  time: str | None = None) -> dict:
    """Log a manual change to an EDI-originated order. A reason is required."""
    if not reason.strip():
        raise ValueError("a reason is required for a manual change")
    extra = {"time": time} if time else {}
    return append(log, action="change", user=user, item=item, field=field, old=old, new=new,
                  reason=reason, **extra)


def log_findings(log: Path) -> list[Finding]:
    """Denied release attempts in the log, plus any break in the hash chain."""
    out = verify(log)
    for n, line in enumerate(Path(log).read_text().splitlines(), start=1):
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("action") == "release" and not e.get("allowed"):
            out.append(Finding("iam:unauthorized_release", f"{Path(log).name}:{n}", e.get("user", ""),
                               e.get("item", ""), f"{e.get('user')} tried to release {e.get('item')} "
                               f"({e.get('tier')}) without {e.get('needs')}",
                               datetime.strptime(e["time"], "%Y-%m-%d %H:%M:%S")))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("review")
    r.add_argument("--access", required=True)
    r.add_argument("--as-of", help="review date (YYYY-MM-DD); default today")
    rel = sub.add_parser("release")
    rel.add_argument("--access", required=True)
    rel.add_argument("--log", required=True)
    rel.add_argument("--user", required=True)
    rel.add_argument("--item", required=True)
    rel.add_argument("--tier", default="P2")
    rel.add_argument("--reason", required=True)
    v = sub.add_parser("verify")
    v.add_argument("--log", required=True)
    a = ap.parse_args()

    if a.cmd == "review":
        as_of = date.fromisoformat(a.as_of) if a.as_of else None
        for f in review(json.loads(Path(a.access).read_text()), as_of):
            print(f"{f.key}: {f.detail}")
    elif a.cmd == "release":
        ok = release(json.loads(Path(a.access).read_text()), Path(a.log), a.user, a.item, a.tier, a.reason)
        print("released" if ok else "denied (logged)")
    else:
        problems = verify(Path(a.log))
        print("audit log intact" if not problems else problems[0].detail)


if __name__ == "__main__":
    main()
