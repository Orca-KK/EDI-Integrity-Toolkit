"""Group findings into tiered alerts and hold any alert that contradicts itself."""
from __future__ import annotations

import json
from datetime import datetime
from dataclasses import asdict, dataclass, field

from decode import Decoded, Dictionary
from findings import Finding

TIER_ORDER = ["P1", "P2", "P3", "P4"]
MAX_EXAMPLES = 5


@dataclass
class Alert:
    tier: str
    title: str
    what: str
    why: str
    impact: str
    fix: list[str]
    owner: str
    trace: list[str]
    key: str
    partner: str
    count: int
    documents: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    escalate_after_minutes: int | None = None
    channel: str = ""
    copy_to_security: bool = False
    known_code: bool = True
    problems: list[str] = field(default_factory=list)


def build_alerts(findings: list[Finding], dictionary: Dictionary) -> list[Alert]:
    # Group by resolved entry so two codes for one root cause become one alert
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.group or dictionary.canonical(f.key), f.partner), []).append(f)

    alerts = []
    for (key, partner), items in groups.items():
        dec: Decoded = dictionary.decode(key)
        if dec.tier == "P4" and dec.category == "ack":
            continue  # accepted acknowledgments are not news
        items.sort(key=lambda f: (f.ts or datetime.min, f.key != key))
        times = [f.ts for f in items if f.ts]
        docs = sorted({f.doc_no or f.file for f in items})
        tier = dictionary.tiers.get(dec.tier, {})
        noun = "document" if len(docs) == 1 else "documents"
        when = ""
        if times:
            when = f", {times[0]:%Y-%m-%d %H:%M}" + (f" to {times[-1]:%Y-%m-%d %H:%M}" if times[-1] != times[0] else "")
        example = next((f for f in items if f.key == key), items[0])

        def line(f: Finding) -> str:
            # AK3/AK4 lines under an AK5 show their own meaning
            label = "" if f.key == key else f"{f.key} {dictionary.decode(f.key).meaning} | "
            return f"{label}{f.trace or f.file}: {f.detail}"

        alerts.append(Alert(
            tier=dec.tier,
            title=f"[{dec.tier}] {dec.meaning} ({key}) - {partner}",
            what=(f"{len(items)} access finding{'s' if len(items) > 1 else ''} for user {partner}{when}"
                  if key.startswith("iam:") else f"{len(docs)} {noun} from/to {partner}{when}"),
            why=f"{dec.meaning}. Example: {example.detail}",
            impact=dec.impact,
            fix=dec.fix,
            owner=dec.owner,
            trace=[line(f) for f in items[:MAX_EXAMPLES]],
            key=key, partner=partner, count=len(docs), documents=docs,
            first_seen=f"{times[0]:%Y-%m-%d %H:%M}" if times else "",
            last_seen=f"{times[-1]:%Y-%m-%d %H:%M}" if times else "",
            escalate_after_minutes=tier.get("escalate_after_minutes"),
            channel=tier.get("channel", ""),
            copy_to_security=dec.security and dec.tier in ("P1", "P2"),
            known_code=dec.known,
        ))
    for a in alerts:
        a.problems = check_alert(a)
    alerts.sort(key=lambda a: (TIER_ORDER.index(a.tier) if a.tier in TIER_ORDER else 9, -a.count, a.key))
    return alerts


def check_alert(a: Alert) -> list[str]:
    """Problems that would make an alert misleading or useless. Empty list = safe to send."""
    problems = []
    if a.count <= 0:
        problems.append(f"count is {a.count} but the alert reports a failure")
    if a.count != len(a.documents):
        problems.append(f"count {a.count} does not match {len(a.documents)} listed documents")
    if a.tier in ("P1", "P2") and not a.fix:
        problems.append("no fix steps for a high-priority alert")
    if not a.owner or a.owner == "Unassigned":
        problems.append("no owner")
    return problems


def to_markdown(a: Alert) -> str:
    lines = [f"### {a.title}", "",
             f"- **What:** {a.what}",
             f"- **Why:** {a.why}",
             f"- **Impact:** {a.impact}",
             "- **Fix:** " + (" -> ".join(a.fix) if a.fix else "none listed"),
             f"- **Owner:** {a.owner}" + (" (copy to Security)" if a.copy_to_security else ""),
             "- **Trace:**"]
    lines += [f"    - {t}" for t in a.trace]
    if len(a.trace) == MAX_EXAMPLES and a.count > MAX_EXAMPLES:
        lines.append(f"    - ... and {a.count - MAX_EXAMPLES} more documents (see findings.csv)")
    route = f"{a.channel}" + (f"; escalate if open after {a.escalate_after_minutes} min" if a.escalate_after_minutes else "")
    lines.append(f"- **Routing:** {route}")
    if not a.known_code:
        lines.append("- **Note:** code not in the dictionary; an issue-register entry was opened")
    if a.problems:
        lines.append(f"- **HELD, alert defect:** {'; '.join(a.problems)}")
    return "\n".join(lines)


def write_alerts(alerts: list[Alert], md_path, json_path) -> None:
    sendable = [a for a in alerts if not a.problems]
    held = [a for a in alerts if a.problems]
    parts = ["# SCIRM alerts", "",
             f"{len(sendable)} alerts ready to send, {len(held)} held for defects.", ""]
    for tier in TIER_ORDER:
        group = [a for a in sendable if a.tier == tier]
        if group:
            parts += [f"## {tier}", ""] + [to_markdown(a) + "\n" for a in group]
    if held:
        parts += ["## Held (alert defects)", ""] + [to_markdown(a) + "\n" for a in held]
    md_path.write_text("\n".join(parts))
    json_path.write_text(json.dumps([asdict(a) for a in alerts], indent=2))
