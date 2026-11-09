"""Read 997 acknowledgments and turn AK3/AK4/AK5 codes into findings."""
from __future__ import annotations

from findings import Doc, Finding, el, trace_id


def read_997(d: Doc) -> list[Finding]:
    out: list[Finding] = []
    group = el(d.first("AK1"), 2)
    current_st, segment = "", ""
    errors: list[Finding] = []
    for s in d.segs:
        tag = s[0]
        if tag == "AK2":
            current_st, errors = f"{el(s, 1)} #{el(s, 2)}", []
        elif tag == "AK3":
            segment = f"{el(s, 1)} at position {el(s, 2)}"
            if el(s, 4):
                errors.append(Finding(f"x12:AK3:{el(s, 4)}", d.file, d.sender, f"group {group}",
                                      f"{current_st}: segment {segment}", d.ts, trace_id(d)))
        elif tag == "AK4":
            bad = f", bad value '{el(s, 4)}'" if el(s, 4) else ""
            errors.append(Finding(f"x12:AK4:{el(s, 3)}", d.file, d.sender, f"group {group}",
                                  f"{current_st}: segment {segment}, element {el(s, 1)} "
                                  f"(data element {el(s, 2)}){bad}", d.ts, trace_id(d)))
        elif tag == "AK5":
            status = el(s, 1)
            if status != "A":
                reasons = ", ".join(x for x in s[2:] if x)
                out.append(Finding(f"x12:AK5:{status}", d.file, d.sender, f"group {group}",
                                   f"{d.sender} answered {current_st} with {status}"
                                   + (f" (AK5 codes {reasons})" if reasons else ""), d.ts, trace_id(d)))
                for e in errors:
                    e.group = f"x12:AK5:{status}"
                out += errors
            errors = []
    return out


def acknowledgment_findings(docs: list[Doc]) -> list[Finding]:
    out = []
    for d in docs:
        if d.st == "997":
            out += read_997(d)
    return out
