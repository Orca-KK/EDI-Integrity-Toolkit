"""Read 997 functional acknowledgments and turn their codes into findings.

A rejected 997 is just numbers (AK5*R*5, AK3*N1*5**8, AK4*1*66*1). This module says which segment
and element failed and attaches the dictionary key for each code, so the decoder can explain it.

    AK1  group being acknowledged       AK2  transaction set being acknowledged
    AK3  segment error (AK304 = code)   AK4  element error (AK403 = code, AK404 = bad value)
    AK5  transaction set status (A accepted, E accepted with errors, R rejected)
"""
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
