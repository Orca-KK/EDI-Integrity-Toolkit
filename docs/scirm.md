# SCIRM: Supply Chain Integration Resilience Model

SCIRM is the layer that sits on top of the detector. The detector answers "is this document suspicious?" SCIRM answers the questions that come after it, which are the ones that cost the most time in day-to-day operations:

1. **Where is the lag?** Which hop is slow, for which partner, and is it getting worse?
2. **What broke?** EDI and warehouse errors that hold documents or block downstream work.
3. **What does this code mean?** An error often arrives as a bare number with no explanation, owner or fix.
4. **Who needs to know, and how fast?** Alerts that reach the right owner, once, with what to do.

## How it works

```
 Intake  ->  Validate  ->  Decode  ->  Notify  ->  Resolve
   |            ^            ^                        |
   |            +--- lessons: new rules + entries ----+
   v                                                  v
 +---------------------------- Issue register ---------------------------+
 |             every case logged, decoded and measured                   |
 +-----------------------------------------------------------------------+
   Security and IAM (integrity, role-based release, audit)  |  Trace IDs and metrics
```

| Step | Module | What it does |
| --- | --- | --- |
| Intake | `findings.py`, `run.py` | Loads X12 files and, optionally, the EDI product's error log. Every result becomes one `Finding` shape. |
| Validate | `detector/edi_detect.py`, `prevalidate.py` | Detector layers 1-3, plus checks that run before transformation: ship-to cross-reference (with ID normalization and a GS1 check-digit test) and delivery date vs lead time. |
| Decode | `decode.py`, `dictionary.json`, `ack997.py` | Every code gets a meaning, likely causes, fix steps, owner and tier. 997 AK3/AK4/AK5 codes are read and explained segment by segment. Site-specific product codes map in through `local_codes.json`. |
| Measure | `trace.py` | A trace ID per document (`sender:group control:document number`). Lag per partner for document -> 997 and 850 -> 855, reported as a median and a 95th percentile, plus late and missing counts. |
| Notify | `notify.py` | Groups repeats into one alert, merges findings that share a root cause, uses the seven-part format, routes by tier and copies security-relevant alerts to Security. Holds any alert whose numbers contradict themselves. |
| Access | `access.py` | Reviews roles for separation-of-duties conflicts and dormant privileged accounts. Only permitted roles can release held documents (security holds need a higher permission), and every release and manual change goes into an audit log whose entries are chained by SHA-256 hashes. |
| Learn | `register.py` | Codes with no dictionary entry open an issue-register row automatically, once each. |

## Design choices

- **Collect now, complete later.** The register needs only five fields at intake (ID, date, source, raw evidence, symptom). The model is useful from the first logged issue; the other steps are added as the register shows where they pay off.
- **Group on the root cause, not the code.** A translator's own code for "ship-to not found" and the pre-validation finding for the same order become one alert. A rejected 997 with four AK3/AK4 errors is one alert with four trace lines, not five alerts.
- **An unknown code is never dropped.** It is alerted as P2 with the raw text and goes to the register. Decode coverage is a tracked metric.
- **Check the alert before it is sent.** An alert that reports a failure with a count of zero, or lists more documents than it counts, is held and reported as a defect. I've seen real alerts report a document count of zero next to a failed document.
- **Standard library only, synthetic data only.** Nothing here contains real partner, employer or customer data. Real product codes belong in the git-ignored `scirm/local_codes.json`.

## Alert tiers

| Tier | Meaning | Channel | Escalate if open |
| --- | --- | --- | --- |
| P1 | Possible fraud, diversion or impersonation; payments or shipments at risk | Chat/pager + ticket | 30 min |
| P2 | Documents held or rejected with a known fix; missing acknowledgments; unknown codes | Chat + ticket | 4 h |
| P3 | Accepted with errors, padding issues, late PO acknowledgments, lead-time conflicts | Daily digest | None |
| P4 | Recovered or informational | Weekly report | None |

These are starting values, kept in `dictionary.json` so a site can tune them without touching code.

## The failure cases (`scirm/cases.py`)

`cases.py` writes five X12 files, a translator error log, an access model and an audit log that reproduce common real-world failures with made-up data. Each case maps to an entry in `register/issues.csv`.

| Case | Pattern | What SCIRM produces |
| --- | --- | --- |
| C1 | Ship-to ID zero-padded | P3 format alert: it matches a known DC only after removing padding |
| C2 | Ship-to sent as a GLN but fails the GS1 check digit | P2 "no cross-reference" alert, merged with the translator's own code for the same order |
| C3 | Requested delivery inside the lead time | P3 alert that heads off manual date edits |
| C4 | Supplier rejects our PO (AK5 R; AK3 8; AK4 1 and 7) | One P2 alert naming each failed segment and element |
| C5 | Supplier accepts with errors (AK4 8, invalid date) | One P3 alert |
| C6 | Translator log reports "documents: 0" for a failed document | Decoded through `local_codes`, and listed as a source alert defect |
| C7 | Translator code no one has decoded | P2 alert and a new issue-register row |
| C8 | A user who can change remit-to details and approve payments | P2 separation-of-duties alert |
| C9 | A privileged account unused for 155 days | P3 dormant-account alert |
| C10 | An analyst tries to release a security hold; later an audit entry is edited | P2 denied-release alert; P1 tampered-log alert |

## Results so far

On the generator's default dataset (seed 42: 3,426 documents, 6 months, 6 suppliers):

| Measure | Result |
| --- | --- |
| Findings | 191 |
| Alerts after grouping | 37 (18 P1, 13 P2, 6 P3) |
| Decode coverage | 100% |
| Alerts held for defects | 0 |
| Detector recall / precision | 100% / 100% (unchanged by SCIRM) |
| 997 lag, all partners | median under 1 h, 95th percentile about 1.4 h, none missing |
| 850 -> 855 lag | median 26-32 h per supplier; 95th percentile 78-131 h; 140 of 399 POs over a 48 h window |

The 855 result is the useful one: the medians look healthy, but the 95th percentiles show a long tail an average would hide. The 48-hour window is wall-clock, so weekends count against it. A business-hours window is on the roadmap.

**Read these numbers with care.** The data is synthetic, and I wrote the generator, the detector and SCIRM. The results show the model works as designed; they don't measure it on real trading data.

## Next

- Business-hours SLA windows, set per partner
- Wave-performance intake: per-wave cases, distinct items and step durations, from a WMS export
- Alert delivery to chat or ticket webhooks (today alerts are written to `alerts.md` and `alerts.json`)
- 855 spec validator for partner onboarding
