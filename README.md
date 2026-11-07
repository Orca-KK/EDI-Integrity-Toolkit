# EDI Transaction Integrity Toolkit

Tools for catching tampered, fraudulent, or broken EDI transactions before they reach the ERP or trigger a payment. I'm building them for small and mid-sized manufacturers and distributors that don't have a security team.

Current version: **v0.3**. v0.1 added a synthetic data generator and a rule-based detector. v0.2 added **SCIRM**, a resilience layer that decodes errors, measures lag, and turns findings into alerts people can act on. v0.3 adds access controls: a separation-of-duties review, role-based release of held documents, and a tamper-evident audit log.

## Background

I work with ERP, warehouse management, and EDI systems day to day. Purchase orders, ship notices, and invoices move between companies over EDI constantly, but at a small company nobody is usually checking whether an invoice's remit-to address was changed, whether the goods on an invoice ever shipped, or whether a file came from a look-alike sender ID. Large companies pay for tools that watch for this. I wanted something one IT person could run for free.

This repo is one piece of a larger set of security resources I'm putting together for supply chain business systems: ERP, WMS, EDI, and access control.

## What's in the repo

| Path | What it is |
| --- | --- |
| `generator/edi_synth.py` | Creates realistic fake EDI traffic with labeled attacks |
| `detector/edi_detect.py` | Checks EDI files and reports anything suspicious |
| `scirm/` | The Supply Chain Integration Resilience Model: pre-validation, error decoding, lag tracing, alerts, access controls, issue register |
| `scirm/dictionary.json` | Error dictionary: each code's meaning, causes, fix, owner and alert tier |
| `register/issues.csv` | The issue register, started with five anonymized patterns from real operations |
| `tests/` | Tests for all three |
| `docs/detector.md` | Every detection rule, full results, and known weak spots |
| `docs/scirm.md` | How SCIRM works, the failure cases it reproduces, and results so far |
| `docs/threat-model.md` | Each check mapped to STRIDE and MITRE ATT&CK |

Python 3.10 or newer. No other packages needed.

## Generating test data

I didn't want to work with real EDI files since they carry partner names, prices, and bank details. So the generator simulates a made-up manufacturer trading with up to 10 made-up suppliers and writes X12 (004010) files:

| Set | Document | From / to |
| --- | --- | --- |
| 850 | Purchase order | Buyer to supplier |
| 855 | PO acknowledgment | Supplier to buyer |
| 856 | Ship notice (sometimes split into partial shipments) | Supplier to buyer |
| 810 | Invoice, one per shipment | Supplier to buyer |
| 997 | Functional acknowledgment | Receiver back to sender |

Each supplier gets its own ordering pattern, items, prices, and lead times. I also put in the normal mess you see in real trading: partial shipments, small price corrections, late acknowledgments.

After that, a share of the documents is altered or added to simulate attacks and errors. Every one is written to `labels.csv`, which is the answer key for scoring the detector.

| Label | What it simulates |
| --- | --- |
| `remit_to_change` | Invoice asks to be paid at a new remit-to address (payment redirection) |
| `price_inflation` | Invoice price well above the PO price |
| `quantity_overbilled` | Invoice bills more units than shipped |
| `invoice_without_shipment` | Invoice for goods that never shipped |
| `duplicate_invoice` | Same charges billed again under a new or slightly changed invoice number |
| `unknown_sender` | File from a look-alike sender ID that isn't registered |
| `replayed_control_number` | Interchange control number reused from an earlier file |
| `ship_to_diverted` | Ship notice sends goods to an unapproved address |
| `unusual_purchase_order` | PO entered on a weekend night with an abnormal quantity |

```bash
python generator/edi_synth.py --out sample --months 6 --suppliers 6 --anomaly-rate 0.03 --seed 42
```

| Option | Default | |
| --- | --- | --- |
| `--out` | `./sample` | Output folder (must be new or empty) |
| `--months` | 6 | Months of trading |
| `--suppliers` | 6 | Number of suppliers, 1 to 10 |
| `--anomaly-rate` | 0.03 | Share of business documents to alter, 0 to 0.2 |
| `--start` | 2026-01-05 | First trading day |
| `--seed` | 42 | Same seed, same output |

Output:

```
sample/
  edi/               one interchange per file
  labels.csv         answer key: one row per file
  master_data.json   the buyer's trusted records (registered suppliers, remit-to addresses, prices, approved ship-to)
  summary.json       counts by document type and anomaly type
```

The detector only gets `edi/` and `master_data.json`. `labels.csv` stays out of it until scoring.

## Running the detector

```bash
python detector/edi_detect.py --edi sample/edi --master sample/master_data.json --out results --labels sample/labels.csv
```

It writes every finding and the reason for it to `results/findings.csv`. `--labels` is optional; with it, the detector also scores itself and saves `results/evaluation.json`.

So far it covers three layers:

1. **Structure:** broken envelopes, unregistered senders, reused control numbers
2. **Business rules:** invoice vs. PO vs. ship notice on items, prices, and quantities; duplicate invoices
3. **Changes:** remit-to and ship-to addresses that don't match the buyer's records; POs entered off-hours with unusual quantities

On 16 generated datasets (seeds 101–116, 37,712 documents, 747 planted anomalies) it caught 745 and raised no false alarms. Keep in mind I wrote the generator and the detector together, so that mostly shows the rules work on the attack patterns I designed. It says nothing yet about real trading data. The weak spots are written up in `docs/detector.md`.

On the same datasets I also ran x12-doctor, an open-source X12 checker for the same document types. It reliably caught replayed files but reported nothing on most of the other planted problems, because they are correctly formatted documents carrying the wrong content. The setup, results and caveats are in `docs/comparison.md`.

## Running the full model (SCIRM)

The detector finds suspicious documents. In day-to-day operations, though, most of the time goes elsewhere: errors that arrive as bare codes, documents stuck on hold, acknowledgments that come back late or never, and alerts nobody can act on. SCIRM wraps the detector in a loop that handles those:

```
intake -> validate -> decode -> notify -> resolve -> (lessons back into validate and decode)
```

```bash
python scirm/run.py --edi sample/edi --master sample/master_data.json --out results --labels sample/labels.csv
```

It writes `report.md` (a one-page summary), `alerts.md` / `alerts.json` (tiered alerts), `findings.csv` (every finding, decoded), `lag.csv` and `metrics.json`. On the default dataset, 191 findings become 37 alerts, every finding is decoded, and the detector's score is unchanged.

To see the failure patterns it was built for, generate the cases folder and run it with a translator error log and the issue register:

```bash
python scirm/cases.py --master sample/master_data.json --out cases
python scirm/run.py --edi cases/edi --master cases/master_data.json --out results_cases \
    --translator-errors cases/translator_errors.jsonl \
    --local-codes scirm/local_codes.example.json --register results_cases/issues.csv \
    --access cases/access.json --audit-log cases/audit.jsonl
```

| What SCIRM adds | Problem it addresses |
| --- | --- |
| Error dictionary + 997 reader | A code like `AK4*3*355*7` becomes "Invalid code value in PO1, element 3 (unit of measure): 'BX'", with the fix and the owner |
| Ship-to pre-validation | Unmapped or zero-padded locations are caught at receipt with a clear reason, instead of turning up as a coded hold or a sales order that won't save |
| Delivery-date check | Orders whose requested date ignores lead time are flagged before someone edits them by hand |
| Trace IDs + lag | Median and 95th-percentile lag per partner for document -> 997 and PO -> 855, plus late and missing counts |
| Tiered alerts | Repeats grouped, shared root causes merged, seven-part format, security copies, and self-contradicting alerts held back |
| Access controls | Flags anyone who can both change a supplier's remit-to details and approve payment, and privileged accounts nobody uses. Only permitted roles can release held documents, and security holds need a higher permission. Every release and manual change goes into an audit log chained by SHA-256 hashes, so an edited entry is detectable |
| Issue register | Five fields to log an issue; unknown codes are added automatically |

Details are in `docs/scirm.md`.

## Tests

```bash
python -m unittest discover -s tests -v
```

There are 37. The original 12 check that every generated file has a valid envelope, that invoice totals add up, that every label matches what's actually in the file, and that the detector gets at least 95% recall and precision on three datasets it wasn't tuned on. The 25 SCIRM tests cover GS1 check digits, ship-to normalization, lead-time rules, the dictionary and site overlay, alert grouping and defect holds, the issue register, lag measurement, separation of duties, role-based release, the audit log's hash chain, and both end-to-end runs.

## Roadmap

- [x] Structure checks (v0.1)
- [x] Business-rule checks (v0.1)
- [x] Change alerts (v0.1)
- [x] SCIRM: error dictionary, 997 decoding, ship-to and lead-time pre-validation (v0.2)
- [x] SCIRM: trace IDs, acknowledgment lag, tiered alerts, issue register (v0.2)
- [ ] Business-hours SLA windows per partner; wave-performance intake from a WMS export
- [x] Access controls: separation-of-duties review, role-based release, tamper-evident audit log (v0.3)
- [ ] Alert delivery to chat and ticket webhooks; an HTTP API over the stateless checks
- [ ] Machine-learning behavior scoring: a baseline per trading partner, scored by precision and recall for each anomaly type
- [ ] Live mode: check files as they arrive over AS2 (OpenAS2) and send alerts to a log platform
- [ ] Pilot with a company on its own systems and data

## Limitations

- Everything so far runs on synthetic data. Real validation needs a pilot partner running it on their own systems.
- The generator writes a practical subset of X12 004010, one transaction per interchange. It hasn't been checked against any trading partner's implementation guide.
- Rogue POs take the next number after the normal sequence, so their numbers are higher than POs dated around them. Don't build a rule on that.
- The detector reads a whole folder at once. A live version would need to hold an invoice until its ship notice shows up.
- SCIRM's lag windows are wall-clock hours, so weekends count against them.
- The issue register's starting entries describe patterns I've seen at work in general terms only. They contain no names, IDs or data.
- Generated files are marked as test data (`ISA15 = T`).

## Data rules

Don't commit real EDI files, partner names, prices, bank details, or anything from an employer. Healthcare transaction sets such as 837 claims are out of scope. This project isn't affiliated with ASC X12 and doesn't reproduce the X12 standards or implementation guides.

## License

MIT License, © 2026 Ken Ntwiga. See `LICENSE`.
