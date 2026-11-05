# EDI Transaction Integrity Toolkit

Tools for catching tampered, fraudulent, or broken EDI transactions before they reach the ERP or trigger a payment. I'm building them for small and mid-sized manufacturers and distributors that don't have a security team.

Current version: **v0.1** (synthetic data generator and rule-based detector). The machine-learning layer is next.

## Background

I work with ERP, warehouse management, and EDI systems day to day. Purchase orders, ship notices, and invoices move between companies over EDI constantly, but at a small company nobody is usually checking whether an invoice's remit-to address was changed, whether the goods on an invoice ever shipped, or whether a file came from a look-alike sender ID. Large companies pay for tools that watch for this. I wanted something one IT person could run for free.

This repo is one piece of a larger set of security resources I'm putting together for supply chain business systems: ERP, WMS, EDI, and access control.

## What's in the repo

| Path | What it is |
| --- | --- |
| `generator/edi_synth.py` | Creates realistic fake EDI traffic with labeled attacks |
| `detector/edi_detect.py` | Checks EDI files and reports anything suspicious |
| `tests/` | Tests for both |
| `docs/detector.md` | Every detection rule, full results, and known weak spots |

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

On 16 generated datasets (42,252 documents, 837 planted anomalies) it caught 834 and raised no false alarms. Keep in mind I wrote the generator and the detector together, so that mostly shows the rules work on the attack patterns I designed. It says nothing yet about real trading data. The weak spots are written up in `docs/detector.md`.

## Tests

```bash
python -m unittest discover -s tests -v
```

There are 12. They check that every generated file has a valid envelope, that invoice totals add up, that every label matches what's actually in the file, and that the detector gets at least 95% recall and precision on three datasets it wasn't tuned on.

## Roadmap

- [x] Structure checks (v0.1)
- [x] Business-rule checks (v0.1)
- [x] Change alerts (v0.1)
- [ ] Machine-learning behavior scoring: a baseline per trading partner, scored by precision and recall for each anomaly type
- [ ] Live mode: check files as they arrive over AS2 (OpenAS2) and send alerts to a log platform
- [ ] Pilot with a company on its own systems and data

## Limitations

- Everything so far runs on synthetic data. Real validation needs a pilot partner running it on their own systems.
- The generator writes a practical subset of X12 004010, one transaction per interchange. It hasn't been checked against any trading partner's implementation guide.
- Rogue POs take the next number after the normal sequence, so their numbers are higher than POs dated around them. Don't build a rule on that.
- The detector reads a whole folder at once. A live version would need to hold an invoice until its ship notice shows up.
- Generated files are marked as test data (`ISA15 = T`).

## Data rules

Don't commit real EDI files, partner names, prices, bank details, or anything from an employer. Healthcare transaction sets such as 837 claims are out of scope. This project isn't affiliated with ASC X12 and doesn't reproduce the X12 standards or implementation guides.

## License

MIT License, © 2026 Ken Ntwiga. See `LICENSE`.
