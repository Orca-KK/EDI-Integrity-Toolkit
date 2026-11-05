# EDI Transaction Integrity Toolkit

Free, open tools that help small and mid-sized manufacturers and distributors detect tampered, fraudulent, or broken EDI transactions before they reach the ERP or trigger a payment.

Part of the **Supply Chain Business-Systems Security Toolkit**.

> **Status: v0.1.** The synthetic data generator and the rule-based detector (layers 1–3) are complete and tested. Machine-learning behavior scoring (layer 4) is next.

## Why this exists

EDI (Electronic Data Interchange) carries purchase orders, ship notices, and invoices between companies. Large enterprises use commercial tools to monitor it. Small manufacturers usually have one IT person and no way to tell whether an invoice's payment address was quietly changed, an invoice bills goods that never shipped, or a document came from a look-alike sender. This project provides that capability for free.

## What's here now: the synthetic data generator

`generator/edi_synth.py` simulates a fictitious small manufacturer trading with up to 10 fictitious suppliers and writes realistic X12 (004010) files:

| Set | Document | Direction |
| --- | --- | --- |
| 850 | Purchase order | Buyer → supplier |
| 855 | Purchase order acknowledgment | Supplier → buyer |
| 856 | Advance ship notice (sometimes split into partial shipments) | Supplier → buyer |
| 810 | Invoice (one per shipment) | Supplier → buyer |
| 997 | Functional acknowledgment | Receiver → sender, for every document |

Each supplier has its own normal behavior (order cadence, items, prices, lead times), with realistic noise: partial shipments, small legitimate price corrections and late acknowledgments.

A configurable share of documents is then altered or added to simulate attacks and errors. Every one is recorded in `labels.csv`, so detection results can be measured exactly.

| Anomaly | What it simulates |
| --- | --- |
| `remit_to_change` | Invoice asks for payment to a new remit-to address (payment redirection fraud) |
| `price_inflation` | Invoice unit price well above the purchase order price |
| `quantity_overbilled` | Invoice bills more units than were shipped |
| `invoice_without_shipment` | Invoice for goods that were never shipped |
| `duplicate_invoice` | Same charges billed again under a new or slightly altered invoice number |
| `unknown_sender` | Document from a look-alike, unregistered sender ID |
| `replayed_control_number` | Interchange control number reused from an earlier file |
| `ship_to_diverted` | Ship notice sends goods to an unapproved address |
| `unusual_purchase_order` | Buyer-side purchase order entered on a weekend night with an abnormal quantity |

### Running it

Requires Python 3.10 or newer. No other packages.

```bash
python generator/edi_synth.py --out ./sample --months 6 --suppliers 6 --anomaly-rate 0.03 --seed 42
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--out` | `./sample` | Output folder (must be new or empty) |
| `--months` | 6 | Months of trading to simulate |
| `--suppliers` | 6 | Number of suppliers (1–10) |
| `--anomaly-rate` | 0.03 | Share of business documents to alter (0–0.2) |
| `--start` | 2026-01-05 | First trading day |
| `--seed` | 42 | Same seed gives identical output |

### Output

```
sample/
  edi/               one interchange per file, e.g. 20260112_0926_000123_PINEFASTEN_810.edi
  labels.csv         one row per file: transaction set, sender, document number, anomaly type, detail
  master_data.json   the buyer's trusted reference data: registered suppliers, remit-to addresses, item prices, approved ship-to
  summary.json       counts by transaction set and anomaly type
```

A detector should use only `edi/` and `master_data.json`. Keep `labels.csv` aside for scoring.

### Test it

```bash
python -m unittest discover -s tests -v
```

The 12 tests check every generated file's envelope (ISA length, matching control numbers, segment counts), invoice totals, and that every labeled anomaly is actually present in the data. They also run the detector on three datasets it was not tuned on and require at least 95% recall and precision.

## The detector (layers 1–3)

`detector/edi_detect.py` checks a folder of EDI files against the buyer's trusted master data and writes every finding, with the reason, to `findings.csv`.

```bash
python detector/edi_detect.py --edi sample/edi --master sample/master_data.json --out results --labels sample/labels.csv
```

On 16 generated datasets (42,252 documents, 837 planted anomalies), it detected 834 (recall 99.6%) with no false alarms. These results come from synthetic data and show that the rules catch the generator's attack patterns; they are not a measure of performance on real trading data. See [docs/detector.md](docs/detector.md) for every rule, the full results, and their limits.

## Roadmap

1. ✅ **Structure checks** (v0.1): envelope validity, control-number sequence and reuse, known sender IDs
2. ✅ **Business-rule checks** (v0.1): invoice vs. purchase order vs. ship notice on items, quantities and prices; duplicate detection
3. ✅ **Change alerts** (v0.1): remit-to, ship-to and new-sender changes compared with master data
4. **Behavior scoring:** per-partner baselines with machine-learning anomaly scoring (for example, Isolation Forest), evaluated with precision and recall per anomaly type
5. **Lab integration:** inspect files as they arrive over AS2 (OpenAS2) and send alerts to a log platform

## Limitations

- **All data is synthetic and fictitious.** Results on this data show that the method works on known attack patterns; they do not replace validation in a real environment. Pilot partners run the toolkit on their own systems, with their own data.
- The generator writes a practical subset of X12 004010 segments, one transaction per interchange, and is not validated against any trading partner's implementation guide.
- Rogue purchase orders take the next number after the normal sequence, so their numbers are higher than POs dated around them. A detector should not rely on this.
- Files are marked as test data (`ISA15 = T`).

## Data and safety rules

- Never commit real EDI files, partner names, prices, bank details or any employer data to this repository.
- Healthcare transaction sets (such as 837 claims) are out of scope.
- This project is not affiliated with ASC X12 and does not reproduce X12 standards or implementation guides.

## License

MIT License, © 2026 Ken Ntwiga. See `LICENSE`.
