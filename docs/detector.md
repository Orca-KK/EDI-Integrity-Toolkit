# Detector (layers 1–3): usage and results

`detector/edi_detect.py` checks a folder of X12 EDI files against the buyer's trusted master data and writes every finding to `findings.csv`.

## Checks

| Layer | Rule | What it catches |
| --- | --- | --- |
| 1 Structure | `envelope_invalid` | Malformed envelope: wrong ISA length, mismatched control numbers, wrong segment count |
| 1 Structure | `unknown_sender` | Sender ID not registered in master data (including look-alike IDs) |
| 1 Structure | `replayed_control_number` | Interchange control number the sender already used |
| 2 Business | `invoice_no_po` | Invoice references a purchase order that doesn't exist |
| 2 Business | `invoice_without_shipment` | Invoice for a PO with no ship notice |
| 2 Business | `price_above_po` | Invoice price more than 3% above the PO price, or an item not on the PO |
| 2 Business | `quantity_over_shipped` | Total billed exceeds what had shipped by the invoice date |
| 2 Business | `duplicate_invoice` | Same charges billed again (identical partial shipments are allowed) |
| 3 Changes | `remit_to_changed` | Invoice remit-to address differs from the registered one |
| 3 Changes | `ship_to_not_approved` | Ship notice sends goods to an unapproved location |
| 3 Changes | `unusual_purchase_order` | PO entered on a weekend or outside 06:00–20:00 with a quantity over 3× the item's median |

## Run it

```bash
python generator/edi_synth.py --out sample --seed 42
python detector/edi_detect.py --edi sample/edi --master sample/master_data.json --out results --labels sample/labels.csv
```

`--labels` is optional. With it, the detector scores itself and writes `results/evaluation.json`.

## Results on synthetic data

Measured on 16 generated datasets (6 suppliers, 6 months, 4% anomaly rate each), none of which were used to set the thresholds after the first tuning pass:

| Measure | Result |
| --- | --- |
| Documents checked | 42,252 |
| Labeled anomalies | 837 |
| Detected | 834 (recall 99.6%) |
| False alarms | 0 (precision 100%) |

The three misses were rogue purchase orders whose quantity was less than 3× the item's normal median.

## Read these results carefully

- **The data is synthetic.** The detector was developed alongside the generator, so these figures show that the rules work on the attack patterns the generator produces. They are not a measure of performance on real trading data.
- **The off-hours rule is easier here than in real life.** In the synthetic data, normal purchase orders never arrive at night or on weekends. Real companies often have scheduled systems that do, so the off-hours and quantity thresholds need tuning for each site.
- **It works in batch mode.** It reads a whole folder at once. A live version would hold invoices until the related ship notice arrives.
- **Next:** layer 4 (machine-learning behavior scoring) to catch subtler patterns, and validation with a pilot partner on their own systems.
