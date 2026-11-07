# Comparison with x12-doctor

[x12-doctor](https://github.com/Adeloi-Official/x12-doctor) (v0.1.0, Apache-2.0) is an open-source checker for the same X12 document types this toolkit reads: 850, 855, 856, 810 and 997. It explains format errors in plain English and scans folders for duplicate control numbers, missing acknowledgments and out-of-order flows. It is the closest open tool I found, so I ran both on identical data.

## Setup

- 16 datasets from `generator/edi_synth.py`, seeds 101–116, anomaly rate 0.04
- 37,712 files in total, 747 planted problems, scored against `labels.csv`
- x12-doctor: `x12doctor scan <folder> --format json --all --fail-on info`, default settings
- Detector: `detector/edi_detect.py` with the dataset's `master_data.json`

Reproduce:

```bash
pip install x12-doctor
python benchmarks/compare_x12doctor.py --seeds 101-116 --anomaly-rate 0.04
```

## Results

Full figures, including the by-type counts with every x12-doctor finding included, are in [`benchmarks/comparison/comparison.json`](../benchmarks/comparison/comparison.json). Example documents the detector caught and x12-doctor did not are in [`benchmarks/comparison/examples.json`](../benchmarks/comparison/examples.json).

| Problem type | Planted | Detector | x12-doctor |
| --- | ---: | ---: | ---: |
| Billed more than shipped | 84 | 84 | 2 |
| Duplicate invoice | 84 | 84 | 0 |
| Invoice with no shipment | 82 | 82 | 0 |
| Look-alike sender | 83 | 83 | 0 |
| Price above the PO | 83 | 83 | 0 |
| Remit-to (bank) address changed | 86 | 86 | 0 |
| Replayed file | 79 | 79 | 79 |
| Shipment diverted | 83 | 83 | 0 |
| Unusual purchase order | 83 | 81 | 0 |
| **Total** | **747** | **745** | **81** |

The detector raised no alerts on clean documents.

## How x12-doctor was scored

- A planted document counts as caught if x12-doctor reported any finding on it, either in its own report or in a cross-file finding that names it.
- A duplicate control number is credited to every file that carries that sender and number, so x12-doctor gets credit for all 79 replays.
- Two of its checks are left out of the main column because they fire on clean files in this data: the CTT01 line count on 856s (the generator counts HL loops, x12-doctor counts SN1 segments; implementation guides differ on this) and document timing. Counting those too, x12-doctor touches 223 of the 747 planted files, but only because every 856 and some invoices trip those two checks whether or not anything was planted. `comparison.json` has both figures.

## What this shows

Almost every planted problem here is a correctly formatted document with the wrong content: a changed bank address, a price above the order, a second bill for the same goods, a shipment sent somewhere else. A format checker is right to pass these. x12-doctor caught what is visible in the envelope (reused control numbers) and missed what can only be seen by comparing a document with the buyer's records and the rest of the order. That second kind of check is what the detector adds.

## Limits

- The data is mine and the detector was built alongside it. x12-doctor was not, so the comparison favours the detector on fraud patterns and says nothing about the many format errors x12-doctor is designed to explain, which the detector does not cover in that depth. The two tools do different jobs and work well together.
- x12-doctor supports partner profiles. With one profile per supplier and files routed per partner, its sender-ID check would catch the look-alike senders. A single mixed folder, as here, cannot use that.
- Commercial EDI platforms were not tested. Their rules are not public and I have no licence to run them.
