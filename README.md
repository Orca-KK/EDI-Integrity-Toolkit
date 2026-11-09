# EDI Integrity Toolkit

Checks X12 supply-chain EDI for fraud, errors and delays before they reach the ERP or trigger a payment. Built for small and mid-sized manufacturers and distributors without a security team.

Version 0.3 · Python 3.10+ · standard library only · MIT

## What it does

- **Detects fraud and integrity problems:** changed remit-to addresses, duplicate or inflated invoices, invoices with no shipment, diverted shipments, look-alike senders, replayed files.
- **Decodes errors:** 997 codes and translator errors become a meaning, a fix and an owner.
- **Pre-validates orders:** unmapped or zero-padded ship-to IDs and delivery dates inside the agreed lead time.
- **Measures lag:** median and 95th-percentile time to 997 and 855, per partner.
- **Sends fewer, better alerts:** grouped, tiered P1 to P4, and held if they contradict themselves.
- **Controls access:** separation-of-duties review, dormant admin accounts, role-based release of held documents, hash-chained audit log.

## Results (synthetic data)

- 745 of 747 planted problems caught across 16 datasets (37,712 files), with no false alarms.
- 191 findings grouped into 37 alerts, all decoded.
- On the same data, x12-doctor, an open-source format checker, caught 81 of 747 (mostly replayed files) and ran 2.4 times slower. See [docs/comparison.md](docs/comparison.md).

The generator and detector were written together, so these figures show the rules work as designed, not how they perform on real trading data.

## Quick start

```bash
python generator/edi_synth.py --out sample --seed 42
python scirm/run.py --edi sample/edi --master sample/master_data.json --out results --labels sample/labels.csv
python -m unittest discover -s tests
```

Open `results/report.md` for the summary.

Failure cases C1-C10:

```bash
python scirm/cases.py --master sample/master_data.json --out cases
python scirm/run.py --edi cases/edi --master cases/master_data.json --out results_cases \
    --translator-errors cases/translator_errors.jsonl --local-codes scirm/local_codes.example.json \
    --register results_cases/issues.csv --access cases/access.json --audit-log cases/audit.jsonl
```

## Layout

- `generator/` fake but realistic X12 traffic (850, 855, 856, 810, 997) with labeled anomalies
- `detector/` structure, business-rule and change checks
- `scirm/` pre-validation, decoding, lag, alerts, access controls, issue register
- `benchmarks/` head-to-head tests against x12-doctor
- `register/issues.csv` issue register, seeded with anonymized patterns
- `docs/` rules, results, threat model (STRIDE and MITRE ATT&CK) and the x12-doctor comparison

## Next

- Business-hours lag windows; D365 batch-job and wave intake
- Alert delivery to chat and tickets; HTTP API
- Behavior scoring per trading partner
- Pilot on a company's own data

## Limits

- Synthetic data only so far; real accuracy needs a pilot.
- A practical subset of X12 004010, not checked against any partner's implementation guide.
- Reads a whole folder at once; lag windows count weekends.

## Data

No real EDI, partner names, prices, bank details or employer data. Generated files are marked as test data (ISA15 = T). Not affiliated with ASC X12.

## License

MIT, © 2026 Ken Ntwiga.
