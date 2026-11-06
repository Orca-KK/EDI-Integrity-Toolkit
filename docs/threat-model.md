# Threat model: what each check defends against

Every check in the toolkit maps to a STRIDE category and, where one fits, a MITRE ATT&CK technique. I used the ATT&CK Enterprise matrix rather than the ICS matrix because ERP, WMS and EDI systems are business IT, not plant-floor control systems.

STRIDE: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service (availability), **E**levation of privilege.

## Integrity and fraud (detector)

| Check | What it catches | STRIDE | ATT&CK |
| --- | --- | --- | --- |
| `unknown_sender` | A look-alike trading partner ID | S | T1656 Impersonation |
| `replayed_control_number` | An old file sent again | T, R | T1565.002 Transmitted Data Manipulation |
| `envelope_invalid` | A file altered or truncated in transit | T | T1565.002 Transmitted Data Manipulation |
| `remit_to_changed` | An invoice asking to be paid somewhere new | T | T1657 Financial Theft; T1656 Impersonation |
| `duplicate_invoice` | The same charges billed twice | T | T1657 Financial Theft |
| `price_above_po`, `quantity_over_shipped` | Inflated invoices | T | T1657 Financial Theft |
| `invoice_no_po`, `invoice_without_shipment` | Invoices for orders or goods that don't exist | T | T1657 Financial Theft |
| `ship_to_not_approved` | Goods redirected to an unapproved address | T | T1565.002 Transmitted Data Manipulation |
| `unusual_purchase_order` | Off-hours orders with abnormal quantities | S, E | T1078 Valid Accounts (a compromised buyer account) |

## Access control (`scirm/access.py`)

| Check | What it catches | STRIDE | ATT&CK |
| --- | --- | --- | --- |
| `iam:sod_conflict` | One person able to change remit-to details and approve payment, or create a supplier and pay it | E | T1078 Valid Accounts; T1657 Financial Theft |
| `iam:dormant_privileged` | Powerful accounts nobody uses | E | T1078 Valid Accounts |
| `iam:unauthorized_release` | Someone without permission trying to release a held document | E | T1078 Valid Accounts |
| `iam:audit_log_tampered` | An edited, inserted or deleted audit entry | R | T1070 Indicator Removal |

## Availability and continuity

These aren't attacks, but they cause the same outcome an attacker wants: orders that stop moving.

| Check | What it catches | STRIDE |
| --- | --- | --- |
| `prevalidation:shipto_xref_missing`, `shipto_id_format` | Orders that would be held for an unmapped location | D |
| `prevalidation:delivery_date_inside_lead_time` | Dates that force manual edits | D |
| `lag:ack_997_missing`, `ack_997_late`, `po_ack_855_*` | Acknowledgments that are late or never come | D |
| `x12:AK5:R` and AK3/AK4 codes | Documents a partner rejected | D |

## Not covered yet

- **Information disclosure (I):** the toolkit doesn't inspect how EDI is transported. Encrypting transport (AS2, SFTP) is the partner connection's job.
- **Credential theft before an attack:** the toolkit sees the result (an unusual order, a remit-to change), not the phishing that came first.

Technique IDs are from attack.mitre.org. Recheck them before quoting, since ATT&CK is revised regularly.
