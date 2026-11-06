"""
SCIRM - Supply Chain Integration Resilience Model.

Turns EDI and warehouse failures from silent, coded holds into decoded, routed and
measured events. The model is a loop around one issue register:

    intake -> validate -> decode -> notify -> resolve -> (lessons back into validate/decode)

Modules
    findings.py     one Finding shape for every source (detector, pre-validation, 997s, lag, translator)
    decode.py       error dictionary: code -> meaning, causes, fix, owner, tier
    prevalidate.py  checks that run before transformation (ship-to cross-reference, delivery dates)
    ack997.py       reads 997 acknowledgments and turns AK3/AK4/AK5 codes into findings
    trace.py        trace IDs and lag between documents (850 -> 855, any document -> 997)
    notify.py       groups findings into tiered, seven-part alerts and checks them before sending
    access.py       separation-of-duties review, role-based release, hash-chained audit log
    register.py     the issue register: five fields at intake, the rest filled in later
    cases.py        writes synthetic files that reproduce common real-world failure patterns
    run.py          runs the whole loop over a folder and writes the results

Only the Python standard library is used.
"""
