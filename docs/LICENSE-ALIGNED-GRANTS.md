# License-aligned grant imports

Initial grants may last at most 365 days. The private authority must additionally
cap expiration at the current signed license expiration. Public distribution has
no private license data and accepts only signatures from the pinned issuer.

Renewal imports accept exact sequence N to N+1, preserving product, channel,
handle and installation key. Historical predecessors are signature-verified at
issuance time solely for provenance; the successor must be currently valid.
Both predecessor files must match current main exactly, or both successor files
must already match for an idempotent retry. Partial/conflicting pairs stop.

Deploy this importer before publishing the first annual or sequence-3 grant.
Use the existing import-grant-renewal workflow with the public-only bundle from
Decian-License-Control. No license, private key, approval receipt, or private
ledger belongs in this repository. This change does not issue a live grant.

## 365II dispatch on the public import device

After the dispatch workflows are merged to `main`, use **Import signed initial update grant** for initial issuance or **Import signed same-key grant renewal** for renewal. Select `m365-incident-investigator`, supply the private authority's signed **public-only** grant bundle and the exact confirmation shown by that workflow. Each operation runs the existing importer and must read back the exact public pair before the authority records completion.

Use the existing one-job `decian-public-update-import` registration in **Decian-Software-Updates**. Confirm the intended protected-main dispatch is queued and the operator-controlled public lane can serve it. The Windows device is `DESKTOP-EPCJMH2` under `NT AUTHORITY\NETWORK SERVICE` with its qualified Python 3.13 and OpenSSL. A private LCC or 365II runner registration cannot serve this public job. While the registration exists, the operator must restrict it to the approved workflow or ensure it is the only eligible queued job. The runner label alone cannot select a particular run. Verify the assigned job and resulting public commit, then let the registration retire. Record the grant sequence and exact pair hashes. A queued run does not advance the grant.

Secure Access retains its existing default hosted import. Public pull-request verification stays on the read-only Linux test workflow.
