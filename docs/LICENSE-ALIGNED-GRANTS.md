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
