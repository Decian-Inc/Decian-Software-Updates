# Signed grant import

This repository accepts a public-only transfer from Decian-License-Control.
`import-update-grant.yml` uses only this repository's built-in GITHUB_TOKEN.
It never receives a private signing key, license record, enrollment receipt or
private issuance ledger. Existing POC content is unchanged.

The reviewed production public pin is `config/update-signing-public-key.pem`.
SPKI DER SHA-256: `baa88c3eb5a53eef5cd0ea19782efbdfb8f0b736c7b1d7e08d9ddb85760934ee`.
Key ID: `rsa-sha256:baa88c3eb5a53eef5cd0ea19782efbdf`.

Manually dispatch the workflow on main with `bundle_base64` from a successful
private preparation checkpoint and confirmation `IMPORT INITIAL GRANT`.
The importer accepts only a signed active sequence-1 secure-access grant with an
allowed channel, opaque identifiers, current validity of no more than seven days,
and an exact grant/signature field set. It performs a single non-forced Git commit
for the pair followed by exact-byte readback. Matching retries do not rewrite it.
Partial or conflicting publication fails closed.

The operator must then run the private LCC completion workflow. Public publication
does not independently establish current private license authority and is not
permission to install software. The private completion step rechecks that authority.
Branch protections and organization workflow permissions remain enforced.

The shared `scripts/update_repository.py`, `scripts/update_public_import.py` and
`scripts/test_update_public_import.py` are maintained identically in LCC and here.
Tests use disposable keys and no live credentials. The public workflows use hosted
Linux runners, not the private Windows self-hosted runner.
