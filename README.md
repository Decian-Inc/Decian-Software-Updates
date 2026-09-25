# Decian Software Updates

Public cryptographically protected software update catalog for Decian products.

## Security boundary

This repository is distribution-only. It must never contain Decian product source code, GitHub credentials, release-signing private keys, installation private keys, raw license secrets, or unencrypted production release payloads.

Endpoints should trust pinned Decian signing keys and cryptographic verification, not repository visibility alone.

## Current state

Update Protocol v1 POC is published under `products/DECIAN-UPDATE-POC/`.

The POC package is intentionally tiny and non-production. It demonstrates signed metadata, AES-256-GCM encrypted release packaging, RSA-OAEP-SHA256 installation-specific release-key wrapping, and detached RSA-PSS-SHA256 signatures.
