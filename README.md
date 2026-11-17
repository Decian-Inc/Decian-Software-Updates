<img src="docs/branding/decian-updates.png" alt="Decian Updates mark" width="112">

# Decian Software Updates

Public, cryptographically protected software update distribution for Decian products.

| Resource | What it covers |
| --- | --- |
| [Public catalog](catalog.json) | The signed catalog entry point for the protocol demonstration. |
| [Update distribution overview](docs/UPDATE-DISTRIBUTION-OVERVIEW.md) | Catalog layout, trust assumptions, verification and update access. |
| [Release import](docs/REAL-UPDATE-IMPORT.md) | How reviewed encrypted releases enter the public feed. |
| [Grant import](UPDATE-GRANT-IMPORT.md) and [license alignment](docs/LICENSE-ALIGNED-GRANTS.md) | How signed installation-specific update access is published. |

## Update Protocol v1 proof of concept

The [protocol demonstration](products/DECIAN-UPDATE-POC/product.json) includes a [release-candidate channel](products/DECIAN-UPDATE-POC/channels/rc.json) and an intentionally small non-production package. It demonstrates signed metadata, AES-256-GCM release encryption, RSA-OAEP-SHA256 installation-specific release-key wrapping, and detached RSA-PSS-SHA256 signatures.

## Distribution boundary

This repository publishes distribution artifacts. Decian product source, GitHub credentials, release-signing private keys, installation private keys, raw license secrets, and unencrypted production release payloads must stay outside it. Installed clients establish trust with pinned Decian signing keys and cryptographic verification.
