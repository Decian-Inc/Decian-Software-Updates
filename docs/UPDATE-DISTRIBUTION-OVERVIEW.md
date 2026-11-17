# Decian Software Updates distribution overview

Decian Software Updates is the public transport for signed update metadata and encrypted release packages. Installed Decian clients use their configured product and channel to evaluate update offers and apply the product's own installation and recovery rules.

## Reading an update offer

| Record | Purpose |
| --- | --- |
| [Catalog](../catalog.json) | Lists the product entry point for the protocol demonstration. The catalog has a [detached signature](../catalog.json.sig). |
| [Product record](../products/DECIAN-UPDATE-POC/product.json) | Identifies the product and links to its channel records. |
| [Channel record](../products/DECIAN-UPDATE-POC/channels/rc.json) | Identifies the offered version and its release record for the demonstration. |
| [Release record](../products/DECIAN-UPDATE-POC/releases/0.1.0-poc.1/release.json) | Identifies the encrypted package and its verification metadata. |

The linked release is a non-production proof of concept. A product's configured channel and current entitlement govern its offers. The demonstration catalog does not represent production release availability.

## Trust and update access

Clients verify signed metadata with pinned Decian signing keys and check that records match the expected product, channel, version, and package. A signed grant binds update access to the intended installation. Its validity and expiration are evaluated by the client. The protocol demonstration uses AES-256-GCM for release packages, RSA-OAEP-SHA256 for installation-specific release-key wrapping, and RSA-PSS-SHA256 for detached signatures.

A publicly readable record provides a distribution path. The update client verifies authenticity and enforces access before using it. If verification or access fails, use the installed product's status for the result and leave the installed version in place.

## Publication

- [Encrypted release import](REAL-UPDATE-IMPORT.md)
- [Signed update-grant import](../UPDATE-GRANT-IMPORT.md)
- [License-aligned update grants](LICENSE-ALIGNED-GRANTS.md)
