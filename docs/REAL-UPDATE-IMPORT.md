# Reviewed real dev update import

This adapter accepts only an authority-signed public handoff emitted after a merged real-release intent. It verifies the current grant, reviewed predecessor and signed payload identity, then uploads/reads back the encrypted asset before an atomic six-file metadata commit. It has no private signing key or private-repository credential.

The workflow import-real-update.yml runs only on reviewed main, with the existing distribution repository contents-write token and explicit PUBLISH REAL DEV UPDATE confirmation. Inputs are product_id, signed bundle_base64, approved handle and exact release_sequence. It uses a self-hosted Windows runner and existing Python 3.13/OpenSSL; it does not install a toolchain.

The exact ciphertext must already be staged under the runner's protected LocalApplicationData/Decian/UpdateReleaseCandidates directory. Authority and distribution runners must either share the same protected runner account/storage or an administrator must transfer only this encrypted file. Do not transfer private request/context files or signing keys. The workflow verifies actual bytes against the signed digest before any upload.

Code provenance: authority pipeline source commit 3b90822a0ef85cbf9e187819842d7fca45e8880f in Decian-License-Control PR #49. The handoff module here includes only public verification; authority signing/generation dependencies are omitted. Eight runtime modules and the ACL helper are covered by authority-side failure/crypto qualification. This repository also tests redirect credential isolation, response bounds and standalone public imports.

Protected-main/environment policies remain active. No force push, asset replacement/deletion or credential fallback is implemented. Draft/partial/conflicting releases stop for review; exact retries reuse the original encrypted bytes.

This code has not yet been production-dispatched. A successful public import makes an encrypted offer available; it does not install the VPN. Authority completion review and the separate VPN broker-host/upgrade test still follow.

## 365II internal dev feed

Choose `m365-incident-investigator` for initial grant import, same-key renewal, and the reviewed real-release import. The signed grant must identify 365II on `dev` with a validity period of at most seven days. The public import continues to accept the original Secure Access transfers through the default `secure-access` scope.

For a 365II release, place only `package.dcu` under `m365-incident-investigator-dev-N` in the protected staging directory. The authority handoff signs the raw Setup digest, ciphertext digest and size, recipient, version, and reviewed public head. The encrypted asset is at most 256 MiB. The asset tag is `m365-incident-investigator-dev-N` and the asset name is `<version>.dcu`. The version is the three-component numeric version embedded in signed Setup.

The first 365II offer is sequence 1 and requires a handoff with both predecessor digests set to JSON null and both live offer files absent. Later offers require exact predecessor digests, the next sequence, and a higher numeric Setup version. Asset upload and anonymous readback are verified before the signed offer and envelope are committed. After uploading, the importer checks the current grant, expiry and reviewed public head again. Secure Access keeps its existing staging path, reviewed source pin, and release namespace.
