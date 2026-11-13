# Reviewed real dev update import

This adapter accepts only an authority-signed public handoff emitted after a merged real-release intent. It verifies the current grant, reviewed predecessor and signed payload identity, then uploads/reads back the encrypted asset before an atomic six-file metadata commit. It has no private signing key or private-repository credential.

The workflow import-real-update.yml runs only on reviewed main, with the existing distribution repository contents-write token and explicit PUBLISH REAL DEV UPDATE confirmation. Inputs are product_id, signed bundle_base64, approved handle and exact release_sequence. It uses a self-hosted Windows runner and existing Python 3.13/OpenSSL; it does not install a toolchain.

The exact ciphertext must already be staged under the runner's protected LocalApplicationData/Decian/UpdateReleaseCandidates directory. Authority and distribution runners must either share the same protected runner account/storage or an administrator must transfer only this encrypted file. Do not transfer private request/context files or signing keys. The workflow verifies actual bytes against the signed digest before any upload.

Code provenance: authority pipeline source commit 3b90822a0ef85cbf9e187819842d7fca45e8880f in Decian-License-Control PR #49. The handoff module here includes only public verification; authority signing/generation dependencies are omitted. Eight runtime modules and the ACL helper are covered by authority-side failure/crypto qualification. This repository also tests redirect credential isolation, response bounds and standalone public imports.

Protected-main/environment policies remain active. No force push, asset replacement/deletion or credential fallback is implemented. Draft/partial/conflicting releases stop for review; exact retries reuse the original encrypted bytes.

This code has not yet been production-dispatched. A successful public import makes an encrypted offer available; it does not install the VPN. Authority completion review and the separate VPN broker-host/upgrade test still follow.

## 365II internal dev feed

Choose `m365-incident-investigator` for initial grant import, same-key renewal, and the reviewed real-release import. The signed grant must identify 365II on `dev` with a validity period of at most seven days. The public import continues to accept the original Secure Access transfers through the default `secure-access` scope.

For a 365II release, place only `package.dcu` under `m365-incident-investigator-dev-N` in the protected staging directory. The authority handoff signs the reviewed Setup or patch digest, ciphertext digest and size, recipient, version, and reviewed public head. The encrypted asset is at most 256 MiB. The asset tag is `m365-incident-investigator-dev-N`. The signed offer names `<version>.dcu` for Setup or `<version>.patch.dcu` for an installed-files patch. Both use a three-component numeric version.

The first 365II offer is sequence 1 and requires a handoff with both predecessor digests set to JSON null and both live offer files absent. Later offers require exact predecessor digests, the next sequence, and a higher numeric product version. Asset upload and anonymous readback are verified before the signed offer and envelope are committed. After uploading, the importer checks the current grant, expiry and reviewed public head again. Secure Access keeps its existing staging path, reviewed source pin, and release namespace.

### Local 365II import when no distribution runner is registered

Use a clean checkout of current, reviewed Decian Software Updates main and the existing authorized GitHub CLI login. Download the signed 365II handoff artifact from the matching private License Control handoff run into a fresh local directory outside the checkout. The artifact name is `365ii-update-handoff-<run_id>-<run_attempt>`. It contains only `handoff.txt` and `package.dcu`. Leave the runner's original staging directory and its access settings in place.

Run the local importer with Python 3.13 and OpenSSL available on PATH:

```powershell
python -IB scripts/update_release_local_365ii.py --artifact-directory $handoffDirectory --handle $approvedHandle --sequence $sequence --confirmation 'PUBLISH REAL DEV UPDATE'
```

The importer requires the same signed handoff, grant, reviewed public head and encrypted bytes as the workflow. The local checkout must match current distribution main. Read the output for the public commit and verified asset. For an exact retry after main advances, update the clean checkout and use the same artifact. The authority completion workflow independently verifies the publication.
