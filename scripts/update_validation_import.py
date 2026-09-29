"""Public-only, initial dev delivery diagnostic. Never installs or renews a release."""
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import update_public_import as common
from update_repository import GitHubRepository, reconcile, require

VERSION = '0.0.0-validation.1'
PREFIX = 'products/secure-access/releases/dev/1/' + VERSION
OFFER = 'products/secure-access/channels/dev/offer'
PAYLOAD = b'Decian Secure Access encrypted delivery validation v1\nNot an installer. No execution is permitted.\n'


def verify_signed(data, signature_bytes, pin):
    signature = common.read_json(signature_bytes)
    require(set(signature) == {'schemaVersion', 'algorithm', 'keyId', 'signatureBase64'}, 'Unexpected signature fields')
    der = common.openssl('pkey', '-pubin', '-in', pin, '-outform', 'DER')
    key_id = 'rsa-sha256:' + hashlib.sha256(der).hexdigest()[:32]
    require(type(signature['schemaVersion']) is int and signature['schemaVersion'] == 1 and
            signature['algorithm'] == 'RSA-PSS-SHA256' and signature['keyId'] == key_id, 'Signature scope mismatch')
    with tempfile.TemporaryDirectory(prefix='decian-validation-verify-') as tmp:
        root = pathlib.Path(tmp)
        (root / 'data').write_bytes(data)
        (root / 'sig').write_bytes(base64.b64decode(signature['signatureBase64'], validate=True))
        common.openssl('dgst', '-sha256', '-verify', pin, '-signature', root / 'sig',
                       '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32', root / 'data')
    return common.read_json(data), key_id


def verify_transfer(encoded, pin, now, grant_bytes, grant_sig):
    require(isinstance(encoded, str) and len(encoded) <= 24000, 'Transfer exceeds limit')
    transfer = common.read_json(base64.b64decode(encoded, validate=True))
    require(set(transfer) == {'schema', 'repository', 'files'} and
            transfer['schema'] == 'decian-validation-transfer/v1' and transfer['repository'] == common.REPOSITORY,
            'Invalid validation transfer')
    # Reuse grant verification, including key size, signature, exact public fields and validity.
    wrapped = {'schema': 'decian-public-grant-transfer/v1', 'repository': common.REPOSITORY,
               'files': {'grant.json': base64.b64encode(grant_bytes).decode(),
                         'grant.sig.json': base64.b64encode(grant_sig).decode()}}
    common.verify_transfer(base64.b64encode(json.dumps(wrapped).encode()).decode(), pin, now)
    grant = common.read_json(grant_bytes)
    require(grant['channel'] == 'dev', 'Diagnostic is dev only')
    envelope_path = PREFIX + '/envelopes/' + grant['updateHandle']
    names = {OFFER + '.json', OFFER + '.sig.json', PREFIX + '/validation.dcu',
             envelope_path + '.json', envelope_path + '.sig.json'}
    require(isinstance(transfer['files'], dict) and set(transfer['files']) == names, 'Unexpected public files')
    files = {p: base64.b64decode(b, validate=True) for p, b in transfer['files'].items()}
    offer, key_id = verify_signed(files[OFFER + '.json'], files[OFFER + '.sig.json'], pin)
    require(set(offer) == {'schemaVersion', 'releaseSequence', 'expiresUtc', 'release'} and
            type(offer['schemaVersion']) is int and offer['schemaVersion'] == 1 and
            type(offer['releaseSequence']) is int and offer['releaseSequence'] == 1, 'Invalid diagnostic offer')
    release = offer['release']
    expected = {'schemaVersion': 1, 'productId': 'secure-access', 'version': VERSION, 'channel': 'dev',
                'packagePath': PREFIX + '/validation.dcu', 'packageAlgorithm': 'AES-256-GCM',
                'plaintextSha256': hashlib.sha256(PAYLOAD).hexdigest(), 'packageSize': len(PAYLOAD) + 36,
                'associatedData': 'DECIAN|UPDATE|1|secure-access|' + VERSION + '|dev',
                'entitlementBasePath': PREFIX + '/envelopes', 'signingKeyId': key_id}
    require(set(release) == set(expected) | {'packageSha256', 'publishedUtc'} and
            all(release[k] == v for k, v in expected.items()) and
            type(release['schemaVersion']) is int and type(release['packageSize']) is int, 'Invalid diagnostic release')
    start, end = common.timestamp(release['publishedUtc']), common.timestamp(offer['expiresUtc'])
    require(start <= now + dt.timedelta(minutes=5) and start < end and now < end <= start + dt.timedelta(days=7)
            and end <= common.timestamp(grant['expiresUtc']), 'Diagnostic expired or outside grant')
    cipher = files[PREFIX + '/validation.dcu']
    require(len(cipher) == expected['packageSize'] and cipher[:8] == b'DCNUPK01' and
            hashlib.sha256(cipher).hexdigest() == release['packageSha256'], 'Ciphertext integrity mismatch')
    envelope, _ = verify_signed(files[envelope_path + '.json'], files[envelope_path + '.sig.json'], pin)
    expected_envelope = {'schemaVersion': 1, 'productId': 'secure-access', 'releaseVersion': VERSION,
        'updateHandle': grant['updateHandle'], 'keyWrapAlgorithm': 'RSA-OAEP-SHA256', 'signingKeyId': key_id}
    require(set(envelope) == set(expected_envelope) | {'wrappedReleaseKeyBase64', 'issuedUtc'} and
            all(envelope[k] == v for k, v in expected_envelope.items()) and type(envelope['schemaVersion']) is int,
            'Recipient envelope mismatch')
    require(start <= common.timestamp(envelope['issuedUtc']) <= now + dt.timedelta(minutes=5) and
            len(base64.b64decode(envelope['wrappedReleaseKeyBase64'], validate=True)) in (384, 512, 768, 1024),
            'Invalid key envelope')
    return files


def import_transfer(repository, encoded, pin, now, handle, expected_commit=None):
    require(re.fullmatch(r'[a-f0-9]{32}', handle) is not None, 'Invalid handle')
    snapshot = repository.snapshot()
    if expected_commit is not None:
        require(snapshot['sha'] == expected_commit, 'Distribution main changed; retry')
    require(repository.read(snapshot, 'config/update-signing-public-key.pem') == pin.read_bytes(), 'Trust pin changed')
    prefix = 'grants/' + handle
    grant, signature = repository.read(snapshot, prefix + '.json'), repository.read(snapshot, prefix + '.sig.json')
    require(grant is not None and signature is not None, 'Published grant required')
    files = verify_transfer(encoded, pin, now, grant, signature)
    actual = {p: repository.read(snapshot, p) for p in files}
    if not all(actual[p] == b for p, b in files.items()):
        require(all(b is None for b in actual.values()), 'Conflicting or partial diagnostic; no overwrite')
        snapshot = reconcile(repository, snapshot, files, 'Publish signed dev delivery diagnostic')
    return {'status': 'validation-package-published', 'public_commit': snapshot['sha'],
            'sha256': {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}}


if __name__ == '__main__':
    try:
        require(os.environ.get('GITHUB_REPOSITORY') == common.REPOSITORY and
                os.environ.get('GITHUB_REF') == 'refs/heads/main' and
                os.environ.get('INPUT_CONFIRMATION') == 'IMPORT VALIDATION PACKAGE', 'Reviewed main and confirmation required')
        pin = pathlib.Path(__file__).resolve().parents[1] / 'config/update-signing-public-key.pem'
        print(json.dumps(import_transfer(GitHubRepository(common.REPOSITORY, os.environ.get('GITHUB_TOKEN'), False),
              os.environ.get('INPUT_BUNDLE', ''), pin, dt.datetime.now(dt.timezone.utc),
              os.environ.get('INPUT_HANDLE', ''), os.environ.get('GITHUB_SHA', '')), sort_keys=True))
    except Exception:
        raise SystemExit('Validation import failed. Check scope, signature, current grant and repository state.') from None
