"""Verify real-release public metadata and ciphertext; does not sign or publish."""
import base64
import datetime as dt
import hashlib
import json
import pathlib
import re
from dataclasses import dataclass
import update_public_import as common
from update_validation_import import verify_signed
from update_release_source import REVIEWED
from update_repository import require

OFFER = 'products/secure-access/channels/dev/offer'


@dataclass(frozen=True)
class VerifiedDelivery:
    sequence: int
    handle: str
    package_sha256: str
    package_size: int
    package_path: str
    # Immutable bytes, not caller-owned dictionaries, preserve verified content.
    files: tuple


def verify_metadata(files, pin, now, grant_bytes, grant_signature):
    require(isinstance(files, dict) and len(files) == 4 and
            all(isinstance(k, str) and isinstance(v, bytes) and len(v) <= 16384 for k, v in files.items()),
            'Exactly four bounded public metadata files required')
    require(OFFER + '.json' in files and OFFER + '.sig.json' in files, 'Missing signed offer')
    # Existing verifier enforces the approved initial grant scope, expiry and RSA strength.
    # Renewal grants remain unsupported until a separately reviewed renewal implementation.
    transfer = {'schema': 'decian-public-grant-transfer/v1', 'repository': common.REPOSITORY,
                'files': {'grant.json': base64.b64encode(grant_bytes).decode(),
                          'grant.sig.json': base64.b64encode(grant_signature).decode()}}
    common.verify_transfer(base64.b64encode(json.dumps(transfer).encode()).decode(), pin, now)
    grant = common.read_json(grant_bytes)
    require(grant['channel'] == 'dev', 'Real beta rehearsal is dev only')
    offer, key_id = verify_signed(files[OFFER + '.json'], files[OFFER + '.sig.json'], pin)
    require(set(offer) == {'schemaVersion', 'releaseSequence', 'expiresUtc', 'release'} and
            type(offer['schemaVersion']) is int and offer['schemaVersion'] == 1 and
            type(offer['releaseSequence']) is int and 2 <= offer['releaseSequence'] <= 9223372036854775807,
            'Invalid real-release offer')
    sequence = offer['releaseSequence']
    prefix = f'products/secure-access/releases/dev/{sequence}/{REVIEWED.version}'
    envelope_path = prefix + '/envelopes/' + grant['updateHandle']
    require(set(files) == {OFFER + '.json', OFFER + '.sig.json', envelope_path + '.json', envelope_path + '.sig.json'},
            'Unexpected metadata paths')
    release = offer['release']
    expected = {'schemaVersion': 1, 'productId': 'secure-access', 'version': REVIEWED.version, 'channel': 'dev',
        'packagePath': f'https://github.com/{common.REPOSITORY}/releases/download/secure-access-dev-{sequence}/{REVIEWED.version}.dcu',
        'packageAlgorithm': 'AES-256-GCM', 'plaintextSha256': REVIEWED.bundle_sha256,
        'packageSize': REVIEWED.bundle_size + 36,
        'associatedData': f'DECIAN|UPDATE|1|secure-access|{REVIEWED.version}|dev',
        'entitlementBasePath': prefix + '/envelopes', 'signingKeyId': key_id}
    require(isinstance(release, dict) and set(release) == set(expected) | {'packageSha256', 'publishedUtc'} and
            all(release[k] == v for k, v in expected.items()) and type(release['schemaVersion']) is int and
            type(release['packageSize']) is int and isinstance(release['packageSha256'], str) and
            re.fullmatch(r'[a-f0-9]{64}', release['packageSha256']) is not None,
            'Release does not bind the reviewed whole bundle')
    start, end = common.timestamp(release['publishedUtc']), common.timestamp(offer['expiresUtc'])
    require(start <= now + dt.timedelta(minutes=5) and start < end and now < end <= start + dt.timedelta(days=7)
            and end <= common.timestamp(grant['expiresUtc']), 'Release expired or outside current grant')
    envelope, _ = verify_signed(files[envelope_path + '.json'], files[envelope_path + '.sig.json'], pin)
    expected_envelope = {'schemaVersion': 1, 'productId': 'secure-access', 'releaseVersion': REVIEWED.version,
        'updateHandle': grant['updateHandle'], 'keyWrapAlgorithm': 'RSA-OAEP-SHA256', 'signingKeyId': key_id}
    require(set(envelope) == set(expected_envelope) | {'wrappedReleaseKeyBase64', 'issuedUtc'} and
            all(envelope[k] == v for k, v in expected_envelope.items()) and type(envelope['schemaVersion']) is int,
            'Recipient envelope mismatch')
    require(start <= common.timestamp(envelope['issuedUtc']) <= now + dt.timedelta(minutes=5) and
            len(base64.b64decode(envelope['wrappedReleaseKeyBase64'], validate=True)) in (384, 512, 768, 1024),
            'Invalid wrapped release key')
    return VerifiedDelivery(sequence, grant['updateHandle'], release['packageSha256'], release['packageSize'],
                            release['packagePath'], tuple(sorted(files.items())))


def verify_ciphertext(path, delivery):
    """Verify a downloaded/staged asset stream. This does not attest remote availability."""
    path = pathlib.Path(path)
    require(not path.is_symlink() and path.is_file(), 'Ciphertext must be a regular file')
    with path.open('rb') as stream:
        magic = stream.read(8)
        require(magic == b'DCNUPK01', 'Unsupported encrypted package')
        digest = hashlib.sha256(magic); size = len(magic)
        while block := stream.read(1024 * 1024):
            size += len(block)
            require(size <= delivery.package_size, 'Oversized ciphertext')
            digest.update(block)
        require(size == delivery.package_size and digest.hexdigest() == delivery.package_sha256,
                'Ciphertext differs from signed metadata')
    return {'sha256': delivery.package_sha256, 'size': delivery.package_size, 'url': delivery.package_path}
