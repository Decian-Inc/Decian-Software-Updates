#!/usr/bin/env python3
"""Verify and import an initial public grant; no private authority credentials."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from update_repository import GitHubRepository, reconcile, require

REPOSITORY = 'Decian-Inc/Decian-Software-Updates'


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def read_json(data):
    require(len(data) <= 16384, 'Transfer exceeds size limit')
    result = json.loads(data, object_pairs_hook=unique)
    require(isinstance(result, dict), 'Expected JSON object')
    return result


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True, timeout=30)
    require(result.returncode == 0, 'Public grant cryptographic verification failed')
    return result.stdout


def timestamp(value):
    require(isinstance(value, str) and value.endswith('Z'), 'Expected UTC timestamp')
    return dt.datetime.fromisoformat(value[:-1] + '+00:00')


def verify_transfer(encoded, pin, now, repository=REPOSITORY):
    require(isinstance(encoded, str) and len(encoded) <= 24000, 'Transfer exceeds size limit')
    transfer = read_json(base64.b64decode(encoded, validate=True))
    require(set(transfer) == {'schema', 'repository', 'files'} and
            transfer['schema'] == 'decian-public-grant-transfer/v1' and
            transfer['repository'] == repository, 'Unexpected transfer scope')
    require(isinstance(transfer['files'], dict) and
            set(transfer['files']) == {'grant.json', 'grant.sig.json'}, 'Only public grant and signature allowed')
    files = {name: base64.b64decode(data, validate=True) for name, data in transfer['files'].items()}
    grant, signature = (read_json(files[name]) for name in ('grant.json', 'grant.sig.json'))
    require(set(grant) == {'schemaVersion', 'productId', 'updateHandle', 'installationKeyId',
            'channel', 'sequence', 'notBeforeUtc', 'expiresUtc', 'status'}, 'Unexpected grant fields')
    require(type(grant['schemaVersion']) is int and grant['schemaVersion'] == 1 and
            type(grant['sequence']) is int and grant['sequence'] == 1 and
            grant['status'] == 'active' and grant['productId'] == 'secure-access' and
            grant['channel'] in ('dev', 'beta', 'stable'), 'Unsupported initial grant scope')
    require(re.fullmatch(r'[a-f0-9]{32}', grant['updateHandle']) is not None and
            re.fullmatch(r'rsa-sha256:[a-f0-9]{32}', grant['installationKeyId']) is not None,
            'Invalid opaque grant identifiers')
    start, end = (timestamp(grant[k]) for k in ('notBeforeUtc', 'expiresUtc'))
    require(start <= now < end <= start + dt.timedelta(days=7), 'Grant is not currently publishable')
    require(set(signature) == {'schemaVersion', 'algorithm', 'keyId', 'signatureBase64'} and
            type(signature['schemaVersion']) is int and signature['schemaVersion'] == 1 and
            signature['algorithm'] == 'RSA-PSS-SHA256', 'Unsupported signature')
    der = openssl('pkey', '-pubin', '-in', pin, '-outform', 'DER')
    details = openssl('pkey', '-pubin', '-in', pin, '-text', '-noout').decode('ascii')
    bits = re.search(r'Public-Key: \((\d+) bit\)', details)
    require(bits is not None and 3072 <= int(bits.group(1)) <= 8192 and 'Modulus:' in details,
            'RSA-3072 or stronger required')
    require(signature['keyId'] == 'rsa-sha256:' + hashlib.sha256(der).hexdigest()[:32], 'Wrong signing key')
    with tempfile.TemporaryDirectory(prefix='decian-public-import-') as temporary:
        root = pathlib.Path(temporary)
        (root / 'grant').write_bytes(files['grant.json'])
        (root / 'signature').write_bytes(base64.b64decode(signature['signatureBase64'], validate=True))
        openssl('dgst', '-sha256', '-verify', pin, '-signature', root / 'signature',
                '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32', root / 'grant')
    prefix = 'grants/' + grant['updateHandle']
    return {prefix + '.json': files['grant.json'], prefix + '.sig.json': files['grant.sig.json']}


def import_transfer(repository, encoded, pin, now, expected_commit=None):
    files = verify_transfer(encoded, pin, now, repository.name)
    snapshot = repository.snapshot()
    if expected_commit is not None:
        require(snapshot['sha'] == expected_commit, 'Workflow checkout is no longer current main')
        require(repository.read(snapshot, 'config/update-signing-public-key.pem') == pin.read_bytes(),
                'Public signing pin differs from current main')
    actual = {name: repository.read(snapshot, name) for name in files}
    if not all(actual[name] == data for name, data in files.items()):
        require(all(data is None for data in actual.values()), 'Existing or partial public grant conflicts; never overwrite')
        snapshot = reconcile(repository, snapshot, files, 'Import verified initial update grant')
    return {'status': 'public-pair-verified', 'public_commit': snapshot['sha'],
            'sha256': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY and
            os.environ.get('GITHUB_REF') == 'refs/heads/main', 'Import requires reviewed distribution main')
    require(os.environ.get('INPUT_CONFIRMATION') == 'IMPORT INITIAL GRANT', 'Explicit import confirmation required')
    pin = pathlib.Path(__file__).resolve().parents[1] / 'config/update-signing-public-key.pem'
    result = import_transfer(GitHubRepository(REPOSITORY, os.environ.get('GITHUB_TOKEN'), False),
                             os.environ.get('INPUT_BUNDLE', ''), pin, dt.datetime.now(dt.timezone.utc),
                             os.environ.get('GITHUB_SHA', ''))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Public import failed; no completion confirmed. Check scope, signature, expiry and repository permissions.') from None
