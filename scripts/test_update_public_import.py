"""Public-only importer tests with disposable signer; no authority data or network."""
import base64
import copy
import datetime as dt
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import update_public_import as importer
import update_repository as repository


class Repository:
    name = importer.REPOSITORY

    def __init__(self):
        self.files, self.writes = {}, []

    def snapshot(self):
        return {'sha': str(len(self.writes)), 'files': self.files.copy()}

    def read(self, snapshot, path):
        return snapshot['files'].get(path)

    def commit(self, snapshot, files, message):
        self.files.update(files)
        self.writes.append(files.copy())


class ImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.temporary.name)
        cls.key, cls.pin = cls.root / 'private.pem', cls.root / 'public.pem'
        importer.openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', cls.key)
        cls.pin.write_bytes(importer.openssl('pkey', '-in', cls.key, '-pubout'))
        cls.keyid = 'rsa-sha256:' + hashlib.sha256(importer.openssl('pkey', '-pubin', '-in', cls.pin, '-outform', 'DER')).hexdigest()[:32]

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        self.grant = {'schemaVersion': 1, 'productId': 'secure-access', 'updateHandle': 'c' * 32,
                      'installationKeyId': 'rsa-sha256:' + 'd' * 32, 'channel': 'dev', 'sequence': 1,
                      'notBeforeUtc': self.now.isoformat().replace('+00:00', 'Z'),
                      'expiresUtc': (self.now + dt.timedelta(days=1)).isoformat().replace('+00:00', 'Z'), 'status': 'active'}
        self.repo = Repository()

    def transfer(self, grant=None):
        data = json.dumps(grant or self.grant).encode()
        source = self.root / 'data'; source.write_bytes(data)
        signature = importer.openssl('dgst', '-sha256', '-sign', self.key, '-sigopt', 'rsa_padding_mode:pss',
                                     '-sigopt', 'rsa_pss_saltlen:32', source)
        envelope = json.dumps({'schemaVersion': 1, 'algorithm': 'RSA-PSS-SHA256', 'keyId': self.keyid,
                               'signatureBase64': base64.b64encode(signature).decode()}).encode()
        return {'schema': 'decian-public-grant-transfer/v1', 'repository': self.repo.name,
                'files': {'grant.json': base64.b64encode(data).decode(), 'grant.sig.json': base64.b64encode(envelope).decode()}}

    def encode(self, transfer):
        return base64.b64encode(json.dumps(transfer).encode()).decode()

    def run_import(self, transfer):
        return importer.import_transfer(self.repo, self.encode(transfer), self.pin, self.now)

    def test_atomic_pair_and_exact_retry(self):
        transfer = self.transfer()
        self.run_import(transfer); self.run_import(transfer)
        self.assertEqual(len(self.repo.writes), 1)
        self.assertEqual(len(self.repo.writes[0]), 2)

    def test_tampered_signature_never_writes(self):
        transfer = self.transfer()
        self.grant['channel'] = 'stable'
        transfer['files']['grant.json'] = base64.b64encode(json.dumps(self.grant).encode()).decode()
        with self.assertRaises(ValueError): self.run_import(transfer)
        self.assertFalse(self.repo.writes)

    def test_private_fields_and_ledger_rejected(self):
        transfer = self.transfer()
        transfer['files']['private-ledger.json'] = 'e30='
        with self.assertRaises(ValueError): self.run_import(transfer)
        self.grant['licenseId'] = 'private'
        with self.assertRaises(ValueError): self.run_import(self.transfer())
        self.assertFalse(self.repo.writes)

    def test_signed_invalid_scopes_expiry_and_path_rejected(self):
        original = self.grant.copy()
        for field, value in [('productId', 'other'), ('sequence', 2), ('sequence', True), ('status', 'revoked'),
                             ('updateHandle', '../outside'), ('channel', 'other'),
                             ('expiresUtc', self.grant['notBeforeUtc']),
                             ('expiresUtc', (self.now + dt.timedelta(days=8)).isoformat().replace('+00:00', 'Z'))]:
            with self.subTest(field=field, value=value):
                self.grant = dict(original, **{field: value})
                with self.assertRaises(ValueError): self.run_import(self.transfer())
        self.assertFalse(self.repo.writes)

    def test_partial_conflict_never_overwritten(self):
        path = 'grants/' + 'c' * 32 + '.json'
        self.repo.files[path] = b'conflict'
        with self.assertRaises(ValueError): self.run_import(self.transfer())
        self.assertEqual(self.repo.files[path], b'conflict')
        self.assertFalse(self.repo.writes)

    def test_wrong_repository_and_duplicate_json_rejected(self):
        transfer = self.transfer(); transfer['repository'] = 'other/repo'
        with self.assertRaises(ValueError): self.run_import(transfer)
        with self.assertRaises(ValueError): importer.read_json(b'{"a":1,"a":2}')

    def test_current_main_and_pin_required(self):
        encoded = self.encode(self.transfer())
        with self.assertRaises(ValueError): importer.import_transfer(self.repo, encoded, self.pin, self.now, 'stale')
        with self.assertRaises(ValueError): importer.import_transfer(self.repo, encoded, self.pin, self.now, '0')
        self.repo.files['config/update-signing-public-key.pem'] = self.pin.read_bytes()
        importer.import_transfer(self.repo, encoded, self.pin, self.now, '0')

    def test_anonymous_adapter_has_no_authorization_and_cannot_mutate(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, limit):
                return json.dumps({'full_name': importer.REPOSITORY, 'private': False, 'default_branch': 'main'}).encode()
        with patch.object(repository.urllib.request, 'build_opener') as build:
            build.return_value.open.return_value = Response()
            repo = repository.GitHubRepository(importer.REPOSITORY, None, False)
            request = build.return_value.open.call_args.args[0]
            self.assertIsNone(request.get_header('Authorization'))
            for method in ['POST', 'PATCH', 'PUT', 'DELETE']:
                with self.assertRaises(ValueError): repo.api(method, '/git/blobs', {})
            with self.assertRaises(ValueError): repository.GitHubRepository('private/repo', None, True)
            self.assertEqual(build.return_value.open.call_count, 1)


if __name__ == '__main__':
    unittest.main()
