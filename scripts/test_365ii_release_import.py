"""Qualify signed 365II publication using disposable keys and in-memory GitHub adapters."""
import base64
import datetime as dt
import hashlib
import unittest

import test_update_public_import as fixtures
import update_public_import as common
import update_release_import as release_import
import update_release_policy as policy
import update_renewal_import as renewal
from update_release_metadata import verify_metadata
from update_release_plan import apply_plan, plan
from update_release_source import REVIEWED, reviewed_for


def digest(data):
    return hashlib.sha256(data).hexdigest()


class MemoryAssets:
    def __init__(self, url):
        self.release = None
        self.package = None
        self.url = url
        self.downloads = []

    def lookup(self, tag):
        if self.release is not None and self.release['tag_name'] == tag:
            return dict(self.release)

    def create(self, tag, commit, body):
        self.release = {'id': 1, 'tag_name': tag, 'target_commitish': commit, 'name': tag,
                        'body': body, 'draft': True, 'prerelease': True, 'assets': []}
        return dict(self.release)

    def read_release(self, release_id):
        assert release_id == self.release['id']
        return dict(self.release)

    def upload(self, release_id, path, size, name):
        self.package = path.read_bytes()
        self.release['assets'] = [{'id': 2, 'name': name, 'size': size, 'state': 'uploaded',
                                   'browser_download_url': self.url.replace('m365-incident-investigator-dev-1', 'untagged-123'), 'digest': 'sha256:' + digest(self.package)}]

    def publish(self, release_id):
        self.release['draft'] = False
        self.release['assets'][0]['browser_download_url'] = self.url

    def check_tag(self, tag, commit, allow_missing=False):
        assert (tag, commit) == (self.release['tag_name'], self.release['target_commitish'])

    def download(self, asset_id, path, size, public_url=None):
        self.downloads.append(public_url)
        path.write_bytes(self.package)


class InvestigatorReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.ImportTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.ImportTests.tearDownClass()

    def setUp(self):
        self.f = fixtures.ImportTests('test_atomic_pair_and_exact_retry')
        self.f.setUp()
        self.repo = self.f.repo
        original_snapshot = self.repo.snapshot
        self.repo.snapshot = lambda: dict(original_snapshot(), sha=f'{len(self.repo.writes):040x}')
        self.repo.files['config/update-signing-public-key.pem'] = self.f.pin.read_bytes()
        self.product = common.INVESTIGATOR
        self.f.grant['productId'] = self.product
        self.handle = self.f.grant['updateHandle']
        self.grant_prefix = f'grants/{self.handle}'
        self.transfer = self.f.transfer()
        self.grant = base64.b64decode(self.transfer['files']['grant.json'])
        self.grant_sig = base64.b64decode(self.transfer['files']['grant.sig.json'])
        self.repo.files.update({self.grant_prefix + '.json': self.grant, self.grant_prefix + '.sig.json': self.grant_sig})
        self.cipher = b'DCNUPK01' + bytes(52)
        self.path = self.f.root / 'setup.dcu'
        self.path.write_bytes(self.cipher)

    def sign(self, value):
        pair = self.f.transfer(value)['files']
        return base64.b64decode(pair['grant.json']), base64.b64decode(pair['grant.sig.json'])

    def offer(self, sequence, version, scope=None, **release_changes):
        product = scope or self.product
        prefix = policy.release_prefix(product, sequence, version)
        size, sha = len(self.cipher), 'a' * 64
        if product == common.SECURE_ACCESS:
            reviewed = reviewed_for(sequence)
            size, sha = reviewed.bundle_size + policy.PACKAGE_HEADER_SIZE, reviewed.bundle_sha256
        release = {
            'schemaVersion': 1, 'productId': product, 'version': version, 'channel': 'dev',
            'packagePath': policy.package_url(product, sequence, f'{version}.dcu'),
            'packageAlgorithm': 'AES-256-GCM', 'plaintextSha256': sha, 'packageSize': size,
            'packageSha256': digest(self.cipher), 'associatedData': f'DECIAN|UPDATE|1|{product}|{version}|dev',
            'entitlementBasePath': prefix + '/envelopes', 'signingKeyId': self.f.keyid,
            'publishedUtc': self.f.grant['notBeforeUtc'],
        }
        release.update(release_changes)
        offer = {'schemaVersion': 1, 'releaseSequence': sequence, 'expiresUtc': self.f.grant['expiresUtc'], 'release': release}
        envelope = {
            'schemaVersion': 1, 'productId': product, 'releaseVersion': version, 'updateHandle': self.handle,
            'keyWrapAlgorithm': 'RSA-OAEP-SHA256', 'wrappedReleaseKeyBase64': base64.b64encode(bytes(384)).decode(),
            'signingKeyId': self.f.keyid, 'issuedUtc': self.f.grant['notBeforeUtc'],
        }
        active = policy.offer_path(product)
        offer_bytes, offer_sig = self.sign(offer)
        envelope_bytes, envelope_sig = self.sign(envelope)
        envelope_path = prefix + '/envelopes/' + self.handle
        return {active + '.json': offer_bytes, active + '.sig.json': offer_sig,
                envelope_path + '.json': envelope_bytes, envelope_path + '.sig.json': envelope_sig}

    def handoff(self, files, sequence, previous=(None, None), **changes):
        payload = {
            'schema': 'decian-reviewed-release-handoff/v1', 'repository': common.REPOSITORY,
            'authority_commit': 'b' * 40, 'intent_sha256': 'c' * 64, 'sequence': sequence, 'handle': self.handle,
            'public_head': self.repo.snapshot()['sha'], 'previous_offer_sha256': previous[0],
            'previous_signature_sha256': previous[1], 'grant_sha256': digest(self.grant),
            'grant_signature_sha256': digest(self.grant_sig),
            'created_utc': self.f.grant['notBeforeUtc'], 'expires_utc': self.f.grant['expiresUtc'],
            'files': {name: base64.b64encode(data).decode() for name, data in files.items()},
        }
        payload.update(changes)
        data, signature = self.sign(payload)
        return self.f.encode({'payload': base64.b64encode(data).decode(), 'signature': base64.b64encode(signature).decode()})

    def publish(self, encoded, assets):
        return release_import.publish(self.repo, assets, encoded, self.f.pin, self.handle, self.path,
                                      clock=lambda: self.f.now, product=self.product)

    def test_explicit_initial_grant_scope_and_limit(self):
        self.repo.files.pop(self.grant_prefix + '.json')
        self.repo.files.pop(self.grant_prefix + '.sig.json')
        encoded = self.f.encode(self.transfer)
        with self.assertRaises(ValueError):
            common.import_transfer(self.repo, encoded, self.f.pin, self.f.now)
        common.import_transfer(self.repo, encoded, self.f.pin, self.f.now, product=self.product)
        too_long = (self.f.now + dt.timedelta(days=8)).isoformat().replace('+00:00', 'Z')
        for change in ({'channel': 'beta'}, {'expiresUtc': too_long}):
            with self.assertRaises(ValueError):
                common.verify_transfer(self.f.encode(self.f.transfer(dict(self.f.grant, **change))),
                                       self.f.pin, self.f.now, product=self.product)
        self.assertEqual(len(self.repo.writes), 1)

    def test_365ii_same_key_renewal_keeps_product_and_channel(self):
        expiry = (self.f.now + dt.timedelta(days=2)).isoformat().replace('+00:00', 'Z')
        new_grant = dict(self.f.grant, sequence=2, expiresUtc=expiry)
        transfer = {'schema': 'decian-public-renewal-transfer/v1', 'repository': common.REPOSITORY,
                    'previous': self.transfer['files'], 'files': self.f.transfer(new_grant)['files']}
        with self.assertRaises(ValueError):
            renewal.import_transfer(self.repo, self.f.encode(transfer), self.f.pin, self.f.now)
        renewal.import_transfer(self.repo, self.f.encode(transfer), self.f.pin, self.f.now, product=self.product)
        self.assertEqual(len(self.repo.writes), 1)
        self.assertEqual(common.read_json(self.repo.files[self.grant_prefix + '.json'])['sequence'], 2)

    def test_license_aligned_365ii_successors_preserve_short_offer_and_original_recipient(self):
        from update_release_metadata import verify_metadata

        issued = common.timestamp(self.f.grant['notBeforeUtc'])
        previous = self.transfer['files']

        def stamp(value):
            return value.isoformat().replace('+00:00', 'Z')

        for sequence, days in ((2, 90), (3, 365)):
            start = issued + dt.timedelta(hours=sequence - 2)
            grant = dict(self.f.grant, sequence=sequence, notBeforeUtc=stamp(start),
                         expiresUtc=stamp(start + dt.timedelta(days=days)))
            signed = self.f.transfer(grant)['files']
            renewal_bundle = {'schema': 'decian-public-renewal-transfer/v1', 'repository': common.REPOSITORY,
                              'previous': previous, 'files': signed}
            for _ in range(2):
                renewal.import_transfer(self.repo, self.f.encode(renewal_bundle), self.f.pin, start,
                                        product=self.product)
            data, sig = (base64.b64decode(signed[name]) for name in ('grant.json', 'grant.sig.json'))
            offer = self.offer(1, '0.8.4')
            verify_metadata(offer, self.f.pin, start, data, sig, self.product)
            path = policy.offer_path(self.product)
            oversized_offer = common.read_json(offer[path + '.json'])
            oversized_offer['expiresUtc'] = stamp(issued + dt.timedelta(days=8))
            offer[path + '.json'], offer[path + '.sig.json'] = self.sign(oversized_offer)
            with self.assertRaises(ValueError):
                verify_metadata(offer, self.f.pin, start, data, sig, self.product)
            previous = signed
        self.assertEqual(len(self.repo.writes), 2)

        for change in ({'expiresUtc': stamp(start + dt.timedelta(days=365, seconds=1))},
                       {'channel': 'beta'}, {'productId': common.SECURE_ACCESS}):
            files = self.f.transfer(dict(grant, **change))['files']
            pair = {name: base64.b64decode(value) for name, value in files.items()}
            with self.assertRaises(ValueError):
                renewal.verify_pair(pair, self.f.pin, start, self.product)

    def test_initial_offer_public_asset_readback_and_exact_retry(self):
        other = policy.offer_path(common.SECURE_ACCESS) + '.json'
        self.repo.files[other] = b'preserve Secure Access'
        handoff = self.handoff(self.offer(1, '0.8.4'), 1)
        url = policy.package_url(self.product, 1, '0.8.4.dcu')
        assets = MemoryAssets(url)
        first = self.publish(handoff, assets)
        self.assertEqual(first, self.publish(handoff, assets))
        self.assertEqual(assets.downloads, [None, url, None, url])
        self.assertEqual(len(self.repo.writes), 1)
        self.assertEqual(len(self.repo.writes[0]), 6)
        self.assertEqual(self.repo.files[other], b'preserve Secure Access')
        self.assertEqual(assets.release['tag_name'], self.product + '-dev-1')

    def test_new_draft_missing_from_release_list_uses_returned_id_to_completion(self):
        class LaggingListAssets(MemoryAssets):
            discoveries = 0
            creates = 0
            def lookup(self, tag):
                self.discoveries += 1
                if self.release is not None:
                    raise AssertionError('A known release must be read by ID, not relisted')
                return None
            def create(self, *args):
                self.creates += 1
                return super().create(*args)
        assets = LaggingListAssets(policy.package_url(self.product, 1, '0.8.4.dcu'))
        self.publish(self.handoff(self.offer(1, '0.8.4'), 1), assets)
        self.assertEqual((assets.discoveries, assets.creates), (1, 1))
        self.assertFalse(assets.release['draft'])
        self.assertEqual(assets.release['assets'][0]['id'], 2)
        self.assertEqual(len(self.repo.writes), 1)

    def test_lost_create_reply_discovers_same_draft_without_second_create(self):
        class LostCreateAssets(MemoryAssets):
            creates = 0
            def create(self, *args):
                self.creates += 1
                super().create(*args)
                raise OSError('Fixture reply lost after server created the draft')
        assets = LostCreateAssets(policy.package_url(self.product, 1, '0.8.4.dcu'))
        self.publish(self.handoff(self.offer(1, '0.8.4'), 1), assets)
        self.assertEqual(assets.creates, 1)
        self.assertFalse(assets.release['draft'])
        self.assertEqual(len(self.repo.writes), 1)

    def test_ambiguous_upload_is_reconciled_without_a_second_post(self):
        from update_release_cli import UploadFailure
        class LostReplyAssets(MemoryAssets):
            uploads = 0
            def upload(self, release_id, path, size, name):
                self.uploads += 1
                super().upload(release_id, path, size, name)
                raise UploadFailure('timeout')
        assets = LostReplyAssets(policy.package_url(self.product, 1, '0.8.4.dcu'))
        handoff = self.handoff(self.offer(1, '0.8.4'), 1)
        first = self.publish(handoff, assets)
        self.assertEqual(first, self.publish(handoff, assets))
        self.assertEqual(assets.uploads, 1)
        self.assertEqual(len(self.repo.writes), 1)
        self.assertEqual(assets.release['assets'][0]['id'], 2)

    def test_unconfirmed_upload_preserves_draft_and_reports_safe_code(self):
        from update_release_cli import UploadFailure
        class FailedAssets(MemoryAssets):
            uploads = 0
            def upload(self, release_id, path, size, name):
                self.uploads += 1
                raise UploadFailure('http-413')
        assets = FailedAssets(policy.package_url(self.product, 1, '0.8.4.dcu'))
        with self.assertRaises(UploadFailure) as found:
            self.publish(self.handoff(self.offer(1, '0.8.4'), 1), assets)
        self.assertEqual(found.exception.code, 'http-413')
        self.assertEqual(assets.uploads, 1)
        self.assertTrue(assets.release['draft'])
        self.assertEqual(assets.release['assets'], [])
        self.assertEqual(self.repo.writes, [])

    def test_preexisting_conflicting_asset_is_never_uploaded_or_overwritten(self):
        class ConflictAssets(MemoryAssets):
            uploads = 0
            def create(self, tag, commit, body):
                super().create(tag, commit, body)
                self.release['assets'] = [{'id': 99, 'name': 'conflict.dcu', 'size': 60, 'state': 'uploaded'}]
                return dict(self.release)
            def upload(self, *args):
                self.uploads += 1
                raise AssertionError('Must preserve conflicting asset')
        assets = ConflictAssets(policy.package_url(self.product, 1, '0.8.4.dcu'))
        with self.assertRaisesRegex(ValueError, 'Asset identity conflicts'):
            self.publish(self.handoff(self.offer(1, '0.8.4'), 1), assets)
        self.assertEqual(assets.uploads, 0)
        self.assertEqual(assets.release['assets'][0]['id'], 99)
        self.assertEqual(self.repo.writes, [])

    def test_installed_patch_uses_signed_name_and_round_trips(self):
        url = policy.package_url(self.product, 1, '0.8.7.patch.dcu')
        policy.validate_public_url(url)
        handoff = self.handoff(self.offer(1, '0.8.7', packagePath=url), 1)
        assets = MemoryAssets(url)
        first = self.publish(handoff, assets)
        self.assertEqual(first, self.publish(handoff, assets))
        self.assertEqual(assets.release['assets'][0]['name'], '0.8.7.patch.dcu')
        self.assertEqual(assets.downloads, [None, url, None, url])
        self.assertEqual(len(self.repo.writes), 1)

    def test_patch_url_is_bound_to_exact_numeric_version_and_product(self):
        for name in ('0.8.6.patch.dcu', '0.8.7-beta.patch.dcu', '0.8.7.patch.dcu?x=1'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                url = policy.package_url(self.product, 1, name)
                verify_metadata(self.offer(1, '0.8.7', packagePath=url), self.f.pin, self.f.now,
                                self.grant, self.grant_sig, self.product)
        with self.assertRaises(ValueError):
            policy.validate_public_url(policy.package_url(common.SECURE_ACCESS, 2, '0.4.19.patch.dcu'))

    def test_final_asset_url_must_match_after_draft_publication(self):
        handoff = self.handoff(self.offer(1, '0.8.4'), 1)

        class WrongFinalUrlAssets(MemoryAssets):
            def publish(self, release_id):
                self.release['draft'] = False

        assets = WrongFinalUrlAssets(policy.package_url(self.product, 1, '0.8.4.dcu'))
        with self.assertRaises(ValueError):
            self.publish(handoff, assets)
        self.assertEqual(assets.downloads, [None])
        self.assertFalse(self.repo.writes)

    def test_initial_offer_refuses_partial_or_fabricated_predecessor_and_stale_head(self):
        files = self.offer(1, '0.8.4')
        url = policy.package_url(self.product, 1, '0.8.4.dcu')
        for handoff in (self.handoff(files, 1, ('a' * 64, None)),
                        self.handoff(files, 1, public_head='d' * 40)):
            assets = MemoryAssets(url)
            with self.assertRaises(ValueError):
                self.publish(handoff, assets)
            self.assertIsNone(assets.release)
        self.repo.files[policy.offer_path(self.product) + '.sig.json'] = b'partial'
        with self.assertRaises(ValueError):
            self.publish(self.handoff(files, 1), MemoryAssets(url))
        self.assertFalse(self.repo.writes)

    def test_signed_second_offer_requires_exact_predecessor_and_newer_setup(self):
        first = self.offer(1, '0.8.4')
        initial = plan(self.repo, first, self.f.pin, self.f.now, self.handle, self.repo.snapshot()['sha'],
                       None, None, product=self.product)
        apply_plan(self.repo, initial)
        path = policy.offer_path(self.product)
        predecessor = (digest(first[path + '.json']), digest(first[path + '.sig.json']))
        for sequence, version, reviewed in ((2, '0.8.4', predecessor), (3, '0.8.5', predecessor),
                                            (2, '0.8.5', (predecessor[0], 'e' * 64))):
            with self.assertRaises(ValueError):
                plan(self.repo, self.offer(sequence, version), self.f.pin, self.f.now, self.handle,
                     self.repo.snapshot()['sha'], *reviewed, product=self.product)
        assets = MemoryAssets(policy.package_url(self.product, 2, '0.8.5.dcu'))
        self.publish(self.handoff(self.offer(2, '0.8.5'), 2, predecessor), assets)
        self.assertEqual(len(self.repo.writes), 2)
        archive = policy.release_prefix(self.product, 1, '0.8.4') + '/offer.json'
        self.assertEqual(self.repo.files[archive], first[path + '.json'])

    def test_scope_binding_and_package_limits(self):
        for change in ({'packagePath': policy.package_url(common.SECURE_ACCESS, 1, '0.8.4.dcu')},
                       {'productId': common.SECURE_ACCESS}, {'channel': 'beta'},
                       {'packageSize': policy.INVESTIGATOR_MAX_PACKAGE_SIZE + 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify_metadata(self.offer(1, '0.8.4', **change), self.f.pin, self.f.now,
                                self.grant, self.grant_sig, self.product)
        with self.assertRaises(ValueError):
            verify_metadata(self.offer(1, '0.08.4'), self.f.pin, self.f.now, self.grant, self.grant_sig, self.product)
        with self.assertRaises(ValueError):
            verify_metadata(self.offer(1, '0.8.4'), self.f.pin, self.f.now, self.grant, self.grant_sig)

    def test_expiry_during_asset_upload_blocks_offer_commit(self):
        handoff = self.handoff(self.offer(1, '0.8.4'), 1)
        fixture = self

        class ExpiringAssets(MemoryAssets):
            def upload(self, release_id, path, size, name):
                super().upload(release_id, path, size, name)
                fixture.f.now += dt.timedelta(days=1)

        with self.assertRaises(ValueError):
            self.publish(handoff, ExpiringAssets(policy.package_url(self.product, 1, '0.8.4.dcu')))
        self.assertFalse(self.repo.writes)

    def test_secure_access_pinned_legacy_scope_still_verifies(self):
        grant, signature = self.sign(dict(self.f.grant, productId=common.SECURE_ACCESS))
        files = self.offer(2, REVIEWED.version, scope=common.SECURE_ACCESS)
        delivery = verify_metadata(files, self.f.pin, self.f.now, grant, signature)
        self.assertEqual(delivery.asset_name, '0.4.19.dcu')
        self.assertEqual(delivery.package_size, REVIEWED.bundle_size + policy.PACKAGE_HEADER_SIZE)
        with self.assertRaises(ValueError):
            verify_metadata(self.offer(2, REVIEWED.version, scope=common.SECURE_ACCESS, plaintextSha256='0' * 64),
                            self.f.pin, self.f.now, grant, signature)

    def test_secure_access_current_grant_accepts_each_reviewed_source(self):
        grant, signature = self.sign(dict(self.f.grant, productId=common.SECURE_ACCESS, sequence=3))
        for sequence, version in ((2, '0.4.19'), (3, '0.4.20'), (4, '0.4.26'), (5, '0.4.27'), (6, '0.4.29')):
            with self.subTest(sequence=sequence):
                reviewed = reviewed_for(sequence)
                files = self.offer(sequence, version, scope=common.SECURE_ACCESS)
                delivery = verify_metadata(files, self.f.pin, self.f.now, grant, signature)
                self.assertEqual((delivery.sequence, delivery.version), (sequence, version))
                self.assertEqual(delivery.asset_name, version + '.dcu')
                self.assertEqual(delivery.package_size, reviewed.bundle_size + policy.PACKAGE_HEADER_SIZE)
                policy.validate_public_url(delivery.package_path)

    def test_secure_access_dev5_requires_its_exact_version_source_and_sequence(self):
        grant, signature = self.sign(dict(self.f.grant, productId=common.SECURE_ACCESS, sequence=3))
        previous, reviewed = reviewed_for(4), reviewed_for(5)
        for changes in ({'plaintextSha256': previous.bundle_sha256},
                        {'packageSize': previous.bundle_size + policy.PACKAGE_HEADER_SIZE},
                        {'packageSize': reviewed.bundle_size},
                        {'packagePath': policy.package_url(common.SECURE_ACCESS, 4, '0.4.27.dcu')}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_metadata(self.offer(5, reviewed.version, scope=common.SECURE_ACCESS, **changes),
                                self.f.pin, self.f.now, grant, signature)
        with self.assertRaises(ValueError):
            verify_metadata(self.offer(5, previous.version, scope=common.SECURE_ACCESS),
                            self.f.pin, self.f.now, grant, signature)
        for sequence in (True, 7):
            with self.subTest(sequence=sequence), self.assertRaisesRegex(ValueError, 'no reviewed source'):
                reviewed_for(sequence)

    def test_secure_access_dev6_binds_new_source_and_preserves_current_grant(self):
        grant, signature = self.sign(dict(self.f.grant, productId=common.SECURE_ACCESS, sequence=3))
        reviewed = reviewed_for(6)
        files = self.offer(6, reviewed.version, scope=common.SECURE_ACCESS)
        delivery = verify_metadata(files, self.f.pin, self.f.now, grant, signature)
        self.assertEqual((delivery.sequence, delivery.version, delivery.package_size),
                         (6, '0.4.29', 182078620 + policy.PACKAGE_HEADER_SIZE))
        for changes in ({'plaintextSha256': reviewed_for(5).bundle_sha256},
                        {'packageSize': reviewed_for(5).bundle_size + policy.PACKAGE_HEADER_SIZE},
                        {'packageSize': reviewed.bundle_size},
                        {'packagePath': policy.package_url(common.SECURE_ACCESS, 5, '0.4.29.dcu')}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_metadata(self.offer(6, reviewed.version, scope=common.SECURE_ACCESS, **changes),
                                self.f.pin, self.f.now, grant, signature)
        for version in ('0.4.27', '0.4.28'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                verify_metadata(self.offer(6, version, scope=common.SECURE_ACCESS),
                                self.f.pin, self.f.now, grant, signature)

    def test_secure_access_dev4_refuses_wrong_version_digest_and_size(self):
        grant, signature = self.sign(dict(self.f.grant, productId=common.SECURE_ACCESS, sequence=3))
        for version in ('0.4.19', '0.4.20', '0.4.21'):
            with self.subTest(version=version), self.assertRaises(ValueError):
                verify_metadata(self.offer(4, version, scope=common.SECURE_ACCESS),
                                self.f.pin, self.f.now, grant, signature)
        reviewed = reviewed_for(4)
        for changes in ({'plaintextSha256': REVIEWED.bundle_sha256},
                        {'packageSize': reviewed.bundle_size},
                        {'packagePath': policy.package_url(common.SECURE_ACCESS, 3, '0.4.26.dcu')}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                verify_metadata(self.offer(4, reviewed.version, scope=common.SECURE_ACCESS, **changes),
                                self.f.pin, self.f.now, grant, signature)

    def test_secure_access_public_url_binds_sequence_to_reviewed_version(self):
        for sequence in (2, 3, 4, 5, 6):
            for version in ('0.4.19', '0.4.20', '0.4.21', '0.4.26', '0.4.27', '0.4.28', '0.4.29'):
                url = policy.package_url(common.SECURE_ACCESS, sequence, version + '.dcu')
                with self.subTest(sequence=sequence, version=version):
                    if version == reviewed_for(sequence).version:
                        policy.validate_public_url(url)
                    else:
                        with self.assertRaises(ValueError):
                            policy.validate_public_url(url)
        with self.assertRaises(ValueError):
            policy.validate_public_url(policy.package_url(common.SECURE_ACCESS, 5, '0.4.26.dcu'))
