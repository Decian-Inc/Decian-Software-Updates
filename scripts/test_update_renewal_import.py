"""Public-only first-renewal verification with a disposable RSA key."""
import base64
import datetime as dt
import json
import unittest
import test_update_public_import as fixture
import update_renewal_import as importer

class RenewalImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):fixture.ImportTests.setUpClass()
    @classmethod
    def tearDownClass(cls):fixture.ImportTests.tearDownClass()
    def setUp(self):
        self.f=fixture.ImportTests();self.f.setUp()
        old=dict(self.f.grant,notBeforeUtc=(self.f.now-dt.timedelta(days=9)).isoformat().replace('+00:00','Z'),
            expiresUtc=(self.f.now-dt.timedelta(days=2)).isoformat().replace('+00:00','Z'))
        self.previous=self.f.transfer(old)['files']
        self.new=dict(self.f.grant,sequence=2)
        self.transfer={'schema':'decian-public-renewal-transfer/v1','repository':self.f.repo.name,
            'previous':self.previous,'files':self.f.transfer(self.new)['files']}
        prefix='grants/'+old['updateHandle']
        for name,suffix in [('grant.json','.json'),('grant.sig.json','.sig.json')]:
            self.f.repo.files[prefix+suffix]=base64.b64decode(self.previous[name])
        self.f.repo.files['config/update-signing-public-key.pem']=self.f.pin.read_bytes()
    def run_import(self):return importer.import_transfer(self.f.repo,self.f.encode(self.transfer),self.f.pin,self.f.now)
    def test_expired_predecessor_atomic_renewal_and_exact_retry(self):
        self.run_import();self.run_import()
        self.assertEqual(len(self.f.repo.writes),1);self.assertEqual(len(self.f.repo.writes[0]),2)
    def test_mismatched_key_sequence_or_expiry_rejected(self):
        for field,value in [('installationKeyId','rsa-sha256:'+'e'*32),('sequence',3),('sequence',True),('channel','beta'),('expiresUtc',self.new['notBeforeUtc'])]:
            self.transfer['files']=self.f.transfer(dict(self.new,**{field:value}))['files']
            with self.assertRaises(ValueError):self.run_import()
        self.assertFalse(self.f.repo.writes)
    def test_annual_grant_and_repeated_renewals(self):
        for sequence in (2,3,4):
            new=dict(self.new,sequence=sequence,
                expiresUtc=(self.f.now+dt.timedelta(days=365)).isoformat().replace('+00:00','Z'))
            self.transfer['files']=self.f.transfer(new)['files']
            self.run_import()
            from update_release_metadata import verify_current_grant
            pair = {name: base64.b64decode(data) for name, data in self.transfer['files'].items()}
            self.assertEqual(verify_current_grant(pair['grant.json'], pair['grant.sig.json'],
                self.f.pin, self.f.now), new)
            with self.assertRaises(ValueError):
                verify_current_grant(pair['grant.json'] + b' ', pair['grant.sig.json'], self.f.pin, self.f.now)
            self.transfer['previous']=self.transfer['files']
            self.f.now+=dt.timedelta(days=366)
            self.new=dict(new,notBeforeUtc=self.f.now.isoformat().replace('+00:00','Z'))
        self.assertEqual(len(self.f.repo.writes),3)

    def test_over_year_and_sequence_skip_rejected(self):
        for change in ({'expiresUtc':(self.f.now+dt.timedelta(days=366)).isoformat().replace('+00:00','Z')},{'sequence':4}):
            self.transfer['files']=self.f.transfer(dict(self.new,**change))['files']
            with self.assertRaises(ValueError):self.run_import()
        self.assertFalse(self.f.repo.writes)

    def test_missing_changed_and_partial_predecessor_rejected(self):
        p=next(p for p in self.f.repo.files if p.startswith('grants/'))
        self.f.repo.files[p]+=b' '
        with self.assertRaises(ValueError):self.run_import()
        del self.f.repo.files[p]
        with self.assertRaises(ValueError):self.run_import()
        self.assertFalse(self.f.repo.writes)
    def test_private_field_and_signature_tamper_rejected(self):
        self.transfer['files']['private-ledger.json']='e30='
        with self.assertRaises(ValueError):self.run_import()
        del self.transfer['files']['private-ledger.json']
        self.transfer['files']['grant.json']=base64.b64encode(json.dumps(dict(self.new,status='revoked')).encode()).decode()
        with self.assertRaises(ValueError):self.run_import()
        self.assertFalse(self.f.repo.writes)
    def test_lost_write_reply_reconciles_exact_bytes(self):
        original=self.f.repo.commit
        def lost(*args):original(*args);raise OSError('lost reply')
        self.f.repo.commit=lost;self.run_import()
        self.assertEqual(len(self.f.repo.writes),1)
    def test_stale_main_and_pin_rejected(self):
        with self.assertRaises(ValueError):importer.import_transfer(self.f.repo,self.f.encode(self.transfer),self.f.pin,self.f.now,'stale')
        self.f.repo.files['config/update-signing-public-key.pem']=b'changed'
        with self.assertRaises(ValueError):self.run_import()
        self.assertFalse(self.f.repo.writes)

if __name__=='__main__':unittest.main()

