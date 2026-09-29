import base64
import copy
import datetime as dt
import hashlib
import json
import unittest
import test_update_public_import as fixtures
import update_validation_import as validation

class ValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): fixtures.ImportTests.setUpClass()
    @classmethod
    def tearDownClass(cls): fixtures.ImportTests.tearDownClass()
    def setUp(self):
        self.f = fixtures.ImportTests('test_atomic_pair_and_exact_retry'); self.f.setUp()
        self.grant_transfer = self.f.transfer()
        self.grant = base64.b64decode(self.grant_transfer['files']['grant.json'])
        self.grant_sig = base64.b64decode(self.grant_transfer['files']['grant.sig.json'])
        self.cipher = b'DCNUPK01' + bytes(28 + len(validation.PAYLOAD))
        self.envelope_path = validation.PREFIX + '/envelopes/' + self.f.grant['updateHandle']
        self.offer = {'schemaVersion':1,'releaseSequence':1,'expiresUtc':self.f.grant['expiresUtc'],'release':{
            'schemaVersion':1,'productId':'secure-access','version':validation.VERSION,'channel':'dev',
            'packagePath':validation.PREFIX+'/validation.dcu','packageAlgorithm':'AES-256-GCM',
            'packageSha256':hashlib.sha256(self.cipher).hexdigest(),'plaintextSha256':hashlib.sha256(validation.PAYLOAD).hexdigest(),
            'packageSize':len(self.cipher),'associatedData':'DECIAN|UPDATE|1|secure-access|'+validation.VERSION+'|dev',
            'entitlementBasePath':validation.PREFIX+'/envelopes','signingKeyId':self.f.keyid,'publishedUtc':self.f.grant['notBeforeUtc']}}
        self.envelope = {'schemaVersion':1,'productId':'secure-access','releaseVersion':validation.VERSION,
            'updateHandle':self.f.grant['updateHandle'],'keyWrapAlgorithm':'RSA-OAEP-SHA256',
            'wrappedReleaseKeyBase64':base64.b64encode(bytes(384)).decode(),'signingKeyId':self.f.keyid,'issuedUtc':self.f.grant['notBeforeUtc']}
        self.repo = self.f.repo
        self.repo.files = {'config/update-signing-public-key.pem':self.f.pin.read_bytes(),
            'grants/'+self.f.grant['updateHandle']+'.json':self.grant,
            'grants/'+self.f.grant['updateHandle']+'.sig.json':self.grant_sig}
    def sign(self, value):
        result = self.f.transfer(value)['files']
        return result['grant.json'], result['grant.sig.json']
    def transfer(self):
        offer, sig = self.sign(self.offer); envelope, esig = self.sign(self.envelope)
        return {'schema':'decian-validation-transfer/v1','repository':self.repo.name,'files':{
            validation.OFFER+'.json':offer,validation.OFFER+'.sig.json':sig,
            self.envelope_path+'.json':envelope,self.envelope_path+'.sig.json':esig,
            validation.PREFIX+'/validation.dcu':base64.b64encode(self.cipher).decode()}}
    def run_import(self, transfer):
        return validation.import_transfer(self.repo,self.f.encode(transfer),self.f.pin,self.f.now,self.f.grant['updateHandle'])
    def test_atomic_five_files_exact_retry(self):
        transfer=self.transfer(); self.run_import(transfer); self.run_import(transfer)
        self.assertEqual(len(self.repo.writes),1); self.assertEqual(len(self.repo.writes[0]),5)
    def test_invalid_signed_release_scope(self):
        original=copy.deepcopy(self.offer)
        for field,value in [('packagePath','../bad'),('version','1.0.0'),('channel','beta'),('packageSize',500000000),
                            ('plaintextSha256','0'*64),('productId','other')]:
            self.offer=copy.deepcopy(original); self.offer['release'][field]=value
            with self.subTest(field=field), self.assertRaises(ValueError): self.run_import(self.transfer())
        self.assertFalse(self.repo.writes)
    def test_tamper_private_fields_and_missing_file(self):
        for mode in ('tamper','private','missing'):
            transfer=self.transfer()
            if mode=='tamper': transfer['files'][validation.PREFIX+'/validation.dcu']=base64.b64encode(b'bad').decode()
            elif mode=='private': transfer['files']['private.pem']='eA=='
            else: del transfer['files'][validation.OFFER+'.sig.json']
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.run_import(transfer)
        self.assertFalse(self.repo.writes)
    def test_recipient_expiry_revocation(self):
        self.envelope['updateHandle']='a'*32
        with self.assertRaises(ValueError): self.run_import(self.transfer())
        self.envelope['updateHandle']=self.f.grant['updateHandle']
        self.offer['expiresUtc']=self.f.grant['notBeforeUtc']
        with self.assertRaises(ValueError): self.run_import(self.transfer())
        self.offer['expiresUtc']=self.f.grant['expiresUtc']
        self.repo.files['grants/'+self.f.grant['updateHandle']+'.json']=b'{}'
        with self.assertRaises(ValueError): self.run_import(self.transfer())
        self.assertFalse(self.repo.writes)
    def test_partial_conflict_and_main_change(self):
        transfer=self.transfer(); self.repo.files[validation.OFFER+'.json']=b'partial'
        with self.assertRaises(ValueError): self.run_import(transfer)
        with self.assertRaises(ValueError): validation.import_transfer(self.repo,self.f.encode(transfer),self.f.pin,self.f.now,self.f.grant['updateHandle'],'other')
        self.assertFalse(self.repo.writes)
