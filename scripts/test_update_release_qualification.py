"""No network: qualify disposable drafts using in-memory repository/asset adapters."""
import hashlib
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import update_release_qualification as qa
from update_release_cli import UploadFailure

COMMIT='a'*40


class Repository:
    name=qa.PUBLICATION
    def __init__(self):
        self.main=COMMIT; self.release=None; self.assets=[]; self.mutations=[]; self.calls=[]
    def api(self, method, path, body=None):
        self.calls.append((method,path))
        if method!='GET':self.mutations.append((method,path))
        if (method,path)==('GET','/git/ref/heads/main'):
            return {'object':{'type':'commit','sha':self.main}}
        if (method,path)==('GET','/releases?per_page=100'):
            return [dict(self.release)] if self.release else []
        if (method,path)==('POST','/releases'):
            assert self.release is None and body['draft'] is True and body['prerelease'] is True and body['make_latest']=='false'
            self.release=dict(body,id=7);return dict(self.release)
        if (method,path)==('GET','/releases/7'):return dict(self.release)
        if (method,path)==('GET','/releases/7/assets?per_page=100'):return [dict(a) for a in self.assets]
        raise AssertionError('Unexpected operation: '+method+' '+path)


class Assets:
    def __init__(self, repo):self.repo=repo;self.data={};self.uploads=[];self.downloads=[];self.corrupt=False;self.lost_reply=False;self.drift=False
    def upload(self,token,release_id,path,size,name):
        assert token=='fixture' and release_id==7 and self.repo.release['draft']
        assert name not in self.data
        data=path.read_bytes();assert len(data)==size
        self.uploads.append(name);self.data[name]=data
        self.repo.assets.append({'id':len(self.data)+10,'name':name,'size':size,'state':'uploaded','digest':'sha256:'+hashlib.sha256(data).hexdigest()})
        if self.lost_reply:raise UploadFailure('timeout')
    def download(self,asset_id,target,size):
        asset=next(a for a in self.repo.assets if a['id']==asset_id)
        self.downloads.append(asset_id)
        target.write_bytes(self.data[asset['name']]+(b'changed' if self.corrupt else b''))
        if self.drift:self.repo.main='b'*40


class QualificationTests(unittest.TestCase):
    def execute(self,repo=None,assets=None,attempt='1'):
        repo=repo or Repository();assets=assets or Assets(repo)
        with patch.object(qa,'QUALIFICATION_ASSETS',(('0.0.1.dcu',64),('0.0.2.dcu',128))):
            return qa.qualify_upload(repo,assets,assets.upload,COMMIT,'123',attempt,'fixture')
    def context(self):
        return {'GITHUB_REPOSITORY':qa.PUBLICATION,'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch',
                'GITHUB_ACTOR':'amdecian','GITHUB_TRIGGERING_ACTOR':'amdecian','INPUT_OPERATION':'qualification',
                'INPUT_CONFIRMATION':'QUALIFY PUBLICATION UPLOAD','GITHUB_SHA':COMMIT,'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}
    def test_exact_sizes_and_owner_context(self):
        self.assertEqual(qa.QUALIFICATION_ASSETS,(('0.0.1.dcu',1048576),('0.0.2.dcu',148250440)))
        qa.validate_context(self.context(),platform='nt')
        for key,value in (('GITHUB_ACTOR','other'),('GITHUB_TRIGGERING_ACTOR','other'),('GITHUB_REF','refs/heads/qa'),
                          ('GITHUB_REPOSITORY','other/fork'),('GITHUB_EVENT_NAME','pull_request'),
                          ('INPUT_OPERATION','publish'),('INPUT_CONFIRMATION','PUBLISH REAL DEV UPDATE'),('GITHUB_SHA','bad'),
                          ('GITHUB_RUN_ID','0'),('GITHUB_RUN_ATTEMPT','1;bad')):
            env=self.context();env[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):qa.validate_context(env,platform='nt')
        with self.assertRaises(ValueError):qa.validate_context(self.context(),platform='posix')
    def test_draft_only_exact_upload_readback_and_idempotent_retry(self):
        repo=Repository();assets=Assets(repo)
        first=self.execute(repo,assets);second=self.execute(repo,assets)
        self.assertEqual(first,second)
        self.assertEqual(assets.uploads,['0.0.1.dcu','0.0.2.dcu'])
        self.assertEqual(len(assets.downloads),4)
        self.assertEqual(repo.mutations,[('POST','/releases')])
        self.assertTrue(repo.release['draft'])
        self.assertEqual(repo.release['target_commitish'],COMMIT)
        self.assertFalse(first['anonymous_readback_tested'])
        self.assertTrue(all(path.startswith('/releases') or path=='/git/ref/heads/main' for _,path in repo.calls))
    def test_lost_upload_reply_reconciles_without_second_post(self):
        repo=Repository();assets=Assets(repo);assets.lost_reply=True
        self.assertEqual(self.execute(repo,assets)['status'],'publication-upload-qualification-pass')
        self.assertEqual(len(assets.uploads),2)
        self.assertEqual(repo.mutations,[('POST','/releases')])
    def test_unconfirmed_upload_is_preserved_without_publishing(self):
        repo=Repository();assets=Assets(repo)
        def fail(*_):raise UploadFailure('http-403')
        assets.upload=fail
        with self.assertRaises(UploadFailure):self.execute(repo,assets)
        self.assertEqual(repo.assets,[])
        self.assertTrue(repo.release['draft'])
        self.assertEqual(repo.mutations,[('POST','/releases')])
    def test_conflicting_asset_and_corrupt_readback_fail_closed(self):
        repo=Repository();assets=Assets(repo);self.execute(repo,assets)
        repo.assets[0]['digest']='sha256:'+'0'*64
        with self.assertRaises(ValueError):self.execute(repo,assets)
        self.assertEqual(len(assets.uploads),2)
        repo=Repository();assets=Assets(repo);assets.corrupt=True
        with self.assertRaises(ValueError):self.execute(repo,assets)
        self.assertTrue(repo.release['draft'])
        self.assertEqual(repo.mutations,[('POST','/releases')])
    def test_public_main_drift_never_marks_qualification_pass(self):
        repo=Repository();repo.main='b'*40
        with self.assertRaises(ValueError):self.execute(repo,Assets(repo))
        self.assertEqual(repo.mutations,[])
        repo=Repository();assets=Assets(repo);assets.drift=True
        with self.assertRaises(ValueError):self.execute(repo,assets)
        self.assertTrue(repo.release['draft'])
        self.assertEqual(repo.mutations,[('POST','/releases')])
    def test_qualification_bytes_stream_across_one_megabyte_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/'data'
            digest=qa.write_qualification_file(path,1048577)
            self.assertEqual(path.stat().st_size,1048577)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),digest)
    def test_phase_diagnostics_never_require_raw_exception_text(self):
        def fail():raise OSError('fixture-secret-must-not-be-logged')
        with self.assertRaises(OSError) as found:qa.in_phase('qa-draft-create',fail)
        self.assertEqual(found.exception.publication_phase,'qa-draft-create')
        with self.assertRaises(ValueError):qa.in_phase('untrusted-phase',fail)
    def test_workflow_keeps_native_token_and_normal_publish_contract(self):
        text=(pathlib.Path(__file__).resolve().parents[1]/'.github/workflows/import-real-update.yml').read_text()
        self.assertIn('default: publish',text)
        self.assertIn('options: [publish, qualification]',text)
        self.assertIn('GITHUB_TOKEN: '+chr(36)+'{{ github.token }}',text)
        self.assertNotIn('secrets.',text)
        self.assertNotIn('UPDATE_PUBLICATION_TOKEN',text)
        self.assertIn("NT AUTHORITY\\NETWORK SERVICE",text)
        self.assertIn('runs-on: [decian-public-update-import]',text)
        final=text[text.index('name: Verify reviewed handoff'):]
        self.assertLess(final.index('update_release_qualification.py'),final.index('Initialize-UpdateReleaseStaging.ps1'))
        self.assertIn("INPUT_CONFIRMATION -cne 'PUBLISH REAL DEV UPDATE'",final)
        self.assertIn('update_release_import.py',final)
        for name in ('bundle_base64:','handle:','release_sequence:'):self.assertIn(name,text)
