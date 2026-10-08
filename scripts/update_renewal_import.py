"""Verify a signed first renewal and atomically replace its exact predecessor."""
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import sys
import tempfile
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import update_public_import as common
from update_repository import GitHubRepository, reconcile, require


def verify_pair(files, pin, now):
    require(set(files) == {'grant.json','grant.sig.json'}, 'Only public pair permitted')
    grant = common.read_json(files['grant.json'])
    sig = common.read_json(files['grant.sig.json'])
    require(set(grant) == {'schemaVersion','productId','updateHandle','installationKeyId','channel','sequence','notBeforeUtc','expiresUtc','status'}, 'Invalid renewal grant fields')
    require(type(grant['schemaVersion']) is int and grant['schemaVersion'] == 1 and
            type(grant['sequence']) is int and grant['sequence'] == 2 and
            grant['status'] == 'active' and grant['productId'] == 'secure-access' and
            grant['channel'] == 'dev', 'Only first Secure Access dev renewal supported')
    import re
    require(re.fullmatch(r'[a-f0-9]{32}',grant['updateHandle']) is not None and
            re.fullmatch(r'rsa-sha256:[a-f0-9]{32}',grant['installationKeyId']) is not None, 'Invalid renewal identity')
    start,end=(common.timestamp(grant[k]) for k in ('notBeforeUtc','expiresUtc'))
    require(start <= now < end <= start+dt.timedelta(days=7), 'Renewal expired or future')
    require(set(sig)=={'schemaVersion','algorithm','keyId','signatureBase64'} and
            type(sig['schemaVersion']) is int and sig['schemaVersion']==1 and sig['algorithm']=='RSA-PSS-SHA256', 'Invalid renewal signature envelope')
    der=common.openssl('pkey','-pubin','-in',pin,'-outform','DER')
    details=common.openssl('pkey','-pubin','-in',pin,'-text','-noout').decode('ascii')
    bits=re.search(r'Public-Key: \((\d+) bit\)',details)
    require(bits is not None and 3072<=int(bits.group(1))<=8192 and 'Modulus:' in details, 'RSA-3072 or stronger required')
    require(sig['keyId']=='rsa-sha256:'+hashlib.sha256(der).hexdigest()[:32], 'Renewal signer differs')
    with tempfile.TemporaryDirectory(prefix='decian-renewal-verify-') as temporary:
        root=pathlib.Path(temporary);(root/'grant').write_bytes(files['grant.json'])
        (root/'sig').write_bytes(base64.b64decode(sig['signatureBase64'],validate=True))
        common.openssl('dgst','-sha256','-verify',pin,'-signature',root/'sig',
            '-sigopt','rsa_padding_mode:pss','-sigopt','rsa_pss_saltlen:32',root/'grant')
    return grant


def verify_transfer(encoded,pin,now):
    require(isinstance(encoded,str) and len(encoded)<=24000,'Renewal transfer exceeds limit')
    transfer=common.read_json(base64.b64decode(encoded,validate=True))
    require(set(transfer)=={'schema','repository','previous','files'} and
            transfer['schema']=='decian-public-renewal-transfer/v1' and transfer['repository']==common.REPOSITORY,'Invalid renewal transfer scope')
    previous={n:base64.b64decode(v,validate=True) for n,v in transfer['previous'].items()}
    files={n:base64.b64decode(v,validate=True) for n,v in transfer['files'].items()}
    require(set(previous)=={'grant.json','grant.sig.json'},'Invalid predecessor pair')
    old=common.read_json(previous['grant.json'])
    # Historical signature validation proves provenance only, not current permission.
    original=base64.b64encode(json.dumps({'schema':'decian-public-grant-transfer/v1','repository':common.REPOSITORY,
        'files':transfer['previous']}).encode()).decode()
    common.verify_transfer(original,pin,common.timestamp(old['notBeforeUtc']))
    new=verify_pair(files,pin,now)
    require(all(new[k]==old[k] for k in ('productId','channel','updateHandle','installationKeyId')) and
            common.timestamp(new['notBeforeUtc'])>=common.timestamp(old['notBeforeUtc']) and
            common.timestamp(new['expiresUtc'])>common.timestamp(old['expiresUtc']), 'Renewal identity or validity differs')
    return previous,files,new


def import_transfer(repository,encoded,pin,now,expected_commit=None):
    require(repository.name==common.REPOSITORY,'Unexpected distribution repository')
    previous,files,grant=verify_transfer(encoded,pin,now)
    snapshot=repository.snapshot()
    if expected_commit is not None: require(snapshot['sha']==expected_commit,'Distribution main changed since checkout')
    require(repository.read(snapshot,'config/update-signing-public-key.pem')==pin.read_bytes(),'Public pin differs')
    prefix='grants/'+grant['updateHandle']
    paths={'grant.json':prefix+'.json','grant.sig.json':prefix+'.sig.json'}
    actual={n:repository.read(snapshot,p) for n,p in paths.items()}
    if actual!=files:
        require(actual==previous,'Public predecessor changed or partial pair; renewal held')
        snapshot=reconcile(repository,snapshot,{paths[n]:v for n,v in files.items()},'Import verified same-key first grant renewal')
    return {'status':'renewed-public-pair-verified','public_commit':snapshot['sha'],
            'sha256':{paths[n]:hashlib.sha256(v).hexdigest() for n,v in files.items()}}


def main():
    require(os.environ.get('GITHUB_REPOSITORY')==common.REPOSITORY and os.environ.get('GITHUB_REF')=='refs/heads/main' and
            os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','Explicit distribution main dispatch required')
    require(os.environ.get('INPUT_CONFIRMATION')=='IMPORT SAME-KEY GRANT RENEWAL','Explicit renewal import required')
    pin=pathlib.Path(__file__).resolve().parents[1]/'config/update-signing-public-key.pem'
    print(json.dumps(import_transfer(GitHubRepository(common.REPOSITORY,os.environ.get('GITHUB_TOKEN'),False),
        os.environ.get('INPUT_BUNDLE',''),pin,dt.datetime.now(dt.timezone.utc),os.environ.get('GITHUB_SHA','')),sort_keys=True))

if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('Renewal import held; verify exact predecessor, signature and expiry.') from None
