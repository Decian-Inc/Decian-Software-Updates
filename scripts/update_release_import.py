"""Public-only import: reviewed attestation, exact asset, fresh grant, then CAS offer commit."""
import datetime as dt
import os
import pathlib
import sys
import re
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from update_release_handoff import verify
from update_release_plan import plan, apply_plan
from update_release_upload import ensure_asset
from update_release_metadata import verify_ciphertext
from update_repository import require
from update_public_import import REPOSITORY


def publish(public, assets, encoded, pin, handle, ciphertext, clock=None, expected_sequence=None):
    require(public.name == REPOSITORY and re.fullmatch(r'[a-f0-9]{32}', handle) is not None, 'Invalid public import scope')
    if clock is None: clock = lambda: dt.datetime.now(dt.timezone.utc)
    def current():
        snapshot = public.snapshot()
        require(public.read(snapshot, 'config/update-signing-public-key.pem') == pin.read_bytes(), 'Public trust pin changed')
        grant = public.read(snapshot, 'grants/' + handle + '.json')
        signature = public.read(snapshot, 'grants/' + handle + '.sig.json')
        require(grant is not None and signature is not None, 'Current signed grant required')
        payload, delivery = verify(encoded, pin, clock(), grant, signature)
        require(delivery.handle == handle, 'Import handle differs')
        require(expected_sequence is None or delivery.sequence == expected_sequence, 'Import sequence differs')
        planned = plan(public, dict(delivery.files), pin, clock(), handle, payload['public_head'],
                       payload['previous_offer_sha256'], payload['previous_signature_sha256'])
        require(public.snapshot()['sha'] == snapshot['sha'], 'Distribution changed during import checks')
        return payload, delivery, planned
    payload, delivery, planned = current()
    verify_ciphertext(ciphertext, delivery)
    asset = ensure_asset(assets, delivery, ciphertext, payload['public_head'])
    # Asset upload/readback can take time. Recheck authorization and expiry, never reuse the old plan.
    payload, delivery, planned = current()
    result = apply_plan(public, planned)
    return {'status': 'reviewed-release-published', 'public_commit': result['sha'],
            'intent_sha256': payload['intent_sha256'], 'asset': asset}


def main():
    import json
    from update_repository import GitHubRepository
    from update_release_assets import GitHubAssets
    require(os.name == 'nt' and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY and
            os.environ.get('GITHUB_REF') == 'refs/heads/main' and
            os.environ.get('INPUT_CONFIRMATION') == 'PUBLISH REAL DEV UPDATE', 'Reviewed public main and confirmation required')
    sequence=os.environ.get('INPUT_SEQUENCE','')
    require(re.fullmatch(r'[1-9][0-9]{0,18}',sequence) is not None and 2 <= int(sequence) <= 9223372036854775807,'Invalid sequence')
    public=GitHubRepository(REPOSITORY,os.environ.get('GITHUB_TOKEN'),False)
    require(public.snapshot()['sha']==os.environ.get('GITHUB_SHA'),'Public main changed since checkout')
    pin=pathlib.Path(__file__).resolve().parents[1]/'config/update-signing-public-key.pem'
    ciphertext=pathlib.Path(os.environ['RELEASE_STAGING_ROOT'])/f'dev-{sequence}'/'package.dcu'
    print(json.dumps(publish(public,GitHubAssets(os.environ.get('GITHUB_TOKEN')),os.environ.get('INPUT_BUNDLE',''),
        pin,os.environ.get('INPUT_HANDLE',''),ciphertext,expected_sequence=int(sequence)),sort_keys=True))


if __name__=='__main__':
    try: main()
    except Exception: raise SystemExit('Real-release import stopped. Preserve candidate and release assets; no offer completion is confirmed.') from None
