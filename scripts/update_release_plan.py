"""Compare-before-publish planning for a reviewed dev release. No CLI or credentials."""
from dataclasses import dataclass
import hashlib
import re
import update_public_import as common
from update_validation_import import verify_signed
from update_release_metadata import OFFER, verify_metadata
from update_repository import require, reconcile


@dataclass(frozen=True)
class PublicationPlan:
    base_sha: str
    files: tuple
    already_published: bool


def plan(repository, files, pin, now, handle, expected_head, previous_offer_sha256, previous_signature_sha256):
    require(repository.name == common.REPOSITORY, 'Wrong distribution repository')
    require(isinstance(handle, str) and re.fullmatch(r'[a-f0-9]{32}', handle) is not None, 'Invalid handle')
    for value in (previous_offer_sha256, previous_signature_sha256):
        require(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None, 'Invalid predecessor digest')
    snapshot = repository.snapshot()
    require(repository.read(snapshot, 'config/update-signing-public-key.pem') == pin.read_bytes(), 'Distribution trust pin changed')
    grant = repository.read(snapshot, 'grants/' + handle + '.json')
    signature = repository.read(snapshot, 'grants/' + handle + '.sig.json')
    require(grant is not None and signature is not None, 'Current public grant required')
    delivery = verify_metadata(files, pin, now, grant, signature)
    require(delivery.handle == handle, 'Grant recipient differs')
    writes = dict(delivery.files)
    offer_path = f'products/secure-access/releases/dev/{delivery.sequence}/0.4.19/offer'
    writes[offer_path + '.json'] = writes[OFFER + '.json']
    writes[offer_path + '.sig.json'] = writes[OFFER + '.sig.json']
    actual = {path: repository.read(snapshot, path) for path in writes}
    if all(actual[path] == data for path, data in writes.items()):
        return PublicationPlan(snapshot['sha'], tuple(sorted(writes.items())), True)
    require(snapshot['sha'] == expected_head, 'Distribution changed after review')
    for path in writes:
        if path not in (OFFER + '.json', OFFER + '.sig.json'):
            require(actual[path] is None, 'Existing or partial immutable release evidence; do not overwrite')
    previous, previous_signature = actual[OFFER + '.json'], actual[OFFER + '.sig.json']
    require(previous is not None and previous_signature is not None and
            hashlib.sha256(previous).hexdigest() == previous_offer_sha256 and
            hashlib.sha256(previous_signature).hexdigest() == previous_signature_sha256,
            'Reviewed predecessor offer/signature changed')
    old, _ = verify_signed(previous, previous_signature, pin)
    require(set(old) == {'schemaVersion', 'releaseSequence', 'expiresUtc', 'release'} and
            type(old['schemaVersion']) is int and old['schemaVersion'] == 1 and
            type(old['releaseSequence']) is int and 1 <= old['releaseSequence'] < 9223372036854775807 and
            delivery.sequence == old['releaseSequence'] + 1 and isinstance(old['release'], dict) and
            old['release'].get('productId') == 'secure-access' and old['release'].get('channel') == 'dev',
            'Release must immediately follow the signed dev predecessor')
    # Expired predecessor offers may be replaced; the new grant and offer must be current.
    return PublicationPlan(snapshot['sha'], tuple(sorted(writes.items())), False)


def apply_plan(repository, publication_plan):
    """Low-level CAS write; caller must separately verify reviewed authority and remote asset.

    Deliberately no production workflow calls this function yet.
    """
    require(repository.name == common.REPOSITORY, 'Wrong distribution repository')
    snapshot = repository.snapshot()
    require(snapshot['sha'] == publication_plan.base_sha, 'Distribution changed after planning')
    files = dict(publication_plan.files)
    if publication_plan.already_published:
        require(all(repository.read(snapshot, p) == data for p, data in files.items()), 'Published evidence changed')
        return snapshot
    return reconcile(repository, snapshot, files, 'Publish reviewed encrypted Secure Access dev release')
