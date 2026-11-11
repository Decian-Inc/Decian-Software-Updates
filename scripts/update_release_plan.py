"""Compare-before-publish planning for a reviewed dev release. No CLI or credentials."""
from dataclasses import dataclass
import hashlib
import re
import update_public_import as common
from update_validation_import import verify_signed
from update_release_metadata import verify_metadata
import update_release_policy as policy
from update_repository import require, reconcile


@dataclass(frozen=True)
class PublicationPlan:
    base_sha: str
    files: tuple
    already_published: bool
    product: str


def plan(repository, files, pin, now, handle, expected_head, previous_offer_sha256, previous_signature_sha256,
         product=common.SECURE_ACCESS):
    require(repository.name == common.REPOSITORY, 'Wrong distribution repository')
    require(isinstance(handle, str) and re.fullmatch(r'[a-f0-9]{32}', handle) is not None, 'Invalid handle')
    snapshot = repository.snapshot()
    require(repository.read(snapshot, 'config/update-signing-public-key.pem') == pin.read_bytes(), 'Distribution trust pin changed')
    grant = repository.read(snapshot, 'grants/' + handle + '.json')
    signature = repository.read(snapshot, 'grants/' + handle + '.sig.json')
    require(grant is not None and signature is not None, 'Current public grant required')
    delivery = verify_metadata(files, pin, now, grant, signature, product)
    policy.check_predecessor(product, delivery.sequence, previous_offer_sha256, previous_signature_sha256)
    require(delivery.handle == handle, 'Grant recipient differs')

    writes = dict(delivery.files)
    active_offer = policy.offer_path(product)
    archive_offer = policy.release_prefix(product, delivery.sequence, delivery.version) + '/offer'
    writes[archive_offer + '.json'] = writes[active_offer + '.json']
    writes[archive_offer + '.sig.json'] = writes[active_offer + '.sig.json']
    actual = {path: repository.read(snapshot, path) for path in writes}
    if all(actual[path] == data for path, data in writes.items()):
        return PublicationPlan(snapshot['sha'], tuple(sorted(writes.items())), True, product)

    require(snapshot['sha'] == expected_head, 'Distribution changed after review')
    for path in writes:
        if path not in (active_offer + '.json', active_offer + '.sig.json'):
            require(actual[path] is None, 'Existing or partial immutable release evidence; do not overwrite')

    previous, previous_signature = actual[active_offer + '.json'], actual[active_offer + '.sig.json']
    if policy.first_investigator_offer(product, delivery.sequence):
        require(previous is None and previous_signature is None, 'First 365II dev offer already exists or is partial')
    else:
        require(previous is not None and previous_signature is not None and
                hashlib.sha256(previous).hexdigest() == previous_offer_sha256 and
                hashlib.sha256(previous_signature).hexdigest() == previous_signature_sha256,
                'Reviewed predecessor offer/signature changed')
        old, _ = verify_signed(previous, previous_signature, pin)
        require(set(old) == {'schemaVersion', 'releaseSequence', 'expiresUtc', 'release'} and
                type(old['schemaVersion']) is int and old['schemaVersion'] == 1 and
                type(old['releaseSequence']) is int and 1 <= old['releaseSequence'] < policy.MAX_SEQUENCE and
                delivery.sequence == old['releaseSequence'] + 1 and isinstance(old['release'], dict) and
                old['release'].get('productId') == product and old['release'].get('channel') == 'dev',
                'Release must immediately follow the signed dev predecessor')
        if product == common.INVESTIGATOR:
            require(policy.version_tuple(delivery.version) > policy.version_tuple(old['release'].get('version')),
                    '365II offer must advance the signed Setup version')
    return PublicationPlan(snapshot['sha'], tuple(sorted(writes.items())), False, product)


def apply_plan(repository, publication_plan):
    """Commit a previously verified plan at the exact reviewed public head."""
    require(repository.name == common.REPOSITORY, 'Wrong distribution repository')
    snapshot = repository.snapshot()
    require(snapshot['sha'] == publication_plan.base_sha, 'Distribution changed after planning')
    files = dict(publication_plan.files)
    if publication_plan.already_published:
        require(all(repository.read(snapshot, p) == data for p, data in files.items()), 'Published evidence changed')
        return snapshot
    product_name = '365II' if publication_plan.product == common.INVESTIGATOR else 'Secure Access'
    return reconcile(repository, snapshot, files, f'Publish reviewed encrypted {product_name} dev release')
