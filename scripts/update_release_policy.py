"""Publication scopes shared by the reviewed release import and asset transport."""
import re

from update_public_import import INVESTIGATOR, REPOSITORY, SECURE_ACCESS
from update_repository import require

MAX_SEQUENCE = 2**63 - 1
INVESTIGATOR_MAX_PACKAGE_SIZE = 256 * 1024 * 1024
PACKAGE_HEADER_SIZE = 36
SECURE_ACCESS_ASSET = '0.4.19.dcu'


def version_tuple(value):
    require(isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})', value)
            is not None, 'Expected a three-component signed Setup version')
    parts = tuple(map(int, value.split('.')))
    require(all(part <= 65535 for part in parts), 'Setup version exceeds Windows version resource range')
    return parts


def sequence_valid(product, sequence):
    return (product in (SECURE_ACCESS, INVESTIGATOR) and type(sequence) is int and
            (1 if product == INVESTIGATOR else 2) <= sequence <= MAX_SEQUENCE)


def first_investigator_offer(product, sequence):
    return product == INVESTIGATOR and sequence == 1


def check_predecessor(product, sequence, offer_digest, signature_digest):
    if first_investigator_offer(product, sequence):
        require(offer_digest is None and signature_digest is None, 'First 365II offer requires reviewed absence')
    else:
        require(all(isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None
                    for value in (offer_digest, signature_digest)), 'Invalid reviewed predecessor digests')


def offer_path(product):
    require(product in (SECURE_ACCESS, INVESTIGATOR), 'Unknown dev release product')
    return f'products/{product}/channels/dev/offer'


def release_prefix(product, sequence, version):
    return f'products/{product}/releases/dev/{sequence}/{version}'


def release_tag(product, sequence):
    return f'{product}-dev-{sequence}'


def package_url(product, sequence, asset):
    return f'https://github.com/{REPOSITORY}/releases/download/{release_tag(product, sequence)}/{asset}'


def validate_tag(tag):
    require(isinstance(tag, str), 'Invalid release tag')
    match = re.fullmatch(r'(secure-access|m365-incident-investigator)-dev-([1-9][0-9]{0,18})', tag)
    # Secure Access's diagnostic sequence 1 exists and remains a valid lookup.
    require(match is not None and int(match[2]) <= MAX_SEQUENCE, 'Invalid release tag')
    return match[1]


def validate_asset_name(name):
    require(isinstance(name, str) and name.endswith('.dcu'), 'Invalid release asset name')
    suffix = '.patch.dcu' if name.endswith('.patch.dcu') else '.dcu'
    version_tuple(name[:-len(suffix)])


def validate_public_url(url):
    prefix = f'https://github.com/{REPOSITORY}/releases/download/'
    require(isinstance(url, str) and url.startswith(prefix), 'Invalid public asset URL')
    parts = url[len(prefix):].split('/')
    require(len(parts) == 2, 'Invalid public asset URL')
    product = validate_tag(parts[0])
    validate_asset_name(parts[1])
    if product == SECURE_ACCESS:
        require(parts[1] == SECURE_ACCESS_ASSET, 'Invalid Secure Access asset name')
