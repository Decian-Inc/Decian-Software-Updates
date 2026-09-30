"""Signed public-only proof of merged release review; no private authority records exported."""
import base64
import datetime as dt
import json
import pathlib
import re
import tempfile
import hashlib
import update_public_import as common
from update_release_metadata import OFFER, verify_metadata
from update_validation_import import verify_signed
from update_repository import require

def digest(data): return hashlib.sha256(data).hexdigest()


def verify(encoded, pin, now, grant, grant_signature):
    require(isinstance(encoded, str) and len(encoded) <= 32768, 'Handoff exceeds limit')
    transfer = common.read_json(base64.b64decode(encoded, validate=True))
    require(set(transfer) == {'payload', 'signature'}, 'Unexpected handoff fields')
    payload, _ = verify_signed(base64.b64decode(transfer['payload'], validate=True),
                               base64.b64decode(transfer['signature'], validate=True), pin)
    require(set(payload) == {'schema', 'repository', 'authority_commit', 'intent_sha256', 'sequence', 'handle',
        'public_head', 'previous_offer_sha256', 'previous_signature_sha256', 'grant_sha256', 'grant_signature_sha256',
        'created_utc', 'expires_utc', 'files'} and payload['schema'] == 'decian-reviewed-release-handoff/v1' and
        payload['repository'] == common.REPOSITORY, 'Invalid reviewed release handoff')
    for key in ('authority_commit', 'public_head'):
        require(isinstance(payload[key], str) and re.fullmatch(r'[a-f0-9]{40}', payload[key]) is not None, 'Invalid reviewed commit')
    for key in ('intent_sha256','previous_offer_sha256','previous_signature_sha256','grant_sha256','grant_signature_sha256'):
        require(isinstance(payload[key], str) and re.fullmatch(r'[a-f0-9]{64}', payload[key]) is not None, 'Invalid reviewed digest')
    require(digest(grant) == payload['grant_sha256'] and digest(grant_signature) == payload['grant_signature_sha256'],
            'Public grant differs from reviewed handoff')
    require(isinstance(payload['files'], dict) and len(payload['files']) == 4, 'Unexpected public metadata')
    files = {p: base64.b64decode(b, validate=True) for p, b in payload['files'].items()}
    delivery = verify_metadata(files, pin, now, grant, grant_signature)
    require(type(payload['sequence']) is int and payload['sequence'] == delivery.sequence and payload['handle'] == delivery.handle,
            'Handoff recipient/sequence mismatch')
    start, end = common.timestamp(payload['created_utc']), common.timestamp(payload['expires_utc'])
    offer = common.read_json(files[OFFER + '.json'])
    require(start <= now + dt.timedelta(minutes=5) and start < end and now < end <= start + dt.timedelta(days=7) and
            payload['expires_utc'] == offer['expiresUtc'], 'Handoff is expired or outside offer validity')
    return payload, delivery
