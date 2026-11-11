"""Idempotent draft/upload/readback/publish state machine; never replaces an asset."""
import pathlib
import tempfile

from update_release_metadata import verify_ciphertext
from update_public_import import INVESTIGATOR
import update_release_policy as policy
from update_repository import require


def validate_release(release, tag, public_head, body, expected_id=None):
    require(isinstance(release, dict) and type(release.get('id')) is int and release['id'] > 0 and
            (expected_id is None or release['id'] == expected_id) and
            release.get('tag_name') == tag and release.get('target_commitish') == public_head and
            release.get('name') == tag and release.get('body') == body and release.get('prerelease') is True and
            type(release.get('draft')) is bool, 'Release identity conflicts; do not modify')
    require(isinstance(release.get('assets'), list) and len(release['assets']) <= 1, 'Unexpected release assets')


def validate_asset(asset, delivery, published):
    require(isinstance(asset, dict) and type(asset.get('id')) is int and asset['id'] > 0 and
            asset.get('name') == delivery.asset_name and type(asset.get('size')) is int and
            asset['size'] == delivery.package_size and asset.get('state') == 'uploaded' and
            asset.get('digest') in (None, 'sha256:' + delivery.package_sha256), 'Asset identity conflicts; never overwrite')
    # GitHub may advertise an untagged draft URL. Read drafts by authenticated
    # asset ID and require the signed client URL once the release is public.
    require(not published or asset.get('browser_download_url') == delivery.package_path,
            'Published asset URL differs from signed client URL')


def ensure_asset(assets, delivery, ciphertext, public_head):
    verify_ciphertext(ciphertext, delivery)
    tag = policy.release_tag(delivery.product, delivery.sequence)
    product_name = '365II' if delivery.product == INVESTIGATOR else 'Secure Access'
    body = f'Decian encrypted {product_name} dev package\nSHA256: {delivery.package_sha256}'
    release = assets.lookup(tag)
    if release is None:
        try: assets.create(tag, public_head, body)
        except (RuntimeError, OSError): pass  # Confirm any lost reply by exact readback below.
        release = assets.lookup(tag)
    validate_release(release, tag, public_head, body)
    assets.check_tag(tag, public_head, allow_missing=release['draft'])
    if not release['assets']:
        require(release['draft'], 'Published release is missing its original asset')
        try: assets.upload(release['id'], ciphertext, delivery.package_size, delivery.asset_name)
        except (RuntimeError, OSError): pass
        reread = assets.lookup(tag)
        validate_release(reread, tag, public_head, body, release['id'])
        require(reread['draft'] == release['draft'], 'Release changed during upload')
        release = reread
    require(len(release['assets']) == 1, 'Upload not confirmed; preserve candidate')
    asset = release['assets'][0]
    validate_asset(asset, delivery, published=not release['draft'])

    with tempfile.TemporaryDirectory(prefix='decian-release-readback-') as temporary:
        root = pathlib.Path(temporary)
        assets.download(asset['id'], root/'before.dcu', delivery.package_size)
        verify_ciphertext(root/'before.dcu', delivery)
        if release['draft']:
            try: assets.publish(release['id'])
            except (RuntimeError, OSError): pass
        final = assets.lookup(tag)
        validate_release(final, tag, public_head, body, release['id'])
        require(final['draft'] is False and len(final['assets']) == 1, 'Publication not confirmed')
        final_asset = final['assets'][0]
        validate_asset(final_asset, delivery, published=True)
        require(final_asset['id'] == asset['id'], 'Published asset identity changed')
        assets.check_tag(tag, public_head)
        assets.download(asset['id'], root/'public.dcu', delivery.package_size, public_url=delivery.package_path)
        verify_ciphertext(root/'public.dcu', delivery)
    return {'release_id': release['id'], 'asset_id': asset['id'], 'sha256': delivery.package_sha256,
            'size': delivery.package_size, 'url': delivery.package_path}
