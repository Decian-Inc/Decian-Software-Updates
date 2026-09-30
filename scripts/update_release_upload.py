"""Idempotent draft/upload/readback/publish state machine; never replaces an asset."""
import tempfile
import pathlib
from update_release_metadata import verify_ciphertext
from update_repository import require


def ensure_asset(assets, delivery, ciphertext, public_head):
    verify_ciphertext(ciphertext, delivery)
    tag = f'secure-access-dev-{delivery.sequence}'
    body = 'Decian encrypted Secure Access dev package\nSHA256: ' + delivery.package_sha256
    release = assets.lookup(tag)
    if release is None:
        try: assets.create(tag, public_head, body)
        except (RuntimeError, OSError): pass  # A lost reply is accepted only after exact readback below.
        release = assets.lookup(tag)
    require(release is not None and type(release.get('id')) is int and release['id'] > 0 and
            release.get('tag_name') == tag and release.get('target_commitish') == public_head and
            release.get('name') == tag and release.get('body') == body and release.get('prerelease') is True and
            type(release.get('draft')) is bool, 'Release identity conflicts; do not modify')
    require(isinstance(release.get('assets'), list) and len(release['assets']) <= 1, 'Unexpected release assets')
    if not release['assets']:
        require(release['draft'], 'Published release is missing its original asset')
        try: assets.upload(release['id'], ciphertext, delivery.package_size)
        except (RuntimeError, OSError): pass
        reread = assets.lookup(tag)
        require(reread is not None and reread['id'] == release['id'] and reread['draft'] == release['draft'], 'Release changed during upload')
        release = reread
    require(len(release['assets']) == 1, 'Upload not confirmed; preserve candidate')
    asset = release['assets'][0]
    require(type(asset.get('id')) is int and asset['id'] > 0 and asset.get('name') == '0.4.19.dcu' and
            asset.get('size') == delivery.package_size and asset.get('state') == 'uploaded' and
            asset.get('browser_download_url') == delivery.package_path and
            asset.get('digest') in (None, 'sha256:' + delivery.package_sha256), 'Asset identity conflicts; never overwrite')
    with tempfile.TemporaryDirectory(prefix='decian-release-readback-') as temporary:
        root = pathlib.Path(temporary)
        assets.download(asset['id'], root/'before.dcu', delivery.package_size)
        verify_ciphertext(root/'before.dcu', delivery)
        if release['draft']:
            try: assets.publish(release['id'])
            except (RuntimeError, OSError): pass
        final = assets.lookup(tag)
        require(final is not None and final['id'] == release['id'] and final.get('draft') is False and
                final.get('prerelease') is True and final.get('tag_name') == tag and
                final.get('target_commitish') == public_head and final.get('body') == body and
                len(final.get('assets', [])) == 1 and final['assets'][0]['id'] == asset['id'], 'Publication not confirmed')
        assets.check_tag(tag, public_head)
        # Anonymous download of the exact client URL proves public availability before offer publication.
        assets.download(asset['id'], root/'public.dcu', delivery.package_size, public_url=delivery.package_path)
        verify_ciphertext(root/'public.dcu', delivery)
    return {'release_id': release['id'], 'asset_id': asset['id'], 'sha256': delivery.package_sha256,
            'size': delivery.package_size, 'url': delivery.package_path}
