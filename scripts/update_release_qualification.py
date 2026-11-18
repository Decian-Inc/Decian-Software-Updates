"""Qualify only disposable public draft uploads with the repository workflow token."""
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile

# The Windows embedded Python package omits the script directory from sys.path.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from update_repository import GitHubRepository, require
from update_release_assets import GitHubAssets
from update_release_cli import qualified_cli, upload

PUBLICATION = 'Decian-Inc/Decian-Software-Updates'
QUALIFICATION_ASSETS = (('0.0.1.dcu', 1048576), ('0.0.2.dcu', 148250440))

PHASES = frozenset({'public-main-read', 'qa-draft-discovery', 'qa-draft-read',
                    'qa-assets-read', 'qa-draft-create', 'qa-asset-upload', 'qa-authenticated-readback'})


def in_phase(phase, operation, *args, **kwargs):
    require(phase in PHASES, 'Invalid qualification diagnostic phase')
    try:
        return operation(*args, **kwargs)
    except Exception as error:
        if getattr(error, 'publication_phase', None) not in PHASES:
            error.publication_phase = phase
        raise


def write_qualification_file(path, size):
    marker = b'DECIAN|PUBLICATION|QUALIFICATION|1\n'
    pattern = hashlib.sha256(marker).digest() * 32768
    digest = hashlib.sha256()
    with path.open('xb') as stream:
        remaining = size
        while remaining:
            block = pattern[:min(len(pattern), remaining)]
            stream.write(block)
            digest.update(block)
            remaining -= len(block)
    return digest.hexdigest()

def qualification_release(repo, tag, source_commit, body, release_id=None):
    if release_id is None:
        values = in_phase('qa-draft-discovery', repo.api, 'GET', '/releases?per_page=100')
        require(isinstance(values, list) and len(values) < 100, 'Qualification release listing exceeds its bound')
        matches = [value for value in values if value.get('tag_name') == tag]
        require(len(matches) <= 1, 'Conflicting qualification releases')
        if not matches:
            return None
        release_id = matches[0]['id']
    require(type(release_id) is int and release_id > 0, 'Invalid qualification release ID')
    release = in_phase('qa-draft-read', repo.api, 'GET', f'/releases/{release_id}')
    require(release.get('id') == release_id and release.get('tag_name') == tag and
            release.get('target_commitish') == source_commit and release.get('name') == tag and
            release.get('body') == body and release.get('draft') is True and release.get('prerelease') is True,
            'Qualification draft identity differs')
    return release

def qualification_assets(repo, release_id, expected):
    values = in_phase('qa-assets-read', repo.api, 'GET', f'/releases/{release_id}/assets?per_page=100')
    require(isinstance(values, list) and len(values) <= len(expected), 'Qualification asset list differs')
    seen = {}
    for value in values:
        name = value.get('name')
        require(name in expected and name not in seen and type(value.get('id')) is int and value['id'] > 0 and
                value.get('state') == 'uploaded' and value.get('size') == expected[name]['size'] and
                value.get('digest') == 'sha256:' + expected[name]['sha256'], 'Qualification asset identity differs')
        seen[name] = value
    return seen

def qualify_upload(repo, assets, upload, source_commit, run_id, attempt, token):
    require(repo.name == PUBLICATION and re.fullmatch(r'[a-f0-9]{40}', source_commit) is not None and
            all(re.fullmatch(r'[1-9][0-9]{0,18}', value) is not None for value in (run_id, attempt)),
            'Invalid qualification scope')
    head = in_phase('public-main-read', repo.api, 'GET', '/git/ref/heads/main')['object']
    require(head.get('type') == 'commit' and re.fullmatch(r'[a-f0-9]{40}', head.get('sha', '')) is not None,
            'Invalid qualification target commit')
    require(head['sha'] == source_commit, 'Public main changed before qualification')
    target_commit = source_commit
    tag = f'decian-public-upload-qualification-{run_id}-{attempt}'
    body = ('Decian publication transport qualification v1\nPublisher commit: ' + source_commit +
            '\nTarget commit: ' + target_commit)
    with tempfile.TemporaryDirectory(prefix='decian-publication-qualification-') as temporary:
        root = pathlib.Path(temporary)
        expected = {}
        for name, size in QUALIFICATION_ASSETS:
            expected[name] = {'size': size, 'sha256': write_qualification_file(root / name, size)}
        require(in_phase('public-main-read', repo.api, 'GET', '/git/ref/heads/main')['object']['sha'] == source_commit,
                'Public main changed during fixture preparation')
        release = qualification_release(repo, tag, target_commit, body)
        if release is None:
            created = in_phase('qa-draft-create', repo.api, 'POST', '/releases', {'tag_name': tag, 'target_commitish': target_commit,
                'name': tag, 'body': body, 'draft': True, 'prerelease': True, 'make_latest': 'false'})
            release = qualification_release(repo, tag, target_commit, body, created['id'])
        release_id = release['id']
        seen = qualification_assets(repo, release_id, expected)
        for name, _ in QUALIFICATION_ASSETS:
            if name not in seen:
                try:
                    in_phase('qa-asset-upload', upload, token, release_id, root / name, expected[name]['size'], name)
                except (RuntimeError, OSError):
                    # Reconcile the original draft after an ambiguous reply, without another POST.
                    seen = qualification_assets(repo, release_id, expected)
                    if name not in seen:
                        raise
                seen = qualification_assets(repo, release_id, expected)
            require(name in seen, 'Qualification upload was not confirmed')
            target = root / (name + '.readback')
            in_phase('qa-authenticated-readback', assets.download, seen[name]['id'], target, expected[name]['size'])
            with target.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            require(digest == expected[name]['sha256'] and target.stat().st_size == expected[name]['size'],
                    'Qualification authenticated readback differs')
        qualification_release(repo, tag, target_commit, body, release_id)
        require(set(seen) == set(expected), 'Qualification evidence is incomplete')
        require(in_phase('public-main-read', repo.api, 'GET', '/git/ref/heads/main')['object']['sha'] == source_commit,
                'Public main changed during qualification')
        return {'status': 'publication-upload-qualification-pass', 'release_id': release_id, 'tag': tag,
                'draft': True, 'publisher_commit': source_commit, 'target_commit': target_commit,
                'assets': [{**expected[name], 'name': name, 'id': seen[name]['id']} for name, _ in QUALIFICATION_ASSETS],
                'anonymous_readback_tested': False}

def validate_context(env, platform=None):
    require((os.name if platform is None else platform) == 'nt' and
            env.get('GITHUB_REPOSITORY') == PUBLICATION and env.get('GITHUB_REF') == 'refs/heads/main' and
            env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
            env.get('GITHUB_ACTOR') == 'amdecian' and env.get('GITHUB_TRIGGERING_ACTOR') == 'amdecian' and
            env.get('INPUT_OPERATION') == 'qualification' and
            env.get('INPUT_CONFIRMATION') == 'QUALIFY PUBLICATION UPLOAD' and
            re.fullmatch(r'[a-f0-9]{40}', env.get('GITHUB_SHA', '')) is not None,
            'Owner-confirmed public main qualification is required')
    require(all(re.fullmatch(r'[1-9][0-9]{0,18}', env.get(name, '')) is not None
                for name in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')), 'Invalid qualification run identity')


def main():
    env = os.environ
    validate_context(env)
    token = env.get('GITHUB_TOKEN', '')
    require(isinstance(token, str) and bool(token.strip()), 'Repository workflow token is required')
    qualified_cli()
    public = GitHubRepository(PUBLICATION, token, False)
    result = qualify_upload(public, GitHubAssets(token), upload, env['GITHUB_SHA'],
                            env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT'], token)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        code = getattr(error, 'code', None)
        if code not in {'cli-unqualified', 'cli-unavailable', 'timeout', 'transport', 'response', 'source-changed'} and not (
                isinstance(code, str) and re.fullmatch(r'http-[1-5][0-9]{2}', code)):
            code = None
        match = re.fullmatch(r'GitHub publication request failed: HTTP ([1-5][0-9]{2})', str(error))
        print(json.dumps({'status': 'publication-upload-qualification-stopped',
                          'exception_type': type(error).__name__, 'transport_code': code,
                          'phase': getattr(error, 'publication_phase', None) if getattr(error, 'publication_phase', None) in PHASES else None,
                          'http_status': int(match[1]) if match else None}, sort_keys=True))
        raise SystemExit(1) from None
