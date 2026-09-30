"""Bounded GitHub Release transport. Credentials never follow asset redirects."""
import json
import pathlib
import re
import time
import stat
import urllib.error
import urllib.parse
import urllib.request
from update_public_import import REPOSITORY
from update_repository import GitHubRepository, require
def regular(path):
    path = pathlib.Path(path)
    require(path.is_file(), 'Upload path is not a file')
    for current in (path, *path.parents):
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'Upload reparse/link path refused')


def safe_redirect(url):
    require(isinstance(url, str) and len(url) <= 16384, 'Invalid asset redirect')
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname == 'release-assets.githubusercontent.com' and
            parsed.port in (None, 443) and parsed.username is None and parsed.password is None and not parsed.fragment,
            'Asset redirect origin refused')
    return url


class NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Surface 3xx as HTTPError for explicit credential-free validation.


class GitHubAssets:
    def __init__(self, token=None):
        self.repository = GitHubRepository(REPOSITORY, token, False)
        self.token = token
        self.opener = urllib.request.build_opener(NoFollow())

    def lookup(self, tag):
        require(re.fullmatch(r'secure-access-dev-[1-9][0-9]{0,18}', tag) is not None, 'Invalid release tag')
        # The tag lookup endpoint excludes drafts. Authenticated listing preserves draft retry identity.
        matches = []
        for page in range(1, 11):
            releases = self.repository.api('GET', f'/releases?per_page=100&page={page}')
            require(isinstance(releases, list) and len(releases) <= 100, 'Invalid release listing')
            matches.extend(r for r in releases if r.get('tag_name') == tag)
            if len(releases) < 100: break
        else: raise ValueError('Release listing exceeded bound')
        require(len(matches) <= 1, 'Conflicting release records')
        if not matches: return None
        result = matches[0]
        release_id = result['id']; require(type(release_id) is int and release_id > 0, 'Invalid release ID')
        result['assets'] = self.repository.api('GET', f'/releases/{release_id}/assets?per_page=100')
        require(isinstance(result['assets'], list) and len(result['assets']) < 100, 'Asset listing exceeded bound')
        return result

    def check_tag(self, tag, commit, allow_missing=False):
        try: ref = self.repository.api('GET', '/git/ref/tags/' + tag)
        except RuntimeError as error:
            if allow_missing and str(error) == 'GitHub publication request failed: HTTP 404': return
            raise
        require(ref['object']['type'] == 'commit' and ref['object']['sha'] == commit, 'Release tag target differs')

    def create(self, tag, commit, body):
        require(self.token and re.fullmatch(r'[a-f0-9]{40}', commit) is not None, 'Write token and reviewed commit required')
        self.check_tag(tag, commit, allow_missing=True)
        return self.repository.api('POST', '/releases', {'tag_name': tag, 'target_commitish': commit,
            'name': tag, 'body': body, 'draft': True, 'prerelease': True, 'make_latest': 'false'})

    def upload(self, release_id, path, size):
        require(self.token and type(release_id) is int and release_id > 0, 'Invalid upload scope')
        path = pathlib.Path(path); regular(path)
        require(path.stat().st_size == size <= 250 * 1024 * 1024 + 36, 'Invalid upload length')
        url = f'https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets?name=0.4.19.dcu'
        with path.open('rb') as stream:
            request = urllib.request.Request(url, data=stream, method='POST', headers={
                'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/octet-stream',
                'Content-Length': str(size), 'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Decian-Release-Publisher/1'})
            try:
                with self.opener.open(request, timeout=180) as response:
                    raw = response.read(65537); require(len(raw) <= 65536, 'Upload response exceeds bound')
                    return json.loads(raw)
            except (urllib.error.HTTPError, urllib.error.URLError, OSError):
                raise RuntimeError('Release asset upload not confirmed; reconcile original bytes') from None

    def publish(self, release_id):
        require(self.token and type(release_id) is int and release_id > 0, 'Invalid publish scope')
        return self.repository.api('PATCH', f'/releases/{release_id}', {'draft': False, 'prerelease': True, 'make_latest': 'false'})

    def download(self, asset_id, destination, size, public_url=None):
        require(type(asset_id) is int and asset_id > 0 and 36 <= size <= 250 * 1024 * 1024 + 36, 'Invalid download scope')
        if public_url is not None:
            require(re.fullmatch(r'https://github.com/Decian-Inc/Decian-Software-Updates/releases/download/secure-access-dev-[1-9][0-9]{0,18}/0\.4\.19\.dcu', public_url) is not None,
                    'Invalid public asset URL')
            url = public_url; headers = {}
        else:
            url = f'https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}'
            headers = {'Accept': 'application/octet-stream', **({'Authorization': 'Bearer ' + self.token} if self.token else {})}
        headers['User-Agent'] = 'Decian-Release-Publisher/1'
        destination = pathlib.Path(destination); created = False; deadline = time.monotonic() + 240
        try:
            for _ in range(4):
                try: response = self.opener.open(urllib.request.Request(url, headers=headers), timeout=30)
                except urllib.error.HTTPError as error:
                    if error.code in (301, 302, 303, 307, 308):
                        url = safe_redirect(error.headers.get('Location')); headers = {'User-Agent': 'Decian-Release-Publisher/1'}
                        error.close(); continue
                    raise RuntimeError('Asset download failed: HTTP ' + str(error.code)) from None
                with response:
                    require(response.status == 200 and response.headers.get('Content-Encoding') in (None, 'identity') and
                            response.headers.get('Content-Range') is None, 'Invalid asset response')
                    length = response.headers.get('Content-Length')
                    require(length is None or (length.isdecimal() and int(length) == size), 'Asset response length differs')
                    with destination.open('xb') as output:
                        created = True; total = 0
                        while True:
                            require(time.monotonic() <= deadline, 'Asset download deadline exceeded')
                            block = response.read(min(1024 * 1024, size - total + 1))
                            if not block: break
                            total += len(block); require(total <= size, 'Asset response exceeded expected size')
                            output.write(block)
                        require(total == size, 'Truncated asset response')
                    return destination
            raise ValueError('Asset redirect limit exceeded')
        except Exception:
            if created: destination.unlink(missing_ok=True)
            raise
