"""One bounded upload through the qualified GitHub CLI; never uses a user login."""
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile

from update_repository import require

CLI_PATH = pathlib.Path(r'C:\Program Files\GitHub CLI\gh.exe')
CLI_SHA256 = '2ae2b350c227a618f2d8965b1900aeee13446ff42e17ef0bd5a0b6405c593cfb'
UPLOAD_TIMEOUT = 240
MAX_RESPONSE = 65536


class UploadFailure(RuntimeError):
    """Only fixed codes or a numeric HTTP status may cross into workflow logs."""
    def __init__(self, code):
        require(code in {'cli-unqualified', 'cli-unavailable', 'timeout', 'transport', 'response', 'source-changed'} or
                re.fullmatch(r'http-[1-5][0-9]{2}', code) is not None, 'Invalid upload failure code')
        self.code = code
        super().__init__('Release asset upload not confirmed: ' + code + '; preserve the original candidate and draft')


def qualified_cli():
    # Hash pins the existing signed GitHub CLI 2.100.0. Upgrades require review.
    from update_release_assets import regular
    try:
        require(os.name == 'nt', 'Qualified Windows CLI required')
        regular(CLI_PATH)
        with CLI_PATH.open('rb') as binary:
            digest = hashlib.file_digest(binary, 'sha256').hexdigest()
        require(digest == CLI_SHA256, 'Qualified CLI digest differs')
    except (ValueError, OSError):
        raise UploadFailure('cli-unqualified') from None
    return CLI_PATH


def child_environment(token, config_directory):
    # Do not inherit debug, alternative hosts/tokens, config, extension hooks,
    # API-host overrides, pager or browser commands.
    allowed = {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA',
               'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'SSL_CERT_DIR'}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.update({'GH_TOKEN': token, 'GH_HOST': 'github.com', 'GH_CONFIG_DIR': str(config_directory),
                        'GH_PROMPT_DISABLED': '1', 'GH_NO_UPDATE_NOTIFIER': '1', 'GH_DEBUG': '0',
                        'GH_ACCESSIBLE_PROMPTER': 'disabled', 'NO_COLOR': '1'})
    return environment


def upload(token, release_id, path, size, asset_name):
    from update_public_import import REPOSITORY
    import update_release_policy as policy
    from update_release_assets import regular
    policy.validate_asset_name(asset_name)
    require(isinstance(token, str) and bool(token) and type(release_id) is int and release_id > 0, 'Invalid upload scope')
    require(type(size) is int and policy.PACKAGE_HEADER_SIZE <= size <= policy.INVESTIGATOR_MAX_PACKAGE_SIZE,
            'Invalid upload length')
    path = pathlib.Path(path)
    regular(path)
    cli = qualified_cli()
    url = f'https://uploads.github.com/repos/{REPOSITORY}/releases/{release_id}/assets?name={asset_name}'
    command = [str(cli), 'api', '--hostname', 'github.com', '--method', 'POST',
               '--header', 'Content-Type: application/octet-stream', '--header', f'Content-Length: {size}',
               '--header', 'Accept: application/vnd.github+json',
               '--header', 'X-GitHub-Api-Version: 2022-11-28', '--input', '-', url]
    # The already-open file is stdin. The token is child-environment only, never
    # an argument, shell expansion, config file, stdout or stderr.
    with path.open('rb') as stream, tempfile.TemporaryDirectory(prefix='decian-upload-cli-') as config:
        before = os.fstat(stream.fileno())
        require(before.st_size == size, 'Invalid upload length')
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            try:
                result = subprocess.run(command, stdin=stream, stdout=output, stderr=errors, shell=False,
                                        timeout=UPLOAD_TIMEOUT, check=False, env=child_environment(token, config))
            except subprocess.TimeoutExpired:
                raise UploadFailure('timeout') from None
            except OSError:
                raise UploadFailure('cli-unavailable') from None
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise UploadFailure('source-changed')
            if result.returncode:
                errors.seek(0)
                # Never emit CLI output: even errors can contain URLs or credentials.
                match = re.search(rb'\bHTTP ([1-5][0-9]{2})\b', errors.read(MAX_RESPONSE))
                raise UploadFailure('http-' + match[1].decode('ascii') if match else 'transport')
            output.seek(0)
            raw = output.read(MAX_RESPONSE + 1)
    try:
        require(len(raw) <= MAX_RESPONSE, 'Upload response exceeds bound')
        value = json.loads(raw)
        require(isinstance(value, dict) and type(value.get('id')) is int and value['id'] > 0 and
                value.get('name') == asset_name and type(value.get('size')) is int and value['size'] == size and
                value.get('state') == 'uploaded', 'Upload response identity differs')
        return value
    except (ValueError, UnicodeError, TypeError):
        raise UploadFailure('response') from None


if __name__ == '__main__':
    # Fail-fast runner qualification before a release draft can be created.
    qualified_cli()
    print('Qualified GitHub CLI upload transport: 2.100.0 / sha256:' + CLI_SHA256)
