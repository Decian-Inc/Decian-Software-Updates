import io
import pathlib
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, call
import update_release_assets as transport

class Response(io.BytesIO):
    def __init__(self,data,headers=None,status=200): super().__init__(data); self.status=status; self.headers=headers or {}


class Opener:
    def __init__(self,responses): self.responses=list(responses); self.requests=[]
    def open(self,request,timeout):
        self.requests.append(request); result=self.responses.pop(0)
        if isinstance(result,Exception): raise result
        return result


class TransportTests(unittest.TestCase):
    def test_public_pipeline_has_no_authority_dependencies(self):
        import update_release_import
        self.assertTrue(callable(update_release_import.publish))
    def client(self,responses):
        client=object.__new__(transport.GitHubAssets); client.token='disposable-test-token'; client.opener=Opener(responses); return client

    def test_create_365ii_draft_checks_reviewed_commit_and_exact_release_fields(self):
        client = self.client([])
        client.repository = Mock()
        tag = 'm365-incident-investigator-dev-1'
        commit = 'a' * 40
        body = 'Fixture for encrypted 365II development update'
        release = {'id': 42}
        client.repository.api.side_effect = [RuntimeError('GitHub publication request failed: HTTP 404'), release]

        self.assertIs(client.create(tag, commit, body), release)
        self.assertEqual(client.repository.api.call_args_list, [
            call('GET', '/git/ref/tags/' + tag),
            call('POST', '/releases', {'tag_name': tag, 'target_commitish': commit, 'name': tag,
                                     'body': body, 'draft': True, 'prerelease': True, 'make_latest': 'false'}),
        ])

        client.repository.api.reset_mock()
        with self.assertRaisesRegex(ValueError, 'reviewed commit required'):
            client.create(tag, 'refs/heads/main', body)
        client.repository.api.assert_not_called()

    def test_redirect_strips_credentials_and_streams_exact_bytes(self):
        redirect=urllib.error.HTTPError('https://api.github.com/x',302,'redirect',{'Location':'https://release-assets.githubusercontent.com/path?signature=fixture'},None)
        client=self.client([redirect,Response(bytes(40),{'Content-Length':'40'})])
        with tempfile.TemporaryDirectory() as tmp:
            target=pathlib.Path(tmp)/'asset'; client.download(1,target,40); self.assertEqual(target.stat().st_size,40)
        self.assertIn('Authorization',client.opener.requests[0].headers)
        self.assertNotIn('Authorization',client.opener.requests[1].headers)
    def test_unsafe_redirects_are_rejected(self):
        for url in ['http://release-assets.githubusercontent.com/x','https://evil.invalid/x','https://u@release-assets.githubusercontent.com/x','https://release-assets.githubusercontent.com:444/x','https://release-assets.githubusercontent.com/x#fragment']:
            with self.subTest(url=url):
                with self.assertRaises(ValueError): transport.safe_redirect(url)
    def test_truncation_overflow_range_and_existing_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=pathlib.Path(tmp)/'asset'
            for response in [Response(bytes(39)),Response(bytes(41)),Response(bytes(40),{'Content-Range':'bytes 0-39/40'}),Response(bytes(40),{'Content-Encoding':'gzip'})]:
                with self.assertRaises(ValueError): self.client([response]).download(1,target,40)
                self.assertFalse(target.exists())
            target.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError): self.client([Response(bytes(40))]).download(1,target,40)
            self.assertEqual(target.read_bytes(),b'preserve')
    def test_public_download_never_attaches_token(self):
        client=self.client([Response(bytes(40))])
        with tempfile.TemporaryDirectory() as tmp:
            client.download(1,pathlib.Path(tmp)/'asset',40,public_url='https://github.com/Decian-Inc/Decian-Software-Updates/releases/download/secure-access-dev-2/0.4.19.dcu')
        self.assertNotIn('Authorization',client.opener.requests[0].headers)



# The real CLI tests use a loopback HTTP proxy and a disposable token only.
# Production still constructs an HTTPS uploads.github.com URL; the test runner
# substitutes HTTP after asserting that exact production origin and command.
import contextlib
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import threading
from unittest.mock import patch
import update_release_cli as cli


class CliUploadTests(unittest.TestCase):
    token = 'disposable-upload-transport-test-token'
    name = '0.4.26.dcu'
    data = bytes(range(256)) * 8193 + b'\x00\r\nboundary-end'
    endpoint = 'https://uploads.github.com/repos/Decian-Inc/Decian-Software-Updates/releases/42/assets?name=0.4.26.dcu'

    def response(self, size=None, **changes):
        value = {'id': 7, 'name': self.name, 'size': len(self.data) if size is None else size, 'state': 'uploaded'}
        value.update(changes)
        return json.dumps(value).encode()

    @contextlib.contextmanager
    def source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'original-candidate.dcu'
            path.write_bytes(self.data)
            yield path

    def check_command(self, command, options):
        self.assertEqual(command[-1], self.endpoint)
        self.assertEqual(command[1:6], ['api', '--hostname', 'github.com', '--method', 'POST'])
        self.assertIn('Content-Type: application/octet-stream', command)
        self.assertIn('Content-Length: ' + str(len(self.data)), command)
        self.assertEqual(command[-3:-1], ['--input', '-'])
        self.assertNotIn(self.token, repr(command))
        self.assertFalse(options['shell'])
        self.assertEqual(options['env']['GH_TOKEN'], self.token)
        self.assertEqual(options['env']['GH_HOST'], 'github.com')
        self.assertEqual(list(pathlib.Path(options['env']['GH_CONFIG_DIR']).iterdir()), [])
        self.assertEqual(os.lseek(options['stdin'].fileno(), 0, os.SEEK_CUR), 0)

    def test_qualification_rejects_changed_binary_without_running_it(self):
        import types
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / 'qualified-cli-fixture'
            path.write_bytes(b'disposable binary fixture')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch.object(cli, 'CLI_PATH', path), patch.object(cli, 'CLI_SHA256', digest), patch.object(cli, 'os', types.SimpleNamespace(name='nt')):
                self.assertEqual(cli.qualified_cli(), path)
                path.write_bytes(b'changed binary fixture')
                with self.assertRaises(cli.UploadFailure) as found:
                    cli.qualified_cli()
                self.assertEqual(found.exception.code, 'cli-unqualified')

    def test_child_scope_and_binary_input_without_secret_arguments_or_user_config(self):
        inherited = {'GH_TOKEN': 'wrong', 'GITHUB_TOKEN': 'wrong2', 'GH_ENTERPRISE_TOKEN': 'wrong3',
                     'GH_DEBUG': 'api', 'GH_HOST': 'evil.invalid', 'GH_CONFIG_DIR': 'user-login',
                     'GH_HTTP_UNIX_SOCKET': 'socket', 'GH_PAGER': 'untrusted-command', 'GH_API_HOST': 'evil.invalid',
                     'HTTPS_PROXY': 'http://proxy.invalid:42', 'NO_PROXY': 'localhost'}
        def run(command, **options):
            self.check_command(command, options)
            self.assertNotIn('GITHUB_TOKEN', options['env'])
            self.assertNotIn('GH_ENTERPRISE_TOKEN', options['env'])
            self.assertNotIn('GH_HTTP_UNIX_SOCKET', options['env'])
            self.assertNotIn('GH_API_HOST', options['env'])
            self.assertNotIn('GH_PAGER', options['env'])
            self.assertEqual(options['env']['GH_DEBUG'], '0')
            self.assertEqual(options['env']['HTTPS_PROXY'], inherited['HTTPS_PROXY'])
            self.assertEqual(options['stdin'].read(), self.data)
            options['stdout'].write(self.response())
            return subprocess.CompletedProcess(command, 0)
        with self.source() as path, patch.dict(os.environ, inherited), patch.object(cli, 'qualified_cli', return_value=pathlib.Path('/qualified/gh')), patch.object(cli.subprocess, 'run', side_effect=run) as invoked:
            self.assertEqual(cli.upload(self.token, 42, path, len(self.data), self.name)['id'], 7)
            self.assertEqual(invoked.call_count, 1)

    def test_limits_scope_and_source_length_fail_before_process(self):
        with self.source() as path, patch.object(cli, 'qualified_cli') as qualified, patch.object(cli.subprocess, 'run') as invoked:
            for size in (True, 0, 35, 256*1024*1024+1):
                with self.subTest(size=size), self.assertRaises(ValueError):
                    cli.upload(self.token, 42, path, size, self.name)
            for name in ('../0.4.26.dcu', '0.4.26.dcu?other=1', 'a.dcu'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    cli.upload(self.token, 42, path, len(self.data), name)
            for release_id in (True, 0, -1, '42'):
                with self.subTest(release_id=release_id), self.assertRaises(ValueError):
                    cli.upload(self.token, release_id, path, len(self.data), self.name)
            qualified.assert_not_called()
            with self.assertRaises(ValueError):
                cli.upload(self.token, 42, path, len(self.data)-1, self.name)
            invoked.assert_not_called()

    def test_safe_codes_for_timeout_http_response_and_missing_cli(self):
        with self.source() as path, patch.object(cli, 'qualified_cli', return_value=pathlib.Path('/qualified/gh')):
            for failure, code in ((subprocess.TimeoutExpired(['secret-in-error'], 1), 'timeout'), (OSError(self.token), 'cli-unavailable')):
                with self.subTest(code=code), patch.object(cli.subprocess, 'run', side_effect=failure) as invoked:
                    with self.assertRaises(cli.UploadFailure) as found:
                        cli.upload(self.token, 42, path, len(self.data), self.name)
                    self.assertEqual(found.exception.code, code)
                    self.assertNotIn(self.token, str(found.exception))
                    self.assertEqual(invoked.call_count, 1)
            def run(command, **options):
                options['stderr'].write(('server echoed ' + self.token + ' HTTP 422 https://evil.invalid/private').encode())
                return subprocess.CompletedProcess(command, 1)
            with patch.object(cli.subprocess, 'run', side_effect=run):
                with self.assertRaises(cli.UploadFailure) as found:
                    cli.upload(self.token, 42, path, len(self.data), self.name)
                self.assertEqual(found.exception.code, 'http-422')
                self.assertNotIn(self.token, str(found.exception))
                self.assertNotIn('evil.invalid', str(found.exception))

    def test_response_bound_identity_and_file_drift(self):
        with self.source() as path, patch.object(cli, 'qualified_cli', return_value=pathlib.Path('/qualified/gh')):
            for raw in (b'x'*(cli.MAX_RESPONSE+1), self.response(name='different.dcu'), self.response(size=True), b'{invalid'):
                def run(command, **options):
                    options['stdout'].write(raw)
                    return subprocess.CompletedProcess(command, 0)
                with self.subTest(length=len(raw)), patch.object(cli.subprocess, 'run', side_effect=run):
                    with self.assertRaises(cli.UploadFailure) as found:
                        cli.upload(self.token, 42, path, len(self.data), self.name)
                    self.assertEqual(found.exception.code, 'response')
            def mutate(command, **options):
                with path.open('ab') as changed: changed.write(b'changed')
                options['stdout'].write(self.response())
                return subprocess.CompletedProcess(command, 0)
            with patch.object(cli.subprocess, 'run', side_effect=mutate):
                with self.assertRaises(cli.UploadFailure) as found:
                    cli.upload(self.token, 42, path, len(self.data), self.name)
                self.assertEqual(found.exception.code, 'source-changed')

    @contextlib.contextmanager
    def wire(self, mode='success'):
        records = []
        owner = self
        class Proxy(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_): pass
            def do_CONNECT(self):
                records.append({'method': 'CONNECT', 'target': self.path, 'headers': dict(self.headers)})
                self.send_error(502, 'disposable probe stops before TLS')
            def do_POST(self):
                self.connection.settimeout(10)
                size = int(self.headers.get('Content-Length', '-1'))
                data = self.rfile.read(max(0, size))
                records.append({'method': 'POST', 'target': self.path, 'headers': dict(self.headers), 'data': data})
                if mode == 'reset':
                    self.close_connection = True
                    self.connection.close()
                    return
                if mode == 'timeout':
                    threading.Event().wait(1)
                    self.close_connection = True
                    return
                if mode.startswith('redirect'):
                    self.send_response(int(mode.split('-')[1]) if '-' in mode else 302)
                    self.send_header('Location', 'http://untrusted.invalid/credential-probe')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                raw = owner.response()
                self.send_response(201)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            def do_GET(self):
                records.append({'method': 'GET', 'target': self.path, 'headers': dict(self.headers)})
                raw = owner.response()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        server.handle_error = lambda *_: None
        server.daemon_threads = True
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try: yield records, f'http://127.0.0.1:{server.server_port}'
        finally:
            server.shutdown()
            server.server_close()
            worker.join(3)

    def actual_cli(self):
        # The production uploader deliberately supports only the pinned Windows
        # binary. A different PATH gh can have different redirect/stdin behavior.
        try:
            return cli.qualified_cli()
        except cli.UploadFailure as error:
            if error.code != 'cli-unqualified':
                raise
            self.skipTest('Real wire fixture requires the exact production-qualified Windows GitHub CLI')

    def test_unsupported_platform_cannot_start_any_upload_process(self):
        import types
        with self.source() as path, patch.object(cli, 'os', types.SimpleNamespace(name='posix')), patch.object(cli.subprocess, 'run') as invoked:
            with self.assertRaises(cli.UploadFailure) as found:
                cli.upload(self.token, 42, path, len(self.data), self.name)
            self.assertEqual(found.exception.code, 'cli-unqualified')
            invoked.assert_not_called()

    def run_wire(self, path, proxy, keep_https=False):
        executable = self.actual_cli()
        actual_run = subprocess.run
        def run(command, **options):
            self.check_command(command, options)
            rewritten = list(command)
            if not keep_https:
                rewritten[-1] = rewritten[-1].replace('https://', 'http://', 1)
            environment = options['env']
            for key in list(environment):
                if key.upper().endswith('_PROXY'): del environment[key]
            environment.update({'HTTP_PROXY': proxy, 'HTTPS_PROXY': proxy, 'NO_PROXY': ''})
            options['env'] = environment
            return actual_run(rewritten, **options)
        with patch.object(cli, 'qualified_cli', return_value=executable), patch.object(cli.subprocess, 'run', side_effect=run):
            return cli.upload(self.token, 42, path, len(self.data), self.name)

    def test_actual_cli_proxy_wire_has_exact_binary_length_body_and_scoped_auth(self):
        with self.source() as path, self.wire() as (records, proxy):
            self.assertEqual(self.run_wire(path, proxy)['id'], 7)
        self.assertEqual(len(records), 1)
        request = records[0]
        self.assertEqual(request['method'], 'POST')
        self.assertEqual(request['target'], self.endpoint.replace('https://', 'http://'))
        self.assertEqual(request['headers'].get('Authorization'), 'token ' + self.token)
        self.assertEqual(request['headers'].get('Content-Length'), str(len(self.data)))
        self.assertIsNone(request['headers'].get('Transfer-Encoding'))
        self.assertEqual(request['headers'].get('Content-Type'), 'application/octet-stream')
        self.assertEqual(request['data'], self.data)

    def test_actual_cli_redirect_does_not_forward_credentials_or_ciphertext(self):
        with self.source() as path, self.wire('redirect') as (records, proxy):
            self.run_wire(path, proxy)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]['headers'].get('Authorization'), 'token ' + self.token)
        self.assertEqual(records[1]['method'], 'GET')
        self.assertIsNone(records[1]['headers'].get('Authorization'))
        self.assertNotIn('data', records[1])

    def test_actual_cli_307_308_never_replays_file_to_another_origin(self):
        self.actual_cli()  # Skip the whole test before subTest can consume SkipTest.
        for code in (307, 308):
            with self.subTest(code=code), self.source() as path, self.wire(f'redirect-{code}') as (records, proxy):
                try: self.run_wire(path, proxy)
                except cli.UploadFailure: pass
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]['target'], self.endpoint.replace('https://', 'http://'))

    def test_unqualified_client_skips_loop_tests_before_subtests(self):
        for name in ('test_actual_cli_307_308_never_replays_file_to_another_origin',
                     'test_actual_cli_reset_and_process_deadline_are_bounded_without_second_post'):
            case = type(self)(name)
            result = unittest.TestResult()
            with patch.object(case, 'actual_cli', side_effect=unittest.SkipTest('unqualified fixture client')):
                case.run(result)
            self.assertEqual(len(result.skipped), 1)
            self.assertEqual(result.failures, [])
            self.assertEqual(result.errors, [])

    def test_actual_cli_https_proxy_connect_never_contains_release_token(self):
        with self.source() as path, self.wire() as (records, proxy):
            with self.assertRaises(cli.UploadFailure):
                self.run_wire(path, proxy, keep_https=True)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['method'], 'CONNECT')
        self.assertEqual(records[0]['target'], 'uploads.github.com:443')
        self.assertNotIn(self.token, repr(records[0]['headers']))

    def test_actual_cli_reset_and_process_deadline_are_bounded_without_second_post(self):
        self.actual_cli()  # Skip the whole test before subTest can consume SkipTest.
        for mode in ('reset', 'timeout'):
            with self.subTest(mode=mode), self.source() as path, self.wire(mode) as (records, proxy):
                with patch.object(cli, 'UPLOAD_TIMEOUT', .25 if mode == 'timeout' else 5):
                    with self.assertRaises(cli.UploadFailure) as found:
                        self.run_wire(path, proxy)
                self.assertEqual(found.exception.code, 'timeout' if mode == 'timeout' else 'transport')
            self.assertEqual(len(records), 1)
