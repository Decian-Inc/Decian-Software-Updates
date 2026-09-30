import io
import pathlib
import tempfile
import unittest
import urllib.error
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


