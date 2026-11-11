"""Exercise the local CLI handoff without real credentials or repository writes."""
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

import update_release_local_365ii as local


class LocalPublicationTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.artifact = pathlib.Path(self.scratch.name)
        (self.artifact / 'handoff.txt').write_bytes(b'dGludGVk')
        (self.artifact / 'package.dcu').write_bytes(b'test fixture')
        self.argv = ['publish', '--artifact-directory', str(self.artifact), '--handle', 'a' * 32,
                     '--sequence', '1', '--confirmation', 'PUBLISH REAL DEV UPDATE']

    def test_local_cli_uses_pinned_publisher_and_scope(self):
        with patch.object(sys, 'argv', self.argv), patch.object(local, 'capture', side_effect=['b'*40, '', 'fixture-token']), \
             patch.object(local, 'GitHubRepository') as public, patch.object(local, 'GitHubAssets') as assets, \
             patch.object(local, 'publish', return_value={'status': 'fixture'}) as publish, patch('builtins.print') as output:
            public.return_value.snapshot.return_value = {'sha': 'b' * 40}
            local.main()
        args, options = publish.call_args
        self.assertEqual(args[0:3], (public.return_value, assets.return_value, 'dGludGVk'))
        self.assertEqual(args[4:6], ('a' * 32, self.artifact / 'package.dcu'))
        self.assertEqual(options, {'expected_sequence': 1, 'product': 'm365-incident-investigator'})
        self.assertNotIn('fixture-token', str(output.call_args))

    def test_rejects_extra_private_files_before_reading_credentials(self):
        (self.artifact / 'receipt.json').write_bytes(b'fixture')
        with patch.object(sys, 'argv', self.argv), patch.object(local, 'capture') as capture, self.assertRaises(ValueError):
            local.main()
        capture.assert_not_called()

    def test_stale_checkout_does_not_publish(self):
        with patch.object(sys, 'argv', self.argv), patch.object(local, 'capture', side_effect=['b'*40, '', 'fixture-token']), \
             patch.object(local, 'GitHubRepository') as public, patch.object(local, 'publish') as publish, \
             self.assertRaises(ValueError):
            public.return_value.snapshot.return_value = {'sha': 'c' * 40}
            local.main()
        publish.assert_not_called()
