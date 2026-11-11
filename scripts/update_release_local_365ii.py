"""Import an approved 365II update from the private authority handoff artifact."""
import argparse
import json
import pathlib
import re
import subprocess
import sys

# The documented entry point runs with Python -I from a clean reviewed checkout.
SCRIPTS = pathlib.Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))

from update_public_import import INVESTIGATOR, REPOSITORY
from update_release_assets import GitHubAssets, regular
from update_release_import import publish
from update_release_policy import sequence_valid
from update_repository import GitHubRepository, require


def capture(args, error):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, error)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact-directory', type=pathlib.Path, required=True)
    parser.add_argument('--handle', required=True)
    parser.add_argument('--sequence', type=int, required=True)
    parser.add_argument('--confirmation', required=True)
    args = parser.parse_args()

    require(args.confirmation == 'PUBLISH REAL DEV UPDATE', 'Explicit publication confirmation required')
    require(re.fullmatch(r'[a-f0-9]{32}', args.handle) is not None and sequence_valid(INVESTIGATOR, args.sequence),
            'Exact reviewed 365II handle and sequence required')
    directory = args.artifact_directory.absolute()
    require(directory.is_dir() and {path.name for path in directory.iterdir()} == {'handoff.txt', 'package.dcu'},
            'The authority artifact must contain only handoff.txt and package.dcu')
    handoff, ciphertext = directory / 'handoff.txt', directory / 'package.dcu'
    regular(handoff)
    regular(ciphertext)
    with handoff.open('rb') as stream:
        encoded = stream.read(32769)
    require(0 < len(encoded) <= 32768, 'Signed authority handoff exceeds its size limit')

    checkout = capture(['git', 'rev-parse', 'HEAD'], 'Reviewed publisher checkout required')
    require(re.fullmatch(r'[a-f0-9]{40}', checkout) is not None and
            not capture(['git', 'status', '--porcelain', '--untracked-files=all'], 'Cannot verify publisher checkout'),
            'Use a clean checkout of reviewed distribution main')
    token = capture(['gh', 'auth', 'token', '--hostname', 'github.com'], 'Existing GitHub CLI login required')
    require(bool(token), 'Existing GitHub CLI login required')
    public = GitHubRepository(REPOSITORY, token, False)
    require(public.snapshot()['sha'] == checkout, 'Update the publisher checkout to current reviewed main')
    result = publish(public, GitHubAssets(token), encoded.decode('ascii').strip(), ROOT/'config/update-signing-public-key.pem',
                     args.handle, ciphertext, expected_sequence=args.sequence, product=INVESTIGATOR)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        # Neither subprocess output nor credential-bearing HTTP details are printed.
        # Repository adapters sanitize their own GitHub errors.
        raise SystemExit(f'365II local publication stopped ({type(error).__name__}). Preserve the exact artifact and any release asset.') from None
