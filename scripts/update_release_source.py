"""Fixed reviewed Secure Access package source. No network, signing or execution."""
from dataclasses import dataclass, asdict
import hashlib
import pathlib
import stat
import struct
import os
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from update_repository import require


@dataclass(frozen=True)
class ReviewedSource:
    repository: str
    commit: str
    tag: str
    version: str
    bundle_sha256: str
    bundle_size: int
    installer_sha256: str
    installer_size: int
    net8_sha256: str
    net8_size: int
    net10_sha256: str
    net10_size: int


REVIEWED = ReviewedSource(
    'Decian-Inc/Decian-Secure-Access', '11751c59574b8df6acb4763c5acd828cc1d03e5e',
    'test-update-patch-11751c59', '0.4.19',
    '984ad68b2581f6e3e9277302856d296f538780c04afb5e2c227f2b57dfae0575', 99587049,
    '595684aa8b9178d44a849651e399b688d2e99a92f614917b104adc02321bda98', 99334656,
    'ad9d55de6248d0b258a97a5042d70e865c4724a26ba5aff0a2251dd4ff0b7ce5', 125072,
    'ad4597d36cf15f7ccd975e6fbe0df9bd7b470a2a9fa5af8ced30f19556b4fb58', 127301)


def _inspect(stream, expected):
    """Stream bounded segments; trusted expected is compiled review evidence."""
    header = stream.read(20)
    require(len(header) == 20 and header[:8] == b'DCNUPD01', 'Invalid bundle header')
    lengths = struct.unpack('<III', header[8:])
    require(lengths == (expected.installer_size, expected.net8_size, expected.net10_size)
            and 20 + sum(lengths) == expected.bundle_size <= 250 * 1024 * 1024,
            'Bundle lengths differ from reviewed source')
    full = hashlib.sha256(header)
    for length, digest in zip(lengths, (expected.installer_sha256, expected.net8_sha256, expected.net10_sha256)):
        segment = hashlib.sha256()
        while length:
            block = stream.read(min(length, 1024 * 1024))
            require(block, 'Truncated bundle')
            full.update(block); segment.update(block); length -= len(block)
        require(segment.hexdigest() == digest, 'Reviewed bundle segment changed')
    require(stream.read(1) == b'' and full.hexdigest() == expected.bundle_sha256, 'Bundle digest or end differs')
    return asdict(expected)


def verify_bundle(path):
    path = pathlib.Path(path)
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), 'Bundle must be a regular file')
    with path.open('rb') as stream:
        return _inspect(stream, REVIEWED)


def _assemble(directory, output, expected):
    directory, output = pathlib.Path(directory), pathlib.Path(output)
    names = ('Ironclad-Update-Patch-11751c59-Payload.exe', 'net8.0-windows.json', 'net10.0-windows.json')
    lengths = (expected.installer_size, expected.net8_size, expected.net10_size)
    hashes = (expected.installer_sha256, expected.net8_sha256, expected.net10_sha256)
    created = False
    try:
        with output.open('x+b') as target:
            created = True
            target.write(b'DCNUPD01' + struct.pack('<III', *lengths))
            for name, size, digest in zip(names, lengths, hashes):
                source = directory / name
                require(source.is_file() and not source.is_symlink() and source.stat().st_size == size, 'Source asset type/size differs')
                actual = hashlib.sha256(); remaining = size
                with source.open('rb') as stream:
                    while remaining:
                        block = stream.read(min(remaining, 1024 * 1024)); require(block, 'Truncated source asset')
                        target.write(block); actual.update(block); remaining -= len(block)
                    require(stream.read(1) == b'' and actual.hexdigest() == digest, 'Source asset changed')
            target.flush(); os.fsync(target.fileno()); target.seek(0)
            _inspect(target, expected)
        return asdict(expected)
    except Exception:
        if created: output.unlink(missing_ok=True)
        raise


def assemble(directory, output): return _assemble(directory, output, REVIEWED)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Assemble the exact reviewed bundle; never runs the installer.')
    parser.add_argument('--input-directory', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    assemble(args.input_directory, args.output)
    print('REVIEWED_SOURCE_BUNDLE_READY sha256=' + REVIEWED.bundle_sha256)
