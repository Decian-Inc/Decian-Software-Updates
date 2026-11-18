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


# Sequence 2 remains immutable. New sources require explicit reviewed entries.
REVIEWED_PRODUCT_0420 = ReviewedSource(
    'Decian-Inc/Decian-Secure-Access', '64671952e0a219a51c22b5de771b315f8c06e859',
    'test-product-updater-64671952', '0.4.20',
    '2ef7858effb1da74cfdd673556aaaac5ab29cc4548f3f3feabf84faeb3025d28', 147295915,
    'c50d2cab2e9dbf414b3d17b4fadf487623fec499a976e63d5eb16dc44d722cc3', 147043016,
    'a3fd5cb1e2d0928ab2946af5696ea4ceeab2831b048cb38bd2406c940e8ef6f0', 125325,
    'abc677cd082da2773773b784304ac8842dabad78614539707938ed9a5aaf28eb', 127554)
# The unissued 0.4.21 source was superseded by the owner-approved protected pilot.
# The authority retains the original request and authorization in its release history.
REVIEWED_PRODUCT_0426 = ReviewedSource(
    'Decian-Inc/Decian-Secure-Access', '4023bbb77e2f83e2308796dcf9718eb48816f14d',
    'test-product-updater-4023bbb7', '0.4.26',
    '39c5369c607e6fbd0503e011a2889620e99ba9e77e7905970d8bd14e37a5d9b4', 148250404,
    '5f7f93232478fd013f81b5574d5a84640395b02a82206403118b75d14da7aa1f', 148074256,
    'fc4c054d3772ee0e82a8d9119a3bf10e26c8496ec831510571feec46ba1b4b1e', 87305,
    '9a42f594051d1fc64f53a4575f77b3c64fd9c951f0ccbaea8ae76d4f015e8bef', 88823)
# Owner-approved .27 source; publication remains a separately reviewed operation.
REVIEWED_PRODUCT_0427 = ReviewedSource(
    'Decian-Inc/Decian-Secure-Access', 'e730f30619767a093006a61c1973212d23dc8c39',
    'test-product-updater-e730f306', '0.4.27',
    '65abae4e8f31ca604fef1414c6e58e9955d9f4400bd5f90acd25aaf5e3d2253a', 148251020,
    '42466fe529ddd527f1eaed929403475b5b5fa642ccfc2f4155e08c2cf86bcabc', 148074872,
    '37939990f82ea53fe52ad225a1ea0b8c93d3f1f2782f0c9ce82d234c294b32e5', 87305,
    '3cbcfcedf15c84a823416bb13c94b00ebfe72eddd9dc2580b6d24198f6e93424', 88823)
# Owner-approved .29 source includes the matching self-contained updater variants.
REVIEWED_PRODUCT_0429 = ReviewedSource(
    'Decian-Inc/Decian-Secure-Access', '30d397d620f8d679a3faae1ddc08ec536980bd65',
    'test-product-updater-30d397d6', '0.4.29',
    '43dd1f41d2c1f369111d724f75b6cb8a82675c63c0fdceb9aef7965dffd82555', 182078620,
    '79bf356e551587c28bb9da3370dbbfeef26928f135a0f87f34d1c1d005f11962', 181902472,
    'ccd829ff86b36429245e12109b66d44d28bf2b2175aba3ab1f7def730b7b5bea', 87305,
    '5725cf0c76b1cc379f1f98638b473df707d3358b2a35749017e8b5691c6c9909', 88823)
REVIEWED_BY_SEQUENCE = {
    2: REVIEWED, 3: REVIEWED_PRODUCT_0420, 4: REVIEWED_PRODUCT_0426,
    5: REVIEWED_PRODUCT_0427, 6: REVIEWED_PRODUCT_0429,
}


def reviewed_for(sequence):
    require(type(sequence) is int and sequence in REVIEWED_BY_SEQUENCE,
            'Release sequence has no reviewed source')
    return REVIEWED_BY_SEQUENCE[sequence]


def installer_name(expected):
    if expected.tag.startswith('test-product-updater-'):
        return 'Ironclad-Product-Update-' + expected.commit[:8] + '-Payload.exe'
    return 'Ironclad-Update-Patch-' + expected.commit[:8] + '-Payload.exe'


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


def verify_bundle(path, sequence=2):
    path = pathlib.Path(path)
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), 'Bundle must be a regular file')
    with path.open('rb') as stream:
        return _inspect(stream, reviewed_for(sequence))


def _assemble(directory, output, expected):
    directory, output = pathlib.Path(directory), pathlib.Path(output)
    names = (installer_name(expected), 'net8.0-windows.json', 'net10.0-windows.json')
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


def assemble(directory, output, sequence=2): return _assemble(directory, output, reviewed_for(sequence))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Assemble the exact reviewed bundle; never runs the installer.')
    parser.add_argument('--input-directory', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    parser.add_argument('--release-sequence', type=int, default=2)
    args = parser.parse_args()
    assemble(args.input_directory, args.output, args.release_sequence)
    print('REVIEWED_SOURCE_BUNDLE_READY sha256=' + reviewed_for(args.release_sequence).bundle_sha256)
