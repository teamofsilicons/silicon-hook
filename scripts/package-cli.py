#!/usr/bin/env python3
"""Stage all six prebuilt targets, then validate and pack with Honeycomb."""
import argparse
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import tarfile
import tomllib

TARGETS = {
    'linux-x86_64': ('x86_64-unknown-linux-gnu', 'hook'),
    'linux-aarch64': ('aarch64-unknown-linux-gnu', 'hook'),
    'windows-x86_64': ('x86_64-pc-windows-msvc', 'hook.exe'),
    'windows-aarch64': ('aarch64-pc-windows-msvc', 'hook.exe'),
    'macos-x86_64': ('x86_64-apple-darwin', 'hook'),
    'macos-aarch64': ('aarch64-apple-darwin', 'hook'),
}

def verify_binary(path, target):
    """Reject a binary copied under the wrong operating system or CPU label."""
    with path.open('rb') as executable:
        header = executable.read(64)
        machine = None
        if target.startswith('linux-') and header[:4] == b'\x7fELF' and header[4:6] == bytes([2, 1]):
            machine = struct.unpack_from('<H', header, 18)[0]
            expected = 62 if target.endswith('x86_64') else 183
        elif target.startswith('windows-') and header[:2] == b'MZ' and len(header) == 64:
            executable.seek(struct.unpack_from('<I', header, 60)[0])
            pe = executable.read(6)
            if pe[:4] == b'PE\0\0' and len(pe) == 6:
                machine = struct.unpack_from('<H', pe, 4)[0]
            expected = 0x8664 if target.endswith('x86_64') else 0xAA64
        elif target.startswith('macos-') and header[:4] == b'\xcf\xfa\xed\xfe' and len(header) >= 8:
            machine = struct.unpack_from('<I', header, 4)[0]
            expected = 0x01000007 if target.endswith('x86_64') else 0x0100000C
        else:
            raise ValueError(f'{path}: not a native {target} executable')
        if machine != expected:
            raise ValueError(f'{path}: executable architecture does not match {target}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True, help='Directory containing <Honeycomb target>/<hook or hook.exe>')
    parser.add_argument('--output', type=Path, default=Path('dist'))
    parser.add_argument('--honeycomb', default='honeycomb')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    version = tomllib.loads((root / 'crates/cli/Cargo.toml').read_text())['package']['version']
    manifest = (root / 'honeycomb.yaml').read_text()
    if f'version: "{version}"' not in manifest:
        parser.error('honeycomb.yaml version must match the CLI app release version')
    for target, (_, binary) in TARGETS.items():
        artifact = args.artifacts / target / binary
        if not artifact.is_file() or artifact.stat().st_size == 0 or artifact.is_symlink():
            parser.error(f'Missing prebuilt executable: {artifact}')
        try:
            verify_binary(artifact, target)
        except (ValueError, struct.error) as error:
            parser.error(str(error))
    args.output.mkdir(parents=True, exist_ok=True)
    output = (args.output / f'silicon-hook-{version}.tar.gz').resolve()
    with tempfile.TemporaryDirectory(prefix='hook-release-') as temporary:
        stage = Path(temporary)
        (stage / 'honeycomb.yaml').write_text(manifest)
        for target, (_, binary) in TARGETS.items():
            destination = stage / 'targets' / target / 'bin' / binary
            destination.parent.mkdir(parents=True)
            shutil.copyfile(args.artifacts / target / binary, destination)
            destination.chmod(0o755)
        subprocess.run([args.honeycomb, 'validate', str(stage)], check=True)
        subprocess.run([args.honeycomb, 'pack', str(stage), '--output', str(output)], check=True)
    subprocess.run([args.honeycomb, 'validate', str(output)], check=True)
    expected = {'honeycomb.yaml'} | {f'targets/{target}/bin/{binary}' for target, (_, binary) in TARGETS.items()}
    with tarfile.open(output, 'r:gz') as archive:
        members = archive.getmembers()
        files = {member.name.removeprefix('./') for member in members if member.isfile()}
        if files != expected or any(not (member.isfile() or member.isdir()) for member in members):
            raise SystemExit('Archive must contain only honeycomb.yaml and the six native executables')
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(f'{digest}  {output.name}\n')
    print(f'{output}\nSHA-256: {digest}')

if __name__ == '__main__':
    main()
