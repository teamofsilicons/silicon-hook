#!/usr/bin/env python3
"""Stage all six prebuilt targets, then validate and pack with Honeycomb."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

TARGETS = {
    'linux-x86_64': ('x86_64-unknown-linux-gnu', 'hook'),
    'linux-aarch64': ('aarch64-unknown-linux-gnu', 'hook'),
    'windows-x86_64': ('x86_64-pc-windows-msvc', 'hook.exe'),
    'windows-aarch64': ('aarch64-pc-windows-msvc', 'hook.exe'),
    'macos-x86_64': ('x86_64-apple-darwin', 'hook'),
    'macos-aarch64': ('aarch64-apple-darwin', 'hook'),
}

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
    print(output)

if __name__ == '__main__':
    main()
