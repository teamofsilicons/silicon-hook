#!/usr/bin/env python3
"""Package prebuilt Linux ARM64 backend executables and systemd deployment files."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BINARIES = ('hook-api', 'hook-worker', 'hook-migrate', 'hook-contract')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('package_cli', ROOT / 'scripts/package-cli.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    release_id = revision[:12]
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / f'silicon-hook-backend-{release_id}-linux-aarch64.tar.gz'
    if output.exists():
        parser.error(f'Refusing to replace immutable release: {output}')
    with tempfile.TemporaryDirectory(prefix='hook-backend-') as directory:
        stage = Path(directory)
        (stage / 'bin').mkdir()
        for name in BINARIES:
            source = args.artifacts / name
            if source.is_symlink():
                parser.error(f'Executable must be a regular file: {source}')
            verifier.verify_binary(source, 'linux-aarch64')
            shutil.copyfile(source, stage / 'bin' / name)
            (stage / 'bin' / name).chmod(0o755)
        for source in (ROOT / 'deploy/native').iterdir():
            if source.suffix in ('.py', '.service'):
                shutil.copyfile(source, stage / source.name)
        shutil.copyfile(ROOT / 'deploy/postgres/grant-runtime.sql', stage / 'grant-runtime.sql')
        hashes = {str(path.relative_to(stage)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in sorted(stage.rglob('*')) if path.is_file()}
        (stage / 'manifest.json').write_text(json.dumps({
            'release_id': release_id, 'source_revision': revision,
            'target': 'linux-aarch64', 'files': hashes,
        }, indent=2) + '\n')
        with tarfile.open(output, 'w:gz') as archive:
            for path in sorted(stage.rglob('*')):
                archive.add(path, arcname=str(path.relative_to(stage)), recursive=False)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(f'{digest}  {output.name}\n')
    print(json.dumps({'archive': str(output), 'sha256': digest, 'release_id': release_id}))


if __name__ == '__main__':
    main()
