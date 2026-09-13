#!/usr/bin/env python3
"""Build a reproducible, allowlisted CLI source distribution and checked installer."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import tomllib

root = Path(__file__).resolve().parent.parent
version = tomllib.loads((root / 'crates/cli/Cargo.toml').read_text())['package']['version']
output = root / 'docs-site/dist/releases'
output.mkdir(parents=True, exist_ok=True)
manifest = b'''[workspace]\nmembers = ["crates/client", "crates/cli"]\nresolver = "3"\n[profile.release]\ncodegen-units = 1\nlto = "thin"\nstrip = "symbols"\n'''
files = {'Cargo.toml': manifest, 'Cargo.lock': (root / 'packaging/Cargo.lock').read_bytes()}
for directory in ['crates/client', 'crates/cli', 'docs']:
    for path in sorted((root / directory).rglob('*')):
        if path.is_file() and path.suffix in {'.rs', '.toml', '.md', '.sh'}:
            files[str(path.relative_to(root))] = path.read_bytes()
for name in ['LICENSE', 'LICENSE.md', 'LICENSE-APACHE', 'LICENSE-MIT']:
    if (root / name).is_file(): files[name] = (root / name).read_bytes()
buffer = io.BytesIO()
with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0) as compressed:
    with tarfile.open(fileobj=compressed, mode='w') as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(f'silicon-hook-{version}/{name}')
            info.size = len(data)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(data))
content = buffer.getvalue()
name = f'silicon-hook-cli-{version}.tar.gz'
digest = hashlib.sha256(content).hexdigest()
(output / name).write_bytes(content)
(output / f'{name}.sha256').write_text(f'{digest}  {name}\n')
installer = (root / 'docs/install.sh').read_text().replace('@VERSION@', version).replace('@SHA256@', digest)
(root / 'docs-site/dist/install.sh').write_text(installer)
print(f'Packaged {len(files)} source files: {name} (sha256 {digest})')
