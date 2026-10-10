#!/usr/bin/env python3
"""Bundle the guides `hook docs` prints into crates/cli/docs; --check rejects stale or leftover copies."""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
# Every guide `hook docs <topic>` prints; keep in sync with crates/cli/src/main.rs.
paths = ['README.md', 'accounts/README.md', 'api/README.md', 'client/README.md',
         'cli/README.md', 'client/relay.md', 'contracts.md', 'configuration.md',
         'deployment.md', 'telemetry.md', 'releases.md', 'ting-delivery.md']
stale = []
for name in paths:
    source = root / 'docs' / name
    target = root / 'crates/cli/docs' / name
    if args.check:
        if not target.is_file() or target.read_bytes() != source.read_bytes():
            stale.append(name)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
# Copies of guides that are no longer bundled must not linger in the crate.
bundled = {str(Path(name)) for name in paths}
for existing in sorted((root / 'crates/cli/docs').rglob('*.md')):
    relative = str(existing.relative_to(root / 'crates/cli/docs'))
    if relative not in bundled:
        if args.check:
            stale.append(relative + ' (no longer bundled)')
        else:
            existing.unlink()
if stale:
    parser.exit(1, 'Stale CLI guides: ' + ', '.join(stale) + '\nRun python3 scripts/bundle-cli-docs.py\n')
print('CLI guides are current.' if args.check else 'CLI guides bundled.')
