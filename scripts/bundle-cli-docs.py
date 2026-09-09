#!/usr/bin/env python3
"""Bundle canonical guides for cargo publish; --check rejects stale copies."""
import argparse
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
paths = ['README.md', 'api/README.md', 'client/README.md', 'cli/README.md',
         'iam/README.md', 'testing/README.md', 'testing/api.md',
         'testing/client.md', 'testing/cli.md', 'client/relay.md']
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
if stale:
    parser.exit(1, 'Stale CLI guides: ' + ', '.join(stale) + '\nRun python3 scripts/bundle-cli-docs.py\n')
print('CLI guides are current.' if args.check else 'CLI guides bundled.')
