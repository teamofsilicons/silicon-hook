#!/usr/bin/env python3
"""Publish the checked static docs through their existing Vercel project."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
subprocess.run(['npm', 'run', 'build', '--prefix', str(root / 'docs-site')], check=True)
subprocess.run(['npm', 'run', 'check', '--prefix', str(root / 'docs-site')], check=True)
project = root / 'docs-site/.vercel/project.json'
if not project.exists():
    raise SystemExit('Run vercel link --yes --project silicon-hook-docs --cwd docs-site first.')
with tempfile.TemporaryDirectory(prefix='hook-docs-publish-') as directory:
    deployment = Path(directory)
    output = deployment / '.vercel/output'
    output.mkdir(parents=True)
    shutil.copy2(project, deployment / '.vercel/project.json')
    shutil.copytree(root / 'docs-site/dist', output / 'static')
    headers = {item['key']: item['value'] for item in json.loads((root / 'docs-site/vercel.json').read_text())['headers'][0]['headers']}
    (output / 'config.json').write_text(json.dumps({'version': 3, 'routes': [
        {'src': '/(.*)', 'headers': headers, 'continue': True},
        {'handle': 'filesystem'},
        {'src': '/(.*)', 'dest': '/404.html', 'status': 404},
    ]}))
    subprocess.run(['vercel', 'deploy', '--prebuilt', '--prod', '--yes', '--cwd', str(deployment)], check=True)
