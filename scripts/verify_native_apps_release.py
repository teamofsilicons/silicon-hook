#!/usr/bin/env python3
"""Execute an existing, source-pinned Apps archive on its matching native host.

Produces evidence only. It cannot publish packages or modify validation policy.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile
import urllib.request


def check_source(repository, run_id, source):
    request = urllib.request.Request(
        f'https://api.github.com/repos/{repository}/actions/runs/{run_id}',
        headers={'Authorization': 'Bearer ' + os.environ['GH_TOKEN'], 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        run = json.load(response)
    if run['head_sha'] != source or run['conclusion'] != 'success':
        raise ValueError('Archive build must have succeeded at the exact reviewed source revision')


def native_target():
    system = {'Linux': 'linux', 'Darwin': 'macos', 'Windows': 'windows'}[platform.system()]
    machine = platform.machine().lower()
    architecture = {'x86_64': 'x86_64', 'amd64': 'x86_64', 'aarch64': 'aarch64', 'arm64': 'aarch64'}[machine]
    return system + '-' + architecture


def verify(folder, app, version, target, source, verifier, output):
    import yaml
    if native_target() != target:
        raise ValueError('This report requires native execution on the exact target')
    if not all(re.fullmatch('[a-f0-9]{40}', value) for value in [source, verifier]):
        raise ValueError('Both source and verifier commits must be pinned')
    archive = folder / f'{app}-{version}-{target}.tar.gz'
    raw = archive.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    checksums = dict(line.split(maxsplit=1)[::-1] for line in (folder / 'SHA256SUMS').read_text().splitlines() if line.strip())
    if checksums.get(archive.name) != digest:
        raise ValueError('Archive checksum does not match the build artifact')
    with tempfile.TemporaryDirectory(prefix='apps-native-') as directory:
        stage = Path(directory) / 'package'
        stage.mkdir()
        with tarfile.open(archive) as bundle:
            names = set()
            for member in bundle.getmembers():
                path = Path(member.name)
                if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()) or member.name in names:
                    raise ValueError('Unsafe or duplicate archive member')
                names.add(member.name)
            bundle.extractall(stage, filter='data')
        manifest = yaml.safe_load((stage / 'apps.yaml').read_text())
        if (manifest['app_id'], manifest['version'], manifest['command'], list(manifest['targets'])) != (app, version, app, [target]):
            raise ValueError('Apps manifest identity or target mismatch')
        binary = (stage / manifest['targets'][target]['binary']).resolve()
        if not binary.is_relative_to(stage.resolve()) or not binary.is_file():
            raise ValueError('Binary path is outside package')
        binary.chmod(binary.stat().st_mode | 0o111)
        home = Path(directory) / 'empty-home'
        home.mkdir()
        environment = {key: value for key, value in os.environ.items() if key in ['PATH', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'TEMP', 'TMP']}
        environment.update({'HOME': str(home), 'USERPROFILE': str(home), 'SILICON_HOME': str(home),
                            'APPDATA': str(home / 'appdata'), 'LOCALAPPDATA': str(home / 'localappdata'),
                            'XDG_CONFIG_HOME': str(home / 'config'), 'XDG_DATA_HOME': str(home / 'data'),
                            'XDG_CACHE_HOME': str(home / 'cache'), 'NO_COLOR': '1'})
        commands = []
        for arguments in [['--help'], ['accounts', '--json'], ['login', 'status', '--json'], ['--version']]:
            result = subprocess.run([str(binary), *arguments], cwd=home, env=environment, capture_output=True,
                                    text=True, encoding='utf-8', timeout=30)
            commands.append({'argv': arguments, 'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
            if result.returncode != 0:
                raise ValueError(f'{app} {arguments} failed: {result.stderr[:500]}')
        if not (commands[0]['stdout'].strip() or commands[0]['stderr'].strip()):
            raise ValueError('Help was empty')
        if json.loads(commands[1]['stdout']).get('app_id') != app:
            raise ValueError('Wrong Accounts app id')
        if json.loads(commands[2]['stdout']).get('authenticated') is not False:
            raise ValueError('Empty home must be signed out')
        if commands[3]['stdout'].strip() != f'{app} {version}':
            raise ValueError('Version output differs from manifest')
    report = {'app_id': app, 'version': commands[3]['stdout'].strip(), 'source_commit': source,
              'verifier_commit': verifier, 'target': target, 'archive': archive.name, 'sha256': digest,
              'size': len(raw), 'runtime': {'system': platform.system(), 'machine': platform.machine(),
              'platform': platform.platform(), 'python': platform.python_version(), 'native': True},
              'command_results': commands}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'target': target, 'archive': archive.name, 'sha256': digest, 'report': str(output)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-source', action='store_true')
    parser.add_argument('--folder', type=Path, default=Path('release'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--target')
    args = parser.parse_args()
    if args.check_source:
        check_source(os.environ['GITHUB_REPOSITORY'], os.environ['BUILD_RUN_ID'], os.environ['BUILD_SOURCE_COMMIT'])
    else:
        verify(args.folder, os.environ['RELEASE_APP_ID'], os.environ['RELEASE_VERSION'], args.target,
               os.environ['BUILD_SOURCE_COMMIT'], os.environ['GITHUB_SHA'], args.output)
