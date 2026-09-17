"""Check native release verification and private runtime translation before rollout."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('install_native', ROOT / 'deploy/native/install.py')
install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(install)


class NativeDeployment(unittest.TestCase):
    def test_runtime_translation_preserves_opaque_credentials(self):
        values = {'HOOK_DATABASE_URL': 'postgres://user:secret@127.0.0.1/hook_prod?sslrootcert=/run/hook-db/ca.crt',
                  'HOOK_TELEMETRY_SPOOL_DIR': '/var/lib/hook-telemetry',
                  'HOOK_IAM_APP_SECRET': 'opaque:/run/hook-db/ca.crt'}
        converted = install.native_settings(values)
        self.assertIn('/opt/silicon-hook/db-tls/ca.crt', converted['HOOK_DATABASE_URL'])
        self.assertEqual(converted['HOOK_TELEMETRY_SPOOL_DIR'], '/opt/silicon-hook/telemetry-spool')
        self.assertEqual(converted['HOOK_IAM_APP_SECRET'], values['HOOK_IAM_APP_SECRET'])
        environment = install.pg_environment(converted['HOOK_DATABASE_URL'].replace('secret', 's%40ecret'))
        self.assertEqual(environment['PGPASSWORD'], 's@ecret')
        self.assertEqual(environment['PGSSLMODE'], 'verify-full')
        self.assertEqual(environment['PGDATABASE'], 'hook_prod')
        with self.assertRaises(ValueError):
            install.pg_environment(converted['HOOK_DATABASE_URL'].replace('127.0.0.1', 'other.example'))

    @patch.object(install.platform, 'system', return_value='Linux')
    @patch.object(install.platform, 'machine', return_value='aarch64')
    @patch.object(install.shutil, 'which', return_value='/usr/bin/fixture')
    @patch.object(install, 'run', return_value='libc.so.6 => /lib/libc.so.6')
    def test_bundle_rejects_corruption_extra_files_and_symlinks(self, *_):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'bin').mkdir()
            files = {}
            for name in ('hook-api', 'hook-worker', 'hook-migrate', 'hook-contract'):
                path = root / 'bin' / name
                path.write_bytes(b'fixture')
                path.chmod(0o755)
                files['bin/' + name] = hashlib.sha256(path.read_bytes()).hexdigest()
            (root / 'manifest.json').write_text(json.dumps({'release_id': '123456abcdef', 'target': 'linux-aarch64', 'files': files}))
            self.assertEqual(install.verify(root)['release_id'], '123456abcdef')
            (root / 'secret.env').write_text('must not be bundled')
            with self.assertRaises(ValueError): install.verify(root)
            (root / 'secret.env').unlink()
            (root / 'bin/hook-api').write_bytes(b'corrupted')
            with self.assertRaises(ValueError): install.verify(root)
            (root / 'bin/hook-api').unlink()
            (root / 'bin/hook-api').symlink_to(root / 'bin/hook-worker')
            with self.assertRaises(ValueError): install.verify(root)


if __name__ == '__main__':
    unittest.main()
