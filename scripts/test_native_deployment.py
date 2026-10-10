"""Check native release verification and private runtime translation before rollout."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
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
                  'HOOK_APP_SECRET': 'opaque:/run/hook-db/ca.crt'}
        converted = install.native_settings(values)
        self.assertIn('/opt/silicon-hook/db-tls/ca.crt', converted['HOOK_DATABASE_URL'])
        self.assertEqual(converted['HOOK_TELEMETRY_SPOOL_DIR'], '/opt/silicon-hook/telemetry-spool')
        self.assertEqual(converted['HOOK_APP_SECRET'], values['HOOK_APP_SECRET'])
        environment = install.pg_environment(converted['HOOK_DATABASE_URL'].replace('secret', 's%40ecret'))
        self.assertEqual(environment['PGPASSWORD'], 's@ecret')
        self.assertEqual(environment['PGSSLMODE'], 'verify-full')
        self.assertEqual(environment['PGDATABASE'], 'hook_prod')
        with self.assertRaises(ValueError):
            install.pg_environment(converted['HOOK_DATABASE_URL'].replace('127.0.0.1', 'other.example'))

    def test_plan_moves_to_accounts_and_drops_retired_settings(self):
        common = {'HOOK_ENVIRONMENT': 'production', 'HOOK_IAM_BASE_URL': 'https://iam.example',
                  'HOOK_IAM_APP_ID': 'hook', 'HOOK_IAM_APP_SECRET': 'old', 'HOOK_IAM_WEBHOOK_SECRET': 'old'}
        values = {
            'api': {**common, 'HOOK_DATABASE_URL': 'postgres://api@127.0.0.1/hook_prod',
                    'HOOK_TEST_DATABASE_URL': 'postgres://api@127.0.0.1/hook_test',
                    'HOOK_TING_BASE_URL': 'https://ting.example/'},
            'worker': {**common, 'HOOK_DATABASE_URL': 'postgres://worker@127.0.0.1/hook_prod',
                       'HOOK_TELEMETRY_TABLE_KEY': 'table-key'},
            'migration': {**common, 'HOOK_MIGRATOR_DATABASE_URL': 'postgres://postgres@127.0.0.1/hook_prod',
                          'HOOK_TEST_MIGRATOR_DATABASE_URL': 'postgres://postgres@127.0.0.1/hook_test'},
        }
        accounts = {'HOOK_APP_SECRET': 'sa_app_0123456789abcdef', 'HOOK_ACCOUNTS_WEBHOOK_SECRET': 'whsec_0123456789'}
        planned, missing = install.plan(values, accounts)
        self.assertEqual(missing, [])
        self.assertEqual(planned['api'], {
            'HOOK_ENVIRONMENT': 'production', 'HOOK_DATABASE_URL': 'postgres://api@127.0.0.1/hook_prod',
            'ACCOUNTS_URL': 'https://accounts.teamofsilicons.com', **accounts})
        self.assertEqual(planned['worker'], {'HOOK_ENVIRONMENT': 'production', 'HOOK_TELEMETRY_TABLE_KEY': 'table-key',
                                             'HOOK_DATABASE_URL': 'postgres://worker@127.0.0.1/hook_prod'})
        self.assertEqual(set(planned['migration']), {'HOOK_ENVIRONMENT', 'HOOK_MIGRATOR_DATABASE_URL'})
        report = install.changes(values, planned)
        self.assertIn('HOOK_TING_BASE_URL', report['api']['removed'])
        self.assertNotIn('HOOK_TING_URL', planned['api'])
        self.assertEqual(report['api']['added'], ['ACCOUNTS_URL', 'HOOK_ACCOUNTS_WEBHOOK_SECRET', 'HOOK_APP_SECRET'])
        self.assertNotIn('sa_app_0123456789abcdef', json.dumps(report))
        # A later release carries the secrets over without the file.
        again, missing = install.plan(planned, {})
        self.assertEqual((again, missing), (planned, []))
        # Without them the install is refused before anything changes.
        self.assertEqual(install.plan(values, {})[1], ['HOOK_APP_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_SECRET'])
        # Secrets never reach the worker or the migrator, even if set there by hand.
        values['worker']['HOOK_APP_SECRET'] = 'misplaced'
        self.assertNotIn('HOOK_APP_SECRET', install.plan(values, accounts)[0]['worker'])

    def test_accounts_file_must_be_private_and_only_name_accounts_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'accounts.env'
            path.write_text('# Silicon Accounts\nHOOK_APP_SECRET=sa_app_0123456789abcdef\n'
                            'HOOK_ACCOUNTS_WEBHOOK_SECRET=whsec_0123456789\n')
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'owner only'):
                install.accounts_settings(path)
            path.chmod(0o600)
            self.assertEqual(set(install.accounts_settings(path)), {'HOOK_APP_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_SECRET'})
            path.write_text('HOOK_APP_SECRET=sa_app_0123456789abcdef\nHOOK_DATABASE_URL=postgres://x\n')
            with self.assertRaisesRegex(ValueError, 'HOOK_DATABASE_URL'):
                install.accounts_settings(path)
            path.write_text('HOOK_APP_SECRET=\n')
            with self.assertRaisesRegex(ValueError, 'empty'):
                install.accounts_settings(path)
            path.write_text('HOOK_APP_SECRET="sa_app_0123456789abcdef"\n')
            with self.assertRaisesRegex(ValueError, 'without quotes'):
                install.accounts_settings(path)
        self.assertEqual(install.accounts_settings(None), {})

    def test_preview_reports_the_change_by_name_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for role, extra in (('api', 'HOOK_DATABASE_URL=postgres://api@127.0.0.1/hook_prod\n'),
                                ('worker', 'HOOK_DATABASE_URL=postgres://worker@127.0.0.1/hook_prod\n'),
                                ('migration', 'HOOK_MIGRATOR_DATABASE_URL=postgres://postgres@127.0.0.1/hook_prod\n')):
                (root / (role + '.env')).write_text('HOOK_ENVIRONMENT=production\nHOOK_IAM_APP_SECRET=old-secret\n' + extra)
            accounts = root / 'accounts.env'
            accounts.write_text('HOOK_APP_SECRET=sa_app_0123456789abcdef\nHOOK_ACCOUNTS_WEBHOOK_SECRET=whsec_0123456789\n')
            accounts.chmod(0o600)
            output = io.StringIO()
            with patch.object(install, 'ROOT', root), patch.object(install, 'CONFIG', root / 'absent'), \
                    patch.object(install, 'ACCOUNTS_FILE', accounts), \
                    patch.object(install, 'verify', return_value={'release_id': '123456abcdef'}), \
                    patch('sys.argv', ['install.py']), redirect_stdout(output):
                install.main()
            report = json.loads(output.getvalue())
            self.assertEqual(report['missing'], [])
            self.assertEqual(report['configuration']['api']['removed'], ['HOOK_IAM_APP_SECRET'])
            self.assertIn('HOOK_APP_SECRET', report['configuration']['api']['added'])
            self.assertEqual(report['configuration']['worker']['added'], [])
            self.assertNotIn('sa_app_', output.getvalue())
            self.assertNotIn('old-secret', output.getvalue())
            accounts.unlink()
            output = io.StringIO()
            with patch.object(install, 'ROOT', root), patch.object(install, 'CONFIG', root / 'absent'), \
                    patch.object(install, 'ACCOUNTS_FILE', accounts), \
                    patch.object(install, 'verify', return_value={'release_id': '123456abcdef'}), \
                    patch('sys.argv', ['install.py']), redirect_stdout(output):
                install.main()
            self.assertEqual(json.loads(output.getvalue())['missing'], ['HOOK_APP_SECRET', 'HOOK_ACCOUNTS_WEBHOOK_SECRET'])

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
