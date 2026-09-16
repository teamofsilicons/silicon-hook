"""Release packaging regressions. Headers below are synthetic test fixtures only."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('package_cli', Path(__file__).with_name('package-cli.py'))
package_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_cli)


def fixture(target):
    data = bytearray(128)
    if target.startswith('linux-'):
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, 62 if target.endswith('x86_64') else 183)
    elif target.startswith('windows-'):
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 64)
        data[64:68] = b'PE\0\0'
        struct.pack_into('<H', data, 68, 0x8664 if target.endswith('x86_64') else 0xAA64)
    else:
        data[:4] = b'\xcf\xfa\xed\xfe'
        struct.pack_into('<I', data, 4, 0x01000007 if target.endswith('x86_64') else 0x0100000C)
    return data


class Packaging(unittest.TestCase):
    def test_rejects_wrong_cpu_os_and_source_files(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / 'binary'
            for target in package_cli.TARGETS:
                executable.write_bytes(fixture(target))
                package_cli.verify_binary(executable, target)
                for wrong in package_cli.TARGETS.keys() - {target}:
                    with self.assertRaises(ValueError):
                        package_cli.verify_binary(executable, wrong)
            executable.write_text('#!/bin/sh\necho not-a-release\n')
            with self.assertRaises(ValueError):
                package_cli.verify_binary(executable, 'linux-x86_64')

    def test_requires_all_targets_and_validates_before_packing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            argv = ['package-cli.py', '--artifacts', str(root / 'artifacts'), '--output', str(root / 'output')]
            with patch('sys.argv', argv), patch.object(package_cli.subprocess, 'run') as run:
                with self.assertRaises(SystemExit):
                    package_cli.main()
                run.assert_not_called()
            for target, (_, binary) in package_cli.TARGETS.items():
                path = root / 'artifacts' / target / binary
                path.parent.mkdir(parents=True)
                path.write_bytes(fixture(target))
            calls = []
            def record(command, check):
                self.assertTrue(check)
                stage = Path(command[2])
                self.assertTrue((stage / 'honeycomb.yaml').is_file())
                for target, (_, binary) in package_cli.TARGETS.items():
                    self.assertTrue((stage / 'targets' / target / 'bin' / binary).is_file())
                calls.append(command)
            with patch('sys.argv', argv), patch.object(package_cli.subprocess, 'run', side_effect=record):
                package_cli.main()
            self.assertEqual([command[1] for command in calls], ['validate', 'pack'])
            with patch('sys.argv', argv), patch.object(package_cli.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'validate')) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    package_cli.main()
                self.assertEqual(run.call_count, 1)

if __name__ == '__main__':
    unittest.main()
