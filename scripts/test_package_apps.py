"""Silicon Apps packaging checks. Executable headers below are synthetic fixtures, never real binaries."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
import textwrap
import unittest

spec = importlib.util.spec_from_file_location("package_apps", Path(__file__).with_name("package_apps.py"))
package_apps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package_apps)

VERSION = package_apps.cli_version()


def elf(target, interpreter=False, glibc=None):
    arch = target.split("-", 1)[1]
    elf_class, machine = package_apps.ELF_MACHINE[arch]
    data = bytearray(512)
    data[:6] = b"\x7fELF" + bytes([elf_class, 1])
    struct.pack_into("<H", data, 18, machine)
    if elf_class == 2:
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 2)
        first, size = 64, 56
    else:
        struct.pack_into("<I", data, 28, 52)
        struct.pack_into("<HH", data, 42, 32, 2)
        first, size = 52, 32
    struct.pack_into("<I", data, first, 1)
    struct.pack_into("<I", data, first + size, 3 if interpreter else 1)
    if glibc:
        data[300:300 + len(glibc)] = glibc.encode()
    return bytes(data)


def fixture(target):
    system = package_apps.TARGETS[target]
    arch = target.split("-", 1)[1]
    if system == "linux":
        return elf(target)
    data = bytearray(128)
    if system == "macos":
        data[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", data, 4, package_apps.MACHO_CPU[arch])
    else:
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\0\0"
        struct.pack_into("<H", data, 68, package_apps.PE_MACHINE[arch])
    return bytes(data)


def foreign_target():
    """A target this machine cannot run, so discovery is skipped in auto mode."""
    return "windows-x86_64" if package_apps.host_system() != "windows" else "linux-x86_64"


def fake_hook(directory, accounts='{"app_id": "hook"}', status='{"authenticated": false}', version=VERSION,
              writes=False):
    """A shell stand-in for the hook binary answering the discovery commands."""
    script = Path(directory) / "hook"
    touch = 'mkdir -p "$HOME/.silicon-hook"' if writes else ":"
    script.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        {touch}
        case "$*" in
          "--help") echo "hook: a Silicon's signed webhooks" ;;
          "accounts --json") echo '{accounts}' ;;
          "login status --json") echo '{status}' ;;
          "--version") echo "hook {version}" ;;
          *) exit 2 ;;
        esac
        """))
    script.chmod(0o755)
    return script


FAKE_PACKER = textwrap.dedent("""\
    #!{python}
    import json, sys, tarfile
    from pathlib import Path
    args = sys.argv[1:]
    log = Path({log!r})
    with log.open("a") as out:
        out.write(json.dumps(args) + "\\n")
    if args == ["--version"]:
        print("silicon-apps 0.2.0"); sys.exit(0)
    assert "--home" in args and "--server" in args and "--json" in args, args
    if args[0] == "validate":
        print(json.dumps({{"valid": {valid}, "errors": []}})); sys.exit(0 if {valid} else 1)
    if args[0] == "pack":
        stage, output = Path(args[1]), Path(args[args.index("--output") + 1])
        with tarfile.open(output, "w:gz") as archive:
            for name in ["apps.yaml", "bin"]:
                archive.add(stage / name, arcname=name)
            if {extra}:
                archive.add(stage / "apps.yaml", arcname="extra.txt")
        print(json.dumps({{"path": str(output)}})); sys.exit(0)
    sys.exit(3)
    """)


class Manifest(unittest.TestCase):
    def test_renders_one_target_without_comments(self):
        text = package_apps.render_manifest(package_apps.TEMPLATE.read_text(), "1.2.3", "windows-aarch64")
        self.assertEqual(text, "schema_version: 1\napp_id: hook\nversion: 1.2.3\ncommand: hook\ntargets:\n"
                               "  windows-aarch64:\n    binary: bin/hook.exe\n")
        self.assertIn("binary: bin/hook\n", package_apps.render_manifest(package_apps.TEMPLATE.read_text(),
                                                                         "1.2.3", "linux-aarch64"))

    def test_refuses_lost_or_unknown_placeholders(self):
        with self.assertRaises(package_apps.PackageError):
            package_apps.render_manifest("version: 1.0.0\n", "1.0.0", "linux-x86_64")
        with self.assertRaises(package_apps.PackageError):
            package_apps.render_manifest("@VERSION@ @TARGET@ @BINARY@ @OTHER@\n", "1.0.0", "linux-x86_64")

    def test_version_comes_from_the_cli_crate(self):
        self.assertRegex(VERSION, r"^\d+\.\d+\.\d+$")
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "Cargo.toml"
            manifest.write_text('[package]\nname = "x"\nversion = "4.5.6"\n[dependencies]\nversion = "9"\n')
            self.assertEqual(package_apps.cli_version(manifest), "4.5.6")


class Binaries(unittest.TestCase):
    def test_accepts_each_target_and_refuses_every_other(self):
        for target in package_apps.TARGETS:
            package_apps.check_native(fixture(target), target)
            for wrong in package_apps.TARGETS.keys() - {target}:
                with self.assertRaises((package_apps.PackageError, struct.error), msg=f"{target} as {wrong}"):
                    package_apps.check_native(fixture(target), wrong)
        with self.assertRaises(package_apps.PackageError):
            package_apps.check_native(b"#!/bin/sh\necho not a release\n" + bytes(64), "linux-x86_64")

    def test_linux_glibc_ceiling(self):
        self.assertEqual(package_apps.check_native(elf("linux-x86_64"), "linux-x86_64"), "static ELF")
        self.assertIn("2.39", package_apps.check_native(
            elf("linux-aarch64", True, "GLIBC_2.17\0GLIBC_2.39\0GLIBC_2.3.4"), "linux-aarch64"))
        with self.assertRaisesRegex(package_apps.PackageError, "needs glibc 2.40"):
            package_apps.check_native(elf("linux-x86_64", True, "GLIBC_2.28\0GLIBC_2.40"), "linux-x86_64")
        bad = bytearray(elf("linux-x86_64"))
        bad[5] = 2
        with self.assertRaises(package_apps.PackageError):
            package_apps.check_native(bytes(bad), "linux-x86_64")

    def test_backend_packager_entry_point_raises_value_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hook-api"
            path.write_bytes(elf("linux-aarch64", True, "GLIBC_2.28"))
            package_apps.verify_binary(path, "linux-aarch64")
            with self.assertRaises(ValueError):
                package_apps.verify_binary(path, "linux-x86_64")

    def test_refuses_versions_that_differ_or_are_not_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hook.exe"
            path.write_bytes(fixture(foreign_target()))
            for version in ("1.0", "1.0.0-rc.1", "01.0.0", "999.0.0"):
                with self.assertRaises(package_apps.PackageError, msg=version):
                    package_apps.check(version, foreign_target(), path, "auto")
            with self.assertRaises(package_apps.PackageError):
                package_apps.check(VERSION, "linux-riscv64", path, "auto")
            empty = Path(directory) / "empty"
            empty.write_bytes(b"")
            with self.assertRaises(package_apps.PackageError):
                package_apps.check(VERSION, foreign_target(), empty, "auto")


@unittest.skipIf(os.name == "nt", "the stand-in binary is a POSIX shell script")
class Discovery(unittest.TestCase):
    target = {"linux": "linux-x86_64", "macos": "macos-aarch64"}.get(package_apps.host_system(), "linux-x86_64")

    def run_discovery(self, mode="require", **answers):
        with tempfile.TemporaryDirectory() as directory:
            return package_apps.discovery(fake_hook(directory, **answers), self.target, VERSION, mode)

    def test_correct_answers_pass(self):
        self.assertTrue(self.run_discovery())

    def test_runs_a_copy_when_the_mode_bits_are_lost(self):
        with tempfile.TemporaryDirectory() as directory:
            script = fake_hook(directory)
            script.chmod(0o644)  # what a downloaded workflow artifact looks like
            self.assertTrue(package_apps.discovery(script, self.target, VERSION, "require"))
            self.assertEqual(stat.S_IMODE(script.stat().st_mode), 0o644)

    def test_wrong_answers_are_refused(self):
        cases = {
            "accounts": ('{"app_id": "dm"}', "app_id"),
            "status": ('{"authenticated": true, "uuid": "zQo"}', "authenticated false"),
            "version": ("0.0.1", "--version"),
            "writes": (True, "must not write"),
        }
        for field, (value, message) in cases.items():
            with self.subTest(field):
                with self.assertRaisesRegex(package_apps.PackageError, message):
                    self.run_discovery(**{field: value})
        with self.assertRaisesRegex(package_apps.PackageError, "one JSON object"):
            self.run_discovery(accounts="not json")

    def test_other_processor_is_a_note_unless_required(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "hook"
            binary.write_bytes(fixture("linux-aarch64" if self.target != "linux-aarch64" else "linux-x86_64"))
            binary.chmod(0o755)
            if package_apps.host_system() == "linux":
                self.skipTest("this Linux machine may run other processors through binfmt")
            self.assertFalse(package_apps.discovery(binary, self.target, VERSION, "auto"))
            with self.assertRaisesRegex(package_apps.PackageError, "cannot run"):
                package_apps.discovery(binary, self.target, VERSION, "require")

    def test_other_systems_are_skipped_or_refused(self):
        other = "windows-x86_64"
        self.assertFalse(package_apps.discovery(Path("/nonexistent"), other, VERSION, "auto"))
        with self.assertRaisesRegex(package_apps.PackageError, "cannot run on this"):
            package_apps.discovery(Path("/nonexistent"), other, VERSION, "require")


@unittest.skipIf(os.name == "nt", "the stand-in packer is a POSIX script")
class Packing(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.target = foreign_target()
        self.binary = self.root / "built" / package_apps.binary_name(self.target)
        self.binary.parent.mkdir()
        self.binary.write_bytes(fixture(self.target))
        self.log = self.root / "packer.log"

    def tearDown(self):
        self.directory.cleanup()

    def packer(self, valid=True, extra=False):
        path = self.root / f"silicon-apps-{valid}-{extra}"
        path.write_text(FAKE_PACKER.format(python=sys.executable, log=str(self.log), valid=valid, extra=extra))
        path.chmod(0o755)
        return str(path)

    def test_writes_one_archive_and_its_checksum(self):
        output = self.root / "dist"
        archive = package_apps.package(VERSION, self.target, self.binary, output, "auto", self.packer())
        self.assertEqual(archive.name, f"hook-{VERSION}-{self.target}.tar.gz")
        with tarfile.open(archive) as package:
            names = sorted(m.name for m in package.getmembers() if m.isfile())
            manifest = package.extractfile("apps.yaml").read().decode()
        self.assertEqual(names, ["apps.yaml", f"bin/{package_apps.binary_name(self.target)}"])
        self.assertIn(f"  {self.target}:\n    binary: bin/{package_apps.binary_name(self.target)}\n", manifest)
        self.assertNotIn("#", manifest)
        digest, name = (output / f"{archive.name}.sha256").read_text().split()
        self.assertEqual((digest, name), (package_apps.sha256(archive), archive.name))
        commands = [json.loads(line)[0] for line in self.log.read_text().splitlines()]
        self.assertEqual(commands, ["--version", "validate", "pack", "validate", "validate"])

    def test_a_refused_validation_packs_nothing(self):
        with self.assertRaisesRegex(package_apps.PackageError, "validate refused"):
            package_apps.package(VERSION, self.target, self.binary, self.root / "dist", "auto", self.packer(False))
        commands = [json.loads(line)[0] for line in self.log.read_text().splitlines()]
        self.assertNotIn("pack", commands)
        self.assertFalse(list((self.root / "dist").glob("*.tar.gz")))

    def test_an_archive_with_extra_files_is_refused(self):
        with self.assertRaisesRegex(package_apps.PackageError, "exactly"):
            package_apps.package(VERSION, self.target, self.binary, self.root / "dist", "auto",
                                 self.packer(extra=True))
        self.assertFalse(list((self.root / "dist").glob("*.tar.gz")))

    def test_wrong_packer_version_is_refused(self):
        old = self.root / "old-packer"
        old.write_text("#!/bin/sh\necho silicon-apps 0.1.9\n")
        old.chmod(0o755)
        with self.assertRaisesRegex(package_apps.PackageError, "0.2"):
            package_apps.package(VERSION, self.target, self.binary, self.root / "dist", "auto", str(old))

    def test_the_command_line_reports_refusals(self):
        stderr = io.StringIO()
        original, sys.stderr = sys.stderr, stderr
        try:
            code = package_apps.main(["0.0.1", self.target, str(self.binary), "--check-only"])
        finally:
            sys.stderr = original
        self.assertEqual(code, 1)
        self.assertIn("differs from crates/cli/Cargo.toml", stderr.getvalue())
        self.assertEqual(package_apps.main([VERSION, self.target, str(self.binary), "--check-only"]), 0)


if __name__ == "__main__":
    unittest.main()
