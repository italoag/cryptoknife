import errno
import hashlib
import importlib.util
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "package_release.py"
UNIX_TARGET = "aarch64-apple-darwin"
WINDOWS_TARGET = "x86_64-pc-windows-msvc"


def load_packager():
    spec = importlib.util.spec_from_file_location("package_release", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def package_version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert match, "versão não encontrada em Cargo.toml"
    return match.group(1)


def archive_name(version: str, target: str) -> str:
    suffix = ".zip" if "windows" in target else ".tar.gz"
    return f"cryptoknife-{version}-{target}{suffix}"


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unsupported_link_error(e: BaseException) -> bool:
    if isinstance(e, NotImplementedError):
        return True
    if not isinstance(e, OSError):
        return False
    if getattr(e, "winerror", None) in (1314, 50):
        return True
    return e.errno in (errno.ENOSYS, errno.EOPNOTSUPP)


class PackagerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.case = Path(self.tmp.name)
        self.out = self.case / "output"
        self.out.mkdir()
        self.binary = self.case / "cryptoknife"
        self.binary.write_bytes(b"fake-binary\x00\x01")
        self.version = package_version()

    def symlink_or_skip(self, target: Path, link: Path) -> None:
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as e:
            if unsupported_link_error(e):
                self.skipTest(f"symlinks indisponíveis: {e}")
            raise

    def hardlink_or_skip(self, target: Path, link: Path) -> None:
        try:
            os.link(target, link)
        except OSError as e:
            if unsupported_link_error(e):
                self.skipTest(f"hardlinks não suportados: {e}")
            raise

    def run_packager(self, target: str, out: Path = None):
        out = out or self.out
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--binary", str(self.binary),
             "--target", target, "--output-dir", str(out)],
            capture_output=True, text=True, timeout=60,
        )

    def sums_path(self) -> Path:
        return self.out / "SHA256SUMS"

    def sums_lines(self):
        return self.sums_path().read_text(encoding="utf-8").splitlines()

    def check_archive_contents(self, archive: Path, base: str, target: str) -> None:
        exe = "cryptoknife.exe" if "windows" in target else "cryptoknife"
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as bundle:
                names = set(bundle.namelist())
        else:
            with tarfile.open(archive) as bundle:
                names = set(bundle.getnames())
        members = [exe, "README.md", "LICENSE"]
        if (ROOT / "CHANGELOG.md").is_file():
            members.append("CHANGELOG.md")
        for member in members:
            self.assertIn(f"{base}/{member}", names)

    def test_success_tar_gz(self):
        result = self.run_packager(UNIX_TARGET)
        self.assertEqual(result.returncode, 0, result.stderr)
        name = archive_name(self.version, UNIX_TARGET)
        archive = self.out / name
        self.assertTrue(archive.is_file())
        self.check_archive_contents(archive, f"cryptoknife-{self.version}-{UNIX_TARGET}", UNIX_TARGET)
        self.assertEqual(self.sums_lines(), [f"{sha256_of(archive)}  {name}"])

    def test_success_zip(self):
        result = self.run_packager(WINDOWS_TARGET)
        self.assertEqual(result.returncode, 0, result.stderr)
        name = archive_name(self.version, WINDOWS_TARGET)
        archive = self.out / name
        self.assertTrue(archive.is_file())
        self.check_archive_contents(archive, f"cryptoknife-{self.version}-{WINDOWS_TARGET}", WINDOWS_TARGET)

    def test_existing_archive_refused_unchanged(self):
        first = self.run_packager(UNIX_TARGET)
        self.assertEqual(first.returncode, 0, first.stderr)
        archive = self.out / archive_name(self.version, UNIX_TARGET)
        before = archive.read_bytes()
        second = self.run_packager(UNIX_TARGET)
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(archive.read_bytes(), before)

    def test_dangling_archive_symlink_rejected(self):
        for target in (UNIX_TARGET, WINDOWS_TARGET):
            with self.subTest(target=target):
                case = Path(tempfile.mkdtemp(dir=self.case))
                out = case / "output"
                out.mkdir()
                victim = case / "outside-created"
                archive = out / archive_name(self.version, target)
                self.symlink_or_skip(victim, archive)
                result = self.run_packager(target, out)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(victim.exists())
                self.assertTrue(archive.is_symlink())

    def test_sums_symlink_sentinel_preserved(self):
        victim = self.case / "sentinel.txt"
        victim.write_text("SENTINEL\n", encoding="utf-8")
        self.symlink_or_skip(victim, self.sums_path())
        result = self.run_packager(UNIX_TARGET)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(victim.read_text(encoding="utf-8"), "SENTINEL\n")
        self.assertFalse((self.out / archive_name(self.version, UNIX_TARGET)).exists())

    def test_sums_dangling_symlink_no_outside_created(self):
        victim = self.case / "outside-sums.txt"
        self.symlink_or_skip(victim, self.sums_path())
        result = self.run_packager(UNIX_TARGET)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(victim.exists())

    def test_sums_directory_rejected(self):
        self.sums_path().mkdir()
        result = self.run_packager(UNIX_TARGET)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.out / archive_name(self.version, UNIX_TARGET)).exists())

    def test_second_target_appends_preserving_first(self):
        first = self.run_packager(UNIX_TARGET)
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.run_packager(WINDOWS_TARGET)
        self.assertEqual(second.returncode, 0, second.stderr)
        lines = self.sums_lines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].endswith(archive_name(self.version, UNIX_TARGET)))
        self.assertTrue(lines[1].endswith(archive_name(self.version, WINDOWS_TARGET)))

    def test_hardlinked_sums_rejected(self):
        sums = self.sums_path()
        sums.write_text("", encoding="utf-8")
        self.hardlink_or_skip(sums, self.case / "sums-hardlink")
        result = self.run_packager(UNIX_TARGET)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sums.read_text(encoding="utf-8"), "")
        self.assertFalse((self.out / archive_name(self.version, UNIX_TARGET)).exists())

    def test_exclusive_archive_creation_independent_of_preflight(self):
        module = load_packager()
        real_exists = Path.exists
        real_is_symlink = Path.is_symlink
        for target in (UNIX_TARGET, WINDOWS_TARGET):
            with self.subTest(target=target):
                case = Path(tempfile.mkdtemp(dir=self.case))
                out = case / "output"
                out.mkdir()
                archive = out / archive_name(self.version, target)
                archive.write_bytes(b"PREEXISTING")

                def fake_exists(self):
                    if self == archive:
                        return False
                    return real_exists(self)

                def fake_is_symlink(self):
                    if self == archive:
                        return False
                    return real_is_symlink(self)

                argv = [str(SCRIPT), "--binary", str(self.binary),
                        "--target", target, "--output-dir", str(out)]
                with mock.patch.object(Path, "exists", fake_exists), \
                        mock.patch.object(Path, "is_symlink", fake_is_symlink), \
                        mock.patch.object(sys, "argv", argv):
                    with self.assertRaises(FileExistsError):
                        module.main()
                self.assertEqual(archive.read_bytes(), b"PREEXISTING")


if __name__ == "__main__":
    unittest.main()
