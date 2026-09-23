import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "release_version.py"

sys.path.insert(0, str(SCRIPT.parent))
spec = importlib.util.spec_from_file_location("release_version", SCRIPT)
rv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rv)

SHA = "a" * 40


def commit(subject, body=""):
    message = subject if not body else f"{subject}\n\n{body}"
    return rv.Commit.parse(SHA, message)


MANIFEST = """[package]
name = "cryptoknife"
version = "{version}"
edition = "2021"
rust-version = "1.85"

[dependencies]
anyhow = "1.0"
"""

LOCKFILE = """version = 3

[[package]]
name = "anyhow"
version = "1.0.103"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{checksum}"

[[package]]
name = "cryptoknife"
version = "{version}"
"""


class TestVersionParse(unittest.TestCase):
    def test_stable_accepted(self):
        self.assertEqual(str(rv.Version.parse("0.2.0")), "0.2.0")
        self.assertEqual(str(rv.Version.parse("10.20.30")), "10.20.30")

    def test_rejects_invalid(self):
        for text in ("1.02.3", "1.0", "1.0.0-rc.1", "1.0.0+build", "v1.0.0", "", "1.0.0.0"):
            with self.assertRaises(ValueError, msg=text):
                rv.Version.parse(text)


class TestCommitParse(unittest.TestCase):
    def test_kinds_and_breaking_marker(self):
        self.assertEqual(commit("feat: add flag").bump, "minor")
        self.assertEqual(commit("fix(cli): bad flag").bump, "patch")
        self.assertEqual(commit("perf: faster").bump, "patch")
        self.assertEqual(commit("revert: undo").bump, "patch")
        self.assertEqual(commit("feat!: drop api").bump, "major")
        self.assertEqual(commit("docs: readme").bump, "none")
        self.assertEqual(commit("no prefix").bump, "none")

    def test_breaking_footer(self):
        positive = commit("fix: api", "BREAKING CHANGE: removed flag")
        self.assertTrue(positive.breaking)
        self.assertEqual(positive.bump, "major")
        dash = commit("fix: api", "BREAKING-CHANGE: removed flag")
        self.assertTrue(dash.breaking)
        negative = commit("fix: api", "not a breaking footer\n\nordinary body")
        self.assertFalse(negative.breaking)
        malformed = commit("fix: api", "BREAKING CHANGE:")
        self.assertFalse(malformed.breaking)

    def test_release_commit_ignored(self):
        self.assertTrue(commit("chore(release): v1.2.3 [skip ci]").release_commit)
        self.assertEqual(commit("chore(release): v1.2.3 [skip ci]").bump, "none")
        self.assertTrue(commit("chore(release): v1.2.3").release_commit)

    def test_invalid_sha_rejected(self):
        with self.assertRaises(ValueError):
            rv.Commit.parse("abc", "fix: x")


class TestNextVersion(unittest.TestCase):
    def test_bootstrap_uses_manifest(self):
        version, reason = rv.next_version("0.2.0", None, [commit("feat!: x")])
        self.assertEqual((version, reason), ("0.2.0", "bootstrap"))

    def test_bootstrap_rejects_manual_override(self):
        with self.assertRaises(ValueError):
            rv.next_version("0.2.0", None, [], "minor")

    def test_inferred_bumps(self):
        cases = [
            ([commit("fix: x")], "0.2.1"),
            ([commit("perf: x")], "0.2.1"),
            ([commit("feat: x")], "0.3.0"),
            ([commit("feat!: x")], "1.0.0"),
            ([commit("fix: x"), commit("feat: y")], "0.3.0"),
            ([commit("feat: x"), commit("feat!: y")], "1.0.0"),
        ]
        for commits, expected in cases:
            with self.subTest(expected=expected):
                version, _ = rv.next_version("0.2.0", "0.2.0", commits)
                self.assertEqual(version, expected)

    def test_docs_only_noop(self):
        version, reason = rv.next_version("0.2.0", "0.2.0", [commit("docs: x")])
        self.assertIsNone(version)
        self.assertEqual(reason, "none")

    def test_drift_without_bump_rejected(self):
        with self.assertRaises(ValueError):
            rv.next_version("0.3.0", "0.2.0", [commit("docs: x")])

    def test_manual_higher_allowed_lower_rejected(self):
        version, _ = rv.next_version("0.2.0", "0.2.0", [commit("fix: x")], "minor")
        self.assertEqual(version, "0.3.0")
        with self.assertRaises(ValueError):
            rv.next_version("0.2.0", "0.2.0", [commit("feat: x")], "patch")

    def test_manifest_at_next_version_allowed(self):
        version, _ = rv.next_version("0.3.0", "0.2.0", [commit("feat: x")])
        self.assertEqual(version, "0.3.0")

    def test_manifest_drift_rejected(self):
        with self.assertRaises(ValueError):
            rv.next_version("0.9.9", "0.2.0", [commit("feat: x")])


class TestManifestUpdate(unittest.TestCase):
    def test_root_version_updated_only(self):
        source = MANIFEST.format(version="0.2.0")
        result = rv.update_manifest(source, "0.2.0", "0.3.0")
        self.assertIn('version = "0.3.0"', result)
        self.assertIn('anyhow = "1.0"', result)
        self.assertIn('rust-version = "1.85"', result)

    def test_expected_version_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            rv.update_manifest(MANIFEST.format(version="0.2.0"), "9.9.9", "0.3.0")

    def test_lockfile_root_entry_only(self):
        source = LOCKFILE.format(version="0.2.0", checksum="0" * 64)
        result = rv.update_lockfile(source, "cryptoknife", "0.2.0", "0.3.0")
        self.assertIn('name = "anyhow"', result)
        self.assertIn('version = "1.0.103"', result)
        self.assertIn('version = "0.3.0"', result)
        self.assertIn('checksum = "' + "0" * 64 + '"', result)

    def test_lockfile_rejects_missing_local_entry(self):
        with self.assertRaises(ValueError):
            rv.update_lockfile("version = 3\n", "cryptoknife", "0.2.0", "0.3.0")


class TestChangelog(unittest.TestCase):
    NOTES = "## v0.3.0 - 2026-09-23\n\n### Funcionalidades\n\n- algo ([abc1234](https://github.com/o/r/commit/a))\n"

    def test_prepend_and_extract_roundtrip(self):
        changelog = rv.prepend_changelog("# Changelog\n", self.NOTES, "0.3.0")
        extracted = rv.extract_release_notes(changelog, "0.3.0")
        self.assertEqual(extracted, self.NOTES.strip() + "\n")

    def test_empty_existing_gets_header(self):
        changelog = rv.prepend_changelog("", self.NOTES, "0.3.0")
        self.assertTrue(changelog.startswith("# Changelog\n"))

    def test_duplicate_version_rejected(self):
        changelog = rv.prepend_changelog("# Changelog\n", self.NOTES, "0.3.0")
        with self.assertRaises(ValueError):
            rv.prepend_changelog(changelog, self.NOTES, "0.3.0")

    def test_notes_version_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            rv.prepend_changelog("# Changelog\n", self.NOTES, "0.4.0")

    def test_missing_title_rejected(self):
        with self.assertRaises(ValueError):
            rv.prepend_changelog("not markdown\n", self.NOTES, "0.3.0")


class TestRenderNotes(unittest.TestCase):
    def test_groups_and_escaping(self):
        commits = [
            commit("feat: add `x` flag"),
            commit("fix: avoid *crash*"),
            commit("feat!: drop api", "BREAKING CHANGE: removed flag"),
        ]
        notes = rv.render_notes("0.3.0", "2026-09-23", commits, "owner/repo")
        self.assertTrue(notes.startswith("## v0.3.0 - 2026-09-23\n"))
        self.assertIn("### Mudanças incompatíveis", notes)
        self.assertIn("### Funcionalidades", notes)
        self.assertIn("### Correções", notes)
        self.assertIn("\\`x\\`", notes)
        self.assertIn("\\*crash\\*", notes)
        self.assertIn(f"https://github.com/owner/repo/commit/{SHA}", notes)

    def test_release_commit_excluded(self):
        notes = rv.render_notes(
            "0.3.0", "2026-09-23",
            [commit("chore(release): v0.2.0 [skip ci]"), commit("fix: x")],
            "owner/repo",
        )
        self.assertNotIn("chore(release)", notes)

    def test_repository_format_validated(self):
        with self.assertRaises(ValueError):
            rv.render_notes("0.3.0", "2026-09-23", [], "bad repo!")

    def test_date_validated(self):
        with self.assertRaises(ValueError):
            rv.render_notes("0.3.0", "23/09/2026", [], "owner/repo")


if __name__ == "__main__":
    unittest.main()
