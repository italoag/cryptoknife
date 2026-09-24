import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "release.py"

spec = importlib.util.spec_from_file_location("ck_release", SCRIPT)
release = importlib.util.module_from_spec(spec)
sys.modules["ck_release"] = release
spec.loader.exec_module(release)

GIT_ENV = {
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.com",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.com",
    "GIT_AUTHOR_DATE": "2026-09-23T12:00:00+00:00",
    "GIT_COMMITTER_DATE": "2026-09-23T12:00:00+00:00",
}

GH_ENV_KEYS = (
    "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY", "GITHUB_ACTIONS",
    "GITHUB_REF", "GITHUB_REPOSITORY", "GH_TOKEN", "GH_REPO",
    "CRYPTOKNIFE_PLAN_SHA256",
)

MANIFEST = """[package]
name = "cryptoknife"
version = "{version}"
edition = "2021"
rust-version = "1.85"
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


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git(repo: Path, *args, env=None, check=True):
    merged = dict(os.environ)
    merged.update(GIT_ENV)
    if env:
        merged.update(env)
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, env=merged, timeout=30,
    )
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} falhou: {result.stderr}")
    return result


def write_manifest_files(repo: Path, version: str, changelog=None, crlf=False):
    nl = "\r\n" if crlf else "\n"
    (repo / "Cargo.toml").write_bytes(
        MANIFEST.format(version=version).replace("\n", nl).encode())
    (repo / "Cargo.lock").write_bytes(
        LOCKFILE.format(version=version, checksum="0" * 64).replace("\n", nl).encode())
    if changelog is not None:
        (repo / "CHANGELOG.md").write_bytes(changelog.replace("\n", nl).encode())


def init_repo(base: Path, version="0.2.0", changelog=None) -> Path:
    repo = base / "repo"
    repo.mkdir(parents=True)
    git(repo, "init", "-b", "main")
    (repo / ".gitattributes").write_text("* -text\n", encoding="utf-8")
    write_manifest_files(repo, version, changelog)
    (repo / "data.txt").write_text("dados\n", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "feat: estrutura inicial")
    return repo


def commit_file(repo: Path, name: str, content: str, message: str) -> str:
    (repo / name).write_text(content, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message)
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def invoke(*argv, env=None):
    parser = release.build_parser()
    args = parser.parse_args([str(a) for a in argv])
    patched = dict(os.environ)
    for key in GH_ENV_KEYS:
        patched.pop(key, None)
    if env:
        patched.update(env)
    with mock.patch.dict(os.environ, patched, clear=True):
        return args.func(args)


def read_plan(plan_dir: Path) -> dict:
    return json.loads((plan_dir / "_plan.json").read_text(encoding="utf-8"))


def write_plan_file(plan_dir: Path, plan: dict):
    (plan_dir / "_plan.json").write_text(json.dumps(plan), encoding="utf-8")


def prepare(repo: Path, out: Path, *extra, env=None) -> dict:
    invoke(
        "prepare", "--repo", repo, "--repository", "owner/repo",
        "--output-dir", out, *extra,
        env=env,
    )
    return read_plan(out)


class TestPrepareOffline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-release-")
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def plan_dir(self, name="plan") -> Path:
        return self.base / name

    def test_bootstrap_release(self):
        repo = init_repo(self.base)
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        plan = prepare(repo, self.plan_dir(), "--offline")
        self.assertEqual(plan["action"], "release")
        self.assertEqual(plan["reason"], "bootstrap")
        self.assertEqual(plan["version"], "0.2.0")
        self.assertEqual(plan["tag"], "v0.2.0")
        self.assertIsNone(plan["base_tag"])
        self.assertTrue(plan["dry_run"])
        self.assertTrue(plan["offline"])
        self.assertEqual(plan["source_sha"], git(repo, "rev-parse", "HEAD").stdout.strip())
        self.assertEqual(set(plan["files"]), {"Cargo.toml", "Cargo.lock", "CHANGELOG.md"})
        self.assertIsNone(plan["files"]["CHANGELOG.md"]["before_sha256"])
        for tool in ("release.py", "release_version.py"):
            self.assertTrue((self.plan_dir() / "tools" / tool).is_file())
        notes = (self.plan_dir() / "release-notes.md").read_text(encoding="utf-8")
        self.assertTrue(notes.startswith("## v0.2.0 - 2026-09-23"))
        self.assertIn("estrutura inicial", notes)

    def test_patch_bump_after_tag(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        plan = prepare(repo, self.plan_dir(), "--offline")
        self.assertEqual(plan["version"], "0.2.1")
        self.assertEqual(plan["base_tag"], "v0.2.0")
        self.assertEqual(plan["reason"], "patch")

    def test_feat_minor_and_breaking_major(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "feat: nova flag")
        plan = prepare(repo, self.plan_dir("p1"), "--offline")
        self.assertEqual(plan["version"], "0.3.0")
        commit_file(repo, "c.txt", "x", "feat!: api quebrada")
        plan = prepare(repo, self.plan_dir("p2"), "--offline")
        self.assertEqual(plan["version"], "1.0.0")

    def test_docs_only_noop(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "docs: atualiza readme")
        plan = prepare(repo, self.plan_dir(), "--offline")
        self.assertEqual(plan["action"], "noop")

    def test_unreachable_higher_tag_ignored(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        git(repo, "checkout", "--detach", "HEAD")
        sha = commit_file(repo, "side.txt", "x", "feat: ramo paralelo")
        git(repo, "tag", "v9.9.9", sha)
        git(repo, "checkout", "main")
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        plan = prepare(repo, self.plan_dir(), "--offline")
        self.assertEqual(plan["version"], "0.2.1")
        self.assertEqual(plan["base_tag"], "v0.2.0")

    def test_base_tag_version_mismatch_fails(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.5.0")
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        with self.assertRaises(release.ReleaseError):
            prepare(repo, self.plan_dir(), "--offline")

    def test_existing_conflicting_target_tag_fails(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        git(repo, "tag", "v0.2.1")
        with self.assertRaises(release.ReleaseError):
            prepare(repo, self.plan_dir(), "--offline")

    def test_existing_consistent_target_tag_resumes(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        plan = prepare(repo, self.plan_dir(), "--offline")
        invoke("apply", "--repo", repo, "--plan-dir", self.plan_dir())
        git(repo, "add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        git(repo, "commit", "-m", "chore(release): v0.2.1 [skip ci]")
        git(repo, "tag", "-a", "v0.2.1", "-m", "release")
        git(repo, "reset", "--hard", "HEAD~1")
        plan2 = prepare(repo, self.plan_dir("p2"), "--offline")
        self.assertEqual(plan2["action"], "resume")
        self.assertEqual(plan2["version"], "0.2.1")
        self.assertIsNotNone(plan2["existing_tag_sha"])

    def test_tag_tree_conflict_other_code_rejected(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        plan = prepare(repo, self.plan_dir(), "--offline")
        invoke("apply", "--repo", repo, "--plan-dir", self.plan_dir())
        (repo / "data.txt").write_text("conteúdo diferente\n", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-m", "chore(release): v0.2.1 [skip ci]")
        git(repo, "tag", "-a", "v0.2.1", "-m", "release")
        git(repo, "reset", "--hard", "HEAD~1")
        with self.assertRaises(release.ReleaseError):
            prepare(repo, self.plan_dir("p2"), "--offline")

    def test_tag_mode_difference_rejected(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        prepare(repo, self.plan_dir(), "--offline")
        invoke("apply", "--repo", repo, "--plan-dir", self.plan_dir())
        git(repo, "add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        git(repo, "update-index", "--chmod=+x", "CHANGELOG.md")
        git(repo, "commit", "-m", "chore(release): v0.2.1 [skip ci]")
        git(repo, "tag", "-a", "v0.2.1", "-m", "release")
        git(repo, "reset", "--hard", "HEAD~1")
        with self.assertRaises(release.ReleaseError):
            prepare(repo, self.plan_dir("p2"), "--offline")

    def test_tag_gitlink_difference_rejected(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige saída")
        prepare(repo, self.plan_dir(), "--offline")
        invoke("apply", "--repo", repo, "--plan-dir", self.plan_dir())
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},submod")
        git(repo, "add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        git(repo, "commit", "-m", "chore(release): v0.2.1 [skip ci]")
        git(repo, "tag", "-a", "v0.2.1", "-m", "release")
        git(repo, "reset", "--hard", "HEAD~1")
        with self.assertRaises(release.ReleaseError):
            prepare(repo, self.plan_dir("p2"), "--offline")

    @unittest.skipIf(os.name == "nt", "nomes com tab/newline exigem POSIX")
    def test_tree_entries_unusual_filenames(self):
        repo = init_repo(self.base)
        for name in ("tab\tname.txt", "unição.txt", "line\nbreak.txt"):
            (repo / name).write_text("x\n", encoding="utf-8")
        git(repo, "add", "-A")
        git(repo, "commit", "-m", "fix: nomes incomuns")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        entries = release.tree_entries(repo, head)
        for name in ("tab\tname.txt", "unição.txt", "line\nbreak.txt"):
            self.assertIn(name.encode("utf-8"), entries)
        self.assertTrue(release.prepared_tree_matches(repo, head, {}, head))

    def test_manual_bump_cannot_downgrade(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "feat: nova flag")
        with self.assertRaises(ValueError):
            prepare(repo, self.plan_dir(), "--offline", "--bump", "patch")
        plan = prepare(repo, self.plan_dir("p2"), "--offline", "--bump", "major")
        self.assertEqual(plan["version"], "1.0.0")

    def test_resume_tag_requires_auto(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        with self.assertRaises(release.ReleaseError):
            prepare(repo, self.plan_dir(), "--offline", "--resume-tag", "v0.2.0", "--bump", "minor")

    def test_resume_tag_rebuilds_plan(self):
        notes = "## v0.2.0 - 2026-09-23\n\n### Funcionalidades\n\n- inicial ([aaaaaaa](https://github.com/o/r/commit/a))\n"
        repo = init_repo(self.base, changelog="# Changelog\n\n" + notes)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: depois da tag")
        plan = prepare(repo, self.plan_dir(), "--offline", "--resume-tag", "v0.2.0")
        self.assertEqual(plan["action"], "resume")
        self.assertEqual(plan["version"], "0.2.0")
        self.assertEqual(plan["release_date"], "2026-09-23")
        peeled = git(repo, "rev-parse", "v0.2.0^{commit}").stdout.strip()
        self.assertEqual(plan["source_sha"], peeled)
        self.assertEqual(plan["existing_tag_sha"], peeled)
        for entry in plan["files"].values():
            self.assertEqual(entry["before_sha256"], entry["sha256"])
        self.assertIn("## v0.2.0", (self.plan_dir() / "release-notes.md").read_text())

    def test_resume_tag_unreachable_fails(self):
        repo = init_repo(self.base)
        git(repo, "checkout", "--detach", "HEAD")
        sha = commit_file(repo, "side.txt", "x", "feat: lado")
        git(repo, "tag", "v0.2.0", sha)
        git(repo, "checkout", "main")
        with self.assertRaises(release.ReleaseError):
            prepare(repo, self.plan_dir(), "--offline", "--resume-tag", "v0.2.0")

    def test_outputs_include_plan_hash(self):
        repo = init_repo(self.base)
        commit_file(repo, "b.txt", "x", "fix: corrige")
        out_file = self.base / "ghout.txt"
        prepare(repo, self.plan_dir(), "--offline",
                env={"GITHUB_OUTPUT": str(out_file)})
        values = dict(
            line.split("=", 1) for line in out_file.read_text().splitlines()
        )
        plan_path = self.plan_dir() / "_plan.json"
        self.assertEqual(values["plan_sha256"], sha256_bytes(plan_path.read_bytes()))
        self.assertEqual(values["version"], "0.2.0")

    def test_unicode_commit_message_in_notes(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige saída com acentuação çãõé")
        prepare(repo, self.plan_dir(), "--offline")
        notes = (self.plan_dir() / "release-notes.md").read_text(encoding="utf-8")
        self.assertIn("corrige saída com acentuação çãõé", notes)

    def test_crlf_metadata_roundtrip(self):
        repo = self.base / "crlf"
        repo.mkdir()
        git(repo, "init", "-b", "main")
        (repo / ".gitattributes").write_text("* -text\n", encoding="utf-8")
        write_manifest_files(repo, "0.2.0", crlf=True)
        git(repo, "add", "-A")
        git(repo, "commit", "-m", "feat: inicial crlf")
        plan_dir = self.base / "plan-crlf"
        plan = prepare(repo, plan_dir, "--offline")
        invoke("apply", "--repo", repo, "--plan-dir", plan_dir)
        payload = (plan_dir / "Cargo.toml").read_bytes()
        source_blob = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "blob", "HEAD:Cargo.toml"],
            capture_output=True, timeout=30,
        ).stdout
        self.assertIn(b"\r\n", source_blob)
        self.assertIn(b"\r\n", payload)
        self.assertEqual(
            plan["files"]["Cargo.toml"]["before_sha256"], sha256_bytes(source_blob)
        )


class TestPrepareOnline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-release-")
        self.base = Path(self.tmp.name)
        self.env = {"GITHUB_REF": "refs/heads/main"}

    def tearDown(self):
        self.tmp.cleanup()

    def remote_state(self, remote_sha, releases=None):
        releases = releases or {}
        return [
            mock.patch.object(release, "git_remote",
                              return_value=SimpleNamespace(stdout="")),
            mock.patch.object(release, "gh_remote_main", return_value=remote_sha),
            mock.patch.object(release, "gh_release_for_tag",
                              side_effect=lambda repo_, tag: releases.get(tag)),
        ]

    def test_ref_outside_main_rejected(self):
        repo = init_repo(self.base)
        with self.assertRaises(release.ReleaseError):
            prepare(repo, self.base / "plan", env={"GITHUB_REF": "refs/heads/feature"})

    def test_superseded_new_candidate_noop(self):
        repo = init_repo(self.base)
        other = commit_file(repo, "b.txt", "x", "fix: concorrente")
        git(repo, "reset", "--hard", "HEAD~1")
        with mock.patch.object(release, "git_remote",
                               return_value=SimpleNamespace(stdout="")), \
             mock.patch.object(release, "gh_remote_main", return_value=other), \
             mock.patch.object(release, "gh_release_for_tag", return_value=None):
            plan = prepare(repo, self.base / "plan", env=self.env)
        self.assertEqual(plan["action"], "noop")
        self.assertEqual(plan["reason"], "superseded")

    def test_unpublished_base_tag_blocks_skip(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: depois")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        with mock.patch.object(release, "git_remote",
                               return_value=SimpleNamespace(stdout="")), \
             mock.patch.object(release, "gh_remote_main", return_value=head), \
             mock.patch.object(release, "gh_release_for_tag", return_value=None):
            with self.assertRaises(release.ReleaseError):
                prepare(repo, self.base / "plan", env=self.env)

    def test_unpublished_base_tag_docs_only_errors(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "docs: pendente")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        with mock.patch.object(release, "git_remote",
                               return_value=SimpleNamespace(stdout="")), \
             mock.patch.object(release, "gh_remote_main", return_value=head), \
             mock.patch.object(release, "gh_release_for_tag", return_value=None):
            with self.assertRaises(release.ReleaseError):
                prepare(repo, self.base / "plan", env=self.env)

    def test_unpublished_tag_on_head_auto_resumes(self):
        repo = init_repo(self.base, changelog="# Changelog\n\n## v0.2.0 - 2026-09-23\n\n### Funcionalidades\n\n- inicial ([aaaaaaa](https://github.com/o/r/commit/a))\n")
        git(repo, "tag", "v0.2.0")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()
        with mock.patch.object(release, "git_remote",
                               return_value=SimpleNamespace(stdout="")), \
             mock.patch.object(release, "gh_remote_main", return_value=head), \
             mock.patch.object(release, "gh_release_for_tag", return_value=None):
            plan = prepare(repo, self.base / "plan", env=self.env)
        self.assertEqual(plan["action"], "resume")
        self.assertEqual(plan["version"], "0.2.0")
        self.assertEqual(plan["source_sha"], head)
        self.assertEqual(plan["existing_tag_sha"], head)
        self.assertEqual(plan["release_date"], "2026-09-23")

    def test_original_event_rerun_resumes_not_superseded(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige")
        plan = prepare(repo, self.base / "p1", "--offline")
        invoke("apply", "--repo", repo, "--plan-dir", self.base / "p1")
        git(repo, "add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        git(repo, "commit", "-m", "chore(release): v0.2.1 [skip ci]")
        git(repo, "tag", "-a", "v0.2.1", "-m", "release")
        release_sha = git(repo, "rev-parse", "HEAD").stdout.strip()
        git(repo, "reset", "--hard", "HEAD~1")
        with mock.patch.object(release, "git_remote",
                               return_value=SimpleNamespace(stdout="")), \
             mock.patch.object(release, "gh_remote_main", return_value=release_sha), \
             mock.patch.object(release, "gh_release_for_tag", return_value=None):
            plan2 = prepare(repo, self.base / "p2", env=self.env)
        self.assertEqual(plan2["action"], "resume")
        self.assertEqual(plan2["version"], "0.2.1")
        self.assertEqual(plan2["existing_tag_sha"], release_sha)


class TestRunEncoding(unittest.TestCase):
    def captured_kwargs(self, text):
        captured = {}

        def fake(argv, **kwargs):
            captured.update(kwargs)
            empty = "" if text else b""
            return SimpleNamespace(returncode=0, stdout=empty, stderr=empty)

        with mock.patch.object(release.subprocess, "run", side_effect=fake):
            release.run(["echo", "ok"], text=text)
        return captured

    def test_text_mode_uses_utf8(self):
        self.assertEqual(self.captured_kwargs(True)["encoding"], "utf-8")

    def test_binary_mode_no_encoding(self):
        self.assertIsNone(self.captured_kwargs(False)["encoding"])


class TestGhApiStatus(unittest.TestCase):
    def make_result(self, status, body="{}", rc=0, sep="\n\n"):
        return SimpleNamespace(
            returncode=rc, stdout=f"HTTP/2 {status}{sep}{body}", stderr="",
        )

    def test_404_absent_403_error(self):
        results = [self.make_result(404, rc=1), self.make_result(200, body="[]")]
        with mock.patch.object(release, "run", side_effect=results):
            self.assertIsNone(release.gh_release_for_tag("o/r", "v1.0.0"))
        for status in (403, 500):
            with mock.patch.object(release, "run", return_value=self.make_result(status, rc=1)):
                with self.assertRaises(release.ReleaseError):
                    release.gh_release_for_tag("o/r", "v1.0.0")

    def test_draft_found_via_list(self):
        draft = {"draft": True, "tag_name": "v0.2.0",
                 "assets": [{"name": "cryptoknife-0.2.0.crate"}]}
        results = [self.make_result(404, rc=1),
                   self.make_result(200, body=json.dumps([draft]))]
        with mock.patch.object(release, "run", side_effect=results) as mocked:
            rel = release.gh_release_for_tag("o/r", "v0.2.0")
        self.assertEqual(rel, draft)
        endpoints = [call.args[0][-1] for call in mocked.call_args_list]
        self.assertEqual(endpoints, [
            "repos/o/r/releases/tags/v0.2.0",
            "repos/o/r/releases?per_page=100&page=1",
        ])

    def test_draft_found_on_second_page(self):
        draft = {"draft": True, "tag_name": "v0.2.0", "assets": [{"name": "a"}]}
        page1 = [{"draft": False, "tag_name": f"v9.{i}.0", "assets": []}
                 for i in range(100)]
        results = [
            self.make_result(404, rc=1),
            self.make_result(200, body=json.dumps(page1)),
            self.make_result(200, body=json.dumps([draft])),
        ]
        with mock.patch.object(release, "run", side_effect=results) as mocked:
            rel = release.gh_release_for_tag("o/r", "v0.2.0")
        self.assertEqual(rel["assets"], [{"name": "a"}])
        endpoints = [call.args[0][-1] for call in mocked.call_args_list]
        self.assertTrue(endpoints[-1].endswith("page=2"))

    def test_tag_200_skips_list(self):
        published = {"draft": False, "tag_name": "v0.2.0", "assets": []}
        with mock.patch.object(release, "run",
                               return_value=self.make_result(200, body=json.dumps(published))) as mocked:
            rel = release.gh_release_for_tag("o/r", "v0.2.0")
        self.assertEqual(rel, published)
        self.assertEqual(mocked.call_count, 1)

    def test_list_http_errors_raise(self):
        for status in (403, 500, 404):
            results = [self.make_result(404, rc=1),
                       self.make_result(status, body="[]", rc=1)]
            with mock.patch.object(release, "run", side_effect=results):
                with self.assertRaises(release.ReleaseError, msg=str(status)):
                    release.gh_release_for_tag("o/r", "v1.0.0")

    def test_malformed_list_rejected(self):
        for body in ("{}", json.dumps(["x"]), "não é json"):
            results = [self.make_result(404, rc=1), self.make_result(200, body=body)]
            with mock.patch.object(release, "run", side_effect=results):
                with self.assertRaises(release.ReleaseError, msg=body):
                    release.gh_release_for_tag("o/r", "v1.0.0")

    def test_malformed_draft_from_list_rejected(self):
        drafts = [
            {"tag_name": "v1.0.0", "assets": []},
            {"draft": "yes", "tag_name": "v1.0.0", "assets": []},
            {"draft": True, "tag_name": "v1.0.0"},
            [{"draft": True, "tag_name": "v1.0.0", "assets": []},
             {"draft": True, "tag_name": "v1.0.0", "assets": []}],
        ]
        for draft in drafts:
            body = json.dumps(draft if isinstance(draft, list) else [draft])
            results = [self.make_result(404, rc=1), self.make_result(200, body=body)]
            with mock.patch.object(release, "run", side_effect=results):
                with self.assertRaises(release.ReleaseError, msg=body):
                    release.gh_release_for_tag("o/r", "v1.0.0")

    def test_200_nonzero_cli_fails(self):
        with mock.patch.object(release, "run", return_value=self.make_result(200, rc=1)):
            with self.assertRaises(release.ReleaseError):
                release.gh_release_for_tag("o/r", "v1.0.0")

    def test_crlf_header_parsed(self):
        body = json.dumps({"draft": True, "tag_name": "v1.0.0", "assets": []})
        with mock.patch.object(release, "run",
                               return_value=self.make_result(200, body=body, sep="\r\n\r\n")):
            result = release.gh_release_for_tag("o/r", "v1.0.0")
        self.assertTrue(result["draft"])

    def test_malformed_release_rejected(self):
        for body in ("{}", json.dumps({"draft": "yes", "tag_name": "v1.0.0", "assets": []}),
                     json.dumps({"draft": True, "tag_name": "v9.9.9", "assets": []}),
                     json.dumps({"draft": True, "tag_name": "v1.0.0"})):
            with mock.patch.object(release, "run", return_value=self.make_result(200, body=body)):
                with self.assertRaises(release.ReleaseError, msg=body):
                    release.gh_release_for_tag("o/r", "v1.0.0")


class TestPlanValidation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-release-")
        self.base = Path(self.tmp.name)
        self.repo = init_repo(self.base)
        git(self.repo, "tag", "v0.2.0")
        commit_file(self.repo, "b.txt", "x", "fix: corrige")
        self.plan_dir = self.base / "plan"
        self.plan = prepare(self.repo, self.plan_dir, "--offline")

    def tearDown(self):
        self.tmp.cleanup()

    def rewrite(self, **changes):
        plan = dict(self.plan)
        plan.update(changes)
        write_plan_file(self.plan_dir, plan)
        return plan

    def test_extra_top_field_rejected(self):
        plan = self.rewrite(**{"unexpected": 1})
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)

    def test_load_plan_env_hash(self):
        good = sha256_bytes((self.plan_dir / "_plan.json").read_bytes())
        with mock.patch.dict(os.environ, {"CRYPTOKNIFE_PLAN_SHA256": good}):
            release.load_plan(self.plan_dir)
        for bad in ("xyz", "0" * 64):
            with mock.patch.dict(os.environ, {"CRYPTOKNIFE_PLAN_SHA256": bad}):
                with self.assertRaises(release.ReleaseError, msg=bad):
                    release.load_plan(self.plan_dir)

    def test_schema_version_bool_rejected(self):
        self.rewrite(schema_version=True)
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)

    def test_missing_field_rejected(self):
        plan = dict(self.plan)
        del plan["reason"]
        write_plan_file(self.plan_dir, plan)
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)

    def test_missing_managed_file_rejected(self):
        files = dict(self.plan["files"])
        del files["Cargo.lock"]
        self.rewrite(files=files)
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)

    def test_extra_managed_file_rejected(self):
        files = dict(self.plan["files"])
        files["../evil.txt"] = {"before_sha256": None, "sha256": "0" * 64}
        self.rewrite(files=files)
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)

    def test_corrupted_payload_rejected(self):
        (self.plan_dir / "Cargo.toml").write_text("corrompido", encoding="utf-8")
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)

    def test_bad_source_sha_rejected(self):
        self.rewrite(source_sha="xyz")
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)

    def test_wrong_metadata_version_rejected(self):
        self.rewrite(version="9.9.9")
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)

    def test_notes_wrong_date_rejected(self):
        notes = (self.plan_dir / "release-notes.md").read_bytes().replace(
            b"2026-09-23", b"2026-09-24", 1)
        (self.plan_dir / "release-notes.md").write_bytes(notes)
        plan = dict(self.plan)
        plan["notes_sha256"] = sha256_bytes(notes)
        write_plan_file(self.plan_dir, plan)
        with self.assertRaises(release.ReleaseError):
            release.load_plan(self.plan_dir)


class TestRepoBoundVerification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-release-")
        self.base = Path(self.tmp.name)
        self.repo = init_repo(self.base)
        git(self.repo, "tag", "v0.2.0")
        commit_file(self.repo, "b.txt", "x", "fix: corrige")
        self.plan_dir = self.base / "plan"
        self.plan = prepare(self.repo, self.plan_dir, "--offline")

    def tearDown(self):
        self.tmp.cleanup()

    def test_before_hash_not_committed_source_rejected(self):
        plan = dict(self.plan)
        files = dict(plan["files"])
        files["Cargo.toml"] = dict(files["Cargo.toml"], before_sha256="f" * 64)
        plan["files"] = files
        write_plan_file(self.plan_dir, plan)
        with self.assertRaises(release.ReleaseError):
            invoke("apply", "--repo", self.repo, "--plan-dir", self.plan_dir)

    def test_lock_dependency_change_rejected(self):
        payload = (self.plan_dir / "Cargo.lock").read_bytes().replace(
            b'1.0.103', b'9.9.9')
        (self.plan_dir / "Cargo.lock").write_bytes(payload)
        plan = dict(self.plan)
        files = dict(plan["files"])
        files["Cargo.lock"] = dict(files["Cargo.lock"], sha256=sha256_bytes(payload))
        plan["files"] = files
        write_plan_file(self.plan_dir, plan)
        with self.assertRaises(release.ReleaseError):
            invoke("apply", "--repo", self.repo, "--plan-dir", self.plan_dir)

    def test_head_mismatch_rejected(self):
        commit_file(self.repo, "c.txt", "x", "fix: muda head")
        with self.assertRaises(release.ReleaseError):
            invoke("apply", "--repo", self.repo, "--plan-dir", self.plan_dir)


class TestGitBlob(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-release-")
        self.repo = init_repo(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_file_returns_none(self):
        self.assertIsNone(release.git_blob(self.repo, "HEAD", "CHANGELOG.md"))

    def test_bad_ref_raises_not_absent(self):
        with self.assertRaises(release.ReleaseError):
            release.git_blob(self.repo, "0" * 40, "Cargo.toml")

    def test_non_blob_entry_rejected(self):
        (self.repo / "sub").mkdir()
        commit_file(self.repo, "sub/file.txt", "x", "fix: cria subdir")
        with self.assertRaises(release.ReleaseError):
            release.git_blob(self.repo, "HEAD", "sub")


class TestApply(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-release-")
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_apply_and_idempotent(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "fix: corrige")
        plan_dir = self.base / "plan"
        prepare(repo, plan_dir, "--offline")
        invoke("apply", "--repo", repo, "--plan-dir", plan_dir)
        self.assertIn('version = "0.2.1"', (repo / "Cargo.toml").read_text())
        self.assertTrue((repo / "CHANGELOG.md").is_file())
        self.assertIn("## v0.2.1", (repo / "CHANGELOG.md").read_text())
        invoke("apply", "--repo", repo, "--plan-dir", plan_dir)

    @unittest.skipIf(os.name == "nt", "modo executável exige POSIX")
    def test_apply_preserves_executable_mode(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        git(repo, "update-index", "--chmod=+x", "Cargo.toml")
        git(repo, "commit", "-m", "fix: modo executável")
        plan_dir = self.base / "plan"
        prepare(repo, plan_dir, "--offline")
        invoke("apply", "--repo", repo, "--plan-dir", plan_dir)
        self.assertTrue(os.stat(repo / "Cargo.toml").st_mode & 0o111)

    def test_apply_noop_rejected(self):
        repo = init_repo(self.base)
        git(repo, "tag", "v0.2.0")
        commit_file(repo, "b.txt", "x", "docs: apenas docs")
        plan_dir = self.base / "plan"
        prepare(repo, plan_dir, "--offline")
        with self.assertRaises(release.ReleaseError):
            invoke("apply", "--repo", repo, "--plan-dir", plan_dir)


class FakeGh:
    def __init__(self, tag="v0.2.1"):
        self.release = None
        self.calls = []
        self.tag = tag

    def api(self, endpoint, method="GET"):
        if "/releases/tags/" in endpoint:
            if self.release is None or self.release["draft"]:
                return 404, "{}", 1
            return 200, json.dumps(self.release), 0
        if "/releases?per_page=100&page=" in endpoint:
            return 200, json.dumps([self.release] if self.release is not None else []), 0
        if endpoint.endswith("git/ref/heads/main"):
            return 200, json.dumps({"object": {"sha": "0" * 40}}), 0
        raise AssertionError(f"endpoint gh inesperado: {endpoint}")

    def run(self, argv, **kwargs):
        self.calls.append([str(a) for a in argv])
        if argv[1] == "api":
            status, body, rc = self.api(argv[-1])
            return SimpleNamespace(returncode=rc, stdout=f"HTTP/2 {status}\n\n{body}", stderr="")
        if argv[1:3] == ["release", "create"]:
            self.release = {"draft": True, "tag_name": argv[3], "body": "", "assets": []}
            notes = Path(argv[argv.index("--notes-file") + 1]).read_text()
            self.release["body"] = notes
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[1:3] == ["release", "upload"]:
            assets = self.release.setdefault("assets", [])
            names = {a["name"] for a in assets}
            for path in argv[4:]:
                if str(path).startswith("-"):
                    break
                path = Path(path)
                if path.name not in names:
                    assets.append({
                        "name": path.name,
                        "digest": f"sha256:{sha256_bytes(path.read_bytes())}",
                    })
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[1:3] == ["release", "edit"]:
            self.calls[-1].append("--edited")
            self.release["draft"] = False
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[1:3] == ["release", "download"]:
            raise AssertionError("download inesperado")
        raise AssertionError(f"comando gh inesperado: {argv}")


class PublishFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-release-")
        self.base = Path(self.tmp.name)
        self.repo = init_repo(self.base)
        git(self.repo, "tag", "v0.2.0")
        commit_file(self.repo, "b.txt", "x", "fix: corrige")
        self.bare = self.base / "remote.git"
        git(self.base, "init", "--bare", "-b", "main", self.bare)
        git(self.repo, "remote", "add", "origin", str(self.bare))
        git(self.repo, "push", "-u", "origin", "main", "--tags")
        self.plan_dir = self.base / "plan"
        prepare(self.repo, self.plan_dir, "--offline")
        plan = read_plan(self.plan_dir)
        plan["dry_run"] = False
        plan["offline"] = False
        write_plan_file(self.plan_dir, plan)
        invoke("apply", "--repo", self.repo, "--plan-dir", self.plan_dir)
        self.assets_dir = self.base / "assets"
        self.assets_dir.mkdir()
        local = {}
        for name in release.release_assets(plan["version"]):
            if name == "SHA256SUMS":
                continue
            payload = self.plan_dir / name
            data = payload.read_bytes() if payload.exists() else name.encode()
            (self.assets_dir / name).write_bytes(data)
            local[name] = sha256_bytes(data)
        (self.assets_dir / "SHA256SUMS").write_text(
            "".join(f"{local[n]}  {n}\n" for n in sorted(local)), encoding="utf-8"
        )
        self.gh = FakeGh()
        self.env = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_REPOSITORY": "owner/repo",
        }
        self.refresh_plan_hash()
        self.real_run = release.run

    def tearDown(self):
        self.tmp.cleanup()

    def refresh_plan_hash(self):
        self.env["CRYPTOKNIFE_PLAN_SHA256"] = sha256_bytes(
            (self.plan_dir / "_plan.json").read_bytes()
        )

    def fake_run(self, argv, **kwargs):
        argv = [str(a) for a in argv]
        if argv[0] == "gh":
            result = self.gh.run(argv, **kwargs)
            if kwargs.get("check", True) and result.returncode != 0 and not (
                argv[1] == "api" and "HTTP/2 404" in result.stdout
            ):
                raise release.ReleaseError(f"gh falhou: {result.returncode}")
            return result
        return self.real_run(argv, **kwargs)

    def publish(self):
        with mock.patch.object(release, "run", side_effect=self.fake_run):
            return invoke(
                "publish", "--repo", self.repo, "--plan-dir", self.plan_dir,
                "--assets-dir", self.assets_dir, env=self.env,
            )

    def remote_has_tag(self, tag="v0.2.1") -> bool:
        return git(self.bare, "rev-parse", "-q", "--verify", f"refs/tags/{tag}", check=False).returncode == 0

    def setup_existing_tag(self) -> str:
        git(self.repo, "add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        git(self.repo, "commit", "-m", "chore(release): v0.2.1 [skip ci]")
        git(self.repo, "tag", "-a", "v0.2.1", "-m", "release")
        git(self.repo, "push", "origin", "main", "refs/tags/v0.2.1")
        peeled = git(self.repo, "rev-parse", "v0.2.1^{commit}").stdout.strip()
        plan = read_plan(self.plan_dir)
        plan["existing_tag_sha"] = peeled
        plan["action"] = "resume"
        plan["source_sha"] = peeled
        for entry in plan["files"].values():
            entry["before_sha256"] = entry["sha256"]
        write_plan_file(self.plan_dir, plan)
        self.refresh_plan_hash()
        return peeled

    def marker(self, peeled):
        return release.DRAFT_MARKER.format(tag="v0.2.1", source=peeled)


class TestPublish(PublishFixture):
    def test_refuses_dry_run_and_offline(self):
        for flag in ("dry_run", "offline"):
            plan = read_plan(self.plan_dir)
            plan[flag] = True
            write_plan_file(self.plan_dir, plan)
            self.refresh_plan_hash()
            with mock.patch.object(release, "run", side_effect=self.fake_run):
                with self.assertRaises(release.ReleaseError):
                    self.publish()
            mutating = [c for c in self.gh.calls if c[1] != "api"]
            self.assertEqual(mutating, [])
            plan[flag] = False
            write_plan_file(self.plan_dir, plan)
            self.refresh_plan_hash()

    def test_missing_trusted_hash_refused(self):
        env = {k: v for k, v in self.env.items() if k != "CRYPTOKNIFE_PLAN_SHA256"}
        with self.assertRaises(release.ReleaseError):
            invoke("publish", "--repo", self.repo, "--plan-dir", self.plan_dir,
                   "--assets-dir", self.assets_dir, env=env)
        env = dict(self.env, CRYPTOKNIFE_PLAN_SHA256="xyz")
        with self.assertRaises(release.ReleaseError):
            invoke("publish", "--repo", self.repo, "--plan-dir", self.plan_dir,
                   "--assets-dir", self.assets_dir, env=env)
        self.assertEqual(self.gh.calls, [])
        self.assertFalse(self.remote_has_tag())

    def test_stale_plan_hash_rejected(self):
        plan = read_plan(self.plan_dir)
        plan["reason"] = "tampered"
        write_plan_file(self.plan_dir, plan)
        with self.assertRaises(release.ReleaseError):
            self.publish()
        self.assertEqual(self.gh.calls, [])
        self.assertFalse(self.remote_has_tag())

    def test_wrong_env_rejected(self):
        for key, value in (
            ("GITHUB_ACTIONS", "false"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_REPOSITORY", "other/repo"),
        ):
            env = dict(self.env, **{key: value})
            with self.assertRaises(release.ReleaseError):
                invoke("publish", "--repo", self.repo, "--plan-dir", self.plan_dir,
                       "--assets-dir", self.assets_dir, env=env)

    def test_full_publish_flow(self):
        result = self.publish()
        self.assertEqual(result, 0)
        remote_main = git(self.bare, "rev-parse", "main").stdout.strip()
        local_head = git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(remote_main, local_head)
        self.assertTrue(self.remote_has_tag())
        message = git(self.repo, "log", "-1", "--format=%s").stdout.strip()
        self.assertEqual(message, "chore(release): v0.2.1 [skip ci]")
        self.assertFalse(self.gh.release["draft"])
        self.assertEqual(len(self.gh.release["assets"]), 7)
        self.assertIn("cryptoknife-release tag=v0.2.1", self.gh.release["body"])
        edit = [c for c in self.gh.calls if c[1:3] == ["release", "edit"]][0]
        self.assertIn("--latest", edit)

    def test_rerun_after_atomic_push_no_second_push(self):
        peeled = self.setup_existing_tag()
        self.gh.release = None
        pushes = []
        real_remote = release.git_remote

        def recording(repo_, *a, **kw):
            if a and a[0] == "push":
                pushes.append(a)
            return real_remote(repo_, *a, **kw)

        with mock.patch.object(release, "git_remote", side_effect=recording), \
             mock.patch.object(release, "run", side_effect=self.fake_run):
            result = invoke(
                "publish", "--repo", self.repo, "--plan-dir", self.plan_dir,
                "--assets-dir", self.assets_dir, env=self.env,
            )
        self.assertEqual(result, 0)
        self.assertEqual(pushes, [])
        self.assertFalse(self.gh.release["draft"])

    def test_publish_retry_after_failed_gh_create(self):
        first = self.publish()
        self.assertEqual(first, 0)
        self.assertTrue(self.remote_has_tag())
        git(self.repo, "reset", "--hard", "HEAD~1")
        git(self.repo, "checkout", "--detach", "HEAD")
        plan = read_plan(self.plan_dir)
        peeled = git(self.repo, "rev-parse", "v0.2.1^{commit}").stdout.strip()
        plan["action"] = "resume"
        plan["existing_tag_sha"] = peeled
        write_plan_file(self.plan_dir, plan)
        self.refresh_plan_hash()
        self.gh.release = None
        invoke("apply", "--repo", self.repo, "--plan-dir", self.plan_dir)
        with mock.patch.object(release, "run", side_effect=self.fake_run):
            result = invoke(
                "publish", "--repo", self.repo, "--plan-dir", self.plan_dir,
                "--assets-dir", self.assets_dir, env=self.env,
            )
        self.assertEqual(result, 0)
        remote_tag = git(self.bare, "rev-parse", "v0.2.1^{commit}").stdout.strip()
        self.assertEqual(remote_tag, peeled)

    def test_stale_remote_main_blocks_push(self):
        other = self.base / "other"
        git(self.base, "clone", self.bare, other)
        commit_file(other, "c.txt", "x", "fix: commit concorrente")
        git(other, "push", "origin", "main")
        with self.assertRaises(release.ReleaseError):
            self.publish()
        self.assertFalse(self.remote_has_tag())
        remote_main = git(self.bare, "rev-parse", "main").stdout.strip()
        self.assertEqual(remote_main, git(other, "rev-parse", "HEAD").stdout.strip())

    def test_atomic_push_rejects_stale_refs(self):
        git(self.repo, "add", "Cargo.toml", "Cargo.lock", "CHANGELOG.md")
        git(self.repo, "commit", "-m", "chore(release): v0.2.1 [skip ci]")
        git(self.repo, "tag", "-a", "v0.2.1", "-m", "release")
        release.git_remote(self.repo, "fetch", "origin",
                           "refs/heads/main:refs/remotes/origin/main", "--tags")
        other = self.base / "other"
        git(self.base, "clone", self.bare, other)
        commit_file(other, "c.txt", "x", "fix: corrida")
        git(other, "push", "origin", "main")
        with self.assertRaises(release.ReleaseError):
            release.git_remote(self.repo, "push", "--atomic", "origin",
                               "HEAD:refs/heads/main", "refs/tags/v0.2.1")
        self.assertFalse(self.remote_has_tag())

    def test_existing_draft_identical_assets_skips_upload(self):
        peeled = self.setup_existing_tag()
        marker = self.marker(peeled)
        assets = [
            {"name": name,
             "digest": f"sha256:{sha256_bytes((self.assets_dir / name).read_bytes())}"}
            for name in release.release_assets("0.2.1")
        ]
        self.gh.release = {"draft": True, "tag_name": "v0.2.1", "body": marker, "assets": assets}
        result = self.publish()
        self.assertEqual(result, 0)
        uploads = [c for c in self.gh.calls if c[1:3] == ["release", "upload"]]
        self.assertEqual(uploads, [])
        apis = [c[-1] for c in self.gh.calls if c[1] == "api"]
        self.assertTrue(any("releases?per_page=100" in e for e in apis))
        self.assertFalse(self.gh.release["draft"])

    def test_conflicting_draft_asset_fails(self):
        peeled = self.setup_existing_tag()
        self.gh.release = {
            "draft": True, "tag_name": "v0.2.1", "body": self.marker(peeled),
            "assets": [{"name": "CHANGELOG.md", "digest": "sha256:" + "0" * 64}],
        }
        with self.assertRaises(release.ReleaseError):
            self.publish()
        edits = [c for c in self.gh.calls if c[1:3] == ["release", "edit"]]
        self.assertEqual(edits, [])

    def test_foreign_draft_without_marker_fails(self):
        self.setup_existing_tag()
        self.gh.release = {"draft": True, "tag_name": "v0.2.1", "body": "draft humano", "assets": []}
        with self.assertRaises(release.ReleaseError):
            self.publish()

    def test_published_complete_noop(self):
        assets = [{"name": n, "digest": "sha256:" + "0" * 64}
                  for n in release.release_assets("0.2.1")]
        self.gh.release = {"draft": False, "tag_name": "v0.2.1", "body": "", "assets": assets}
        result = self.publish()
        self.assertEqual(result, 0)
        edits = [c for c in self.gh.calls if c[1:3] == ["release", "edit"]]
        self.assertEqual(edits, [])

    def test_published_incomplete_fails(self):
        self.gh.release = {"draft": False, "tag_name": "v0.2.1", "body": "", "assets": []}
        with self.assertRaises(release.ReleaseError):
            self.publish()

    def test_partial_upload_failure_keeps_draft(self):
        def flaky(argv, **kw):
            if argv[1:3] == ["release", "upload"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="boom")
            return FakeGh.run(self.gh, argv, **kw)
        self.gh.run = flaky
        with self.assertRaises(release.ReleaseError):
            self.publish()
        edits = [c for c in self.gh.calls if c[1:3] == ["release", "edit"]]
        self.assertEqual(edits, [])

    def test_missing_assets_after_upload_fails(self):
        def noop_upload(argv, **kw):
            if argv[1:3] == ["release", "upload"]:
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            return FakeGh.run(self.gh, argv, **kw)
        self.gh.run = noop_upload
        with self.assertRaises(release.ReleaseError):
            self.publish()
        edits = [c for c in self.gh.calls if c[1:3] == ["release", "edit"]]
        self.assertEqual(edits, [])

    def test_retry_after_failed_edit_no_duplicate_upload(self):
        edits = {"count": 0}

        def flaky(argv, **kw):
            if argv[1:3] == ["release", "edit"]:
                edits["count"] += 1
                if edits["count"] == 1:
                    return SimpleNamespace(returncode=1, stdout="", stderr="boom")
            return FakeGh.run(self.gh, argv, **kw)

        self.gh.run = flaky
        with self.assertRaises(release.ReleaseError):
            self.publish()
        self.assertTrue(self.gh.release["draft"])
        self.assertEqual(len(self.gh.release["assets"]), 7)

        git(self.repo, "reset", "--hard", "HEAD~1")
        git(self.repo, "checkout", "--detach", "HEAD")
        plan = read_plan(self.plan_dir)
        peeled = git(self.repo, "rev-parse", "v0.2.1^{commit}").stdout.strip()
        plan["action"] = "resume"
        plan["existing_tag_sha"] = peeled
        write_plan_file(self.plan_dir, plan)
        self.refresh_plan_hash()
        invoke("apply", "--repo", self.repo, "--plan-dir", self.plan_dir)
        self.gh.run = lambda argv, **kw: FakeGh.run(self.gh, argv, **kw)
        result = self.publish()
        self.assertEqual(result, 0)
        uploads = [c for c in self.gh.calls if c[1:3] == ["release", "upload"]]
        creates = [c for c in self.gh.calls if c[1:3] == ["release", "create"]]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(len(creates), 1)
        self.assertFalse(self.gh.release["draft"])
        self.assertEqual(len(self.gh.release["assets"]), 7)

    def test_head_mismatch_rejected_before_refs(self):
        commit_file(self.repo, "c.txt", "x", "fix: outro commit")
        with self.assertRaises(release.ReleaseError):
            self.publish()
        self.assertFalse(self.remote_has_tag())

    def test_catalog_defects_rejected_before_push(self):
        for mutate in (
            lambda p: p.write_text("", encoding="utf-8"),
            lambda p: p.write_text("\n".join(p.read_text().splitlines()[:5]) + "\n", encoding="utf-8"),
            lambda p: p.write_text(p.read_text() + p.read_text().splitlines()[0] + "\n", encoding="utf-8"),
            lambda p: p.write_text(p.read_text() + f"{'0' * 64}  SHA256SUMS\n", encoding="utf-8"),
        ):
            sums = self.assets_dir / "SHA256SUMS"
            original = sums.read_bytes()
            mutate(sums)
            try:
                with self.assertRaises(release.ReleaseError):
                    self.publish()
            finally:
                sums.write_bytes(original)
        self.assertFalse(self.remote_has_tag())

    def test_extra_asset_file_rejected(self):
        extra = self.assets_dir / "extra.bin"
        extra.write_bytes(b"x")
        try:
            with self.assertRaises(release.ReleaseError):
                self.publish()
        finally:
            extra.unlink()
        self.assertFalse(self.remote_has_tag())

    @unittest.skipIf(os.name == "nt", "fileMode exige POSIX")
    def test_fresh_publish_mode_change_rejected(self):
        os.chmod(self.repo / "Cargo.toml", 0o755)
        with self.assertRaises(release.ReleaseError):
            self.publish()
        self.assertFalse(self.remote_has_tag())

    def test_changelog_asset_mismatch_rejected(self):
        changelog = self.assets_dir / "CHANGELOG.md"
        changelog.write_bytes(b"divergente\n")
        sums = self.assets_dir / "SHA256SUMS"
        lines = [
            f"{sha256_bytes(changelog.read_bytes())}  CHANGELOG.md"
            if line.endswith("CHANGELOG.md") else line
            for line in sums.read_text().splitlines()
        ]
        sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(release.ReleaseError):
            self.publish()
        self.assertFalse(self.remote_has_tag())


class TestPublishLatestFlag(PublishFixture):
    def test_older_resume_not_latest_over_newer_published(self):
        peeled = self.setup_existing_tag()
        newer = release.release_assets("0.3.0")
        releases = {"v0.2.1": None}
        def api(endpoint, method="GET"):
            if "/releases/tags/v0.3.0" in endpoint:
                return 200, json.dumps({
                    "draft": False, "tag_name": "v0.3.0",
                    "assets": [{"name": n} for n in newer],
                }), 0
            return FakeGh.api(self.gh, endpoint, method)
        self.gh.api = api
        git(self.repo, "tag", "v0.3.0")
        git(self.repo, "push", "origin", "refs/tags/v0.3.0")
        other = self.base / "other"
        git(self.base, "clone", self.bare, other)
        commit_file(other, "c.txt", "x", "feat: avança main")
        git(other, "push", "origin", "main")
        result = self.publish()
        self.assertEqual(result, 0)
        edit = [c for c in self.gh.calls if c[1:3] == ["release", "edit"]][0]
        self.assertIn("--latest=false", edit)

    def test_newer_draft_does_not_block_latest(self):
        peeled = self.setup_existing_tag()
        draft_newer = {"draft": True, "tag_name": "v0.3.0", "assets": []}
        def api(endpoint, method="GET"):
            if "/releases/tags/v0.3.0" in endpoint:
                return 404, "{}", 1
            if "/releases?per_page=100&page=" in endpoint:
                releases = [draft_newer]
                if self.gh.release is not None:
                    releases.append(self.gh.release)
                return 200, json.dumps(releases), 0
            return FakeGh.api(self.gh, endpoint, method)
        self.gh.api = api
        git(self.repo, "tag", "v0.3.0")
        git(self.repo, "push", "origin", "refs/tags/v0.3.0")
        result = self.publish()
        self.assertEqual(result, 0)
        edit = [c for c in self.gh.calls if c[1:3] == ["release", "edit"]][0]
        self.assertIn("--latest", edit)
        self.assertNotIn("--latest=false", edit)


class TestCollect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-release-")
        self.base = Path(self.tmp.name)
        self.repo = init_repo(self.base)
        git(self.repo, "tag", "v0.2.0")
        commit_file(self.repo, "b.txt", "x", "fix: corrige")
        self.plan_dir = self.base / "plan"
        self.plan = prepare(self.repo, self.plan_dir, "--offline")
        self.version = self.plan["version"]
        self.artifacts = self.base / "downloads"
        self.artifacts.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def archive_dir(self, name: str, content: bytes, with_sums=True) -> Path:
        sub = self.artifacts / name
        sub.mkdir(parents=True, exist_ok=True)
        (sub / name).write_bytes(content)
        if with_sums:
            (sub / "SHA256SUMS").write_text(
                f"{sha256_bytes(content)}  {name}\n", encoding="utf-8"
            )
        return sub

    def fill(self, skip=()):
        targets = {
            f"cryptoknife-{self.version}-{t}.tar.gz" for t in release.TAR_TARGETS
        } | {f"cryptoknife-{self.version}-{t}.zip" for t in release.ZIP_TARGETS}
        for name in sorted(targets):
            if name in skip:
                continue
            self.archive_dir(name, name.encode())
        crate = f"cryptoknife-{self.version}.crate"
        if crate not in skip:
            (self.artifacts / "src").mkdir(exist_ok=True)
            (self.artifacts / "src" / crate).write_bytes(b"crate")
        if "CHANGELOG.md" not in skip:
            (self.artifacts / "src").mkdir(exist_ok=True)
            (self.artifacts / "src" / "CHANGELOG.md").write_bytes(
                (self.plan_dir / "CHANGELOG.md").read_bytes()
            )

    def collect(self, out="assets"):
        return invoke(
            "collect", "--repo", self.repo, "--plan-dir", self.plan_dir,
            "--artifacts-dir", self.artifacts,
            "--output-dir", self.base / out,
        )

    def test_collect_success(self):
        self.fill()
        self.assertEqual(self.collect(), 0)
        out = self.base / "assets"
        names = sorted(p.name for p in out.iterdir())
        self.assertEqual(len(names), 7)
        self.assertIn("SHA256SUMS", names)
        sums = (out / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(sums), 6)
        self.assertNotIn("SHA256SUMS", " ".join(sums))

    def test_missing_archive_fails(self):
        self.fill(skip={f"cryptoknife-{self.version}-x86_64-pc-windows-msvc.zip"})
        with self.assertRaises(release.ReleaseError):
            self.collect()

    def test_missing_sums_fails(self):
        self.fill()
        name = f"cryptoknife-{self.version}-x86_64-unknown-linux-gnu.tar.gz"
        (self.artifacts / name / "SHA256SUMS").unlink()
        with self.assertRaises(release.ReleaseError):
            self.collect()

    def test_wrong_digest_fails(self):
        self.fill()
        name = f"cryptoknife-{self.version}-aarch64-apple-darwin.tar.gz"
        (self.artifacts / name / name).write_bytes(b"adulterado")
        with self.assertRaises(release.ReleaseError):
            self.collect()

    def test_duplicate_fails(self):
        self.fill()
        name = f"cryptoknife-{self.version}-x86_64-apple-darwin.tar.gz"
        other = self.artifacts / "dup" / name
        other.parent.mkdir()
        other.write_bytes(b"dup")
        with self.assertRaises(release.ReleaseError):
            self.collect()

    def test_symlink_fails(self):
        self.fill()
        name = f"cryptoknife-{self.version}.crate"
        crate = self.artifacts / "src" / name
        crate.unlink()
        crate.symlink_to(self.plan_dir / "Cargo.toml")
        with self.assertRaises((release.ReleaseError, OSError)):
            self.collect()


if __name__ == "__main__":
    unittest.main()
