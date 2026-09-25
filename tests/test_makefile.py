import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST = "test-host-triple"

GENERIC_STUB = """#!/usr/bin/env python3
import json, os, sys
name = os.path.basename(sys.argv[0])
argv = sys.argv[1:]
log = os.environ.get("STUB_LOG")
if log:
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"tool": name, "argv": argv,
                            "target_dir": os.environ.get("CARGO_TARGET_DIR")}) + "\\n")
if name == "rustc" and argv == ["-vV"]:
    print("release: 1.0.0")
    print("host: test-host-triple")
if name == "cargo-deny" and argv == ["--version"]:
    print(os.environ.get("STUB_DENY_VERSION", "cargo-deny 0.18.6"))
fail = os.environ.get("STUB_FAIL_" + name.replace("-", "_").upper())
selector = os.environ.get("STUB_FAIL_COMMAND")
if selector and selector not in argv:
    fail = None
sys.exit(int(fail or 0))
"""

PYTHON_STUB = """#!/usr/bin/env python3
import json, os, sys
argv = sys.argv[1:]
intercept = argv[:3] == ["-m", "unittest", "discover"] or (
    argv and argv[0].startswith("scripts/")
)
log = os.environ.get("STUB_LOG")
if intercept:
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"tool": "python3", "argv": argv}) + "\\n")
    sys.exit(0)
os.execv(sys.executable, [sys.executable] + argv)
"""

TOOLS = ("cargo", "rustc", "rustup", "actionlint", "cargo-deny", "gh")

INHERITED_VARS = {
    "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "GNUMAKEFLAGS",
    "CARGO_TARGET_DIR", "TARGET", "BASELINE", "BENCH_OUTPUT", "PLAN_DIR",
    "DIST_DIR", "BUMP", "RESUME_TAG", "CONFIRM", "ARGS", "TEST_ARGS",
    "REPOSITORY", "CARGO", "RUSTC", "RUSTUP", "PYTHON", "ACTIONLINT",
    "CARGO_DENY", "GH",
}


def have_gnu_make() -> bool:
    if os.name == "nt" or not Path("/bin/sh").exists():
        return False
    make = shutil.which("make")
    if not make:
        return False
    try:
        result = subprocess.run(
            [make, "--version"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "GNU Make" in result.stdout


@unittest.skipUnless(
    have_gnu_make(), "requer GNU Make e shell POSIX; stubs POSIX-only")
class TestMakefile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ck-makefile-")
        self.base = Path(self.tmp.name)
        self.bin_dir = self.base / "stub bin"
        self.bin_dir.mkdir(parents=True)
        self.log = self.base / "calls.jsonl"
        for name in TOOLS:
            path = self.bin_dir / name
            path.write_text(GENERIC_STUB, encoding="utf-8")
            path.chmod(0o755)
        python_stub = self.bin_dir / "python3"
        python_stub.write_text(PYTHON_STUB, encoding="utf-8")
        python_stub.chmod(0o755)
        self.env = {
            key: value for key, value in os.environ.items()
            if key not in INHERITED_VARS and not key.startswith("STUB_")
        }
        self.env["STUB_LOG"] = str(self.log)

    def tearDown(self):
        self.tmp.cleanup()

    def tool_vars(self):
        values = {
            "CARGO": str(self.bin_dir / "cargo"),
            "RUSTC": str(self.bin_dir / "rustc"),
            "RUSTUP": str(self.bin_dir / "rustup"),
            "ACTIONLINT": str(self.bin_dir / "actionlint"),
            "CARGO_DENY": str(self.bin_dir / "cargo-deny"),
            "GH": str(self.bin_dir / "gh"),
            "PYTHON": str(self.bin_dir / "python3"),
        }
        return [f"{key}={value}" for key, value in values.items()]

    def make(self, *args, env=None, check=False):
        merged = dict(self.env)
        if env:
            merged.update(env)
        result = subprocess.run(
            ["make", *args, *self.tool_vars()],
            cwd=ROOT, env=merged, capture_output=True, text=True, timeout=60,
        )
        if check and result.returncode != 0:
            raise AssertionError(f"make {' '.join(args)} falhou: {result.stderr}")
        return result

    def calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def tool_calls(self, name):
        return [entry["argv"] for entry in self.calls() if entry["tool"] == name]

    def test_default_and_help_without_tools(self):
        dead = ["CARGO=/nonexistent/cargo", "RUSTC=/nonexistent/rustc",
                "PYTHON=/nonexistent/python3", "GH=/nonexistent/gh"]
        for args in ((), ("help",)):
            result = subprocess.run(
                ["make", *args, *dead], cwd=ROOT, env=self.env,
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            public = (
                "all", "doctor", "setup", "setup-msrv", "setup-audit", "fetch",
                "build", "build-release", "release", "check", "run", "test",
                "test-rust", "test-python", "fmt", "fmt-check", "clippy",
                "workflow-lint", "lint", "msrv", "audit", "verify", "ci",
                "doc", "doc-open", "install", "package", "package-cross",
                "package-source", "benchmark", "release-plan",
                "release-preview", "release-publish", "release-resume",
                "ci-run", "audit-run", "ci-status", "release-status", "clean",
            )
            for target in public:
                self.assertIn(f"make {target}", result.stdout)
            self.assertIn("make help", result.stdout)
        self.assertFalse(self.log.exists())

    def test_build_and_release_locked_target(self):
        self.make("build", f"TARGET={HOST}", check=True)
        self.make("release", f"TARGET={HOST}", check=True)
        cargo = self.tool_calls("cargo")
        self.assertEqual(cargo[0], ["build", "--locked", "--target", HOST])
        self.assertEqual(cargo[1], ["build", "--locked", "--release", "--target", HOST])

    def test_target_dir_export_and_windows_exe(self):
        target_dir = str(self.base / "dir com espaco")
        self.make("package-cross", "TARGET=x86_64-pc-windows-msvc",
                  f"CARGO_TARGET_DIR={target_dir}", "DIST_DIR=out-cross", check=True)
        recorded = [entry["target_dir"] for entry in self.calls()
                    if entry.get("target_dir") is not None]
        self.assertTrue(recorded)
        self.assertTrue(all(value == target_dir for value in recorded))
        python = self.tool_calls("python3")[0]
        binary = python[python.index("--binary") + 1]
        self.assertEqual(
            binary,
            f"{target_dir}/x86_64-pc-windows-msvc/release/cryptoknife.exe",
        )
        self.assertNotIn("--smoke", python)
        self.assertIn("x86_64-pc-windows-msvc", python[python.index("--target") + 1])

    def test_native_package_includes_smoke(self):
        self.make("package", f"TARGET={HOST}", check=True)
        python = self.tool_calls("python3")[0]
        self.assertIn("--smoke", python)
        binary = python[python.index("--binary") + 1]
        self.assertEqual(binary, f"target/{HOST}/release/cryptoknife")
        self.assertNotIn("--clobber", python)
        self.assertNotIn("--force", python)

    def test_run_default_help_and_test_args(self):
        self.make("run", f"TARGET={HOST}", check=True)
        self.make("test-rust", f"TARGET={HOST}",
                  "TEST_ARGS=cli_output --nocapture", check=True)
        cargo = self.tool_calls("cargo")
        self.assertEqual(cargo[0][-2:], ["--", "--help"])
        self.assertEqual(cargo[1][-3:], ["--", "cli_output", "--nocapture"])

    def test_quality_gate_arguments(self):
        self.make("fmt-check", check=True)
        self.make("clippy", f"TARGET={HOST}", check=True)
        self.make("msrv", f"TARGET={HOST}", check=True)
        self.make("workflow-lint", check=True)
        self.make("audit", check=True)
        cargo = self.tool_calls("cargo")
        self.assertIn(["fmt", "--all", "--", "--check"], cargo)
        clippy = next(a for a in cargo if a and a[0] == "clippy")
        self.assertEqual(clippy[-2:], ["-D", "warnings"])
        msrv = next(a for a in cargo if a[0] == "+1.85.0")
        self.assertIn("--locked", msrv)
        self.assertIn("--all-targets", msrv)
        actionlint = self.tool_calls("actionlint")[0]
        self.assertEqual(actionlint, [
            ".github/workflows/audit.yml",
            ".github/workflows/rust.yml",
            ".github/workflows/release.yml",
        ])
        deny = self.tool_calls("cargo-deny")
        self.assertIn(["--locked", "check", "advisories", "licenses", "sources"], deny)

    def test_audit_wrong_deny_version_fails(self):
        result = self.make("audit", env={"STUB_DENY_VERSION": "cargo-deny 9.9.9"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.tool_calls("cargo-deny"), [["--version"]])

    def test_verify_calls_all_checks(self):
        self.make("verify", f"TARGET={HOST}", check=True)
        cargo = [a[0] for a in self.tool_calls("cargo")]
        self.assertIn("check", cargo)
        self.assertIn("test", cargo)
        self.assertIn("clippy", cargo)
        self.assertIn("+1.85.0", cargo)
        self.assertIn(["-m", "unittest", "discover"],
                      [a[:3] for a in self.tool_calls("python3")])
        self.assertTrue(self.tool_calls("cargo-deny"))
        self.assertTrue(self.tool_calls("actionlint"))

    def test_verify_propagates_failures(self):
        result = self.make(
            "verify", f"TARGET={HOST}",
            env={"STUB_FAIL_CARGO": "7", "STUB_FAIL_COMMAND": "test"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(["test", "--locked", "--target", HOST, "--"],
                      [a[:5] for a in self.tool_calls("cargo")])
        self.assertEqual(self.tool_calls("cargo-deny"), [])
        self.log.unlink()
        result = self.make(
            "verify", f"TARGET={HOST}",
            env={"STUB_FAIL_CARGO_DENY": "3", "STUB_FAIL_COMMAND": "check"},
        )
        self.assertNotEqual(result.returncode, 0)
        cargo = [a[0] for a in self.tool_calls("cargo")]
        self.assertIn("check", cargo)
        self.assertIn("test", cargo)
        self.assertIn("clippy", cargo)
        self.assertIn("+1.85.0", cargo)
        self.assertEqual(self.tool_calls("cargo-deny"), [
            ["--version"],
            ["--locked", "check", "advisories", "licenses", "sources"],
        ])

    def test_confirm_guards(self):
        for target in ("clean", "release-publish", "release-resume",
                       "ci-run", "audit-run", "release-preview"):
            result = self.make(target)
            self.assertNotEqual(result.returncode, 0, target)
        self.assertFalse(self.log.exists())

    def test_remote_dispatch_argv(self):
        self.make("release-publish", "CONFIRM=yes", check=True)
        gh = self.tool_calls("gh")[-1]
        self.assertEqual(gh, [
            "workflow", "run", "release.yml", "--repo", "italoag/cryptoknife",
            "--ref", "main", "-f", "dry_run=false", "-f", "bump=auto",
        ])
        self.make("release-resume", "CONFIRM=yes", "RESUME_TAG=v0.2.1", check=True)
        gh = self.tool_calls("gh")[-1]
        self.assertEqual(gh, [
            "workflow", "run", "release.yml", "--repo", "italoag/cryptoknife",
            "--ref", "main", "-f", "dry_run=false", "-f", "bump=auto",
            "-f", "resume_tag=v0.2.1",
        ])
        self.make("release-preview", "CONFIRM=yes", check=True)
        gh = self.tool_calls("gh")[-1]
        self.assertIn("dry_run=true", gh)
        self.assertIn("--ref", gh)
        self.assertIn("main", gh)
        self.make("ci-run", "CONFIRM=yes", check=True)
        self.assertIn("rust.yml", self.tool_calls("gh")[-1])
        self.make("audit-run", "CONFIRM=yes", check=True)
        self.assertIn("audit.yml", self.tool_calls("gh")[-1])
        self.make("clean", "CONFIRM=yes", check=True)
        self.assertEqual(self.tool_calls("cargo")[-1], ["clean"])

    def test_invalid_bump_and_resume_tag(self):
        for args in (
            ("release-publish", "CONFIRM=yes", "BUMP=bogus"),
            ("release-preview", "CONFIRM=yes", "BUMP=bogus"),
            ("release-plan", "BUMP=bogus"),
            ("release-resume", "CONFIRM=yes"),
            ("release-resume", "CONFIRM=yes", "RESUME_TAG=v0.2"),
            ("release-resume", "CONFIRM=yes", "RESUME_TAG=v1.02.3"),
            ("release-resume", "CONFIRM=yes", "RESUME_TAG=v0.2.1", "BUMP=minor"),
            ("release-publish", "CONFIRM=yes", "RESUME_TAG=v0.2.1"),
        ):
            result = self.make(*args)
            self.assertNotEqual(result.returncode, 0, args)
        self.assertEqual(self.tool_calls("gh"), [])

    def test_baseline_and_native_guards(self):
        result = self.make("benchmark", f"TARGET={HOST}")
        self.assertNotEqual(result.returncode, 0)
        result = self.make("benchmark", f"TARGET={HOST}",
                           f"BASELINE={self.base / 'inexistente'}")
        self.assertNotEqual(result.returncode, 0)
        baseline = self.base / "baseline-bin"
        baseline.write_text("x", encoding="utf-8")
        result = self.make("benchmark", f"TARGET={HOST}", f"BASELINE={baseline}")
        self.assertNotEqual(result.returncode, 0)
        for target in ("package", "run", "test-rust"):
            result = self.make(target, "TARGET=x86_64-pc-windows-msvc")
            self.assertNotEqual(result.returncode, 0, target)
        self.assertEqual(self.tool_calls("cargo"), [])
        self.assertEqual(self.tool_calls("python3"), [])

    def test_benchmark_success_routes(self):
        baseline = self.base / "baseline-bin"
        baseline.write_text("x", encoding="utf-8")
        baseline.chmod(0o755)
        out = str(self.base / "bench out" / "benchmark.json")
        self.make("benchmark", f"TARGET={HOST}", f"BASELINE={baseline}",
                  f"BENCH_OUTPUT={out}", check=True)
        bench = self.tool_calls("python3")[-1]
        self.assertEqual(bench[0], "scripts/benchmark.py")
        self.assertEqual(bench[bench.index("--baseline") + 1], str(baseline))
        self.assertEqual(
            bench[bench.index("--candidate") + 1],
            f"target/{HOST}/release/cryptoknife",
        )
        self.assertEqual(bench[bench.index("--output") + 1], out)

    def test_baseline_same_as_candidate_rejected(self):
        target_dir = self.base / "tdir"
        candidate = target_dir / HOST / "release" / "cryptoknife"
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"bin")
        candidate.chmod(0o755)
        result = self.make(
            "benchmark", f"TARGET={HOST}",
            f"CARGO_TARGET_DIR={target_dir}", f"BASELINE={candidate}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(candidate.read_bytes(), b"bin")
        self.assertEqual(self.tool_calls("cargo"), [])

    @unittest.skipIf(os.name == "nt", "symlink exige POSIX")
    def test_baseline_symlink_to_candidate_rejected(self):
        target_dir = self.base / "tdir"
        candidate = target_dir / HOST / "release" / "cryptoknife"
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(b"bin")
        candidate.chmod(0o755)
        baseline = self.base / "alias-baseline"
        baseline.symlink_to(candidate)
        result = self.make(
            "benchmark", f"TARGET={HOST}",
            f"CARGO_TARGET_DIR={target_dir}", f"BASELINE={baseline}",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.tool_calls("cargo"), [])

    def test_setup_docs_and_install_routes(self):
        for target in ("setup", "setup-msrv", "setup-audit", "fetch",
                       "doc", "doc-open", "install"):
            self.make(target, check=True)
        rustup = self.tool_calls("rustup")
        self.assertIn(["component", "add", "rustfmt", "clippy"], rustup)
        self.assertIn(
            ["toolchain", "install", "1.85.0", "--profile", "minimal"], rustup)
        cargo = self.tool_calls("cargo")
        self.assertIn(["fetch", "--locked"], cargo)
        self.assertIn(
            ["install", "cargo-deny@0.18.6", "--locked", "--registry",
             "crates-io"], cargo)
        self.assertIn(["doc", "--locked", "--no-deps"], cargo)
        self.assertIn(["doc", "--locked", "--no-deps", "--open"], cargo)
        self.assertIn(["install", "--path", ".", "--locked"], cargo)

    def test_release_plan_offline_no_gh(self):
        self.make("release-plan", f"PLAN_DIR={self.base / 'plan'}", check=True)
        python = self.tool_calls("python3")[-1]
        self.assertEqual(python[0], "scripts/release.py")
        self.assertIn("prepare", python)
        self.assertIn("--offline", python)
        self.assertIn("--bump", python)
        self.assertIn("--output-dir", python)
        self.assertEqual(self.tool_calls("gh"), [])

    def test_package_source_locked_no_dirty(self):
        self.make("package-source", check=True)
        cargo = self.tool_calls("cargo")[-1]
        self.assertEqual(cargo, ["package", "--locked"])
        self.assertNotIn("--allow-dirty", cargo)


if __name__ == "__main__":
    unittest.main()
