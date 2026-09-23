use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn bin() -> Command {
  Command::new(env!("CARGO_BIN_EXE_cryptoknife"))
}

fn run(dir: &Path, args: &[&str]) -> Output {
  let mut cmd = bin();
  cmd.args(args).current_dir(dir);
  cmd.output().unwrap()
}

fn run_stdin(dir: &Path, args: &[&str], input: &[u8]) -> Output {
  let mut cmd = bin();
  cmd
    .args(args)
    .current_dir(dir)
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
  let mut child = cmd.spawn().unwrap();
  child.stdin.take().unwrap().write_all(input).unwrap();
  child.wait_with_output().unwrap()
}

fn code(output: &Output) -> Option<i32> {
  output.status.code()
}

const HELLO_BLAKE3: &str = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
const HELLO_CRC32: &str = "0d4a1185";

#[test]
fn help_lists_flags_and_version_matches() {
  let dir = tempfile::tempdir().unwrap();
  let help = run(dir.path(), &["--help"]);
  let text = String::from_utf8_lossy(&help.stdout);
  assert!(text.contains("--algorithm"));
  assert!(text.contains("--jobs"));
  assert!(text.contains("--json"));
  assert!(text.contains("--log-file"));

  let gen_help = run(dir.path(), &["generate", "--help"]);
  let gen_text = String::from_utf8_lossy(&gen_help.stdout);
  assert!(gen_text.contains("--force"));
  assert!(gen_text.contains("--format"));
  assert!(gen_text.contains("--output"));

  let ver_help = run(dir.path(), &["verify", "--help"]);
  let ver_text = String::from_utf8_lossy(&ver_help.stdout);
  assert!(ver_text.contains("--format"));
  assert!(ver_text.contains("--root"));

  let version = run(dir.path(), &["--version"]);
  let ver_out = String::from_utf8_lossy(&version.stdout);
  assert!(ver_out.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn global_flags_before_and_after_subcommand() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "hello world").unwrap();
  let before = run(dir.path(), &["-a", "blake3", "generate", "d.txt"]);
  assert_eq!(code(&before), Some(0));
  let after = run(
    dir.path(),
    &["generate", "-a", "blake3", "d.txt", "--force"],
  );
  assert_eq!(code(&after), Some(0));
}

#[test]
fn quiet_suppresses_success_but_not_errors() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "hello world").unwrap();
  let gen = run(dir.path(), &["-q", "generate", "d.txt"]);
  assert_eq!(code(&gen), Some(0));
  assert!(gen.stdout.is_empty());

  std::fs::remove_file(dir.path().join("d.txt.blake3")).unwrap();
  let ver = run(dir.path(), &["-q", "verify", "d.txt"]);
  assert_eq!(code(&ver), Some(1));
  let stderr = String::from_utf8_lossy(&ver.stderr);
  assert!(stderr.contains("MISSING-CHECKSUM"));
}

#[test]
fn json_events_and_summary_reconcile() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "hello world").unwrap();
  let gen = run(dir.path(), &["--json", "generate", "d.txt"]);
  assert_eq!(code(&gen), Some(0));
  let mut summary_seen = false;
  let mut file_seen = false;
  for line in String::from_utf8_lossy(&gen.stdout).lines() {
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["schema_version"], 1);
    match v["type"].as_str().unwrap() {
      "file" => {
        file_seen = true;
        assert_eq!(v["status"], "generated");
        assert_eq!(v["algorithm"], "blake3");
        assert_eq!(v["digest"], HELLO_BLAKE3);
      }
      "summary" => {
        summary_seen = true;
        assert_eq!(v["exit_code"], 0);
        assert_eq!(v["succeeded"], 1);
        assert_eq!(v["selected"], 1);
      }
      other => panic!("tipo inesperado: {}", other),
    }
  }
  assert!(file_seen && summary_seen);
}

#[test]
fn color_always_json_has_no_ansi() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "x").unwrap();
  let out = run(
    dir.path(),
    &["--color", "always", "--json", "generate", "d.txt"],
  );
  let stdout = String::from_utf8_lossy(&out.stdout);
  assert!(!stdout.contains('\u{1b}'), "ANSI in JSON: {}", stdout);
}

#[test]
fn no_progress_piped_has_no_ansi() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "x").unwrap();
  let out = run(dir.path(), &["--no-progress", "generate", "d.txt"]);
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(!stderr.contains('\u{1b}'), "ANSI: {}", stderr);
}

#[cfg(unix)]
#[test]
fn human_output_escapes_control_chars() {
  let dir = tempfile::tempdir().unwrap();
  let name = "evil\nname.txt";
  std::fs::write(dir.path().join(name), "x").unwrap();
  let out = run(dir.path(), &["-v", "generate", name]);
  let stdout = String::from_utf8_lossy(&out.stdout);
  let stderr = String::from_utf8_lossy(&out.stderr);
  assert!(stdout.contains("evil\\u000aname"), "stdout: {}", stdout);
  assert!(!stdout.contains("evil\nname"), "stdout: {}", stdout);
  assert!(!stderr.contains("evil\nname"), "stderr: {}", stderr);
}

#[test]
fn color_always_human_label_ansi() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "x").unwrap();
  let out = run(
    dir.path(),
    &["--color", "always", "-v", "generate", "d.txt"],
  );
  let stdout = String::from_utf8_lossy(&out.stdout);
  assert!(stdout.contains('\u{1b}'), "esperava ANSI: {}", stdout);
}

#[test]
fn color_never_and_no_color_have_no_ansi() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "x").unwrap();
  let never = run(dir.path(), &["--color", "never", "-v", "generate", "d.txt"]);
  let stdout = String::from_utf8_lossy(&never.stdout);
  assert!(!stdout.contains('\u{1b}'), "ANSI: {}", stdout);

  let mut cmd = bin();
  cmd
    .args(["-v", "generate", "d.txt"])
    .current_dir(dir.path())
    .env("NO_COLOR", "1");
  let out = cmd.output().unwrap();
  let stdout = String::from_utf8_lossy(&out.stdout);
  assert!(!stdout.contains('\u{1b}'), "ANSI NO_COLOR: {}", stdout);
}

#[test]
fn raw_stdin_hashes_hello_world() {
  let dir = tempfile::tempdir().unwrap();
  let out = run_stdin(dir.path(), &["generate", "-"], b"hello world");
  assert_eq!(code(&out), Some(0));
  let stdout = String::from_utf8_lossy(&out.stdout);
  assert_eq!(stdout.trim(), HELLO_BLAKE3);
}

#[test]
fn raw_stdin_rejects_combinations() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "x").unwrap();
  let mixed = run_stdin(dir.path(), &["generate", "-", "d.txt"], b"x");
  assert_eq!(code(&mixed), Some(2));
  let fmt = run_stdin(dir.path(), &["generate", "-", "--format", "manifest"], b"x");
  assert_eq!(code(&fmt), Some(2));
  let root = run_stdin(dir.path(), &["generate", "-", "--root", "."], b"x");
  assert_eq!(code(&root), Some(2));
}

#[test]
fn raw_file_stdout_and_collision() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "hello world").unwrap();
  let out = run(
    dir.path(),
    &["generate", "d.txt", "--format", "raw", "-o", "-"],
  );
  assert_eq!(code(&out), Some(0));
  let stdout = String::from_utf8_lossy(&out.stdout);
  assert_eq!(stdout.trim(), HELLO_BLAKE3);

  let out_file = dir.path().join("digest.txt");
  std::fs::write(&out_file, "SENTINEL").unwrap();
  let fail = run(
    dir.path(),
    &["generate", "d.txt", "--format", "raw", "-o", "digest.txt"],
  );
  assert_eq!(code(&fail), Some(3));
  assert_eq!(std::fs::read_to_string(&out_file).unwrap(), "SENTINEL");

  let ok = run(
    dir.path(),
    &[
      "generate",
      "d.txt",
      "--format",
      "raw",
      "-o",
      "digest.txt",
      "--force",
    ],
  );
  assert_eq!(code(&ok), Some(0));
  assert_eq!(
    std::fs::read_to_string(&out_file).unwrap().trim(),
    HELLO_BLAKE3
  );

  let dir_out = run(dir.path(), &["generate", ".", "--format", "raw", "-o", "x"]);
  assert_eq!(code(&dir_out), Some(2));

  let same = run(
    dir.path(),
    &["generate", "d.txt", "--format", "raw", "-o", "d.txt"],
  );
  assert_eq!(code(&same), Some(2));
}

#[test]
fn sidecar_input_and_orphans() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("d.txt.blake3"), HELLO_BLAKE3).unwrap();

  let direct = run(dir.path(), &["verify", "d.txt.blake3"]);
  assert_eq!(code(&direct), Some(0));

  std::fs::write(dir.path().join("gone.txt.blake3"), HELLO_BLAKE3).unwrap();
  let orphan = run(dir.path(), &["verify", "gone.txt.blake3"]);
  assert_eq!(code(&orphan), Some(1));

  let dir_orphan = run(dir.path(), &["verify", "."]);
  assert_eq!(code(&dir_orphan), Some(1));
  let stderr = String::from_utf8_lossy(&dir_orphan.stderr);
  assert!(stderr.contains("MISSING-DATA"), "stderr: {}", stderr);
}

#[test]
fn directory_respects_selected_algorithm() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("d.txt.blake3"), HELLO_BLAKE3).unwrap();
  std::fs::write(dir.path().join("d.txt.sfv"), HELLO_CRC32).unwrap();
  std::fs::write(dir.path().join("other.txt.sfv"), HELLO_CRC32).unwrap();
  std::fs::write(dir.path().join("other.txt.blake3"), HELLO_BLAKE3).unwrap();
  std::fs::write(dir.path().join("other.txt"), "hello world").unwrap();

  let blake3_only = run(dir.path(), &["-a", "blake3", "verify", "."]);
  assert_eq!(code(&blake3_only), Some(0));

  let crc = run(dir.path(), &["-a", "crc32", "verify", "."]);
  assert_eq!(code(&crc), Some(0));
}

#[test]
fn overlapping_data_and_sidecar_single_match() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("d.txt.blake3"), HELLO_BLAKE3).unwrap();
  let out = run(dir.path(), &["--json", "verify", "d.txt", "d.txt.blake3"]);
  assert_eq!(code(&out), Some(0));
  let matched = String::from_utf8_lossy(&out.stdout)
    .lines()
    .filter(|l| l.contains("\"matched\""))
    .count();
  assert_eq!(matched, 1);
}

#[test]
fn sfv_document_and_legacy_sidecar() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("list.sfv"), "data.txt 0D4A1185\n").unwrap();
  let out = run(dir.path(), &["verify", "list.sfv"]);
  assert_eq!(
    code(&out),
    Some(0),
    "stdout: {} stderr: {}",
    String::from_utf8_lossy(&out.stdout),
    String::from_utf8_lossy(&out.stderr)
  );

  let dir2 = tempfile::tempdir().unwrap();
  std::fs::write(dir2.path().join("data.txt"), "hello world").unwrap();
  std::fs::write(dir2.path().join("data.txt.sfv"), "0d4a1185\n").unwrap();
  let legacy = run(dir2.path(), &["verify", "data.txt.sfv"]);
  assert_eq!(code(&legacy), Some(0));

  let dir3 = tempfile::tempdir().unwrap();
  std::fs::write(dir3.path().join("my file.txt"), "hello world").unwrap();
  std::fs::write(
    dir3.path().join("list.sfv"),
    "; comment\r\n\r\nmy file.txt 0D4A1185\r\n",
  )
  .unwrap();
  let sfv = run(dir3.path(), &["verify", "list.sfv"]);
  assert_eq!(code(&sfv), Some(0));
}

#[test]
fn manifest_roundtrip_and_handcrafted() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::create_dir(dir.path().join("sub")).unwrap();
  std::fs::write(dir.path().join("a.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("sub/b.txt"), "hello world").unwrap();

  let gen = run(
    dir.path(),
    &[
      "generate",
      "a.txt",
      "sub/b.txt",
      "--format",
      "manifest",
      "-o",
      "out.ckmanifest",
    ],
  );
  assert_eq!(code(&gen), Some(0));
  let doc = std::fs::read_to_string(dir.path().join("out.ckmanifest")).unwrap();
  assert!(doc.contains("\"type\":\"manifest\""));
  assert!(doc.contains("\"type\":\"end\""));
  assert!(!dir.path().join("a.txt.blake3").exists());

  let ver = run(dir.path(), &["verify", "out.ckmanifest"]);
  assert_eq!(
    code(&ver),
    Some(0),
    "stdout: {} stderr: {}",
    String::from_utf8_lossy(&ver.stdout),
    String::from_utf8_lossy(&ver.stderr)
  );

  let dir2 = tempfile::tempdir().unwrap();
  std::fs::write(dir2.path().join("data.txt"), "hello world").unwrap();
  let handcrafted = format!(
    "{{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}}\n{{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"data.txt\",\"digest\":\"{}\"}}\n{{\"type\":\"end\",\"entries\":1}}\n",
    HELLO_BLAKE3
  );
  std::fs::write(dir2.path().join("m.ckmanifest"), &handcrafted).unwrap();
  let hand = run(dir2.path(), &["verify", "m.ckmanifest"]);
  assert_eq!(code(&hand), Some(0));
}

#[test]
fn manifest_invalid_documents_fail() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  let good_line = format!(
    "{{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"data.txt\",\"digest\":\"{}\"}}\n",
    HELLO_BLAKE3
  );
  let header = "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n";

  // tampered digest -> mismatched (1)
  let tampered = format!(
    "{}{{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"data.txt\",\"digest\":\"{}\"}}\n{{\"type\":\"end\",\"entries\":1}}\n",
    header, "0".repeat(64)
  );
  std::fs::write(dir.path().join("t.ckmanifest"), tampered).unwrap();
  assert_eq!(code(&run(dir.path(), &["verify", "t.ckmanifest"])), Some(1));

  // missing file -> MissingData (1)
  let missing = format!(
    "{}{{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"absent.txt\",\"digest\":\"{}\"}}\n{{\"type\":\"end\",\"entries\":1}}\n",
    header, HELLO_BLAKE3
  );
  std::fs::write(dir.path().join("m.ckmanifest"), missing).unwrap();
  assert_eq!(code(&run(dir.path(), &["verify", "m.ckmanifest"])), Some(1));

  // no footer -> 3
  std::fs::write(
    dir.path().join("nf.ckmanifest"),
    format!("{}{}", header, good_line),
  )
  .unwrap();
  assert_eq!(
    code(&run(dir.path(), &["verify", "nf.ckmanifest"])),
    Some(3)
  );

  // wrong count -> 3
  let count = format!("{}{{\"type\":\"end\",\"entries\":9}}\n", header);
  std::fs::write(dir.path().join("c.ckmanifest"), count).unwrap();
  assert_eq!(code(&run(dir.path(), &["verify", "c.ckmanifest"])), Some(3));

  // unknown version -> 3
  std::fs::write(
    dir.path().join("v.ckmanifest"),
    "{\"schema_version\":2,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n{\"type\":\"end\",\"entries\":0}\n",
  )
  .unwrap();
  assert_eq!(code(&run(dir.path(), &["verify", "v.ckmanifest"])), Some(3));

  // malformed line -> 3
  std::fs::write(
    dir.path().join("ml.ckmanifest"),
    format!("{}oops\n", header),
  )
  .unwrap();
  assert_eq!(
    code(&run(dir.path(), &["verify", "ml.ckmanifest"])),
    Some(3)
  );

  // duplicate entry -> 3
  let dup = format!(
    "{}{}{}{{\"type\":\"end\",\"entries\":2}}\n",
    header, good_line, good_line
  );
  std::fs::write(dir.path().join("d.ckmanifest"), dup).unwrap();
  assert_eq!(code(&run(dir.path(), &["verify", "d.ckmanifest"])), Some(3));

  // path escape -> 3
  let esc = format!(
    "{}{{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"../x\",\"digest\":\"{}\"}}\n{{\"type\":\"end\",\"entries\":1}}\n",
    header, HELLO_BLAKE3
  );
  std::fs::write(dir.path().join("e.ckmanifest"), esc).unwrap();
  assert_eq!(code(&run(dir.path(), &["verify", "e.ckmanifest"])), Some(3));
}

#[test]
fn manifest_stdout_stdin_roundtrip() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  let gen = run(
    dir.path(),
    &["generate", "data.txt", "--format", "manifest", "-o", "-"],
  );
  assert_eq!(code(&gen), Some(0));
  let doc = gen.stdout.clone();
  assert!(String::from_utf8_lossy(&doc).contains("\"entries\":1"));

  let ver = run_stdin(dir.path(), &["verify", "-", "--format", "manifest"], &doc);
  assert_eq!(code(&ver), Some(0));

  let bad = run_stdin(
    dir.path(),
    &["verify", "-", "--format", "manifest"],
    &doc[..doc.len() / 2],
  );
  assert_eq!(code(&bad), Some(3));

  let auto = run_stdin(dir.path(), &["verify", "-"], &doc);
  assert_eq!(code(&auto), Some(2));
}

#[cfg(unix)]
#[test]
fn manifest_symlink_escape_rejected() {
  let dir = tempfile::tempdir().unwrap();
  let outside = tempfile::tempdir().unwrap();
  std::fs::write(outside.path().join("secret.txt"), "hello world").unwrap();
  std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
  let doc = format!(
    "{{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}}\n{{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"link/secret.txt\",\"digest\":\"{}\"}}\n{{\"type\":\"end\",\"entries\":1}}\n",
    HELLO_BLAKE3
  );
  std::fs::write(dir.path().join("m.ckmanifest"), doc).unwrap();
  let out = run(dir.path(), &["verify", "m.ckmanifest"]);
  assert_eq!(code(&out), Some(3));
}

#[test]
fn log_file_outside_appends_inside_rejected() {
  let dir = tempfile::tempdir().unwrap();
  let logdir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "hello world").unwrap();
  let log = logdir.path().join("ck.log");
  let out = run(
    dir.path(),
    &["generate", "d.txt", "--log-file", log.to_str().unwrap()],
  );
  assert_eq!(code(&out), Some(0));
  let content = std::fs::read_to_string(&log).unwrap();
  assert!(content.contains("Resumo") || content.contains("GENERATED"));

  let inside = run(
    dir.path(),
    &["generate", ".", "--log-file", "inside.log", "--force"],
  );
  assert_eq!(code(&inside), Some(3));
  assert!(!dir.path().join("inside.log").exists());

  let equal = run(
    dir.path(),
    &["generate", "d.txt", "--log-file", "d.txt", "--force"],
  );
  assert_eq!(code(&equal), Some(3));
  assert_eq!(
    std::fs::read_to_string(dir.path().join("d.txt")).unwrap(),
    "hello world"
  );
}

#[test]
fn invalid_combinations_exit_two() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "x").unwrap();
  let cases: Vec<Vec<&str>> = vec![
    vec!["generate", "d.txt", "--output", "x"],
    vec!["generate", "d.txt", "--root", "."],
    vec!["generate", "d.txt", "--format", "manifest"],
    vec![
      "generate", "d.txt", "--format", "manifest", "-o", "-", "--json",
    ],
    vec!["generate", "d.txt", "--format", "sfv", "-o", "x.sfv"],
    vec!["-a", "sha3-256", "verify", "d.txt.blake3"],
  ];
  for args in cases {
    let out = run(dir.path(), &args);
    assert_eq!(code(&out), Some(2), "args {:?} -> {:?}", args, code(&out));
  }
}

#[cfg(unix)]
fn wait_with_deadline(child: &mut std::process::Child, secs: u64) -> std::process::ExitStatus {
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
  loop {
    if let Some(status) = child.try_wait().unwrap() {
      return status;
    }
    if std::time::Instant::now() >= deadline {
      let _ = child.kill();
      let _ = child.wait();
      panic!("processo não terminou dentro de {}s", secs);
    }
    std::thread::sleep(std::time::Duration::from_millis(50));
  }
}

#[cfg(unix)]
#[test]
fn sigint_blocked_stdin_exits_130() {
  let dir = tempfile::tempdir().unwrap();
  let mut child = bin()
    .args(["generate", "-"])
    .current_dir(dir.path())
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
  std::thread::sleep(std::time::Duration::from_millis(300));
  let status = Command::new("kill")
    .args(["-INT", &child.id().to_string()])
    .status()
    .unwrap();
  assert!(status.success());
  let status = wait_with_deadline(&mut child, 5);
  assert_eq!(status.code(), Some(130));
  assert!(dir.path().read_dir().unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn sigint_verify_stdin_partial_line_exits_130() {
  let dir = tempfile::tempdir().unwrap();
  let mut child = bin()
    .args(["verify", "-", "--format", "manifest"])
    .current_dir(dir.path())
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
  child
    .stdin
    .as_mut()
    .unwrap()
    .write_all(b"{\"schema_version\":1")
    .unwrap();
  std::thread::sleep(std::time::Duration::from_millis(300));
  let status = Command::new("kill")
    .args(["-INT", &child.id().to_string()])
    .status()
    .unwrap();
  assert!(status.success());
  let status = wait_with_deadline(&mut child, 5);
  assert_eq!(status.code(), Some(130));
}

#[cfg(unix)]
#[test]
fn sigint_large_file_no_partial_sidecar() {
  let dir = tempfile::tempdir().unwrap();
  let big = dir.path().join("big.bin");
  std::fs::File::create(&big)
    .unwrap()
    .set_len(2 * 1024 * 1024 * 1024)
    .unwrap();
  let mut child = bin()
    .args(["-a", "whirlpool", "generate", "big.bin"])
    .current_dir(dir.path())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
  std::thread::sleep(std::time::Duration::from_millis(300));
  let status = Command::new("kill")
    .args(["-INT", &child.id().to_string()])
    .status()
    .unwrap();
  assert!(status.success());
  let status = wait_with_deadline(&mut child, 5);
  assert_eq!(status.code(), Some(130));
  assert!(!dir.path().join("big.bin.whirlpool").exists());
}

#[test]
fn raw_stdout_rejects_json() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "x").unwrap();
  let stdin = run_stdin(dir.path(), &["generate", "-", "--json"], b"x");
  assert_eq!(code(&stdin), Some(2));
  let file = run(
    dir.path(),
    &["generate", "d.txt", "--format", "raw", "-o", "-", "--json"],
  );
  assert_eq!(code(&file), Some(2));
  assert!(!dir.path().join("log.txt").exists());
}

#[test]
fn raw_file_rejects_root_and_missing_input() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("d.txt"), "x").unwrap();
  let root = run(
    dir.path(),
    &["generate", "d.txt", "--format", "raw", "--root", "."],
  );
  assert_eq!(code(&root), Some(2));
  let missing = run(dir.path(), &["generate", "missing.txt", "--format", "raw"]);
  assert_eq!(code(&missing), Some(3));
}

#[test]
fn log_file_protects_implicit_sidecar_target() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("data.txt.blake3"), HELLO_BLAKE3).unwrap();
  let out = run(
    dir.path(),
    &["verify", "data.txt", "--log-file", "data.txt.blake3"],
  );
  assert_eq!(code(&out), Some(3));
  assert_eq!(
    std::fs::read_to_string(dir.path().join("data.txt.blake3")).unwrap(),
    HELLO_BLAKE3
  );
}

#[test]
fn log_file_inside_doc_root_rejected() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  std::fs::write(
    dir.path().join("list"),
    concat!(
      "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n",
      "{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"data.txt\",\"digest\":\"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24\"}\n",
      "{\"type\":\"end\",\"entries\":1}\n"
    ),
  )
  .unwrap();
  let out = run(
    dir.path(),
    &[
      "verify",
      "list",
      "--format",
      "manifest",
      "--log-file",
      "data.txt",
    ],
  );
  assert_eq!(code(&out), Some(3));
  assert_eq!(
    std::fs::read_to_string(dir.path().join("data.txt")).unwrap(),
    "hello world"
  );
}

#[test]
fn directory_sfv_defers_missing_checksum() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("list.sfv"), "data.txt 0D4A1185\n").unwrap();
  let ok = run(dir.path(), &["verify", ".", "-a", "crc32"]);
  assert_eq!(
    code(&ok),
    Some(0),
    "stderr: {}",
    String::from_utf8_lossy(&ok.stderr)
  );

  std::fs::write(dir.path().join("other.txt"), "hello world").unwrap();
  let one_missing = run(dir.path(), &["verify", ".", "-a", "crc32"]);
  assert_eq!(code(&one_missing), Some(1));

  std::fs::write(dir.path().join("list.sfv"), "data.txt nothex!!\n").unwrap();
  let bad = run(dir.path(), &["verify", ".", "-a", "crc32"]);
  assert_eq!(code(&bad), Some(3));
}

#[cfg(unix)]
#[test]
fn log_file_hardlink_alias_rejected() {
  use std::os::unix::fs::symlink;
  let dir = tempfile::tempdir().unwrap();
  std::fs::create_dir(dir.path().join("sub")).unwrap();
  std::fs::write(dir.path().join("sub/data.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("sub/data.txt.blake3"), HELLO_BLAKE3).unwrap();
  std::fs::hard_link(
    dir.path().join("sub/data.txt.blake3"),
    dir.path().join("alias.log"),
  )
  .unwrap();
  let out = run(dir.path(), &["verify", "sub", "--log-file", "alias.log"]);
  assert_eq!(code(&out), Some(3));
  assert_eq!(
    std::fs::read_to_string(dir.path().join("sub/data.txt.blake3")).unwrap(),
    HELLO_BLAKE3
  );

  // symlink em diretório intermediário não deve vazar geração
  let real = tempfile::tempdir().unwrap();
  std::fs::create_dir(real.path().join("real")).unwrap();
  std::fs::write(real.path().join("real/data.txt"), "hello world").unwrap();
  symlink(real.path().join("real"), dir.path().join("link")).unwrap();
  let esc = run(
    dir.path(),
    &[
      "generate",
      "link",
      "--format",
      "manifest",
      "-o",
      "doc.ckmanifest",
      "--root",
      ".",
      "--force",
    ],
  );
  assert_ne!(code(&esc), Some(0));
}
