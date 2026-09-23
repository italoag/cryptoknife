use std::path::Path;
use std::process::{Command, Output};

fn bin() -> Command {
  Command::new(env!("CARGO_BIN_EXE_cryptoknife"))
}

fn run(dir: &Path, args: &[&str]) -> Output {
  bin().args(args).current_dir(dir).output().unwrap()
}

fn code(out: &Output) -> Option<i32> {
  out.status.code()
}

#[test]
fn clean_generate_and_verify_succeeds_without_log() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  let gen = run(dir.path(), &["generate", "data.txt"]);
  assert_eq!(code(&gen), Some(0));
  assert!(dir.path().join("data.txt.blake3").exists());
  assert!(!dir.path().join("cryptoknife.log").exists());
  let ver = run(dir.path(), &["verify", "data.txt"]);
  assert_eq!(code(&ver), Some(0));
  assert!(!dir.path().join("cryptoknife.log").exists());
}

#[test]
fn mismatch_exits_one() {
  let dir = tempfile::tempdir().unwrap();
  let data = dir.path().join("data.txt");
  std::fs::write(&data, "hello world").unwrap();
  let gen = run(dir.path(), &["generate", "data.txt"]);
  assert_eq!(code(&gen), Some(0));
  std::fs::write(&data, "modified").unwrap();
  let ver = run(dir.path(), &["verify", "data.txt"]);
  assert_eq!(code(&ver), Some(1));
}

#[test]
fn missing_sidecar_exits_one() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  let ver = run(dir.path(), &["verify", "data.txt"]);
  assert_eq!(code(&ver), Some(1));
}

#[test]
fn missing_input_exits_three() {
  let dir = tempfile::tempdir().unwrap();
  let ver = run(dir.path(), &["verify", "absent.txt"]);
  assert_eq!(code(&ver), Some(3));
  let gen = run(dir.path(), &["generate", "absent.txt"]);
  assert_eq!(code(&gen), Some(3));
}

#[test]
fn empty_directory_exits_three() {
  let dir = tempfile::tempdir().unwrap();
  let ver = run(dir.path(), &["verify", "."]);
  assert_eq!(code(&ver), Some(3));
  let gen = run(dir.path(), &["generate", "."]);
  assert_eq!(code(&gen), Some(3));
}

#[test]
fn zero_buffer_exits_two_without_side_effects() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  let gen = run(dir.path(), &["generate", "data.txt", "-b", "0"]);
  assert_eq!(code(&gen), Some(2));
  assert!(!dir.path().join("data.txt.blake3").exists());
  assert!(!dir.path().join("cryptoknife.log").exists());
}

#[test]
fn invalid_algorithm_bits_exit_two_for_any_size() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  let small = run(dir.path(), &["generate", "data.txt", "-a", "sha3-123"]);
  assert_eq!(code(&small), Some(2));
  std::fs::write(dir.path().join("large.txt"), vec![b'x'; 10 * 1024 * 1024]).unwrap();
  let large = run(dir.path(), &["generate", "large.txt", "-a", "sha3-123"]);
  assert_eq!(code(&large), Some(2));
  assert!(!dir.path().join("cryptoknife.log").exists());
}

#[test]
fn invalid_jobs_and_memory_exit_two() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  assert_eq!(
    code(&run(dir.path(), &["generate", "data.txt", "--jobs", "0"])),
    Some(2)
  );
  assert_eq!(
    code(&run(dir.path(), &["generate", "data.txt", "--jobs", "65"])),
    Some(2)
  );
  assert_eq!(
    code(&run(
      dir.path(),
      &["generate", "data.txt", "--jobs", "64", "-b", "16777216"]
    )),
    Some(2)
  );
}

#[test]
fn existing_sidecar_preserved_and_force_replaces() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  let sidecar = dir.path().join("data.txt.blake3");
  std::fs::write(&sidecar, "SENTINEL").unwrap();
  let gen = run(dir.path(), &["generate", "data.txt"]);
  assert_eq!(code(&gen), Some(3));
  assert_eq!(std::fs::read_to_string(&sidecar).unwrap(), "SENTINEL");
  let forced = run(dir.path(), &["generate", "data.txt", "--force"]);
  assert_eq!(code(&forced), Some(0));
  assert_ne!(std::fs::read_to_string(&sidecar).unwrap(), "SENTINEL");
  let ver = run(dir.path(), &["verify", "data.txt"]);
  assert_eq!(code(&ver), Some(0));
}

#[test]
fn destination_directory_exits_three() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  std::fs::create_dir(dir.path().join("data.txt.blake3")).unwrap();
  let gen = run(dir.path(), &["generate", "data.txt", "--force"]);
  assert_eq!(code(&gen), Some(3));
  assert!(dir.path().join("data.txt.blake3").is_dir());
}

#[cfg(unix)]
#[test]
fn destination_symlink_exits_three_without_touching_target() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  std::fs::write(dir.path().join("target.txt"), "TARGET").unwrap();
  std::os::unix::fs::symlink(
    dir.path().join("target.txt"),
    dir.path().join("data.txt.blake3"),
  )
  .unwrap();
  for extra in [&[][..], &["--force"][..]] {
    let mut args = vec!["generate", "data.txt"];
    args.extend_from_slice(extra);
    let gen = run(dir.path(), &args);
    assert_eq!(code(&gen), Some(3));
    assert_eq!(
      std::fs::read_to_string(dir.path().join("target.txt")).unwrap(),
      "TARGET"
    );
    assert!(
      std::fs::symlink_metadata(dir.path().join("data.txt.blake3"))
        .unwrap()
        .file_type()
        .is_symlink()
    );
  }
}

#[test]
fn dotless_name_generates_and_sidecars_are_skipped() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("mysfv"), "hello world").unwrap();
  let gen = run(dir.path(), &["generate", "mysfv"]);
  assert_eq!(code(&gen), Some(0));
  assert!(dir.path().join("mysfv.blake3").exists());
  let regen = run(dir.path(), &["generate", ".", "-v", "--force"]);
  assert_eq!(code(&regen), Some(0));
  let stdout = String::from_utf8_lossy(&regen.stdout);
  assert_eq!(stdout.matches("[GENERATED]").count(), 1);
  assert!(!dir.path().join("mysfv.blake3.blake3").exists());
}

#[test]
fn overlapping_inputs_emit_single_result() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  let gen = run(dir.path(), &["generate", ".", "data.txt", "-v"]);
  assert_eq!(code(&gen), Some(0));
  let stdout = String::from_utf8_lossy(&gen.stdout);
  assert_eq!(stdout.matches("[GENERATED]").count(), 1);
}

#[test]
fn recursive_generate_then_verify_succeeds() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("a.txt"), "a").unwrap();
  std::fs::create_dir(dir.path().join("sub")).unwrap();
  std::fs::write(dir.path().join("sub/b.txt"), "b").unwrap();
  let gen = run(dir.path(), &["generate", "."]);
  assert_eq!(code(&gen), Some(0));
  let ver = run(dir.path(), &["verify", "."]);
  assert_eq!(code(&ver), Some(0));
  assert!(!dir.path().join("cryptoknife.log").exists());
  assert!(!dir.path().join("cryptoknife.log.blake3").exists());
}

#[test]
fn uppercase_sidecar_accepted() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
  assert_eq!(code(&run(dir.path(), &["generate", "data.txt"])), Some(0));
  let sidecar = dir.path().join("data.txt.blake3");
  let digest = std::fs::read_to_string(&sidecar).unwrap();
  std::fs::write(&sidecar, digest.to_uppercase()).unwrap();
  let ver = run(dir.path(), &["verify", "data.txt"]);
  assert_eq!(code(&ver), Some(0));
}

#[test]
fn malformed_sidecars_exit_three() {
  for (name, content) in [
    ("short", "abcd".to_string()),
    (
      "nonhex",
      "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(),
    ),
    ("toolong", "a".repeat(5000)),
  ] {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("data.txt"), "hello world").unwrap();
    std::fs::write(dir.path().join("data.txt.blake3"), content).unwrap();
    let ver = run(dir.path(), &["verify", "data.txt"]);
    assert_eq!(code(&ver), Some(3), "case {}", name);
  }
}

#[test]
fn paths_with_spaces_and_unicode_work() {
  let dir = tempfile::tempdir().unwrap();
  let spaced = dir.path().join("meu arquivo ç.txt");
  std::fs::write(&spaced, "hello world").unwrap();
  assert_eq!(
    code(&run(dir.path(), &["generate", "meu arquivo ç.txt"])),
    Some(0)
  );
  assert!(dir.path().join("meu arquivo ç.txt.blake3").exists());
  assert_eq!(
    code(&run(dir.path(), &["verify", "meu arquivo ç.txt"])),
    Some(0)
  );
}

#[cfg(unix)]
#[test]
fn non_utf8_name_sidecar_byte_preserved() {
  use std::ffi::OsStr;
  use std::os::unix::ffi::OsStrExt;
  let dir = tempfile::tempdir().unwrap();
  let name = OsStr::from_bytes(b"bad\xffname.bin");
  let file = dir.path().join(name);
  if let Err(error) = std::fs::write(&file, "hello world") {
    if cfg!(target_os = "macos") && error.raw_os_error() == Some(92) {
      eprintln!("Fixture não UTF-8 indisponível neste filesystem: {error}");
      return;
    }
    panic!("Falha inesperada ao criar fixture não UTF-8: {error}");
  }
  let gen = bin()
    .arg("generate")
    .arg(&file)
    .current_dir(dir.path())
    .output()
    .unwrap();
  assert_eq!(code(&gen), Some(0));
  let mut sidecar_name = name.to_os_string();
  sidecar_name.push(".blake3");
  assert!(dir.path().join(sidecar_name).exists());
  let ver = bin()
    .arg("verify")
    .arg(&file)
    .current_dir(dir.path())
    .output()
    .unwrap();
  assert_eq!(code(&ver), Some(0));
}

#[cfg(unix)]
#[test]
fn explicit_symlink_input_rejected_and_nested_not_followed() {
  let dir = tempfile::tempdir().unwrap();
  std::fs::write(dir.path().join("real.txt"), "hello world").unwrap();
  std::os::unix::fs::symlink(dir.path().join("real.txt"), dir.path().join("link.txt")).unwrap();
  let gen = run(dir.path(), &["generate", "link.txt"]);
  assert_eq!(code(&gen), Some(3));
  assert!(!dir.path().join("link.txt.blake3").exists());
  let gen_dir = run(dir.path(), &["generate", ".", "-v"]);
  assert_eq!(code(&gen_dir), Some(0));
  let stdout = String::from_utf8_lossy(&gen_dir.stdout);
  assert_eq!(stdout.matches("[GENERATED]").count(), 1);
  assert!(!dir.path().join("link.txt.blake3").exists());
}

#[cfg(unix)]
#[test]
fn traversal_error_reported() {
  use std::os::unix::fs::PermissionsExt;
  let dir = tempfile::tempdir().unwrap();
  let blocked = dir.path().join("blocked");
  std::fs::create_dir(&blocked).unwrap();
  std::fs::write(blocked.join("inside.txt"), "x").unwrap();
  std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();
  if std::fs::read_dir(&blocked).is_ok() {
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755)).unwrap();
    eprintln!("Fixture de acesso negado indisponível: processo consegue ler diretório 000");
    return;
  }
  let gen = run(dir.path(), &["generate", "."]);
  std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755)).unwrap();
  assert_eq!(code(&gen), Some(3));
  let stderr = String::from_utf8_lossy(&gen.stderr);
  assert!(stderr.contains("READ-ERROR"), "stderr: {}", stderr);
}
