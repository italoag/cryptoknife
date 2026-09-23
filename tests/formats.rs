use cryptoknife_lib::formats::{
  parse_digest, portable_rel_path, validate_rel_path, ManifestIter, SfvIter,
};
use cryptoknife_lib::Algorithm;
use std::io::BufReader;
use std::path::{Path, PathBuf};

fn manifest_reader(text: &str) -> ManifestIter<BufReader<&[u8]>> {
  ManifestIter::new(BufReader::new(text.as_bytes()))
}

#[test]
fn parse_digest_accepts_upper_and_validates_length() {
  let digest = parse_digest("0D4A1185", Algorithm::CRC32).unwrap();
  assert_eq!(digest, vec![0x0d, 0x4a, 0x11, 0x85]);
  assert!(parse_digest("0d4a11", Algorithm::CRC32).is_err());
  assert!(parse_digest("zzzzzzzz", Algorithm::CRC32).is_err());
  assert!(parse_digest("0d4a1185", Algorithm::BLAKE3).is_err());
}

#[test]
fn portable_rel_path_rules() {
  assert_eq!(portable_rel_path(Path::new("a/b.txt")).unwrap(), "a/b.txt");
  assert!(portable_rel_path(Path::new("../x")).is_err());
  assert!(portable_rel_path(Path::new("/abs")).is_err());
  #[cfg(not(windows))]
  assert!(portable_rel_path(Path::new("a\\b")).is_err());
  #[cfg(windows)]
  assert_eq!(portable_rel_path(Path::new("a\\b")).unwrap(), "a/b");
  assert!(portable_rel_path(Path::new("a:b")).is_err());
  assert!(portable_rel_path(Path::new("")).is_err());
}

#[test]
fn validate_rel_path_rejects_escapes() {
  assert!(validate_rel_path("data.txt").is_ok());
  assert!(validate_rel_path("sub/dir/f.bin").is_ok());
  assert!(validate_rel_path("../escape").is_err());
  assert!(validate_rel_path("/absolute").is_err());
  assert!(validate_rel_path("C:\\win").is_err());
  assert!(validate_rel_path("back\\slash").is_err());
  assert!(validate_rel_path("a/./b").is_err());
  assert!(validate_rel_path("").is_err());
  assert!(validate_rel_path("nul\0l").is_err());
}

#[test]
fn manifest_roundtrip_entries() {
  let doc = concat!(
    "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n",
    "{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"data.txt\",\"digest\":\"D74981EFA70A0C880B8D8C1985D075DBCBF679B99A5F9914E5AAF96B831A9E24\"}\n",
    "{\"type\":\"end\",\"entries\":1}\n"
  );
  let entries: Vec<_> = manifest_reader(doc).collect();
  assert_eq!(entries.len(), 1);
  let entry = entries[0].as_ref().unwrap();
  assert_eq!(entry.path, PathBuf::from("data.txt"));
  assert_eq!(entry.algorithm, Algorithm::BLAKE3);
  assert_eq!(
    entry.digest,
    "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
  );
}

#[test]
fn manifest_rejects_truncated_and_bad_docs() {
  // sem footer
  let truncated = concat!(
    "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n",
    "{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"a\",\"digest\":\"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24\"}\n"
  );
  let results: Vec<_> = manifest_reader(truncated).collect();
  assert!(results.iter().any(|r| r.is_err()));

  // contagem divergente
  let bad_count = concat!(
    "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n",
    "{\"type\":\"end\",\"entries\":5}\n"
  );
  let results: Vec<_> = manifest_reader(bad_count).collect();
  assert!(results.iter().any(|r| r.is_err()));

  // versão desconhecida
  let bad_version = "{\"schema_version\":2,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n";
  let results: Vec<_> = manifest_reader(bad_version).collect();
  assert!(results.iter().any(|r| r.is_err()));

  // linha malformada
  let malformed = concat!(
    "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n",
    "not json\n"
  );
  let results: Vec<_> = manifest_reader(malformed).collect();
  assert!(results.iter().any(|r| r.is_err()));

  // vazio
  let results: Vec<_> = manifest_reader("").collect();
  assert!(results.iter().any(|r| r.is_err()));

  // caminho absoluto
  let abs = concat!(
    "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n",
    "{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"/etc/passwd\",\"digest\":\"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24\"}\n",
    "{\"type\":\"end\",\"entries\":1}\n"
  );
  let results: Vec<_> = manifest_reader(abs).collect();
  assert!(results.iter().any(|r| r.is_err()));

  // linha acima do limite de 64KiB
  let oversized = format!(
    "{{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}}\n{}\n",
    "x".repeat(70 * 1024)
  );
  let results: Vec<_> = manifest_reader(&oversized).collect();
  assert!(results.iter().any(|r| r.is_err()));
}

#[test]
fn sfv_parses_entries_comments_and_crlf() {
  let doc = "; comment\n\ndata.txt 0D4A1185\r\nsub file.bin  12345678\n";
  let entries: Vec<_> = SfvIter::new(BufReader::new(doc.as_bytes())).collect();
  assert_eq!(entries.len(), 2);
  let first = entries[0].as_ref().unwrap();
  assert_eq!(first.path, PathBuf::from("data.txt"));
  assert_eq!(first.algorithm, Algorithm::CRC32);
  assert_eq!(first.digest, "0d4a1185");
  let second = entries[1].as_ref().unwrap();
  assert_eq!(second.path, PathBuf::from("sub file.bin"));
  assert_eq!(second.digest, "12345678");
}

#[test]
fn sfv_rejects_bad_lines() {
  let bad = "data.txt nothex!!\n";
  let entries: Vec<_> = SfvIter::new(BufReader::new(bad.as_bytes())).collect();
  assert!(entries.iter().any(|r| r.is_err()));
}

struct CountingReader {
  inner: std::io::Cursor<Vec<u8>>,
  reads: std::rc::Rc<std::cell::Cell<usize>>,
}

impl std::io::Read for CountingReader {
  fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
    self.inner.read(buf)
  }
}

impl std::io::BufRead for CountingReader {
  fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
    self.reads.set(self.reads.get() + 1);
    self.inner.fill_buf()
  }
  fn consume(&mut self, amt: usize) {
    self.inner.consume(amt)
  }
  fn read_until(&mut self, byte: u8, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    self.reads.set(self.reads.get() + 1);
    self.inner.read_until(byte, buf)
  }
}

#[test]
fn manifest_fused_after_error_no_more_reads() {
  let reads = std::rc::Rc::new(std::cell::Cell::new(0));
  let doc = "not json\nrest\n".to_string();
  let mut iter = ManifestIter::new(CountingReader {
    inner: std::io::Cursor::new(doc.into_bytes()),
    reads: reads.clone(),
  });
  assert!(iter.next().unwrap().is_err());
  let after_err = reads.get();
  assert!(after_err > 0);
  assert!(iter.next().is_none());
  assert!(iter.next().is_none());
  assert_eq!(reads.get(), after_err);
}

#[test]
fn manifest_rejects_trailing_records() {
  let digest = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
  let entry = format!(
    "{{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"a\",\"digest\":\"{}\"}}\n",
    digest
  );
  let header = "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n";
  let end = "{\"type\":\"end\",\"entries\":1}\n";

  // registro após footer
  let doc = format!("{}{}{}{}", header, entry, end, entry);
  let results: Vec<_> = manifest_reader(&doc).collect();
  assert!(results.iter().any(|r| r.is_err()));

  // segundo footer
  let doc = format!("{}{}{}{}", header, entry, end, end);
  let results: Vec<_> = manifest_reader(&doc).collect();
  assert!(results.iter().any(|r| r.is_err()));

  // segundo header após footer
  let doc = format!("{}{}{}{}", header, entry, end, header);
  let results: Vec<_> = manifest_reader(&doc).collect();
  assert!(results.iter().any(|r| r.is_err()));

  // linhas em branco após footer são aceitas
  let doc = format!("{}{}{}\n  \n", header, entry, end);
  let results: Vec<_> = manifest_reader(&doc).collect();
  assert_eq!(results.len(), 1);
  assert!(results[0].is_ok());
}

#[test]
fn manifest_rejects_duplicate_json_keys() {
  let doc = concat!(
    "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n",
    "{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"a\",\"path\":\"b\",\"digest\":\"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24\"}\n",
    "{\"type\":\"end\",\"entries\":1}\n"
  );
  let results: Vec<_> = manifest_reader(doc).collect();
  assert!(results.iter().any(|r| r.is_err()));
}

#[test]
fn manifest_rejects_duplicate_entries() {
  let entry = "{\"type\":\"checksum\",\"algorithm\":\"blake3\",\"path\":\"a\",\"digest\":\"d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24\"}\n";
  let doc = format!(
    "{}{}{}{}",
    "{\"schema_version\":1,\"type\":\"manifest\",\"format\":\"cryptoknife\"}\n",
    entry,
    entry,
    "{\"type\":\"end\",\"entries\":2}\n"
  );
  let results: Vec<_> = manifest_reader(&doc).collect();
  assert!(results.iter().any(|r| r.is_err()));
}

#[test]
fn sfv_rejects_duplicate_names() {
  for doc in [
    "a.txt 0D4A1185\na.txt 0D4A1185\n",
    "a.txt 0D4A1185\na.txt 12345678\n",
  ] {
    let entries: Vec<_> = SfvIter::new(BufReader::new(doc.as_bytes())).collect();
    assert!(
      entries.iter().any(|r| r.is_err()),
      "documento {:?} deve falhar",
      doc
    );
  }
}

#[test]
fn sfv_accepts_trailing_whitespace() {
  let doc = "data.txt 0D4A1185   \n";
  let entries: Vec<_> = SfvIter::new(BufReader::new(doc.as_bytes())).collect();
  assert_eq!(entries.len(), 1);
  let e = entries[0].as_ref().unwrap();
  assert_eq!(e.path, PathBuf::from("data.txt"));
  assert_eq!(e.digest, "0d4a1185");
}

#[test]
fn sfv_rejects_leading_name_whitespace() {
  let doc = "  data.txt 0D4A1185\n";
  let entries: Vec<_> = SfvIter::new(BufReader::new(doc.as_bytes())).collect();
  assert!(entries.iter().any(|r| r.is_err()));
}

#[test]
fn parse_sidecar_rules_by_algorithm() {
  use cryptoknife_lib::formats::parse_sidecar;
  use std::ffi::OsStr;
  // digest isolado para todos
  assert!(parse_sidecar("0D4A1185\n", Algorithm::CRC32, None).is_ok());
  // CRC32 convencional exige nome igual ao arquivo de dados
  assert!(parse_sidecar(
    "data.txt 0D4A1185\n",
    Algorithm::CRC32,
    Some(OsStr::new("data.txt"))
  )
  .is_ok());
  assert!(parse_sidecar(
    "outro.txt 0D4A1185\n",
    Algorithm::CRC32,
    Some(OsStr::new("data.txt"))
  )
  .is_err());
  // não-CRC aceita apenas digest isolado
  assert!(parse_sidecar(
    "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24\n",
    Algorithm::BLAKE3,
    Some(OsStr::new("data.txt"))
  )
  .is_ok());
  assert!(parse_sidecar(
    "data.txt d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24\n",
    Algorithm::BLAKE3,
    Some(OsStr::new("data.txt"))
  )
  .is_err());
}
